import os
import sys
import time
import json
import glob
import numpy as np
import pandas as pd

# Required imports
try:
    import torch
    import torch.nn as nn
    import onnxruntime as ort
    from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score, confusion_matrix
except ImportError:
    pass

print("=" * 85)
print("REAL CAN-FD TELEMETRY EVALUATION & RASPBERRY PI 4 LATENCY SIMULATION")
print("=" * 85)

TARGET_DIR = r"c:\Users\tapan\Downloads\7th sem Capstone\Anti Gravity\Phase 2\models\Physical Kinematics IDS FINAL\ONNX Optimized"
FP32_ONNX_PATH = os.path.join(TARGET_DIR, "v30_physical_kinematics_fp32.onnx")
INT8_ONNX_PATH = os.path.join(TARGET_DIR, "v30_physical_kinematics_dynamic_int8.onnx")
PTH_PATH = os.path.join(TARGET_DIR, "lstm_physical_autoencoder.pth")
SCALER_PATH = os.path.join(TARGET_DIR, "physical_scaler_config.json")
THRESH_PATH = os.path.join(TARGET_DIR, "physical_anomaly_threshold.json")

# 1. 14D Kinematic Extractor Logic (Matching GatewayIDSExtractor)
PHYSICAL_FEATURE_NAMES = [
    'vehicle_speed', 'engine_rpm', 'steering_angle', 'brake_pressure',
    'wheel_speed_fl', 'wheel_speed_fr', 'wheel_speed_rl', 'wheel_speed_rr',
    'coolant_temp', 'loo_wheel_fl', 'loo_wheel_fr', 'loo_wheel_rl', 'loo_wheel_rr',
    'speed_wheel_delta'
]
NUM_FEATURES = len(PHYSICAL_FEATURE_NAMES)
SEQ_LEN = 30

def parse_vectorized_telemetry(df: pd.DataFrame) -> np.ndarray:
    can_ids = df['ID']
    out = pd.DataFrame(index=df.index)
    
    # 0x0D0 (208): Speed & RPM - Causal ZOH
    s_spd = pd.Series(np.nan, index=df.index, dtype=np.float32)
    s_rpm = pd.Series(np.nan, index=df.index, dtype=np.float32)
    mask_208 = (can_ids == 208)
    if 'Signal_6_of_ID' in df.columns: s_spd[mask_208] = df.loc[mask_208, 'Signal_6_of_ID']
    if 'Signal_2_of_ID' in df.columns: s_rpm[mask_208] = df.loc[mask_208, 'Signal_2_of_ID']
    out['speed'] = s_spd.ffill().fillna(0.0)
    out['rpm'] = s_rpm.ffill().fillna(600.0)
    
    # 0x354 (852): Steering & Brake - Causal ZOH
    s_steer = pd.Series(np.nan, index=df.index, dtype=np.float32)
    s_brake = pd.Series(np.nan, index=df.index, dtype=np.float32)
    mask_852 = (can_ids == 852)
    if 'Signal_1_of_ID' in df.columns: s_steer[mask_852] = df.loc[mask_852, 'Signal_1_of_ID']
    if 'Signal_3_of_ID' in df.columns: s_brake[mask_852] = df.loc[mask_852, 'Signal_3_of_ID']
    out['steering'] = s_steer.ffill().fillna(32768.0)
    out['brake'] = s_brake.ffill().fillna(120.0)
    
    # 0x6E0 (1760): 4 Wheels - Causal ZOH
    mask_1760 = (can_ids == 1760)
    for col, name in [('Signal_1_of_ID', 'wheel_fl'), ('Signal_2_of_ID', 'wheel_fr'), ('Signal_3_of_ID', 'wheel_rl'), ('Signal_4_of_ID', 'wheel_rr')]:
        s_w = pd.Series(np.nan, index=df.index, dtype=np.float32)
        if col in df.columns: s_w[mask_1760] = df.loc[mask_1760, col]
        out[name] = s_w.ffill().fillna(0.0)
        
    # 0x4E7 (1255): Coolant - Causal ZOH
    s_cool = pd.Series(np.nan, index=df.index, dtype=np.float32)
    mask_1255 = (can_ids == 1255)
    if 'Signal_2_of_ID' in df.columns: s_cool[mask_1255] = df.loc[mask_1255, 'Signal_2_of_ID']
    out['coolant'] = s_cool.ffill().fillna(140.0)
    
    fl = out['wheel_fl'].values; fr = out['wheel_fr'].values; rl = out['wheel_rl'].values; rr = out['wheel_rr'].values
    med_not_fl = np.median(np.column_stack([fr, rl, rr]), axis=1)
    med_not_fr = np.median(np.column_stack([fl, rl, rr]), axis=1)
    med_not_rl = np.median(np.column_stack([fl, fr, rr]), axis=1)
    med_not_rr = np.median(np.column_stack([fl, fr, rl]), axis=1)
    
    out['loo_wheel_fl'] = np.abs(fl - med_not_fl).astype(np.float32)
    out['loo_wheel_fr'] = np.abs(fr - med_not_fr).astype(np.float32)
    out['loo_wheel_rl'] = np.abs(rl - med_not_rl).astype(np.float32)
    out['loo_wheel_rr'] = np.abs(rr - med_not_rr).astype(np.float32)
    
    mean_wheels = (fl + fr + rl + rr) / 4.0
    out['speed_wheel_delta'] = np.abs(out['speed'].values - mean_wheels).astype(np.float32)
    return out.values.astype(np.float32)

class PhysicalKinematicsScaler:
    def __init__(self, window_size: int = 30):
        self.window_size = window_size
        self.min_vals = np.array([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], dtype=np.float32)
        self.max_vals = np.array([4000.0, 8000.0, 65535.0, 255.0, 4000.0, 4000.0, 4000.0, 4000.0, 255.0, 1000.0, 1000.0, 1000.0, 1000.0, 1000.0], dtype=np.float32)
        self.diff_vals = self.max_vals - self.min_vals

    def transform(self, raw_matrix: np.ndarray) -> np.ndarray:
        return (raw_matrix - self.min_vals) / self.diff_vals

def sliding_windows(data, w=30):
    n = len(data) - w + 1
    if n <= 0: return np.empty((0, w, data.shape[1]), dtype=np.float32)
    strides = (data.strides[0], data.strides[0], data.strides[1])
    return np.lib.stride_tricks.as_strided(data, shape=(n, w, data.shape[1]), strides=strides)

print("Real Telemetry Ingestion Pipeline Initialized.")
