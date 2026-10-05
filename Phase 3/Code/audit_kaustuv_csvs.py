"""Read-only forensic audit of Phase 3 CSVs from Git repo commit 3239724.
Never writes to Git repo/. Usage: python audit_kaustuv_csvs.py
"""
import csv, os, statistics as st, datetime as dt

D = r"C:\Users\tapan\Downloads\7th sem Capstone\Git repo\Phase 3\DockerLab\simulation_results"
def rd(n): return list(csv.DictReader(open(os.path.join(D, n), newline="")))
def f(x):
    try: return float(x)
    except: return None
def ts(ns): return dt.datetime.fromtimestamp(int(ns) / 1e9, dt.timezone.utc).isoformat()

print("=== tcpdump_latency_summary.csv ===")
t = rd("tcpdump_latency_summary.csv")
print("rows", len(t), "sessions", sorted(set(r["session_id"] for r in t)))
print("epoch first/last", ts(t[0]["timestamp_epoch_ns"]), ts(t[-1]["timestamp_epoch_ns"]))
for s in sorted(set(r["session_id"] for r in t)):
    rs = [r for r in t if r["session_id"] == s]
    idx = [int(r["frame_idx"]) for r in rs]
    ifat = [f(r["ifat_us"]) for r in rs if f(r["ifat_us"]) is not None]
    jit = set(r["arrival_jitter_ns"] for r in rs)
    epoch = [int(r["timestamp_epoch_ns"]) for r in rs]
    rel = [f(r["timestamp_rel_us"]) for r in rs]
    # rel vs epoch consistency
    bad = sum(1 for a, b in zip(epoch, rel) if abs((a - epoch[0]) / 1000 - b) > 1)
    print(s, "n", len(rs), "idx", min(idx), max(idx), "expected_total", set(r["total_frames_expected"] for r in rs),
          "ifat set", sorted(set(ifat))[:5], "jitter", jit, "dur", set(r["frame_duration_us"] for r in rs),
          "rel/epoch mismatch", bad, "active", sorted(set(r["payload_active_bytes"] for r in rs)))
    if ifat:
        print("   ifat < frame_duration (physically impossible, frames overlap):",
              sum(1 for x in ifat if x < f(rs[0]["frame_duration_us"])))
print("distinct roles", set(r["frame_role"] for r in t), "protocols", set(r["protocol_name"] for r in t))

print("\n=== perf_stat_summary.csv ===")
p = rd("perf_stat_summary.csv")
print("rows", len(p), "cols", len(p[0]))
print("timestamps", [r[list(p[0])[1]] for r in p][:3], "...")
for r in p:
    k = list(r)
    print({c: r[c] for c in k[:1] + k[5:7] + k[8:12] if c in r})
vals = [f(v) for r in p for v in r.values() if f(v) is not None]
print("fraction of numeric values that are multiples of 1000:",
      round(sum(1 for v in vals if v == int(v) and int(v) % 1000 == 0) / len(vals), 2))
print("dupe rows (ascon decrypt/tag verify identical metrics):")
a = {k: v for k, v in p[2].items() if k not in list(p[2])[:8]}
b = {k: v for k, v in p[6].items() if k not in list(p[6])[:8]}
print("  BM_003 vs BM_007 identical numeric tail:", a == b)

print("\n=== fault_recovery_runs.csv ===")
fr = rd("fault_recovery_runs.csv")
print("rows", len(fr))
for r in fr:
    sent = int(r["initial_frames_sent"]) + int(r["retransmitted_frames_count"]) + int(r["control_frames_count"])
    tot = int(r["total_frames_on_wire"])
    lat = f(r["end_to_end_latency_us"]); nom = f(r["nominal_clean_time_us"]); ov = f(r["recovery_overhead_latency_us"])
    flags = []
    if sent != tot: flags.append(f"frames {sent}!={tot}")
    if abs((nom or 0) + (ov or 0) - (lat or 0)) > 1: flags.append(f"lat {nom}+{ov}!={lat}")
    if lat and lat > 50000 and r["ftti_violation_flag"] == "False": flags.append("ftti flag wrong")
    print(r["run_id"], r["scenario_name"][:28], r["protocol_name"][:10], "p=", r["channel_loss_rate_p"],
          "lat_us", lat, "recov", r["recovery_success"], r["termination_status_code"], flags)
