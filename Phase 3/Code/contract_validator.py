"""
contract_validator.py
=====================
Automated validation engine for Phase 3 Data Contracts.
Loads config/data_contract_schemas.json and validates CSV data handoffs against:
- Column presence, order, and count
- Data types (uint, int, float, string, boolean)
- Enum values and regex patterns
- Numeric boundary ranges (including ISO 26262 / ASIL-D zero major page fault constraints)
- Nullability rules
"""

import os
import csv
import json
import re
from typing import Dict, List, Tuple, Any, Optional

class DataContractValidator:
    def __init__(self, schema_path: Optional[str] = None):
        if schema_path is None:
            # Default to config/data_contract_schemas.json relative to project root
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            schema_path = os.path.join(base_dir, 'config', 'data_contract_schemas.json')
        
        self.schema_path = schema_path
        with open(schema_path, 'r', encoding='utf-8') as f:
            self.schema_data = json.load(f)
        
        self.contracts = self.schema_data.get('contracts', {})

    def get_contract_names(self) -> List[str]:
        return list(self.contracts.keys())

    def validate_csv(self, contract_name: str, csv_path: str) -> Tuple[bool, List[str]]:
        """
        Validates a CSV file against the specified contract schema.
        Returns (is_valid, list_of_error_strings).
        """
        errors = []
        if contract_name not in self.contracts:
            return False, [f"Contract '{contract_name}' not defined in schema. Valid contracts: {list(self.contracts.keys())}"]
        
        if not os.path.exists(csv_path):
            return False, [f"CSV file not found: {csv_path}"]
        
        contract_spec = self.contracts[contract_name]
        col_specs = contract_spec.get('columns', {})
        expected_cols = list(col_specs.keys())

        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            try:
                header = next(reader)
            except StopIteration:
                return False, [f"CSV file is completely empty: {csv_path}"]

            # 1. Header validation
            if header != expected_cols:
                missing = [c for c in expected_cols if c not in header]
                extra = [c for c in header if c not in expected_cols]
                if missing:
                    errors.append(f"Header missing expected columns: {missing}")
                if extra:
                    errors.append(f"Header contains unexpected extra columns: {extra}")
                if len(header) != len(expected_cols):
                    errors.append(f"Header column count mismatch: got {len(header)}, expected {len(expected_cols)}")
                if not missing and not extra:
                    errors.append(f"Header column order mismatch: got {header}, expected {expected_cols}")
                if len(errors) > 5:
                    return False, errors

            # 2. Row by row validation
            row_idx = 1
            for row in reader:
                row_idx += 1
                if not row or (len(row) == 1 and row[0].strip() == ''):
                    continue  # Skip empty trailing lines
                
                if len(row) != len(header):
                    errors.append(f"Row {row_idx}: column count mismatch (got {len(row)}, expected {len(header)})")
                    continue

                for col_name, raw_val in zip(header, row):
                    if col_name not in col_specs:
                        continue
                    spec = col_specs[col_name]
                    val_str = raw_val.strip()
                    
                    # Nullability check: only truly empty string '' or explicit 'null' count as null
                    is_nullable = spec.get('nullable', False)
                    if val_str == '' or val_str.lower() == 'null':
                        if not is_nullable:
                            errors.append(f"Row {row_idx}, Column '{col_name}': Non-nullable field is empty/null")
                        continue

                    # Type and value checks
                    col_type = spec.get('type')
                    typed_val = None

                    # Boolean
                    if col_type == 'boolean':
                        if val_str.lower() in ('true', '1', 't', 'yes'):
                            typed_val = True
                        elif val_str.lower() in ('false', '0', 'f', 'no'):
                            typed_val = False
                        else:
                            errors.append(f"Row {row_idx}, Column '{col_name}': Invalid boolean '{val_str}'")
                            continue

                    # Integers (uint8, uint16, uint32, uint64, int64)
                    elif 'int' in col_type:
                        try:
                            typed_val = int(val_str)
                        except ValueError:
                            errors.append(f"Row {row_idx}, Column '{col_name}': Value '{val_str}' cannot be parsed as integer ({col_type})")
                            continue
                        
                        if col_type.startswith('uint') and typed_val < 0:
                            errors.append(f"Row {row_idx}, Column '{col_name}': Unsigned integer cannot be negative ({typed_val})")

                    # Floats
                    elif col_type == 'float64' or col_type == 'float':
                        try:
                            typed_val = float(val_str)
                        except ValueError:
                            errors.append(f"Row {row_idx}, Column '{col_name}': Value '{val_str}' cannot be parsed as float")
                            continue

                    # Strings
                    elif col_type == 'string':
                        typed_val = val_str

                    # Enum validation
                    if 'enum' in spec:
                        allowed_enum = spec['enum']
                        if typed_val not in allowed_enum and str(typed_val) not in allowed_enum:
                            errors.append(f"Row {row_idx}, Column '{col_name}': Value '{typed_val}' not in allowed enum {allowed_enum}")

                    # Regex validation
                    if 'validation' in spec and isinstance(spec['validation'], str):
                        pattern = spec['validation']
                        if not re.match(pattern, str(raw_val)):
                            errors.append(f"Row {row_idx}, Column '{col_name}': Value '{raw_val}' does not match regex pattern '{pattern}'")

                    # Range / Min / Max / Allowed list validation
                    if 'validation' in spec and isinstance(spec['validation'], dict):
                        v_rules = spec['validation']
                        if 'min' in v_rules and typed_val is not None:
                            if typed_val < v_rules['min']:
                                errors.append(f"Row {row_idx}, Column '{col_name}': Value {typed_val} violates min bound ({v_rules['min']})")
                        if 'max' in v_rules and typed_val is not None:
                            if typed_val > v_rules['max']:
                                errors.append(f"Row {row_idx}, Column '{col_name}': Value {typed_val} violates max bound ({v_rules['max']})")
                        if 'allowed' in v_rules and typed_val is not None:
                            if typed_val not in v_rules['allowed']:
                                errors.append(f"Row {row_idx}, Column '{col_name}': Value {typed_val} not in allowed set {v_rules['allowed']}")
                        if 'asil_d_constraint' in v_rules and v_rules['asil_d_constraint'] == 'MUST_BE_ZERO_IN_STEADY_STATE':
                            if typed_val != 0:
                                errors.append(f"Row {row_idx}, Column '{col_name}': ASIL-D VIOLATION: Major page faults must be 0, got {typed_val}")

        is_valid = (len(errors) == 0)
        return is_valid, errors

if __name__ == '__main__':
    validator = DataContractValidator()
    print("Validator initialized with contracts:", validator.get_contract_names())
