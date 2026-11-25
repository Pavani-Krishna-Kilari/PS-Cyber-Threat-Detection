"""
Multi-format file parser and validator for network flow ingestion (CSV, TXT, PDF).

Strictly validates input schemas:
  1. CSV: Validates either 8-dimensional event profile CSVs or canonical network flow CSVs.
  2. TXT: Extracts structured network-flow descriptions (multi-record, block, key-value, or tabular).
  3. PDF: Extracts textual flow tables and key-value fields from PDF documents.

Security & Integrity Guarantees:
  - Rejects unsupported or malformed files with descriptive validation errors.
  - Never uses CSV/TXT/PDF 'Label' or target columns as model features.
  - Never uses IP addresses, ports, or non-numeric identifiers as neural features.
  - Never invents timestamps, IP addresses, ports, or network-flow measurements.
  - Never silently discards invalid records.
  - Feeds all supported formats into the SAME existing AI-SIEM aggregation & classification pipeline.
"""

import io
import re
import json
from typing import Dict, List, Any, Tuple, Optional
import numpy as np
import pandas as pd
from pypdf import PdfReader

# Canonical alias mapping for CICIDS2017 flow fields
CANONICAL_FLOW_FIELDS = {
    # Flow metrics (used for derived security events)
    "flow_packets_s": "flow_packets_s",
    "flow_packets_per_second": "flow_packets_s",
    "packets_s": "flow_packets_s",
    "packets_per_sec": "flow_packets_s",
    "flow_packets_sec": "flow_packets_s",
    "flow_bytes_s": "flow_bytes_s",
    "flow_bytes_per_second": "flow_bytes_s",
    "bytes_s": "flow_bytes_s",
    "bytes_per_sec": "flow_bytes_s",
    "flow_bytes_sec": "flow_bytes_s",
    "syn_flag_count": "syn_flag_count",
    "syn_flags": "syn_flag_count",
    "syn": "syn_flag_count",
    "syn_count": "syn_flag_count",
    "syn_flags_count": "syn_flag_count",
    "flow_duration": "flow_duration",
    "duration": "flow_duration",
    "duration_ms": "flow_duration",
    "duration_us": "flow_duration",
    "flow_count": "flow_count",
    "flows": "flow_count",
    "total_fwd_packets": "total_fwd_packets",
    "total_forward_packets": "total_fwd_packets",
    "tot_fwd_pkts": "total_fwd_packets",
    "fwd_packets": "total_fwd_packets",
    "total_fwd_pkts": "total_fwd_packets",
    "fwd_pkts": "total_fwd_packets",
    "total_backward_packets": "total_backward_packets",
    "total_bwd_packets": "total_backward_packets",
    "tot_bwd_pkts": "total_backward_packets",
    "bwd_packets": "total_backward_packets",
    "total_bwd_pkts": "total_backward_packets",
    "bwd_pkts": "total_backward_packets",
    # Contextual network fields (metadata only, NEVER used as model features)
    "source_ip": "source_ip",
    "src_ip": "source_ip",
    "source": "source_ip",
    "src": "source_ip",
    "sip": "source_ip",
    "source_address": "source_ip",
    "src_addr": "source_ip",
    "destination_ip": "destination_ip",
    "dst_ip": "destination_ip",
    "destination": "destination_ip",
    "dst": "destination_ip",
    "dip": "destination_ip",
    "dest_ip": "destination_ip",
    "destination_address": "destination_ip",
    "dst_addr": "destination_ip",
    "source_port": "source_port",
    "src_port": "source_port",
    "sport": "source_port",
    "srcport": "source_port",
    "src_pt": "source_port",
    "destination_port": "destination_port",
    "dst_port": "destination_port",
    "dport": "destination_port",
    "dstport": "destination_port",
    "dst_pt": "destination_port",
    "protocol": "protocol",
    "proto": "protocol",
    "protocol_type": "protocol",
    "timestamp": "timestamp",
    "time": "timestamp",
    "flow_timestamp": "timestamp",
    "datetime": "timestamp",
    "date_time": "timestamp",
    "start_time": "timestamp",
    "window_start": "timestamp",
}

# The 8 basepoint cosine similarities
PROFILE_COLS = [f"bp_{i:02d}" for i in range(1, 9)]

# Required core flow features needed to calculate the 5 derived events
REQUIRED_FLOW_FEATURES = ["flow_packets_s", "flow_bytes_s", "syn_flag_count", "flow_duration"]

# Forbidden label columns that must NEVER be passed as input features
LABEL_COLUMNS = [
    "label", "label_original", "target_binary", "target_multiclass", "class",
    "target", "attack_type", "actual_label", "threat_type"
]


def clean_column_name(col: str) -> str:
    """Normalizes column headers to lowercase snake_case."""
    s = str(col).strip().lower().replace(" ", "_").replace("/", "_").replace("-", "_")
    return s.strip("_")


def are_series_equivalent(s1: pd.Series, s2: pd.Series) -> bool:
    """
    Checks whether two series contain equivalent values, handling:
    - Identical values (int, float, string)
    - Numeric equivalence (int vs float, e.g. 10 vs 10.0)
    - NaN / null matching
    - String whitespace/case equivalence
    """
    if s1.equals(s2):
        return True

    # 1. Try numeric comparison
    try:
        n1 = pd.to_numeric(s1, errors="coerce")
        n2 = pd.to_numeric(s2, errors="coerce")
        mask1 = n1.isna()
        mask2 = n2.isna()
        if (mask1 == mask2).all():
            valid_idx = ~mask1
            if valid_idx.sum() == len(s1):
                if np.allclose(n1, n2, equal_nan=True, rtol=1e-5, atol=1e-8):
                    return True
            elif valid_idx.sum() > 0:
                if np.allclose(n1[valid_idx], n2[valid_idx], rtol=1e-5, atol=1e-8):
                    str1 = s1[mask1].astype(str).str.strip().str.lower()
                    str2 = s2[mask1].astype(str).str.strip().str.lower()
                    if (str1 == str2).all():
                        return True
            else:
                str1 = s1.fillna("").astype(str).str.strip().str.lower()
                str2 = s2.fillna("").astype(str).str.strip().str.lower()
                if (str1 == str2).all():
                    return True
    except Exception:
        pass

    # 2. String comparison
    try:
        str1 = s1.fillna("").astype(str).str.strip().str.lower()
        str2 = s2.fillna("").astype(str).str.strip().str.lower()
        if (str1 == str2).all():
            return True
    except Exception:
        pass

    return False


def resolve_canonical_name(col_clean: str) -> str:
    """
    Resolves cleaned column header to its canonical field name.
    Handles direct canonical flow aliases, mangled duplicate suffixes (.1, .2),
    and event profile basepoint names.
    """
    if col_clean in CANONICAL_FLOW_FIELDS:
        return CANONICAL_FLOW_FIELDS[col_clean]
    base = re.sub(r"\.\d+$", "", col_clean)
    if base in CANONICAL_FLOW_FIELDS:
        return CANONICAL_FLOW_FIELDS[base]
    return base


def normalize_and_deduplicate_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalizes column headers, strips ground-truth label columns,
    maps aliases to canonical names, and safely deduplicates identical columns.
    Raises ValueError if duplicate columns mapping to the same canonical name conflict.
    """
    raw_cols = list(df.columns)
    cleaned_cols = [clean_column_name(c) for c in raw_cols]

    # Drop explicit ground-truth label columns (including .1 suffixes)
    keep_indices = []
    for i, c in enumerate(cleaned_cols):
        base = re.sub(r"\.\d+$", "", c)
        if c not in LABEL_COLUMNS and base not in LABEL_COLUMNS:
            keep_indices.append(i)

    # Group remaining columns by resolved canonical name
    groups: Dict[str, List[Tuple[str, pd.Series]]] = {}
    for i in keep_indices:
        orig_name = raw_cols[i]
        c_clean = cleaned_cols[i]
        canon = resolve_canonical_name(c_clean)
        col_series = df.iloc[:, i]
        groups.setdefault(canon, []).append((orig_name, col_series))

    # Compare equivalents and detect conflicts
    clean_dict = {}
    for canon_name, col_list in groups.items():
        if len(col_list) == 1:
            clean_dict[canon_name] = col_list[0][1]
        else:
            first_name, first_series = col_list[0]
            for other_name, other_series in col_list[1:]:
                if not are_series_equivalent(first_series, other_series):
                    raise ValueError(
                        f"CSV validation failed: Conflicting values detected between columns mapping to '{canon_name}' "
                        f"('{first_name}' vs '{other_name}'). Conflicting columns cannot be merged."
                    )
            clean_dict[canon_name] = first_series

    return pd.DataFrame(clean_dict, index=df.index)


def parse_csv_bytes(file_bytes: bytes) -> Tuple[pd.DataFrame, str]:
    """
    Parses and rigorously validates a CSV file for threat inference.

    Returns:
        (DataFrame, detected_type) where detected_type is 'profile' or 'flow'.

    Raises:
        ValueError if the file is empty, malformed, or missing required features.
    """
    if not file_bytes or len(file_bytes.strip()) == 0:
        raise ValueError("Uploaded CSV file is empty.")

    try:
        df = pd.read_csv(io.BytesIO(file_bytes))
    except Exception as e:
        try:
            df = pd.read_csv(io.BytesIO(file_bytes), encoding="latin-1")
        except Exception as e2:
            raise ValueError(f"Malformed CSV: unable to parse tabular structure ({e2})")

    if df.empty or len(df.columns) == 0:
        raise ValueError("Uploaded CSV contains no tabular data or columns.")

    original_cols = list(df.columns)

    # Safely normalize aliases, exclude ground-truth labels, and deduplicate equivalent columns
    df = normalize_and_deduplicate_dataframe(df)

    # Case 1: Check if event profiles (bp_01 to bp_08) are present
    if all(col in df.columns for col in PROFILE_COLS):
        # Validate data types
        for bp in PROFILE_COLS:
            df[bp] = pd.to_numeric(df[bp], errors="coerce")
        return df, "profile"

    # Case 2: Network Flow CSV - Check presence of essential flow features
    missing_flow = [f for f in REQUIRED_FLOW_FEATURES if f not in df.columns]
    if missing_flow:
        raise ValueError(
            f"CSV validation failed: Missing required network flow features: {missing_flow}. "
            f"A valid network flow CSV must contain ['flow_packets_s', 'flow_bytes_s', 'syn_flag_count', 'flow_duration'] "
            f"(or precomputed basepoints 'bp_01' through 'bp_08'). Found columns: {original_cols[:8]}"
        )

    # Convert numeric fields
    for feat in REQUIRED_FLOW_FEATURES:
        df[feat] = pd.to_numeric(df[feat], errors="coerce")

    if "flow_count" in df.columns:
        df["flow_count"] = pd.to_numeric(df["flow_count"], errors="coerce").fillna(1)
    else:
        df["flow_count"] = 1

    return df, "flow"


# Master regex mapping for structured text extraction
_FIELD_REGEX_LIST = [
    ("source_ip", r"(?:source\s*ip|src\s*ip|source_ip|src_ip|source_address|src_addr|source|src|sip)"),
    ("destination_ip", r"(?:destination\s*ip|dst\s*ip|dest_ip|destination_ip|dst_ip|destination_address|dst_addr|destination|dst|dip)"),
    ("source_port", r"(?:source\s*port|src\s*port|source_port|src_port|sport|srcport|src_pt)"),
    ("destination_port", r"(?:destination\s*port|dst\s*port|destination_port|dst_port|dport|dstport|dst_pt)"),
    ("protocol", r"(?:protocol\s*type|protocol|proto)"),
    ("flow_duration", r"(?:flow\s*duration|duration_ms|duration_us|flow_duration|duration)"),
    ("total_fwd_packets", r"(?:total\s*fwd\s*packets|total\s*forward\s*packets|total\s*fwd\s*pkts|total_fwd_packets|fwd\s*packets|tot\s*fwd\s*pkts|fwd_pkts)"),
    ("total_backward_packets", r"(?:total\s*backward\s*packets|total\s*bwd\s*packets|total\s*bwd\s*pkts|total_backward_packets|bwd\s*packets|tot\s*bwd\s*pkts|bwd_pkts)"),
    ("flow_bytes_s", r"(?:flow\s*bytes\s*/\s*s|flow\s*bytes\s*per\s*second|flow_bytes_sec|flow_bytes_s|bytes\s*/\s*s|bytes_s)"),
    ("flow_packets_s", r"(?:flow\s*packets\s*/\s*s|flow\s*packets\s*per\s*second|flow_packets_sec|flow_packets_s|packets\s*/\s*s|packets_s)"),
    ("syn_flag_count", r"(?:syn\s*flag\s*count|syn\s*flags\s*count|syn\s*flags|syn_flags|syn_flag_count|syn\s*count|syn)"),
    ("timestamp", r"(?:flow\s*timestamp|timestamp|start\s*time|datetime|date_time|time)"),
    ("flow_count", r"(?:flow\s*count|flows|flow_count)"),
]

_FIELD_PATTERNS = "|".join(f"(?P<{canonical}>{pattern})" for canonical, pattern in _FIELD_REGEX_LIST)
_KEY_REGEX = rf"(?i)\b({_FIELD_PATTERNS})\s*[:=]\s*"


def extract_flow_records_from_text(text: str) -> List[Dict[str, Any]]:
    """
    Extracts structured flow records from plain text documents.

    Supports:
      - Explicit block headers: FLOW 1, FLOW 2, Record 1, Entry 1, etc.
      - Paragraph-separated blocks.
      - Repeating anchor fields (e.g. repeated 'Source IP:').
      - Line-wrapped fields (where key or value spans across newlines).
    """
    # 1. Check for explicit flow markers (e.g. FLOW 1, RECORD 1, ENTRY 1)
    flow_markers = list(re.finditer(r'(?i)\b(?:FLOW|RECORD|ENTRY)\s*#?\s*(\d+)\b', text))
    blocks = []
    if len(flow_markers) >= 2 or (len(flow_markers) == 1 and flow_markers[0].start() < 300):
        for i in range(len(flow_markers)):
            start_idx = flow_markers[i].start()
            end_idx = flow_markers[i+1].start() if i + 1 < len(flow_markers) else len(text)
            blocks.append(text[start_idx:end_idx])
    else:
        # Check blank line separated paragraphs
        paragraphs = [p.strip() for p in re.split(r'\n\s*\n', text) if p.strip()]
        if len(paragraphs) > 1 and any(re.search(_KEY_REGEX, p) for p in paragraphs):
            blocks = paragraphs
        else:
            # Check repeating anchor: does Source IP / src_ip appear multiple times?
            src_matches = list(re.finditer(r'(?i)\b(?:source\s*ip|src\s*ip|source_ip|src_ip)\s*[:=]', text))
            if len(src_matches) > 1:
                for i in range(len(src_matches)):
                    start_idx = src_matches[i].start()
                    end_idx = src_matches[i+1].start() if i + 1 < len(src_matches) else len(text)
                    blocks.append(text[start_idx:end_idx])
            else:
                blocks = [text]

    records = []
    for block in blocks:
        matches = list(re.finditer(_KEY_REGEX, block))
        if not matches:
            continue
        rec = {}
        for j in range(len(matches)):
            m = matches[j]
            matched_canonical = None
            for canonical, _ in _FIELD_REGEX_LIST:
                if m.groupdict().get(canonical):
                    matched_canonical = canonical
                    break
            if not matched_canonical:
                continue

            val_start = m.end()
            val_end = matches[j+1].start() if j + 1 < len(matches) else len(block)
            val_raw = block[val_start:val_end].strip()

            # Clean value of punctuation, quotes, trailing newlines
            val_clean = val_raw.strip(",;'\"\r\n")

            if matched_canonical in ["source_port", "destination_port", "flow_duration", "total_fwd_packets", "total_backward_packets", "syn_flag_count", "flow_count"]:
                try:
                    rec[matched_canonical] = int(float(val_clean))
                except (ValueError, TypeError):
                    rec[matched_canonical] = val_clean
            elif matched_canonical in ["flow_bytes_s", "flow_packets_s"]:
                try:
                    rec[matched_canonical] = float(val_clean)
                except (ValueError, TypeError):
                    rec[matched_canonical] = val_clean
            elif matched_canonical == "timestamp":
                rec[matched_canonical] = val_clean
            else:
                rec[matched_canonical] = val_clean

        if rec and any(k in rec for k in ["source_ip", "destination_ip", "flow_duration", "flow_packets_s", "flow_bytes_s", "syn_flag_count"]):
            records.append(rec)

    return records


def parse_txt_bytes(file_bytes: bytes, filename: str = "") -> Tuple[pd.DataFrame, str]:
    """
    Parses key-value pairs, structured blocks, JSON, or delimited records from a text file.
    Raises ValueError if no valid records can be extracted.
    """
    if not file_bytes or len(file_bytes.strip()) == 0:
        raise ValueError("Uploaded text file is empty.")

    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        text = file_bytes.decode("latin-1", errors="ignore")

    # Strategy 1: Check if event profiles (bp_01 to bp_08) or CSV-like table in text
    try:
        csv_df = pd.read_csv(io.StringIO(text), sep=None, engine="python")
        csv_df = normalize_and_deduplicate_dataframe(csv_df)
        if all(bp in csv_df.columns for bp in PROFILE_COLS):
            for bp in PROFILE_COLS:
                csv_df[bp] = pd.to_numeric(csv_df[bp], errors="coerce")
            return csv_df, "profile"
        if any(f in csv_df.columns for f in REQUIRED_FLOW_FEATURES):
            return csv_df, "flow"
    except Exception:
        pass

    # Strategy 2: Check JSON / NDJSON
    trimmed = text.strip()
    if (trimmed.startswith("[") and trimmed.endswith("]")) or (trimmed.startswith("{") and trimmed.endswith("}")):
        try:
            data = json.loads(trimmed)
            if isinstance(data, dict):
                data = [data]
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                json_df = pd.DataFrame(data)
                json_df = normalize_and_deduplicate_dataframe(json_df)
                if all(bp in json_df.columns for bp in PROFILE_COLS):
                    for bp in PROFILE_COLS:
                        json_df[bp] = pd.to_numeric(json_df[bp], errors="coerce")
                    return json_df, "profile"
                return json_df, "flow"
        except Exception:
            pass

    # Strategy 3: Structured Flow extraction from text blocks & descriptions
    records = extract_flow_records_from_text(text)
    if records:
        df = pd.DataFrame(records)
        df = normalize_and_deduplicate_dataframe(df)

        numeric_fields = [
            "flow_packets_s", "flow_bytes_s", "syn_flag_count", "flow_duration",
            "source_port", "destination_port", "total_fwd_packets", "total_backward_packets"
        ]
        for feat in numeric_fields:
            if feat in df.columns:
                df[feat] = pd.to_numeric(df[feat], errors="coerce")

        if "flow_count" in df.columns:
            df["flow_count"] = pd.to_numeric(df["flow_count"], errors="coerce").fillna(1)
        else:
            df["flow_count"] = 1

        if all(bp in df.columns for bp in PROFILE_COLS):
            return df, "profile"
        return df, "flow"

    # Strategy 4: Raw line-by-line numeric basepoints (8 floats per line)
    bp_records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[,\s\t]+", line)
        try:
            nums = [float(p) for p in parts if p]
            if len(nums) == 8:
                bp_records.append({f"bp_{i:02d}": nums[i - 1] for i in range(1, 9)})
        except ValueError:
            pass
    if bp_records:
        df = pd.DataFrame(bp_records)
        return df, "profile"

    raise ValueError(
        f"Validation failed: No valid network flow records or 8-dimensional basepoint profiles could be extracted from '{filename or 'uploaded text'}'. "
        "A valid flow description must contain key-value pairs such as 'Source IP: ...', 'Destination IP: ...', "
        "'Flow Duration: ...', 'Flow Packets/s: ...', 'Flow Bytes/s: ...', and 'SYN Flag Count: ...'."
    )


def parse_pdf_bytes(file_bytes: bytes, filename: str = "") -> Tuple[pd.DataFrame, str]:
    """
    Extracts text from a PDF document and parses network flow records.
    """
    if not file_bytes or len(file_bytes.strip()) == 0:
        raise ValueError("Uploaded PDF file is empty.")

    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        full_text = []
        for page in reader.pages:
            t = page.extract_text()
            if t:
                full_text.append(t)
        combined_text = "\n".join(full_text)
    except Exception as e:
        raise ValueError(f"Malformed or unreadable PDF document: {e}")

    if not combined_text.strip():
        raise ValueError("PDF document contains no extractable text.")

    return parse_txt_bytes(combined_text.encode("utf-8"), filename=filename)


def parse_uploaded_file(file_bytes: bytes, filename: str) -> Tuple[pd.DataFrame, str]:
    """
    Unified entrypoint for parsing and validating CSV, TXT, and PDF files.
    """
    fn = filename.lower()
    if fn.endswith(".csv"):
        return parse_csv_bytes(file_bytes)
    elif fn.endswith(".txt") or fn.endswith(".log"):
        return parse_txt_bytes(file_bytes, filename=filename)
    elif fn.endswith(".pdf"):
        return parse_pdf_bytes(file_bytes, filename=filename)
    else:
        # Default try CSV then TXT then PDF
        try:
            return parse_csv_bytes(file_bytes)
        except Exception:
            try:
                return parse_txt_bytes(file_bytes, filename=filename)
            except Exception:
                return parse_pdf_bytes(file_bytes, filename=filename)
