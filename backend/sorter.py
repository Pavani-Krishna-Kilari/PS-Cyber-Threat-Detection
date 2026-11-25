"""
Disk-Based External Sort Module for AI-SIEM.
Sorts large, out-of-order network flow CSV files chronologically by (timestamp, source_row)
using a bounded-memory external merge sort.
"""

import csv
import heapq
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Iterator

import numpy as np
import pandas as pd

from backend.parser import clean_column_name, resolve_canonical_name


def parse_timestamp_fast(ts_str: str) -> pd.Timestamp:
    """Parses a timestamp string to pandas Timestamp safely."""
    try:
        return pd.to_datetime(ts_str)
    except Exception:
        return pd.Timestamp.min


def external_sort_csv(
    input_path: Path,
    output_path: Path,
    chunk_size: int = 50000
) -> Dict[str, Any]:
    """
    Performs a 2-phase external merge sort on a raw network flow CSV:
      Phase 1: Read input in chunks of chunk_size rows, sort stably by (timestamp, source_row),
               and spill sorted runs to temporary files on disk.
      Phase 2: K-way merge sorted runs using heapq.merge into output_path line-by-line.

    Guarantees:
      - Memory usage is strictly bounded by chunk_size in Phase 1 and K lines in Phase 2.
      - Output is 100% chronologically ordered.
      - Stable tie-breaking using original source_row preserves exact offline pipeline semantics.
    """
    start_time = time.time()
    input_path = Path(input_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_dir = Path(tempfile.mkdtemp(prefix="ai_siem_extsort_", dir=str(output_path.parent)))
    run_files: List[Path] = []
    total_rows = 0
    global_min_t: Optional[pd.Timestamp] = None
    global_max_t: Optional[pd.Timestamp] = None

    try:
        # -------------------------------------------------------------
        # Phase 1: Chunk-wise In-Memory Sort & Spill to Temporary Runs
        # -------------------------------------------------------------
        run_idx = 0
        header_cols: List[str] = []
        has_source_row = False

        # Read in chunks using pandas
        for chunk in pd.read_csv(input_path, chunksize=chunk_size, low_memory=False):
            if chunk.empty:
                continue

            # Standardize column names for timestamp identification
            col_map = {c: clean_column_name(c) for c in chunk.columns}
            chunk = chunk.rename(columns=col_map)

            # Ensure source_row exists for deterministic tie-breaking
            if "source_row" not in chunk.columns:
                chunk["source_row"] = np.arange(total_rows, total_rows + len(chunk), dtype="int64")
            else:
                has_source_row = True
                chunk["source_row"] = pd.to_numeric(chunk["source_row"], errors="coerce").fillna(total_rows).astype("int64")

            # Parse timestamps strictly
            chunk["timestamp"] = pd.to_datetime(chunk["timestamp"], errors="coerce")
            unparseable = chunk["timestamp"].isna().sum()
            if unparseable > 0:
                chunk = chunk.dropna(subset=["timestamp"]).reset_index(drop=True)

            if chunk.empty:
                continue

            # Track global time bounds
            c_min = chunk["timestamp"].min()
            c_max = chunk["timestamp"].max()
            if global_min_t is None or c_min < global_min_t:
                global_min_t = c_min
            if global_max_t is None or c_max > global_max_t:
                global_max_t = c_max

            # Stable sort chunk in memory: timestamp ascending, source_row ascending
            chunk_sorted = chunk.sort_values(["timestamp", "source_row"], kind="stable").reset_index(drop=True)

            if not header_cols:
                header_cols = list(chunk_sorted.columns)

            # Spill to run file
            run_file = tmp_dir / f"run_{run_idx:05d}.csv"
            chunk_sorted.to_csv(run_file, index=False)
            run_files.append(run_file)
            run_idx += 1
            total_rows += len(chunk_sorted)

            # Explicit garbage collection of in-memory chunk
            del chunk, chunk_sorted

        if not run_files:
            raise ValueError("Input CSV contained zero valid tabular network flow records.")

        # -------------------------------------------------------------
        # Phase 2: K-Way Stream Merge into output_path
        # -------------------------------------------------------------
        def line_generator(r_path: Path) -> Iterator[Tuple[pd.Timestamp, int, str]]:
            """Yields (timestamp, source_row, line_str) for each row in a run file."""
            with open(r_path, "r", encoding="utf-8", newline="") as f:
                reader = csv.reader(f)
                run_header = next(reader, None)
                if not run_header:
                    return
                ts_idx = run_header.index("timestamp")
                sr_idx = run_header.index("source_row")

                for row in reader:
                    if not row:
                        continue
                    ts_val = parse_timestamp_fast(row[ts_idx])
                    try:
                        sr_val = int(row[sr_idx])
                    except (ValueError, TypeError):
                        sr_val = 0
                    yield (ts_val, sr_val, row)

        generators = [line_generator(rp) for rp in run_files]

        # Use heapq.merge to pull the minimum (ts, sr) across all K runs
        with open(output_path, "w", encoding="utf-8", newline="") as out_f:
            writer = csv.writer(out_f)
            writer.writerow(header_cols)

            merged_iter = heapq.merge(*generators, key=lambda x: (x[0], x[1]))
            for _, _, row_data in merged_iter:
                writer.writerow(row_data)

    finally:
        # Clean up temporary run directory
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)

    elapsed = time.time() - start_time
    global_t0 = global_min_t.floor("min") if global_min_t is not None else None

    return {
        "status": "SORTED",
        "total_rows": total_rows,
        "runs_created": len(run_files),
        "global_min_timestamp": global_min_t.isoformat() if global_min_t is not None else None,
        "global_max_timestamp": global_max_t.isoformat() if global_max_t is not None else None,
        "global_t0": global_t0.isoformat() if global_t0 is not None else None,
        "sorted_file": str(output_path),
        "elapsed_seconds": round(elapsed, 2)
    }
