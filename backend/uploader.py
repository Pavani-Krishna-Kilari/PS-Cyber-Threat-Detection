"""
Chunked File Upload and Streaming Staging Service for AI-SIEM.
Handles multi-chunk uploads, incremental SHA-256 verification, and on-disk staging
without loading multi-gigabyte files into RAM.
"""

import hashlib
import json
import os
import shutil
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from src.config import PROJECT_ROOT, get_soc_data_dir
import backend.database as db


def get_uploads_root() -> Path:
    """Returns the root directory for uploaded files and chunks, respecting SOC_DATA_DIR."""
    d = get_soc_data_dir() / "uploads"
    d.mkdir(parents=True, exist_ok=True)
    return d


UPLOADS_ROOT = get_uploads_root()


def get_upload_dir(upload_id: str) -> Path:
    """Returns the dedicated on-disk staging directory for an upload session."""
    d = get_uploads_root() / upload_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def compute_file_sha256(filepath: Path, buffer_size: int = 1024 * 1024) -> str:
    """
    Computes full-file SHA-256 incrementally in 1 MB blocks.
    Memory footprint is strictly bounded to buffer_size.
    """
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            block = f.read(buffer_size)
            if not block:
                break
            hasher.update(block)
    return hasher.hexdigest()


def init_chunked_upload(
    filename: str,
    file_size: int,
    file_hash: str,
    total_chunks: int
) -> Dict[str, Any]:
    """
    Initializes a chunked upload session or recovers an existing one if the file hash matches.
    """
    if not filename or file_size <= 0 or total_chunks <= 0:
        raise ValueError("Invalid upload parameters: filename, file_size, and total_chunks must be positive.")
    
    if not file_hash or len(file_hash) != 64:
        raise ValueError("Invalid file_hash: must be a 64-character SHA-256 hexadecimal string.")

    # 1. Check for existing session with the exact same file identity
    existing = db.find_upload_session_by_hash(file_hash, file_size)
    if existing:
        upload_id = existing["upload_id"]
        up_status = existing["upload_status"]
        proc_status = existing["processing_status"]

        # Case A: Already processed completely
        if proc_status == "COMPLETED":
            return {
                "action": "ALREADY_COMPLETED",
                "upload_id": upload_id,
                "session_id": existing["session_id"],
                "filename": existing["filename"],
                "file_hash": file_hash,
                "status": "COMPLETED",
                "message": "File has already been uploaded and processed completely."
            }

        # Case B: Upload complete, processing pending or in-progress
        if up_status == "UPLOAD_COMPLETE":
            latest_chk = db.get_latest_checkpoint(upload_id)
            return {
                "action": "RESUME_PROCESSING",
                "upload_id": upload_id,
                "session_id": existing["session_id"],
                "filename": existing["filename"],
                "file_hash": file_hash,
                "status": proc_status,
                "total_batches": existing["total_batches"],
                "completed_batches": existing["completed_batches"],
                "last_checkpoint": latest_chk,
                "message": "File transfer already completed. Ready to resume processing."
            }

        # Case C: Upload in-progress or interrupted
        if up_status in ("UPLOADING", "PENDING", "FAILED"):
            completed = db.get_completed_chunks(upload_id)
            return {
                "action": "RESUME_UPLOAD",
                "upload_id": upload_id,
                "session_id": existing["session_id"],
                "filename": existing["filename"],
                "file_hash": file_hash,
                "status": up_status,
                "total_chunks": existing["total_chunks"],
                "completed_chunks": completed,
                "uploaded_chunks_count": len(completed),
                "message": f"Resuming file transfer: {len(completed)} of {existing['total_chunks']} chunks already uploaded."
            }

    # 2. Fresh upload session
    upload_id = f"UPL-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    session_id = f"SESS-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    upload_dir = get_upload_dir(upload_id)
    (upload_dir / "chunks").mkdir(parents=True, exist_ok=True)

    session_rec = db.create_upload_session(
        upload_id=upload_id,
        session_id=session_id,
        filename=filename,
        file_size=file_size,
        file_hash=file_hash,
        total_chunks=total_chunks
    )

    return {
        "action": "NEW_UPLOAD",
        "upload_id": upload_id,
        "session_id": session_id,
        "filename": filename,
        "file_hash": file_hash,
        "total_chunks": total_chunks,
        "completed_chunks": [],
        "uploaded_chunks_count": 0,
        "status": "UPLOADING",
        "message": f"Upload session created for {filename} ({total_chunks} chunks expected)."
    }


def save_upload_chunk(
    upload_id: str,
    chunk_index: int,
    chunk_bytes: bytes
) -> Dict[str, Any]:
    """
    Saves a binary chunk directly to disk and records receipt in the database.
    Idempotent: resending an already received chunk updates the part file and returns success.
    """
    session = db.get_upload_session(upload_id)
    if not session:
        raise ValueError(f"Upload session '{upload_id}' not found.")
    
    if session["upload_status"] == "UPLOAD_COMPLETE":
        # Already finalized, return current status idempotently
        completed = db.get_completed_chunks(upload_id)
        return {
            "upload_id": upload_id,
            "chunk_index": chunk_index,
            "status": "ALREADY_FINALIZED",
            "uploaded_chunks_count": len(completed)
        }

    total_chunks = session["total_chunks"]
    if chunk_index < 0 or chunk_index >= total_chunks:
        raise ValueError(f"Invalid chunk_index {chunk_index}: must be between 0 and {total_chunks - 1}.")

    upload_dir = get_upload_dir(upload_id)
    chunks_dir = upload_dir / "chunks"
    chunks_dir.mkdir(parents=True, exist_ok=True)
    part_path = chunks_dir / f"chunk_{chunk_index:05d}.part"

    # Write chunk to disk
    with open(part_path, "wb") as f:
        f.write(chunk_bytes)

    # Record in database ledger
    chunk_size = len(chunk_bytes)
    count = db.record_upload_chunk(upload_id, chunk_index, chunk_size)

    return {
        "upload_id": upload_id,
        "chunk_index": chunk_index,
        "chunk_size": chunk_size,
        "uploaded_chunks_count": count,
        "total_chunks": total_chunks,
        "is_complete": count >= total_chunks
    }


def get_upload_progress(upload_id: str) -> Dict[str, Any]:
    """Returns current upload and processing progress for an upload session."""
    session = db.get_upload_session(upload_id)
    if not session:
        raise ValueError(f"Upload session '{upload_id}' not found.")

    completed = db.get_completed_chunks(upload_id)
    total_chunks = session["total_chunks"]
    all_chunks_set = set(range(total_chunks))
    completed_set = set(completed)
    missing = sorted(list(all_chunks_set - completed_set))

    latest_chk = db.get_latest_checkpoint(upload_id)

    return {
        "upload_id": upload_id,
        "session_id": session["session_id"],
        "filename": session["filename"],
        "file_size": session["file_size"],
        "file_hash": session["file_hash"],
        "total_chunks": total_chunks,
        "uploaded_chunks_count": len(completed),
        "completed_chunks": completed,
        "missing_chunks": missing,
        "upload_status": session["upload_status"],
        "sort_status": session["sort_status"],
        "processing_status": session["processing_status"],
        "total_rows": session["total_rows"],
        "processed_rows": session["processed_rows"],
        "total_batches": session["total_batches"],
        "completed_batches": session["completed_batches"],
        "last_checkpoint": latest_chk,
        "error_message": session["error_message"]
    }


def finalize_chunked_upload(upload_id: str, file_hash: str) -> Dict[str, Any]:
    """
    Assembles staged chunk parts into a single source.csv file on disk,
    verifies full-file SHA-256 incrementally, and marks upload complete.
    """
    session = db.get_upload_session(upload_id)
    if not session:
        raise ValueError(f"Upload session '{upload_id}' not found.")

    upload_dir = get_upload_dir(upload_id)
    chunks_dir = upload_dir / "chunks"
    source_csv = upload_dir / "source.csv"

    # Check if already finalized and hash verified
    if session["upload_status"] == "UPLOAD_COMPLETE" and source_csv.exists():
        return {
            "upload_id": upload_id,
            "session_id": session["session_id"],
            "status": "UPLOAD_COMPLETE",
            "source_csv": str(source_csv),
            "file_size": source_csv.stat().st_size,
            "file_hash": session["file_hash"],
            "message": "Upload already finalized and verified."
        }

    total_chunks = session["total_chunks"]
    completed = db.get_completed_chunks(upload_id)
    if len(completed) < total_chunks:
        missing = sorted(list(set(range(total_chunks)) - set(completed)))
        raise ValueError(f"Cannot finalize upload: missing {len(missing)} chunk(s). Missing indices: {missing[:10]}")

    # Stream assemble chunks into source.csv with 1 MB buffer
    with open(source_csv, "wb") as out_f:
        for idx in range(total_chunks):
            part_path = chunks_dir / f"chunk_{idx:05d}.part"
            if not part_path.exists():
                raise FileNotFoundError(f"Missing chunk file on disk: {part_path}")
            with open(part_path, "rb") as in_f:
                shutil.copyfileobj(in_f, out_f, length=1024 * 1024)

    # Incrementally verify full-file SHA-256
    computed_hash = compute_file_sha256(source_csv)
    expected_hash = file_hash or session["file_hash"]

    if computed_hash.lower() != expected_hash.lower():
        # Hash mismatch: corrupted transfer!
        if source_csv.exists():
            source_csv.unlink()
        db.update_upload_status(upload_id, upload_status="FAILED", error_message="Integrity check failed: SHA-256 hash mismatch.")
        raise ValueError(
            f"Integrity check failed: Computed SHA-256 '{computed_hash}' does not match expected '{expected_hash}'."
        )

    # Success: delete chunk parts to free disk space
    for idx in range(total_chunks):
        part_path = chunks_dir / f"chunk_{idx:05d}.part"
        if part_path.exists():
            part_path.unlink()

    actual_size = source_csv.stat().st_size
    db.update_upload_status(upload_id, upload_status="UPLOAD_COMPLETE")
    db.update_upload_progress(upload_id, total_rows=0)

    return {
        "upload_id": upload_id,
        "session_id": session["session_id"],
        "status": "UPLOAD_COMPLETE",
        "source_csv": str(source_csv),
        "file_size": actual_size,
        "file_hash": computed_hash,
        "message": f"Successfully assembled and verified {actual_size:,} bytes."
    }


PROTECTED_INCIDENT_UPLOADS = {"UPL-20261118220457-b41aa8a7"}


def cleanup_upload(upload_id: str) -> bool:
    """Cancels and purges all disk artifacts and staging records for an upload."""
    if upload_id in PROTECTED_INCIDENT_UPLOADS:
        raise ValueError(
            f"Upload session '{upload_id}' is protected for forensic diagnostic audit and cannot be purged."
        )
    upload_dir = get_upload_dir(upload_id)
    if upload_dir.exists():
        shutil.rmtree(upload_dir, ignore_errors=True)
    return db.cancel_and_cleanup_upload(upload_id)
