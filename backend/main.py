"""
FastAPI Server for AI-Based SIEM Cyber Threat Detection System.
Provides REST endpoints and serves the Vanilla JS/HTML/CSS frontend.
"""

from pathlib import Path
import threading
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Request, Response, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from src.config import PROJECT_ROOT
from backend.schemas import (
    ProfileInput,
    FlowInput,
    EnsembleConfigInput,
    SinglePredictionResponse,
    BatchPredictionResponse,
    AnomalyInput,
    AnomalyPredictionResponse,
    AssistantQueryInput,
    AssistantQueryResponse,
    UploadInitRequest,
    UploadFinalizeRequest,
    ProcessStartRequest,
    ProcessResumeRequest
)
import backend.database as db
import backend.uploader as uploader
from backend.aggregator import (
    AggregatorError,
    InsufficientTemporalSpanError,
    MissingFeatureColumnsError,
    InvalidTimestampError,
    InvalidBenchmarkAnnotationError
)
from backend.service import siem_service
from backend.auth import (
    LoginRequest,
    GoogleSSORequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ContactAdminRequest,
    AuthResponse,
    authenticate_operator,
    authenticate_google_sso,
    get_current_user,
    revoke_session,
    request_password_recovery,
    reset_password_with_token,
    submit_access_clearance_request,
    extract_token_from_request,
    get_google_oauth_auth_url,
    verify_drift_access,
    require_head_of_soc,
    get_current_user_from_request,
    is_head_of_soc,
    IS_PRODUCTION
)
import backend.training_manager as tm

app = FastAPI(
    title="AI SIEM Threat Detection API",
    description="Full-stack AI-based SIEM system for cyber threat detection using Artificial Neural Networks based on Event Profiles",
    version="1.0.0"
)

# Enable CORS for external frontends or dev servers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = PROJECT_ROOT / "frontend"


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/status", summary="System Health & Subsystem Status")
def get_status() -> Dict[str, Any]:
    return siem_service.get_system_status()


@app.get("/api/dashboard/summary", summary="Current Analysis Session Telemetry Summary")
def get_dashboard_summary(request: Request, token: Optional[str] = Query(None)) -> Dict[str, Any]:
    """
    Returns actual detection counts from the latest user input analysis.
    Starts at 0 for all counters before user uploads or analyzes traffic.
    Data Drift analysis is strictly reserved for Head of SOC operators.
    """
    summary = siem_service.get_dashboard_summary()
    if summary and isinstance(summary, dict) and "drift_analysis" in summary:
        user = get_current_user_from_request(request, token)
        if not (user and is_head_of_soc(user)):
            summary = {k: v for k, v in summary.items() if k != "drift_analysis"}
    return summary


@app.get("/api/dataset/overview", summary="Dataset Inspection & Preprocessing Statistics (Historical)")
def get_dataset_overview() -> Dict[str, Any]:
    return siem_service.get_dataset_stats()


@app.get("/api/profiles/overview", summary="Event Profile & Basepoint Telemetry (Historical)")
def get_profiles_overview() -> Dict[str, Any]:
    return siem_service.get_profile_stats()


@app.get("/api/models/benchmarks", summary="Phase 4 Model Comparison & Evaluation Report")
def get_model_benchmarks() -> Dict[str, Any]:
    return siem_service.get_model_benchmarks()


@app.post("/api/models/predict/profile", response_model=SinglePredictionResponse, summary="Analyze Single Event Profile")
def predict_profile(payload: ProfileInput) -> SinglePredictionResponse:
    vec = [
        payload.bp_01, payload.bp_02, payload.bp_03, payload.bp_04,
        payload.bp_05, payload.bp_06, payload.bp_07, payload.bp_08
    ]
    res = siem_service.predict_single_profile(vec)
    return SinglePredictionResponse(**res)


@app.post("/api/models/predict/flow", response_model=SinglePredictionResponse, summary="Analyze Single Network Flow")
def predict_flow(payload: FlowInput) -> SinglePredictionResponse:
    res = siem_service.predict_single_flow(payload.model_dump())
    return SinglePredictionResponse(**res)


@app.post("/api/detect/upload", summary="Upload CSV, TXT, or PDF for Threat Triage")
@app.post("/api/analyze", summary="Alias: Upload Network Traffic for Threat Triage")
async def upload_file(file: UploadFile = File(...)) -> Dict[str, Any]:
    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    
    try:
        result = siem_service.process_file_upload(contents, file.filename or "uploaded_file.csv")
        return result
    except (InsufficientTemporalSpanError, MissingFeatureColumnsError, InvalidTimestampError, InvalidBenchmarkAnnotationError, AggregatorError) as ae:
        raise HTTPException(
            status_code=422,
            detail={
                "error": ae.__class__.__name__,
                "message": str(ae),
                "details": getattr(ae, "details", {})
            }
        )
    except (ValueError, TypeError) as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")


# =====================================================================
# Resumable Chunked Upload Endpoints
# =====================================================================

@app.post("/api/upload/init", summary="Initialize or Recover Chunked File Upload Session")
def init_upload_endpoint(payload: UploadInitRequest) -> Dict[str, Any]:
    try:
        res = uploader.init_chunked_upload(
            filename=payload.filename,
            file_size=payload.file_size,
            file_hash=payload.file_hash,
            total_chunks=payload.total_chunks
        )
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initialize upload: {str(e)}")


@app.post("/api/upload/chunk", summary="Upload a Binary File Slice")
async def upload_chunk_endpoint(
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    chunk_file: UploadFile = File(...)
) -> Dict[str, Any]:
    chunk_bytes = await chunk_file.read()
    if not chunk_bytes:
        raise HTTPException(status_code=400, detail=f"Chunk {chunk_index} is empty.")
    try:
        res = uploader.save_upload_chunk(
            upload_id=upload_id,
            chunk_index=chunk_index,
            chunk_bytes=chunk_bytes
        )
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save chunk {chunk_index}: {str(e)}")


@app.get("/api/upload/status", summary="Query Upload & Checkpoint Progress")
def get_upload_status_endpoint(upload_id: str = Query(...)) -> Dict[str, Any]:
    try:
        return uploader.get_upload_progress(upload_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload/finalize", summary="Assemble Chunks and Verify Full-File SHA-256")
def finalize_upload_endpoint(payload: UploadFinalizeRequest) -> Dict[str, Any]:
    try:
        res = uploader.finalize_chunked_upload(
            upload_id=payload.upload_id,
            file_hash=payload.file_hash
        )
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Finalization failed: {str(e)}")


@app.delete("/api/upload/{upload_id}", summary="Cancel Upload and Purge Staged Files")
def cancel_upload_endpoint(upload_id: str) -> Dict[str, Any]:
    session = db.get_upload_session(upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{upload_id}' not found.")

    if siem_service.is_stream_worker_running(upload_id) or session.get("processing_status") == "PROCESSING":
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete upload '{upload_id}' while streaming batch processing is actively in progress. Please pause processing first (/api/process/pause) before cancelling."
        )

    try:
        success = uploader.cleanup_upload(upload_id)
        return {"upload_id": upload_id, "cancelled": success}
    except ValueError as ve:
        raise HTTPException(status_code=403, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to cancel upload: {str(e)}")


# =====================================================================
# Resumable Checkpoint-Based Batch Processing Endpoints
# =====================================================================
logger = logging.getLogger("ai_siem.api")


def _run_stream_worker(upload_id: str, batch_size: int):
    try:
        siem_service.register_worker(upload_id, threading.current_thread())
        siem_service.start_stream_processing(upload_id=upload_id, batch_size=batch_size)
    except Exception as e:
        logger.error(f"Background stream processing error for upload '{upload_id}': {e}", exc_info=True)
    finally:
        siem_service.unregister_worker(upload_id)


@app.post("/api/process/start", summary="Start or Resume Streaming Batch Processing")
def start_process_endpoint(payload: ProcessStartRequest) -> Dict[str, Any]:
    session = db.get_upload_session(payload.upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{payload.upload_id}' not found.")

    if session["processing_status"] == "COMPLETED":
        return {
            "upload_id": payload.upload_id,
            "session_id": session["session_id"],
            "status": "COMPLETED",
            "message": "Processing has already completed."
        }

    if siem_service.is_stream_worker_running(payload.upload_id):
        return {
            "upload_id": payload.upload_id,
            "session_id": session["session_id"],
            "status": "PROCESSING",
            "message": "Streaming batch processing is already actively running in background."
        }

    if payload.sync:
        try:
            res = siem_service.start_stream_processing(
                upload_id=payload.upload_id,
                batch_size=payload.batch_size
            )
            return res
        except (InsufficientTemporalSpanError, MissingFeatureColumnsError, InvalidTimestampError, AggregatorError) as ae:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": ae.__class__.__name__,
                    "message": str(ae),
                    "details": getattr(ae, "details", {})
                }
            )
        except FileNotFoundError as fne:
            raise HTTPException(
                status_code=410,
                detail=f"Source files missing on disk: {str(fne)}. This upload session cannot be resumed because its staging files were purged."
            )
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Processing error: {str(e)}")

    # Asynchronous background execution (default for interactive UI)
    thread = threading.Thread(
        target=_run_stream_worker,
        args=(payload.upload_id, payload.batch_size),
        daemon=True,
        name=f"stream-worker-{payload.upload_id}"
    )
    thread.start()
    return {
        "upload_id": payload.upload_id,
        "session_id": session["session_id"],
        "status": "PROCESSING",
        "message": "Streaming batch processing started in background."
    }


@app.get("/api/process/status", summary="Query Resumable Processing Status & Progress")
def get_process_status_endpoint(upload_id: str = Query(...)) -> Dict[str, Any]:
    try:
        return siem_service.get_stream_processing_status(upload_id)
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/process/resume", summary="Resume Interrupted Processing Session")
def resume_process_endpoint(payload: ProcessResumeRequest) -> Dict[str, Any]:
    session = db.get_upload_session(payload.upload_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Upload session '{payload.upload_id}' not found.")
    if payload.file_hash and session["file_hash"].lower() != payload.file_hash.lower():
        raise HTTPException(
            status_code=409,
            detail="File identity mismatch: provided hash does not match original uploaded file."
        )

    if session["processing_status"] == "COMPLETED":
        return {
            "upload_id": payload.upload_id,
            "session_id": session["session_id"],
            "status": "COMPLETED",
            "message": "Processing has already completed."
        }

    if siem_service.is_stream_worker_running(payload.upload_id):
        return {
            "upload_id": payload.upload_id,
            "session_id": session["session_id"],
            "status": "PROCESSING",
            "message": "Streaming batch processing is already actively running in background."
        }

    # Verify source file presence on disk before attempting resume
    upload_dir = PROJECT_ROOT / "data" / "uploads" / payload.upload_id
    if not (upload_dir / "source.csv").exists() and not (upload_dir / "sorted_source.csv").exists():
        raise HTTPException(
            status_code=410,
            detail=f"Source files missing on disk for upload '{payload.upload_id}'. This upload session cannot be resumed because its staging files were purged."
        )

    if payload.sync:
        try:
            res = siem_service.start_stream_processing(
                upload_id=payload.upload_id,
                batch_size=payload.batch_size
            )
            return res
        except HTTPException:
            raise
        except (InsufficientTemporalSpanError, MissingFeatureColumnsError, InvalidTimestampError, AggregatorError) as ae:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": ae.__class__.__name__,
                    "message": str(ae),
                    "details": getattr(ae, "details", {})
                }
            )
        except FileNotFoundError as fne:
            raise HTTPException(
                status_code=410,
                detail=f"Source files missing on disk: {str(fne)}. This upload session cannot be resumed because its staging files were purged."
            )
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Resume failed: {str(e)}")

    thread = threading.Thread(
        target=_run_stream_worker,
        args=(payload.upload_id, payload.batch_size),
        daemon=True,
        name=f"stream-resume-{payload.upload_id}"
    )
    thread.start()
    return {
        "upload_id": payload.upload_id,
        "session_id": session["session_id"],
        "status": "PROCESSING",
        "message": "Streaming batch processing resumed in background."
    }


@app.post("/api/process/pause", summary="Pause In-Progress Streaming Processing")
def pause_process_endpoint(payload: ProcessStartRequest) -> Dict[str, Any]:
    db.update_upload_status(payload.upload_id, processing_status="PAUSED")
    return {"upload_id": payload.upload_id, "status": "PAUSED"}




@app.get("/api/campaigns", summary="Retrieve Logical Security Campaigns from SQLite")
def get_campaigns_endpoint(
    limit: int = Query(50, ge=1, le=500),
    session_id: Optional[str] = Query(None)
) -> List[Dict[str, Any]]:
    return siem_service.get_campaigns(limit=limit, session_id=session_id)


@app.get("/api/detect/stream", summary="Real-Time Sliding Window Threat Stream from Latest Uploaded CSV")
@app.get("/api/detect/stream/latest", summary="Alias: Real-Time Sliding Window Threat Stream")
def get_stream_event(session_id: Optional[str] = Query(None)) -> Dict[str, Any]:
    return siem_service.get_latest_stream(session_id=session_id)


@app.get("/api/detect/history", summary="Actual Detection History Records from SQLite")
@app.get("/api/history", summary="Alias: Detection History Records")
def get_history(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    verdict: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    session_id: Optional[str] = Query(None)
) -> List[Dict[str, Any]]:
    return siem_service.get_history(limit=limit, offset=offset, verdict=verdict, severity=severity, search=search, session_id=session_id)


# -----------------------------------------------------------------------------
# Persistent Classification Reports & Session Management Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/sessions", summary="List Persistent Upload Sessions & Classification Reports")
def get_sessions_endpoint(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
) -> List[Dict[str, Any]]:
    return siem_service.get_sessions(limit=limit, offset=offset)


@app.get("/api/sessions/count", summary="Total Count of Recorded Upload Sessions")
def get_sessions_count_endpoint() -> Dict[str, int]:
    return {"count": siem_service.get_sessions_count()}


@app.get("/api/sessions/{session_id}", summary="Retrieve Complete Persistent Classification Report")
def get_session_report_endpoint(
    session_id: str,
    request: Request,
    token: Optional[str] = Query(None)
) -> Dict[str, Any]:
    user = get_current_user_from_request(request, token)
    # Regular Security Analyst and unauthenticated callers must not see drift reports;
    # Only authenticated Head of SOC receives drift analysis.
    include_drift = bool(user and is_head_of_soc(user))
    report = siem_service.get_session_report(session_id, include_drift=include_drift)
    if not report:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return report


@app.delete("/api/sessions/{session_id}", summary="Transactionally Delete Single Session Report and Records")
def delete_session_endpoint(session_id: str) -> Dict[str, Any]:
    deleted = siem_service.delete_session(session_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
    return {
        "status": "SUCCESS",
        "message": f"Classification report and history for session '{session_id}' permanently deleted.",
        "session_id": session_id
    }


@app.get("/api/sessions/{session_id}/threats", summary="Retrieve Known Threats for Session")
def get_session_threats_endpoint(
    session_id: str,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0)
) -> List[Dict[str, Any]]:
    return siem_service.get_history(limit=limit, offset=offset, verdict="KNOWN_THREAT", session_id=session_id)


@app.get("/api/sessions/{session_id}/anomalies", summary="Retrieve Unknown Anomalies for Session")
def get_session_anomalies_endpoint(
    session_id: str,
    limit: int = Query(500, ge=1, le=2000),
    offset: int = Query(0, ge=0)
) -> List[Dict[str, Any]]:
    return siem_service.get_history(limit=limit, offset=offset, verdict="UNKNOWN_ANOMALOUS", session_id=session_id)


@app.get("/api/sessions/{session_id}/campaigns", summary="Retrieve Logical Security Campaigns for Session")
def get_session_campaigns_endpoint(
    session_id: str,
    limit: int = Query(500, ge=1, le=2000)
) -> List[Dict[str, Any]]:
    return siem_service.get_campaigns(limit=limit, session_id=session_id)


# -----------------------------------------------------------------------------
# Dual-Layer Data Drift Detection Endpoints (Head of SOC Protected)
# -----------------------------------------------------------------------------

@app.get("/api/drift/latest", summary="Retrieve Latest Data Drift Evaluation Report")
def get_latest_drift_endpoint(request: Request, token: Optional[str] = Query(None)) -> Dict[str, Any]:
    verify_drift_access(request, token)
    report = db.get_latest_drift_report()
    if not report:
        return {
            "has_drift": False,
            "message": "No drift reports recorded yet. Upload a dataset to evaluate data drift."
        }
    return {
        "has_drift": True,
        "report": report
    }


@app.get("/api/drift/history", summary="Retrieve Historical Data Drift Reports")
def get_drift_history_endpoint(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    token: Optional[str] = Query(None)
) -> List[Dict[str, Any]]:
    verify_drift_access(request, token)
    return db.get_drift_reports_history(limit=limit)


@app.get("/api/drift/reference", summary="Retrieve Precalculated Reference Baseline Summary")
def get_drift_reference_endpoint(request: Request, token: Optional[str] = Query(None)) -> Dict[str, Any]:
    verify_drift_access(request, token)
    from src.drift.baseline import load_reference_baseline
    baseline = load_reference_baseline()
    return {
        "experiment": baseline.get("experiment", "exp_b"),
        "created_at": baseline.get("created_at"),
        "n_training_flows": baseline.get("n_training_flows"),
        "n_benign_training_flows": baseline.get("n_benign_training_flows"),
        "n_training_profiles": baseline.get("n_training_profiles"),
        "n_benign_training_profiles": baseline.get("n_benign_training_profiles"),
        "raw_features": baseline.get("raw_features", []),
        "profile_features": baseline.get("profile_features", []),
        "full_reference": {
            "dominant_basepoint_distribution": baseline.get("full_reference", {}).get("dominant_basepoint_distribution", {}),
            "network_features_means": {
                k: v.get("mean") for k, v in baseline.get("full_reference", {}).get("network_features", {}).items()
            },
            "profile_features_means": {
                k: v.get("mean") for k, v in baseline.get("full_reference", {}).get("event_profiles", {}).items()
            }
        }
    }


@app.get("/api/sessions/{session_id}/drift", summary="Retrieve Drift Analysis for a Specific Session")
def get_session_drift_endpoint(
    session_id: str,
    request: Request,
    token: Optional[str] = Query(None)
) -> Dict[str, Any]:
    verify_drift_access(request, token)
    report = db.get_drift_report_by_session(session_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"No drift report found for session '{session_id}'.")
    return report


# -----------------------------------------------------------------------------
# Head of SOC Training Dataset Management & Candidate Model Studio Endpoints
# -----------------------------------------------------------------------------

class CandidateTrainRequest(BaseModel):
    dataset_id: str = Field(..., description="ID of validated candidate dataset")

class CandidateActivateRequest(BaseModel):
    approval_note: Optional[str] = Field("", description="Supervisory authorization justification")

class CandidateRollbackRequest(BaseModel):
    rollback_note: Optional[str] = Field("", description="Supervisory rollback reason")


@app.get("/api/training/studio/overview", summary="Retrieve Candidate Studio Overview (Head of SOC Only)")
def get_training_studio_overview_endpoint(request: Request, token: Optional[str] = Query(None)) -> Dict[str, Any]:
    require_head_of_soc(request, token)
    return tm.get_candidate_studio_overview()


@app.post("/api/training/dataset/validate", summary="Validate Candidate Dataset Schema and Quality (Head of SOC Only)")
async def validate_candidate_dataset_endpoint(
    request: Request,
    file: UploadFile = File(...),
    token: Optional[str] = Query(None)
) -> Dict[str, Any]:
    require_head_of_soc(request, token)
    content = await file.read()
    report = tm.validate_training_dataset(content, file.filename or "dataset.csv")
    return report


@app.post("/api/training/dataset/upload", summary="Upload and Persist Candidate Dataset (Head of SOC Only)")
async def upload_candidate_dataset_endpoint(
    request: Request,
    file: UploadFile = File(...),
    token: Optional[str] = Query(None)
) -> Dict[str, Any]:
    user = require_head_of_soc(request, token)
    content = await file.read()
    try:
        saved_entry = tm.save_uploaded_dataset(content, file.filename or "dataset.csv", user)
        return {"status": "SUCCESS", "dataset": saved_entry}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.post("/api/training/candidate/train", summary="Initiate Isolated Candidate Model Training (Head of SOC Only)")
def train_candidate_endpoint(
    payload: CandidateTrainRequest,
    request: Request,
    token: Optional[str] = Query(None)
) -> Dict[str, Any]:
    user = require_head_of_soc(request, token)
    try:
        candidate_record = tm.train_candidate_model(payload.dataset_id, user)
        return {"status": "SUCCESS", "candidate": candidate_record}
    except (ValueError, FileNotFoundError) as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Candidate training error: {str(e)}")


@app.post("/api/training/candidate/{candidate_id}/activate", summary="Authorize & Activate Candidate Model (Head of SOC Only)")
def activate_candidate_endpoint(
    candidate_id: str,
    payload: CandidateActivateRequest,
    request: Request,
    token: Optional[str] = Query(None)
) -> Dict[str, Any]:
    user = require_head_of_soc(request, token)
    try:
        res = tm.activate_candidate_model(candidate_id, user, payload.approval_note or "")
        return res
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except (ValueError, FileNotFoundError) as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.post("/api/training/candidate/rollback", summary="Rollback to Baseline / Previous Model (Head of SOC Only)")
def rollback_model_endpoint(
    payload: CandidateRollbackRequest,
    request: Request,
    token: Optional[str] = Query(None)
) -> Dict[str, Any]:
    user = require_head_of_soc(request, token)
    try:
        res = tm.rollback_model(user, payload.rollback_note or "")
        return res
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except (ValueError, RuntimeError) as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.delete("/api/history", summary="Clear Detection History and Reset Current Session")
def clear_history() -> Dict[str, Any]:
    from backend.database import clear_all_history
    clear_all_history()
    siem_service.current_analysis_summary = None
    return {"status": "SUCCESS", "message": "Detection history cleared and session reset."}


@app.post("/api/batch/clear", summary="Clear Current Batch Summary and Restore Dashboard Empty State")
def clear_batch_summary() -> Dict[str, Any]:
    """Clears the active batch analysis summary without modifying detection history."""
    siem_service.clear_batch_summary()
    return {"status": "SUCCESS", "message": "Batch summary cleared. Dashboard restored to empty state."}


@app.post("/api/ensemble/configure", summary="Tune Soft-Voting Ensemble Weights & Threshold")
def configure_ensemble(payload: EnsembleConfigInput) -> Dict[str, Any]:
    return siem_service.update_ensemble_config(payload.weights, payload.threshold)


@app.get("/api/anomaly/overview", summary="Isolation Forest Anomaly Telemetry & Metrics")
def get_anomaly_overview() -> Dict[str, Any]:
    return siem_service.get_anomaly_overview()


@app.post("/api/models/predict/anomaly", response_model=AnomalyPredictionResponse, summary="Analyze Profile for Out-of-Distribution Anomalies")
def predict_anomaly(payload: AnomalyInput) -> AnomalyPredictionResponse:
    vec = [
        payload.bp_01, payload.bp_02, payload.bp_03, payload.bp_04,
        payload.bp_05, payload.bp_06, payload.bp_07, payload.bp_08
    ]
    res = siem_service.predict_anomaly(vec)
    return AnomalyPredictionResponse(**res)


@app.post("/api/assistant/chat", response_model=AssistantQueryResponse, summary="Interact with SOC AI Analyst Assistant")
def chat_assistant(payload: AssistantQueryInput) -> AssistantQueryResponse:
    res = siem_service.query_assistant(payload.query, payload.context)
    return AssistantQueryResponse(**res)


# -----------------------------------------------------------------------------
# SOC Authentication & Access Clearance Endpoints
# -----------------------------------------------------------------------------

@app.post("/api/auth/login", response_model=AuthResponse, summary="SOC Operator Authentication")
def login_endpoint(payload: LoginRequest, request: Request, response: Response):
    client_ip = request.client.host if request.client else "127.0.0.1"
    try:
        res = authenticate_operator(
            payload.email,
            payload.password,
            payload.remember_me,
            client_ip=client_ip
        )
        # Set secure HttpOnly, SameSite session cookie
        response.set_cookie(
            key="siem_session",
            value=res["session_token"],
            httponly=True,
            samesite="lax",
            secure=IS_PRODUCTION,
            max_age=res["validity_seconds"],
            path="/"
        )
        return AuthResponse(**res)
    except ValueError as ve:
        raise HTTPException(status_code=401, detail=str(ve))


@app.get("/api/auth/oauth/google/url", summary="Get Google Workspace OAuth 2.0 Auth URL & Status")
def google_oauth_url_endpoint():
    return get_google_oauth_auth_url()


@app.post("/api/auth/google", response_model=AuthResponse, summary="Google Workspace SSO Authentication")
def google_sso_endpoint(payload: GoogleSSORequest, response: Response):
    res = authenticate_google_sso(
        payload.requested_email or "analyst.google@soc-siem.cloud",
        code=payload.code,
        state=payload.state
    )
    # Set secure HttpOnly cookie
    response.set_cookie(
        key="siem_session",
        value=res["session_token"],
        httponly=True,
        samesite="lax",
        secure=IS_PRODUCTION,
        max_age=res["validity_seconds"],
        path="/"
    )
    return AuthResponse(**res)


@app.get("/api/auth/me", summary="Get Authenticated Operator Details")
def get_me_endpoint(request: Request, token: Optional[str] = Query(None)):
    active_token = extract_token_from_request(request, token)
    user = get_current_user(active_token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid token.")
    return {"status": "SUCCESS", "user": user}


@app.get("/api/dashboard/secure-session", summary="Verify Active Authenticated SOC Operator Session")
def verify_secure_session(request: Request, token: Optional[str] = Query(None)):
    """
    Protected dashboard route: validates the session token via HttpOnly cookie, header, or query.
    Returns operator telemetry clearance if valid; raises 401 Unauthorized if invalid or missing.
    """
    active_token = extract_token_from_request(request, token)
    if not active_token:
        raise HTTPException(
            status_code=401,
            detail="Access Denied: Authentication token required to access protected SOC telemetry."
        )
    user = get_current_user(active_token)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Access Denied: Invalid or expired SOC security clearance token."
        )
    return {
        "status": "AUTHENTICATED",
        "clearance": user.get("clearance", "Level 3"),
        "user": user
    }


@app.post("/api/auth/logout", summary="Logout Operator Session")
def logout_endpoint(request: Request, response: Response, token: Optional[str] = Query(None)):
    active_token = extract_token_from_request(request, token)
    revoke_session(active_token)
    response.delete_cookie(key="siem_session", path="/")
    return {"status": "SUCCESS", "message": "Session invalidated."}


@app.post("/api/auth/forgot-password", summary="Password Recovery Protocol")
def forgot_password_endpoint(payload: ForgotPasswordRequest):
    try:
        res = request_password_recovery(payload.email)
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.post("/api/auth/reset-password", summary="Consume One-Time Token to Reset Password")
def reset_password_endpoint(payload: ResetPasswordRequest):
    try:
        res = reset_password_with_token(payload.token, payload.new_password)
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.post("/api/auth/contact-admin", summary="Request SOC Access Clearance")
def contact_admin_endpoint(payload: ContactAdminRequest):
    try:
        res = submit_access_clearance_request(payload.name, payload.email, payload.clearance_level, payload.reason)
        return res
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))


@app.get("/api/auth/config", summary="Retrieve Public Auth Configuration (Safe Demo Flag)")
def get_auth_config_endpoint() -> Dict[str, Any]:
    from backend.auth import ENABLE_DEMO_ACCOUNTS, IS_PRODUCTION
    return {
        "demo_mode": ENABLE_DEMO_ACCOUNTS,
        "is_production": IS_PRODUCTION
    }


# -----------------------------------------------------------------------------
# Static Frontend Serving & Application Routing
# -----------------------------------------------------------------------------
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
    if (FRONTEND_DIR / "css").exists():
        app.mount("/css", StaticFiles(directory=FRONTEND_DIR / "css"), name="css")
    if (FRONTEND_DIR / "js").exists():
        app.mount("/js", StaticFiles(directory=FRONTEND_DIR / "js"), name="js")

    NO_CACHE_HEADERS = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }

    @app.get("/", include_in_schema=False)
    def serve_frontend_index():
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file, headers=NO_CACHE_HEADERS)
        return {"message": "AI SIEM Backend is running. Frontend index.html not found."}

    @app.get("/login", include_in_schema=False)
    def serve_frontend_login():
        login_file = FRONTEND_DIR / "login.html"
        if login_file.exists():
            return FileResponse(login_file, headers=NO_CACHE_HEADERS)
        index_file = FRONTEND_DIR / "index.html"
        if index_file.exists():
            return FileResponse(index_file, headers=NO_CACHE_HEADERS)
        return {"message": "AI SIEM Backend is running. Frontend login.html not found."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
