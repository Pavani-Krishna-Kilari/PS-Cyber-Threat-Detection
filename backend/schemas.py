"""
Pydantic Schemas for SIEM API Payloads and Responses.
"""

from typing import Dict, List, Optional, Any, Union
from pydantic import BaseModel, Field


class ProfileInput(BaseModel):
    """Direct 8-dimensional event profile input."""
    bp_01: float = Field(0.0, ge=0.0, le=1.0)
    bp_02: float = Field(0.0, ge=0.0, le=1.0)
    bp_03: float = Field(0.0, ge=0.0, le=1.0)
    bp_04: float = Field(0.0, ge=0.0, le=1.0)
    bp_05: float = Field(0.0, ge=0.0, le=1.0)
    bp_06: float = Field(0.0, ge=0.0, le=1.0)
    bp_07: float = Field(0.0, ge=0.0, le=1.0)
    bp_08: float = Field(0.0, ge=0.0, le=1.0)


class FlowInput(BaseModel):
    """Raw network flow fields for derived event profiling."""
    source_ip: str = "172.16.0.1"
    destination_ip: str = "192.168.10.50"
    source_port: int = 45000
    destination_port: int = 21
    protocol: int = 6
    flow_duration: float = 5000.0
    flow_packets_s: float = 600000.0
    flow_bytes_s: float = 2500000.0
    syn_flag_count: int = 2
    flow_count: int = 15


class EnsembleConfigInput(BaseModel):
    """Configuration for Soft-Voting Ensemble."""
    weights: List[float] = [1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0]
    threshold: float = Field(0.50, ge=0.01, le=0.99)


class SinglePredictionResponse(BaseModel):
    """Single definitive SIEM verdict with tri-state status and anomaly explanation."""
    verdict: str  # 'NORMAL', 'KNOWN_THREAT', or 'UNKNOWN_ANOMALOUS'
    prediction_status: str = "NORMAL"  # 'NORMAL', 'KNOWN_THREAT', 'UNKNOWN_ANOMALOUS'
    predicted_class: str = "Benign Network Traffic"
    confidence: float = 0.0
    anomaly_status: str = "NORMAL"  # 'NORMAL', 'ANOMALOUS', or 'NOT_EVALUATED'
    anomaly_score: float = 0.0
    detection_reason: str = ""
    requires_investigation: bool = False
    threat_confidence: float = 0.0
    threshold: float = 0.95
    severity: str = "LOW"  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    dominant_basepoint: str = "bp_01"
    dominant_basepoint_similarity: float = 0.0
    profile_vector: List[float] = []
    model_breakdown: Dict[str, float] = {}
    flow_metadata: Optional[Dict[str, Any]] = None
    anomaly: Optional[Dict[str, Any]] = None


class AnomalyInput(BaseModel):
    """8-dimensional event profile for unsupervised anomaly detection."""
    bp_01: float = Field(0.0, ge=0.0, le=1.0)
    bp_02: float = Field(0.0, ge=0.0, le=1.0)
    bp_03: float = Field(0.0, ge=0.0, le=1.0)
    bp_04: float = Field(0.0, ge=0.0, le=1.0)
    bp_05: float = Field(0.0, ge=0.0, le=1.0)
    bp_06: float = Field(0.0, ge=0.0, le=1.0)
    bp_07: float = Field(0.0, ge=0.0, le=1.0)
    bp_08: float = Field(0.0, ge=0.0, le=1.0)


class AnomalyPredictionResponse(BaseModel):
    """Isolation Forest anomaly prediction verdict."""
    is_anomaly: bool
    anomaly_score: float
    normalized_score: float
    verdict: str  # 'ANOMALOUS' or 'NORMAL'
    threshold: float


class AssistantQueryInput(BaseModel):
    """Query payload for the SOC AI Analyst Assistant."""
    query: str
    context: Optional[Dict[str, Any]] = None


class AssistantQueryResponse(BaseModel):
    """AI Analyst reply with structured recommendations."""
    reply: str
    category: str
    suggestions: List[str] = []


class BatchPredictionItem(BaseModel):
    index: int
    id: Optional[str] = None
    source_ip: Optional[str] = "N/A"
    destination_ip: Optional[str] = "N/A"
    destination_port: Optional[int] = 0
    verdict: str  # 'NORMAL', 'KNOWN_THREAT', or 'UNKNOWN_ANOMALOUS'
    prediction_status: str = "NORMAL"
    predicted_class: str = "Benign Network Traffic"
    confidence: float = 0.0
    threat_confidence: float = 0.0
    anomaly_status: str = "NORMAL"
    anomaly_score: float = 0.0
    detection_reason: str = ""
    requires_investigation: bool = False
    severity: str = "LOW"
    dominant_basepoint: str = "bp_01"


class BatchPredictionResponse(BaseModel):
    total_processed: int
    total_records: int = 0
    normal_traffic: int
    normal_events: int = 0
    threats_detected: int = 0
    known_threats: int = 0
    unknown_anomalous: int = 0
    invalid_records: int = 0
    threat_ratio: float = 0.0
    sample_results: List[BatchPredictionItem] = []
    dominant_attack_types: Dict[str, int] = {}
    attack_categories: Dict[str, int] = {}


# =====================================================================
# Chunked Upload & Resumable Processing Schemas
# =====================================================================

class UploadInitRequest(BaseModel):
    filename: str
    file_size: int
    file_hash: str
    total_chunks: int


class UploadFinalizeRequest(BaseModel):
    upload_id: str
    file_hash: str


class ProcessStartRequest(BaseModel):
    upload_id: str
    batch_size: int = 20000
    sync: bool = False


class ProcessResumeRequest(BaseModel):
    upload_id: str
    file_hash: Optional[str] = None
    batch_size: int = 20000
    sync: bool = False

