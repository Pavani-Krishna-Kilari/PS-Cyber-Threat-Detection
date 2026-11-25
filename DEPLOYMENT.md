# Render Cloud Deployment Guide

## Cyber Threat Detection Based on Artificial Neural Networks Using Event Profiles

This document provides instructions for deploying the AI-SIEM Cyber Threat Detection System on [Render](https://render.com), while maintaining compatibility with local Windows development as verified by the local test suite.

---

## 1. Project Overview & Architecture

The application is a full-stack Security Information and Event Management (SIEM) threat detection platform powered by:
- **FastAPI Backend**: Serving REST APIs, chunked streaming ingestion, and static UI assets.
- **Neural Network Inference**: Tri-model soft-voting ensemble (FCNN, CNN, LSTM) evaluated against calibrated thresholds for Experiment B.
- **Unsupervised Anomaly Detection**: Isolation Forest model trained on 8-dimensional event-profile vectors.
- **Data Drift Detection**: Population Stability Index (PSI) and Wasserstein Distance monitoring against a frozen training baseline.
- **Role-Based Access Control (RBAC)**: Enforcing granular permission boundaries between *Head of SOC* (HOD) and *Security Analyst*.
- **Storage Layer**: SQLite (`detection_history.db`) for incident ledger and forensic audit logs, alongside staged chunk uploads and candidate datasets.

---

## 2. System Specifications & Python Environment

- **Python Version**: Recommended `3.10`, `3.11`, or `3.12` for standard Render deployment images. (The test suite has been validated locally on Windows under Python 3.13.12; runtime compatibility with Render's Linux build environment should be verified during initial service deployment).
- **Package Manager**: `pip` using standard `requirements.txt`.
- **Memory Requirements**:
  - Minimum: 1 GB RAM (Standard Web Service).
  - Recommended: 2 GB RAM (ensures comfortable headroom during TensorFlow model loading and batch sliding-window aggregations).
- **Disk Requirements**: Render Persistent Disk mounted at `/var/data` (Minimum: 10 GB to accommodate detection history and file uploads).

---

## 3. Environment Variables

Configure these environment variables in the Render Dashboard (**Dashboard -> Web Service -> Environment**):

| Variable Name | Required | Default (Local) | Render Production Value | Description |
|---|:---:|:---:|:---:|---|
| `SOC_DATA_DIR` | **Yes** | `PROJECT_ROOT/data` | `/var/data` | Central mount point for all mutable runtime data (SQLite DB, uploads, candidate models). |
| `SOC_REQUIRE_EXISTING_DB` | **Yes** | `false` | `true` | Strict mode: aborts startup if database is missing, empty, or unmigrated before SQLite creates an empty file. |
| `SOC_DISABLE_DB_SEEDING` | **Yes** | `0` | `1` | Disables automatic database seeding from repository path; ensures out-of-band persistent disk migration is used. |
| `SOC_ENV` | **Yes** | `development` | `production` | Switches environment mode. In production, secure cookie flags and credential guards are enforced. |
| `SOC_ENABLE_DEMO_ACCOUNTS` | **Yes** | `true` | `false` | Explicitly disables demo credentials (`admin@soc.ai`, `analyst@soc.ai`) in production. |
| `PORT` | Auto | `8000` | Render-assigned (e.g. `10000`) | Listening port assigned automatically by Render's routing mesh. |
| `TF_ENABLE_ONEDNN_OPTS` | Optional | `1` | `0` | Disables TensorFlow oneDNN floating-point warnings in cloud logs. |
| `PYTHONUNBUFFERED` | Optional | `0` | `1` | Ensures Python stdout/stderr logs flush immediately to the Render console. |

---

## 4. Render Web Service Setup

Create a new **Web Service** in Render connected to your GitHub repository:
- **Repository**: `https://github.com/Pavani-Krishna-Kilari/PS-Cyber-Threat-Detection.git`
- **Branch**: `main`
- **Runtime**: `Python`
- **Region**: Choose the region closest to your operations (e.g., Oregon, Frankfurt, Singapore).
- **Instance Type**: `Starter` (or higher) with persistent disk support.

### Build Command
```bash
pip install -r requirements.txt
```

### Start Command
```bash
uvicorn backend.main:app --host 0.0.0.0 --port $PORT
```

---

## 5. Render Persistent Disk Setup

Render web services use an ephemeral filesystem by default; files written outside a mounted persistent disk are destroyed whenever the instance restarts, rebuilds, or redeploys.

To preserve incident detections, uploaded traffic logs, and candidate retraining assets:

1. In your Render Web Service dashboard, navigate to **Disks**.
2. Click **Add Disk** / **Attach Disk**.
3. Configure:
   - **Name**: `soc-persistent-storage`
   - **Mount Path**: `/var/data`
   - **Size**: `10 GB` (or larger depending on log ingestion scale).
4. Save changes. Render will automatically remount `/var/data` on every deployment.

### Storage Layout on Persistent Disk (`/var/data`):
```text
/var/data/
├── detection_history.db           # SQLite database (analysis sessions, detections, audit trails)
├── uploads/                       # Chunked upload staging and temporary incident files
│   └── UPL-*/
│       ├── source.csv
│       └── sorted_source.csv
├── candidate_datasets/            # Datasets uploaded to Candidate Model Studio
│   └── DS-CAND-*.csv
└── models/                        # Candidate model checkpoints and rollback archives
    ├── candidates/
    └── backups/
```

---

## 6. Database Storage Behavior & Seeding

The application implements automatic initialization and migration via `backend/database.py`:
- **Path Resolution**: When `SOC_DATA_DIR` is set to `/var/data`, the database path automatically resolves to `/var/data/detection_history.db`. Canonical path resolution is unified across `get_db_path()`, `get_connection()`, and `validate_production_database()`.
- **Strict Production Database Guard (`SOC_REQUIRE_EXISTING_DB=true`)**: In production, setting `SOC_REQUIRE_EXISTING_DB=true` ensures the application aborts immediately with a descriptive diagnostic error if `/var/data/detection_history.db` is missing, empty (0 bytes), inaccessible, or missing required schema tables and columns. This guarantees that SQLite never creates a silent, blank 0-byte database.
- **Automatic Seeding Prevention (`SOC_DISABLE_DB_SEEDING=1`)**: Disables automatic seeding from the local repository directory, ensuring that Render production runs exclusively against the verified, hard-linked persistent disk database.
- **Normal Local Development Preserved**: When `SOC_REQUIRE_EXISTING_DB` is not enabled, local development on Windows continues to initialize fresh databases and run automated schema migrations normally.
- **Fast Startup Schema Validation**: Rather than running a slow multi-second disk integrity check on every reboot, startup validation verifies file existence, non-zero size, basic SQLite accessibility (`PRAGMA schema_version`), presence of all 16 required tables, and core columns. It does not enforce hardcoded record counts, allowing legitimate new detections and sessions to accumulate over time.
- **Atomic Hard-Link Installation (`install_database_via_hardlink`)**: Out-of-band persistent disk migrations use POSIX hard-linking (`os.link`) with a harmless pre-flight probe. Hard links are strictly verified to raise `FileExistsError` on existing targets, preventing overwriting of an existing database even under concurrent operations. The pre-flight probe confirms that hard links are supported on the persistent disk filesystem before attempting installation; if unsupported, installation safely aborts without attempting any overwrite fallbacks (no `os.replace`, `shutil.move`, or `os.rename`).
- **Database Safety Safeguards**: Data integrity during migration is protected by multiple layered controls: local source backup preservation before transfer, SHA-256 hash verification, a read-only SQLite integrity check (`PRAGMA integrity_check`), exact migration record-count verification (419,191 detections and 561 sessions), strict no-overwrite installation via hard links (`install_database_via_hardlink`), and post-installation schema validation on startup. Note that while local unit and integration tests have validated these safeguards, behavior on the actual Render persistent disk must still be confirmed during the live migration process.
- **Startup Lifecycle**: The `@app.on_event("startup")` hook automatically invokes `init_db()` and directory verification before processing incoming web requests.

---

## 7. Model Artifacts & Drift Baseline Preservation

All trained models and reference baselines are **read-only, immutable assets** tracked in Git and located under `PROJECT_ROOT`:
- **Experiment B Ensemble Models**:
  - `models/saved_exp_b/fcnn_model.keras`
  - `models/saved_exp_b/cnn_model.keras`
  - `models/saved_exp_b/lstm_model.keras`
  - `models/saved_exp_b/ensemble_config.json`
- **Anomaly Detection**:
  - `models/saved_exp_b/isolation_forest.joblib`
  - `models/saved_exp_b/anomaly_config.json`
- **Event Profile Transformation**:
  - `data/processed/event_profiles_exp_b/basepoints.csv`
  - `data/processed/event_profiles_exp_b/event_thresholds.json`
  - `data/processed/event_profiles_exp_b/tfidf_model.json`
- **Statistical Drift Reference Baseline**:
  - `data/reference_baselines/drift_reference_exp_b.json`

> **Note**: Immutable artifacts are NEVER placed on the mutable persistent disk. They are served directly from the application source directory.

---

## 8. Production Authentication & Security Hardening

1. **Demo Accounts Disabled**:
   Setting `SOC_ENV=production` and `SOC_ENABLE_DEMO_ACCOUNTS=false` automatically prevents anyone from logging in using pre-configured demo credentials. Login attempts with demo accounts return `401 Unauthorized`.
2. **Password-Reset Audit Logging**:
   Password-reset tokens and all portions of tokens (full token, prefix, suffix, or masked variants) are never written to application logs or console output. Only safe audit metadata (event name, clean recipient email, and expiration timestamp) is dispatched to logs.
3. **Role-Based Access Control**:
   - **Head of SOC (HOD)**: Full access including Data Drift monitoring, Drift alerts, Retraining Studio, and Model Activation.
   - **Security Analyst**: Access restricted strictly to Threat Analyzer, Live Event Profiling, History, and Incident Triage. Data Drift endpoints return `403 Forbidden` for analysts.
4. **Session Cookie Security**:
   In production (`SOC_ENV=production`), session cookies are automatically marked `Secure`, `HttpOnly`, and `SameSite=Lax`.

---

## 9. Step-by-Step Deployment Procedure

### Step 1: Push Changes to GitHub

> **Prerequisite**: Do not commit, push, or deploy prematurely. Ensure all local deployment tests (`python -m unittest tests.test_render_deployment -v`) and full test suites pass and working directory diffs are verified first.

From your local development machine:
```bash
# 1. Run local test suite verification
python -m unittest tests.test_render_deployment -v

# 2. Stage application code, configuration, tests, scripts (including maintenance server), and docs
git add backend/ src/ run_server.py tests/ scripts/ DEPLOYMENT.md

# 3. Explicitly review staged changes before committing
git status
git diff --staged

# 4. Commit and push to remote repository (only after all checks pass)
git commit -m "Configure Render cloud deployment with persistent storage and security hardening"
git push origin main
```

### Step 2: Configure Render Dashboard
1. Go to [dashboard.render.com](https://dashboard.render.com).
2. Click **New +** -> **Web Service**.
3. Select your repository: `PS-Cyber-Threat-Detection`.
4. Enter configuration:
   - **Name**: `ai-siem-threat-detection`
   - **Runtime**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python scripts/maintenance_server.py` *(starts in isolated maintenance mode for initial migration)*
5. Under **Advanced**, add **Persistent Disk**:
   - **Mount Path**: `/var/data`
   - **Size**: `10 GB`
6. Under **Environment Variables**, add:
   - `SOC_DATA_DIR`: `/var/data`
   - `SOC_REQUIRE_EXISTING_DB`: `true`
   - `SOC_DISABLE_DB_SEEDING`: `1`
   - `SOC_ENV`: `production`
   - `SOC_ENABLE_DEMO_ACCOUNTS`: `false`
   - `TF_ENABLE_ONEDNN_OPTS`: `0`
   - `PYTHONUNBUFFERED`: `1`
7. Click **Create Web Service**.

---

### Step 3: Out-of-Band Database Transfer & Verification
Once the container deploys in maintenance mode (binding to `$PORT` and responding `200 OK` on `/healthz`):

1. **Transfer to Staging Path via Render SFTP-compatible SCP**:
   From your local Windows machine (PowerShell):
   ```powershell
   scp -s "backups/render-migration/detection_history.db" <service-id>@ssh.<region>.render.com:/var/data/detection_history.db.staging
   ```

2. **One-Time Verification in Render Shell**:
   In the Render Dashboard **Shell** tab:
   ```bash
   echo "84ffdee5164a16835b280fb20ae90d41fec84d62c3234a1e85717515543bb926  /var/data/detection_history.db.staging" | sha256sum -c -
   ```
   *Expected:* `/var/data/detection_history.db.staging: OK`

   Then run the one-time forensic check:
   ```bash
   python -c "
   import sqlite3
   conn = sqlite3.connect('file:/var/data/detection_history.db.staging?mode=ro', uri=True)
   assert conn.execute('PRAGMA integrity_check;').fetchone()[0] == 'ok'
   assert conn.execute('SELECT COUNT(*) FROM detections;').fetchone()[0] == 419191
   assert conn.execute('SELECT COUNT(*) FROM analysis_sessions;').fetchone()[0] == 561
   print('ONE-TIME FORENSIC MIGRATION VERIFICATION SUCCESSFUL!')
   "
   ```

3. **Atomic Installation via Hard Link**:
   In the Render Dashboard **Shell** tab:
   ```bash
   python -c "
   from pathlib import Path
   from backend.database import install_database_via_hardlink
   install_database_via_hardlink(
       staging_path=Path('/var/data/detection_history.db.staging'),
       target_path=Path('/var/data/detection_history.db')
   )
   print('DATABASE INSTALLED SAFELY WITHOUT OVERWRITE RISK.')
   "
   ```

4. **Switch to Production Start Command**:
   In the Render Dashboard (**Settings -> Start Command**), change to:
   ```bash
   uvicorn backend.main:app --host 0.0.0.0 --port $PORT
   ```
   Click **Save Changes** / **Manual Deploy**. The application starts, validates the database schema, and begins serving.

---

## 10. Post-Deployment Verification

Once Render finishes deploying, verify the deployment:

1. **System Health Check**:
   ```bash
   curl -s https://<your-service-url>.onrender.com/api/status
   ```
   *Expected Response:*
   ```json
   {
     "status": "OPERATIONAL",
     "service": "AI SIEM Threat Detection System",
     "active_experiment": "B",
     "models_loaded": true,
     "database_status": "CONNECTED"
   }
   ```

2. **Frontend UI**:
   Open `https://<your-service-url>.onrender.com/` in your browser. Verify that the Cyber SOC Dashboard loads with Light/Dark mode toggling and the Model Hub configuration card.

3. **Security Audit**:
   Verify that `GET /api/auth/config` reports `demo_mode: false` and `is_production: true`.

---

## 11. Important Render Tier & Persistent Storage Limitations

1. **Free Tier vs Paid Instance for Persistent Disks**:
   - Render's **Free Tier** web services spin down after 15 minutes of inactivity and **do not support persistent disks**.
   - Persistent Disks require a paid instance type (such as **Starter**, starting at \$7/month plus \$0.25/GB/month for disk).
   - If running on Free Tier without a persistent disk, do NOT set `SOC_DATA_DIR=/var/data` (leave it unset); the database and uploads will operate on the ephemeral local disk, resetting each time the free container sleeps or restarts.
2. **Single Instance Disk Attachment**:
   - A Render Persistent Disk can only be attached to **one instance at a time** (ReadWriteOnce). Do not scale beyond 1 instance when using persistent disk storage with SQLite.
3. **Upload Request Timeouts**:
   - Render proxies enforce a 100-second HTTP request timeout. The application's resumable chunked upload architecture (`/api/upload/chunk`) processes files in small bounded chunks (e.g. 5 MB) specifically to prevent timeout issues on large network captures.
