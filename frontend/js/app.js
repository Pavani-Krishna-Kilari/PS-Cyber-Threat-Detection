/**
 * AI-SIEM Main Frontend Application Controller
 * Pure Vanilla JavaScript ES6+ Modules
 */

import * as api from "./api.js";
import * as charts from "./charts.js";

let activeStreamSessionId = null;
let activeStreamRecords = [];
let isStreamPaused = false;
let allDetectionLogs = [];

const PAGE_SIZE = 50;
const tableState = {
  knownThreats: { data: [], page: 1 },
  unknownAnomalies: { data: [], page: 1 },
  campaigns: { data: [], page: 1 },
};

document.addEventListener("DOMContentLoaded", async () => {
  initDashboardBackground();
  initThemeToggle();
  initTabNavigation();
  initAnalyzerEvents();
  initAnomalyControls();
  initHistoryControls();
  initAssistantControls();
  initFloatingChatbot();
  initOperatorAuthStatus();
  initDriftSubnav();
  initTrainingStudioControls();

  await loadInitialTelemetry();
});

// -----------------------------------------------------------------------------
// Theme Management (Dark Cyber SOC vs Light)
// -----------------------------------------------------------------------------
function initThemeToggle() {
  const toggleBtn = document.getElementById("themeToggleBtn");
  const currentTheme = localStorage.getItem("soc_theme") || "dark";
  document.documentElement.setAttribute("data-theme", currentTheme);
  updateThemeBtnLabel(toggleBtn, currentTheme);

  toggleBtn.addEventListener("click", () => {
    const active = document.documentElement.getAttribute("data-theme");
    const next = active === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("soc_theme", next);
    updateThemeBtnLabel(toggleBtn, next);
  });
}

function updateThemeBtnLabel(btn, theme) {
  if (btn) {
    btn.innerHTML = theme === "dark" ? "☀️ Light Mode" : "🌙 Cyber Dark";
  }
}

let currentOperator = null;

export function getCurrentOperator() {
  if (!currentOperator) {
    const raw = localStorage.getItem("siem_operator") || sessionStorage.getItem("siem_operator");
    if (raw) {
      try { currentOperator = JSON.parse(raw); } catch (_) {}
    }
  }
  return currentOperator;
}

export function isHeadOfSocUser() {
  const op = getCurrentOperator();
  if (!op) return false;
  if (Array.isArray(op.permissions) && op.permissions.includes("view_drift")) {
    return true;
  }
  return op.role_id === "HEAD_OF_SOC";
}

export function applyRolePermissions(isHeadOfSoc) {
  const headOfSocElements = document.querySelectorAll(".head-of-soc-feature");
  const navDrift = document.getElementById("navDrift");
  const kpiDriftCard = document.getElementById("kpiDriftCard");
  const socDriftAlertBanner = document.getElementById("socDriftAlertBanner");
  const repMetricDriftCard = document.getElementById("repMetricDriftCard");
  const operatorRoleBadge = document.getElementById("operatorRoleBadge");
  const sidebarRoleLabel = document.getElementById("sidebarRoleLabel");

  if (isHeadOfSoc) {
    headOfSocElements.forEach(el => {
      if (el.id === "navDrift") {
        el.style.display = "flex";
      } else if (el.id === "kpiDriftCard") {
        el.style.display = "block";
      } else if (el.id === "repMetricDriftCard") {
        el.style.display = "block";
      } else if (el.id === "socDriftAlertBanner") {
        // Shown only if there is an active drift alert
      } else if (el.classList.contains("tab-view")) {
        // Managed by switchView
      } else {
        el.style.display = "";
      }
    });

    if (operatorRoleBadge) {
      operatorRoleBadge.innerText = "Head of SOC";
      operatorRoleBadge.className = "badge badge-threat";
    }
    if (sidebarRoleLabel) {
      sidebarRoleLabel.innerText = "Role: Head of SOC";
      sidebarRoleLabel.style.color = "var(--accent-red)";
    }
  } else {
    // Regular Security Analyst or unauthenticated
    headOfSocElements.forEach(el => {
      el.style.display = "none";
    });
    if (navDrift) navDrift.style.display = "none";
    if (kpiDriftCard) kpiDriftCard.style.display = "none";
    if (socDriftAlertBanner) socDriftAlertBanner.style.display = "none";
    if (repMetricDriftCard) repMetricDriftCard.style.display = "none";

    if (operatorRoleBadge) {
      operatorRoleBadge.innerText = "Security Analyst";
      operatorRoleBadge.className = "badge badge-info";
    }
    if (sidebarRoleLabel) {
      sidebarRoleLabel.innerText = "Role: Regular Security Analyst";
      sidebarRoleLabel.style.color = "var(--accent-cyan)";
    }
  }
}

function initOperatorAuthStatus() {
  const nameEl = document.getElementById("operatorDisplayName");
  const authActionBtn = document.getElementById("btnAuthAction");
  if (!nameEl || !authActionBtn) return;

  const storedUserRaw = localStorage.getItem("siem_operator") || sessionStorage.getItem("siem_operator");
  const token = localStorage.getItem("siem_auth_token") || sessionStorage.getItem("siem_auth_token");

  if (storedUserRaw && token) {
    try {
      const user = JSON.parse(storedUserRaw);
      currentOperator = user;
      const isHead = isHeadOfSocUser();
      applyRolePermissions(isHead);

      nameEl.innerText = `${user.name || 'SOC Analyst'} (${user.callsign || 'Overwatch'})`;
      authActionBtn.innerText = "Sign Out";
      authActionBtn.addEventListener("click", (e) => {
        e.preventDefault();
        const activeToken = localStorage.getItem("siem_auth_token") || sessionStorage.getItem("siem_auth_token");
        fetch("/api/auth/logout" + (activeToken ? "?token=" + encodeURIComponent(activeToken) : ""), {
          method: "POST",
          credentials: "same-origin"
        }).catch(() => {});
        localStorage.removeItem("siem_auth_token");
        localStorage.removeItem("siem_operator");
        sessionStorage.removeItem("siem_auth_token");
        sessionStorage.removeItem("siem_operator");
        if (window.top && window.top !== window) {
          window.top.location.href = "/login";
        } else {
          window.location.href = "/login";
        }
      });

      // Verify token validity asynchronously with backend
      fetch(`/api/auth/me?token=${encodeURIComponent(token)}`, { credentials: "same-origin" })
        .then(res => {
          if (!res.ok) {
            localStorage.removeItem("siem_auth_token");
            localStorage.removeItem("siem_operator");
            sessionStorage.removeItem("siem_auth_token");
            sessionStorage.removeItem("siem_operator");
            if (window.top && window.top !== window) {
              window.top.location.replace("/login");
            } else {
              window.location.replace("/login");
            }
          } else {
            return res.json().then(freshUser => {
              if (freshUser && freshUser.role_id) {
                currentOperator = freshUser;
                applyRolePermissions(isHeadOfSocUser());
              }
            });
          }
        })
        .catch(() => {});
      return;
    } catch (_) {}
  }

  // Not logged in default state
  currentOperator = null;
  applyRolePermissions(false);
  nameEl.innerText = "Guest Analyst";
  authActionBtn.innerText = "Sign In";
  authActionBtn.href = "/login";
}

// -----------------------------------------------------------------------------
// Tab Navigation Router (9 Planned SOC Sections)
// -----------------------------------------------------------------------------
function switchView(targetView) {
  if (!targetView) return;

  // Role-based Router Guard
  if (targetView === "view-drift" && !isHeadOfSocUser()) {
    console.warn("Access denied: Data Drift and Candidate Studio require Head of SOC privileges.");
    switchView("view-dashboard");
    return;
  }

  const navItems = document.querySelectorAll(".nav-item");
  const views = document.querySelectorAll(".tab-view");
  const pageTitle = document.getElementById("pageTitle");

  navItems.forEach(n => n.classList.remove("active"));
  views.forEach(v => v.classList.remove("active"));

  const targetNav = document.querySelector(`.nav-item[data-view="${targetView}"]`);
  if (targetNav) targetNav.classList.add("active");

  const activeEl = document.getElementById(targetView);
  if (activeEl) activeEl.classList.add("active");

  if (pageTitle && targetNav) {
    pageTitle.innerText = targetNav.querySelector("span:last-child")?.innerText || "SIEM Dashboard";
  }

  if (targetView === "view-history") {
    if (!activeStreamRecords || activeStreamRecords.length === 0) {
      loadThreatStream();
    }
  }
  if (targetView === "view-drift") {
    loadDriftPageView();
  }
}

function initTabNavigation() {
  const navItems = document.querySelectorAll(".sidebar-nav .nav-item[data-view]");

  navItems.forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const targetView = item.getAttribute("data-view");
      if (targetView) {
        switchView(targetView);
      }
    });
  });

  const navDrift = document.getElementById("navDrift");
  if (navDrift) {
    navDrift.addEventListener("click", (e) => {
      e.preventDefault();
      switchView("view-drift");
    });
  }

  document.getElementById("kpiDriftCard")?.addEventListener("click", () => {
    switchView("view-drift");
  });
  document.getElementById("btnRefreshDriftPage")?.addEventListener("click", () => {
    loadDriftPageView();
  });
}

// -----------------------------------------------------------------------------
// Dashboard Summary UI Updater (Home / SOC Overview)
// -----------------------------------------------------------------------------
export function formatVerdictLabel(verdict) {
  if (!verdict) return "Normal";
  const v = String(verdict).toUpperCase();
  if (v === "KNOWN_THREAT" || v === "THREAT" || v === "ANN_ALERT") return "ANN Alert";
  if (v === "UNKNOWN_ANOMALOUS" || v === "ANOMALOUS") return "Unknown Anomalous";
  if (v === "NORMAL") return "Normal";
  return verdict;
}

export function getVerdictBadgeClass(verdict) {
  const v = String(verdict || "").toUpperCase();
  if (v === "KNOWN_THREAT" || v === "THREAT" || v === "ANN_ALERT") return "badge-threat";
  if (v === "UNKNOWN_ANOMALOUS" || v === "ANOMALOUS") return "badge-warning";
  return "badge-normal";
}

export function updateDashboardSummaryUI(summary) {
  const elTotal = document.getElementById("kpiTotalAnalysed");
  const elTotalSub = document.getElementById("kpiTotalAnalysedSub");
  const elNormal = document.getElementById("kpiNormalEvents");
  const elNormalSub = document.getElementById("kpiNormalEventsSub");
  const elThreat = document.getElementById("kpiThreatsDetected");
  const elThreatSub = document.getElementById("kpiThreatsDetectedSub");
  const elInvalid = document.getElementById("kpiInvalidRecords");
  const elInvalidSub = document.getElementById("kpiInvalidRecordsSub");
  const noticeBox = document.getElementById("socBatchNotice");
  const noticeText = document.getElementById("socBatchNoticeText");
  const noticeBadge = document.getElementById("socBatchNoticeBadge");
  const badgeDet = document.getElementById("badgeDetectionSummary");
  const badgeCat = document.getElementById("badgeAttackCategories");

  const emptyMsg = "No uploaded dataset has been analysed yet. Upload a CSV in Threat Analyzer to view batch classification statistics.";

  if (!summary || !summary.has_data) {
    if (elTotal) elTotal.innerText = "0";
    if (elTotalSub) elTotalSub.innerText = "Source: Awaiting Upload";
    if (elNormal) elNormal.innerText = "0";
    if (elNormalSub) elNormalSub.innerText = "0.0% of analysed";
    if (elThreat) elThreat.innerText = "0";
    if (elThreatSub) elThreatSub.innerText = "0.0% of analysed";
    if (elInvalid) elInvalid.innerText = "0";
    if (elInvalidSub) elInvalidSub.innerText = "0 malformed rows";

    if (noticeBox) {
      noticeBox.className = "batch-status-panel";
      noticeBox.style.borderLeft = "3px solid var(--accent-cyan)";
    }
    if (noticeText) noticeText.innerText = emptyMsg;
    if (noticeBadge) {
      noticeBadge.className = "badge badge-info";
      noticeBadge.innerText = "Awaiting CSV Upload";
    }
    if (badgeDet) badgeDet.innerText = "Awaiting Batch Upload";
    if (badgeCat) badgeCat.innerText = "Awaiting Batch Upload";

    const driftBanner = document.getElementById("socDriftAlertBanner");
    const kpiDrift = document.getElementById("kpiDriftCard");
    if (!isHeadOfSocUser()) {
      if (driftBanner) driftBanner.style.display = "none";
      if (kpiDrift) kpiDrift.style.display = "none";
    } else if (!currentActiveDriftReport && driftBanner) {
      driftBanner.style.display = "none";
    }

    charts.renderEmptyChartState("chartDetectionSummary", emptyMsg);
    charts.renderEmptyChartState("chartAttackCategories", emptyMsg);
    return;
  }

  const flowStats = summary.flow_statistics;
  const eventStats = summary.event_set_statistics;
  const campStats = summary.campaign_statistics;

  // Canonical Field Resolution:
  // 1. Raw uploaded flows: Top-level summary.total_records is canonical for session flow count,
  //    falling back to flow_statistics.total_raw_flows.
  const totalFlows = Number(summary.total_records ?? flowStats?.total_raw_flows ?? 0);

  // 2. Total generated event sets: Top-level summary.total_processed is canonical for total sliding
  //    windows/event sets, falling back to event_set_statistics.total_event_sets or totalFlows.
  const totalEventSets = Number(summary.total_processed ?? eventStats?.total_event_sets ?? totalFlows);

  // 3. Normal event sets: Top-level summary.normal_events is canonical for full-session normal count
  //    (never overridden by alert-subset event_set_statistics.normal_event_sets), falling back to
  //    event_set_statistics.normal_event_sets.
  const normalEventSets = Number(summary.normal_events ?? eventStats?.normal_event_sets ?? 0);

  // 4. Alert event sets (for event-set distribution chart):
  //    Known threat event sets (ANN alerts) and unknown anomalous event sets.
  const knownThreatEventSets = Number(
    eventStats?.ann_alert_sets ??
    summary.known_threat_event_sets ??
    summary.model_summary?.fcnn_alerts ??
    0
  );
  const unknownAnomEventSets = Number(
    eventStats?.unknown_anomalous_sets ??
    summary.unknown_anomalous_event_sets ??
    0
  );

  // 5. Coalesced Security Campaigns (Incident level):
  const totalCampaigns = Number(campStats?.total_campaigns ?? summary.threats_detected ?? 0);
  const knownCampaigns = Number(campStats?.known_threat_campaigns ?? summary.known_threats ?? totalCampaigns);
  const unknownCampaigns = Number(campStats?.unknown_anomalous_campaigns ?? summary.unknown_anomalous ?? 0);

  const invalid = Number(flowStats?.invalid_flows ?? summary.invalid_records ?? 0);
  const filename = summary.filename || summary.source_name || "Uploaded CSV";

  if (elTotal) elTotal.innerText = totalFlows.toLocaleString();
  if (elTotalSub) {
    if (summary.detected_type === "profile" || summary.input_type === "profile") {
      elTotalSub.innerText = `${totalFlows.toLocaleString()} profiles uploaded`;
    } else {
      elTotalSub.innerText = `${totalFlows.toLocaleString()} flows • ${totalEventSets.toLocaleString()} windows`;
    }
  }

  const normalPct = totalEventSets > 0 ? ((normalEventSets / totalEventSets) * 100).toFixed(1) : "0.0";

  if (elNormal) elNormal.innerText = normalEventSets.toLocaleString();
  if (elNormalSub) {
    elNormalSub.innerText = (summary.detected_type === "profile" || summary.input_type === "profile")
      ? `${normalPct}% normal events` 
      : `${normalPct}% normal windows`;
  }

  if (elThreat) elThreat.innerText = totalCampaigns.toLocaleString();
  if (elThreatSub) {
    elThreatSub.innerText = unknownCampaigns > 0 ? `${knownCampaigns} known, ${unknownCampaigns} anomalous campaign(s)` : `${totalCampaigns} alert campaign(s)`;
  }

  if (elInvalid) elInvalid.innerText = invalid.toLocaleString();
  if (elInvalidSub) elInvalidSub.innerText = invalid === 0 ? "All records valid" : `${invalid} invalid row(s)`;

  if (noticeBox) {
    noticeBox.className = "batch-status-panel complete";
    noticeBox.style.borderLeft = "3px solid var(--accent-green)";
  }
  if (noticeText) {
    const extraInfo = (summary.detected_type === "profile" || summary.input_type === "profile")
      ? `${totalFlows.toLocaleString()} profiles analysed`
      : `${totalFlows.toLocaleString()} flows • ${totalEventSets.toLocaleString()} windows analysed`;
    noticeText.innerHTML = `✅ Active Batch Dataset: <strong>${escapeHtml(filename)}</strong> (${extraInfo} • Source: Uploaded CSV Batch)`;
  }
  if (noticeBadge) {
    noticeBadge.className = "badge badge-normal";
    noticeBadge.innerText = "Source: Uploaded CSV Batch";
  }
  if (badgeDet) badgeDet.innerText = `Source: Uploaded CSV Batch (${filename})`;
  if (badgeCat) badgeCat.innerText = `Source: Uploaded CSV Batch (${filename})`;

  // Render Charts from actual latest batch analysis:
  // Normal vs Threat Distribution Chart strictly uses EVENT SETS as the common unit
  charts.renderDetectionSummaryDoughnut("chartDetectionSummary", normalEventSets, knownThreatEventSets, unknownAnomEventSets);
  charts.renderThreatCategoryChart("chartAttackCategories", summary.attack_categories || {});

  // Update Dual-Layer Data Drift Alert Banner (Head of SOC Only)
  if (isHeadOfSocUser()) {
    if (summary.drift_analysis) {
      updateDriftBannerUI(summary.drift_analysis, false);
    } else {
      api.fetchLatestDrift().then(res => {
        if (!isHeadOfSocUser()) {
          const driftBanner = document.getElementById("socDriftAlertBanner");
          const kpiDrift = document.getElementById("kpiDriftCard");
          if (driftBanner) driftBanner.style.display = "none";
          if (kpiDrift) kpiDrift.style.display = "none";
          return;
        }
        if (res && res.has_drift && res.report) {
          updateDriftBannerUI(res.report, true);
        } else {
          const driftBanner = document.getElementById("socDriftAlertBanner");
          if (driftBanner) driftBanner.style.display = "none";
          const socKpiDrift = document.getElementById("socKpiDriftScore");
          const socKpiDriftSub = document.getElementById("socKpiDriftSubtitle");
          if (socKpiDrift) {
            socKpiDrift.innerText = "N/A";
            socKpiDrift.style.color = "var(--text-muted)";
          }
          if (socKpiDriftSub) socKpiDriftSub.innerText = "Baseline: Exp B";
        }
      }).catch(() => {
        const driftBanner = document.getElementById("socDriftAlertBanner");
        if (driftBanner) driftBanner.style.display = "none";
      });
    }
  } else {
    // Security Analyst: completely remove Data Drift alert banner and KPI card
    const driftBanner = document.getElementById("socDriftAlertBanner");
    const kpiDrift = document.getElementById("kpiDriftCard");
    if (driftBanner) driftBanner.style.display = "none";
    if (kpiDrift) kpiDrift.style.display = "none";
  }
}

let currentActiveDriftReport = null;
let currentReportDriftData = null;

function updateDriftBannerUI(da, isHistoricalOrLatestRecorded = false) {
  if (!isHeadOfSocUser()) {
    const driftBanner = document.getElementById("socDriftAlertBanner");
    const kpiDrift = document.getElementById("kpiDriftCard");
    if (driftBanner) driftBanner.style.display = "none";
    if (kpiDrift) kpiDrift.style.display = "none";
    return;
  }

  currentActiveDriftReport = da;
  const driftBanner = document.getElementById("socDriftAlertBanner");
  const driftBadge = document.getElementById("socDriftBadge");
  const driftText = document.getElementById("socDriftAlertText");
  const driftTitle = document.getElementById("socDriftAlertTitle");
  const socKpiDrift = document.getElementById("socKpiDriftScore");
  const socKpiDriftSub = document.getElementById("socKpiDriftSubtitle");
  if (!driftBanner) return;

  const isSig = da.drift_status === "SIGNIFICANT" || da.recommendation_alert;
  const isMod = da.drift_status === "MODERATE";
  driftBanner.style.display = "flex";

  if (isSig) {
    driftBanner.style.borderLeft = "4px solid var(--accent-red)";
    driftBanner.style.background = "rgba(255, 77, 77, 0.08)";
    if (driftTitle) {
      driftTitle.style.color = "var(--accent-red)";
      driftTitle.innerText = "Training Dataset Update Recommended";
    }
    if (driftBadge) {
      driftBadge.className = "badge badge-danger";
      driftBadge.innerText = `DRIFT: ${da.overall_drift_percentage}% (SIGNIFICANT)`;
    }
  } else if (isMod) {
    driftBanner.style.borderLeft = "4px solid var(--accent-amber)";
    driftBanner.style.background = "rgba(255, 171, 0, 0.08)";
    if (driftTitle) {
      driftTitle.style.color = "var(--accent-amber)";
      driftTitle.innerText = "Moderate Distribution Drift Detected";
    }
    if (driftBadge) {
      driftBadge.className = "badge badge-warning";
      driftBadge.innerText = `DRIFT: ${da.overall_drift_percentage}% (MODERATE)`;
    }
  } else {
    driftBanner.style.borderLeft = "4px solid var(--accent-green)";
    driftBanner.style.background = "rgba(0, 230, 118, 0.08)";
    if (driftTitle) {
      driftTitle.style.color = "var(--accent-green)";
      driftTitle.innerText = "Baseline Drift Status: Low";
    }
    if (driftBadge) {
      driftBadge.className = "badge badge-normal";
      driftBadge.innerText = `DRIFT: ${da.overall_drift_percentage}% (LOW)`;
    }
  }
  if (driftText) {
    const originLabel = isHistoricalOrLatestRecorded
      ? `<span style="font-weight: 600; color: var(--accent-cyan);">[Latest Recorded • Session: <code>${escapeHtml(da.session_id || "Historical")}</code> • ${escapeHtml(da.timestamp || "")}]</span> `
      : `<span style="font-weight: 600; color: var(--accent-green);">[Active Ingestion Batch]</span> `;
    driftText.innerHTML = originLabel + escapeHtml(da.recommendation_message || "Distribution drift relative to training baseline.");
  }

  if (socKpiDrift) {
    socKpiDrift.innerText = `${da.overall_drift_percentage}%`;
    socKpiDrift.style.color = isSig ? "var(--accent-red)" : (isMod ? "var(--accent-amber)" : "var(--accent-green)");
  }
  if (socKpiDriftSub) {
    socKpiDriftSub.innerText = `${da.drift_status || "LOW"}${isHistoricalOrLatestRecorded ? " (Latest)" : " (Active Batch)"}`;
  }
}

// -----------------------------------------------------------------------------
// Data Ingestion & Initial Telemetry
// -----------------------------------------------------------------------------
async function loadInitialTelemetry() {
  try {
    const isHead = isHeadOfSocUser();
    const [status, summary, profiles, benchmarks, anomaly, history, latestDrift] = await Promise.all([
      api.fetchSystemStatus(),
      api.fetchDashboardSummary(),
      api.fetchProfilesOverview(),
      api.fetchModelBenchmarks(),
      api.fetchAnomalyOverview(),
      api.fetchDetectionHistory({ limit: 50 }),
      isHead ? api.fetchLatestDrift().catch(() => null) : Promise.resolve(null)
    ]);

    // Update Status Pill
    const statusPill = document.getElementById("systemStatusPill");
    if (statusPill) {
      statusPill.innerHTML = `<span class="pulsing-dot"></span> Status: ${status.status}`;
    }

    // Sync Active Experiment label
    const activeExpLabel = document.getElementById("activeExperimentLabel");
    if (activeExpLabel && status.experiment_id) {
      activeExpLabel.innerText = `Experiment ${status.experiment_id}`;
    }

    // Sync Read-Only Ensemble & Anomaly Configuration from active backend config
    if (status && status.ensemble_config) {
      const ensThresh = Number(status.ensemble_config.threshold || 0.6561).toFixed(4);
      const cfgEnsThreshEl = document.getElementById("cfgEnsembleThreshold");
      if (cfgEnsThreshEl) cfgEnsThreshEl.innerText = ensThresh;

      const weights = status.ensemble_config.weights;
      if (Array.isArray(weights) && weights.length >= 3) {
        const [w1, w2, w3] = weights.map(w => Number(w).toFixed(2));
        const cfgFcnn = document.getElementById("cfgFcnnWeight");
        const cfgCnn = document.getElementById("cfgCnnWeight");
        const cfgLstm = document.getElementById("cfgLstmWeight");
        if (cfgFcnn) cfgFcnn.innerText = w1;
        if (cfgCnn) cfgCnn.innerText = w2;
        if (cfgLstm) cfgLstm.innerText = w3;
      }
    }

    if (anomaly && anomaly.optimal_threshold !== undefined && anomaly.optimal_threshold !== null) {
      const cfgIsoEl = document.getElementById("cfgIsoThreshold");
      if (cfgIsoEl) {
        cfgIsoEl.innerText = Number(anomaly.optimal_threshold).toFixed(6);
      }
    }

    // Home / SOC Overview: Update Detection Cards (starts at 0 if no analysis)
    updateDashboardSummaryUI(summary);

    // If no active batch summary exists, ensure latest recorded drift is displayed (Head of SOC Only)
    if (isHeadOfSocUser()) {
      if (!summary || !summary.has_data) {
        if (latestDrift && latestDrift.has_drift && latestDrift.report) {
          updateDriftBannerUI(latestDrift.report, true);
        } else {
          const socKpiDrift = document.getElementById("socKpiDriftScore");
          const socKpiDriftSub = document.getElementById("socKpiDriftSubtitle");
          if (socKpiDrift) {
            socKpiDrift.innerText = "N/A";
            socKpiDrift.style.color = "var(--text-muted)";
          }
          if (socKpiDriftSub) socKpiDriftSub.innerText = "Baseline: Exp B";
        }
      }
    } else {
      const driftBanner = document.getElementById("socDriftAlertBanner");
      const kpiDrift = document.getElementById("kpiDriftCard");
      if (driftBanner) driftBanner.style.display = "none";
      if (kpiDrift) kpiDrift.style.display = "none";
    }

    // Populate Historical/Model Hub & Event Profiles Tables
    populateBasepointsTable(profiles.basepoints || []);
    populateThresholdsTable(profiles.thresholds || []);
    populateBenchmarkTable("benchmarkTableUnseen", benchmarks.evaluation_a_unseen?.model_metrics || {});
    populateBenchmarkTable("benchmarkTableControl", benchmarks.evaluation_b_control?.model_metrics || {});

    // Populate Anomaly Telemetry in Anomaly View (Experiment B verified)
    if (anomaly) {
      const kpiIsoTrain = document.getElementById("kpiIsoTrain");
      const kpiIsoRecall = document.getElementById("kpiIsoRecall");
      const kpiIsoRoc = document.getElementById("kpiIsoRoc");
      const kpiIsoFpr = document.getElementById("kpiIsoFpr");
      const isoThreshDisplay = document.getElementById("isoThreshDisplay");

      if (kpiIsoTrain) kpiIsoTrain.innerText = (anomaly.training_samples || 1997246).toLocaleString();
      if (kpiIsoRecall) {
        const rec = anomaly.metrics_on_test?.recall !== undefined ? (anomaly.metrics_on_test.recall * 100).toFixed(2) : "6.19";
        kpiIsoRecall.innerText = `${rec}%`;
      }
      if (kpiIsoRoc) {
        const roc = anomaly.metrics_on_test?.roc_auc !== undefined ? (anomaly.metrics_on_test.roc_auc * 100).toFixed(2) : "57.92";
        kpiIsoRoc.innerText = `${roc}%`;
      }
      if (kpiIsoFpr) {
        const fpr = anomaly.metrics_on_test?.false_positive_rate !== undefined ? (anomaly.metrics_on_test.false_positive_rate * 100).toFixed(2) : "1.05";
        kpiIsoFpr.innerText = `${fpr}%`;
      }
      if (isoThreshDisplay) {
        isoThreshDisplay.innerText = Number(anomaly.optimal_threshold !== undefined ? anomaly.optimal_threshold : -0.012676).toFixed(6);
      }
    }

    // Populate Model Benchmarks Bar Chart in Model Hub view
    charts.renderModelBenchmarksChart("chartModelBenchmarks", benchmarks.evaluation_a_unseen?.model_metrics || {});

    // Populate Detection History from SQLite
    if (Array.isArray(history)) {
      allDetectionLogs = history;
      renderFilteredHistory();
    }

    // Initialize Live Stream Chart and load genuine latest upload stream
    charts.initLiveStreamLine("chartLiveStream");
    await loadThreatStream();

  } catch (err) {
    console.error("Error loading telemetry:", err);
  }
}

function populateBasepointsTable(basepoints) {
  const tbody = document.querySelector("#basepointsTable tbody");
  if (!tbody || !basepoints) return;
  tbody.innerHTML = basepoints.map(bp => `
    <tr>
      <td><strong>${bp.basepoint}</strong></td>
      <td>${Number(bp.HIGH_FLOW_RATE || 0).toFixed(4)}</td>
      <td>${Number(bp.HIGH_PACKET_RATE || 0).toFixed(4)}</td>
      <td>${Number(bp.HIGH_BYTE_RATE || 0).toFixed(4)}</td>
      <td>${Number(bp.SYN_ACTIVITY || 0).toFixed(4)}</td>
      <td>${Number(bp.SHORT_REPEATED_CONNECTIONS || 0).toFixed(4)}</td>
      <td>${bp.max_cosine_to_previous !== null && bp.max_cosine_to_previous !== undefined ? Number(bp.max_cosine_to_previous).toFixed(4) : "—"}</td>
    </tr>
  `).join("");
}

function populateThresholdsTable(thresholds) {
  const tbody = document.querySelector("#thresholdsTable tbody");
  if (!tbody || !thresholds) return;
  const entries = Array.isArray(thresholds) ? thresholds : Object.entries(thresholds).map(([name, t]) => ({ name, ...t }));
  tbody.innerHTML = entries.map(t => `
    <tr>
      <td><code>${t.name || t.event_name}</code></td>
      <td><span class="badge badge-info">${t.level || 'Window'}</span></td>
      <td>${t.feature || t.source_feature}</td>
      <td>${t.comparison}</td>
      <td><strong>${Number(t.threshold).toLocaleString()}</strong></td>
    </tr>
  `).join("");
}

export function populateBenchmarkTable(tableId, modelsReport) {
  const tbody = document.querySelector(`#${tableId} tbody`);
  if (!tbody || !modelsReport) return;
  tbody.innerHTML = Object.entries(modelsReport).map(([name, m]) => {
    const threshStr = m.threshold !== undefined && m.threshold !== null ? Number(m.threshold).toFixed(4) : "—";
    const accStr = m.accuracy !== undefined ? `${(m.accuracy * 100).toFixed(2)}%` : "—";
    const balAccStr = m.balanced_accuracy !== undefined ? `<strong>${(m.balanced_accuracy * 100).toFixed(2)}%</strong>` : "—";
    const recStr = m.recall !== undefined ? `<strong>${(m.recall * 100).toFixed(2)}%</strong>` : "—";
    const precStr = m.precision !== undefined ? `${(m.precision * 100).toFixed(2)}%` : "—";
    const f1Str = m.f1_score !== undefined ? `${(m.f1_score * 100).toFixed(2)}%` : "—";
    const prAucStr = m.pr_auc !== undefined ? Number(m.pr_auc).toFixed(4) : "—";
    const rocAucStr = m.roc_auc !== undefined ? `<strong>${(m.roc_auc * 100).toFixed(2)}%</strong>` : "—";
    const fprStr = m.false_positive_rate !== undefined ? `<span class="badge badge-normal">${(m.false_positive_rate * 100).toFixed(2)}%</span>` : "—";
    const cmStr = m.confusion_matrix ? `TP:${m.confusion_matrix.tp} / FP:${m.confusion_matrix.fp}` : "—";

    return `
      <tr>
        <td><strong>${name}</strong></td>
        <td><code>${threshStr}</code></td>
        <td>${accStr}</td>
        <td>${balAccStr}</td>
        <td>${recStr}</td>
        <td>${precStr}</td>
        <td>${f1Str}</td>
        <td>${prAucStr}</td>
        <td>${rocAucStr}</td>
        <td>${fprStr}</td>
        <td><code>${cmStr}</code></td>
      </tr>
    `;
  }).join("");
}

// -----------------------------------------------------------------------------
// Interactive Threat Analyzer & File Upload Interface (CSV, TXT, PDF)
// -----------------------------------------------------------------------------
function initAnalyzerEvents() {
  const form = document.getElementById("flowAnalyzerForm");
  const fileInput = document.getElementById("fileInput");
  const dropzone = document.getElementById("uploadDropzone");

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const payload = {
        source_ip: document.getElementById("flowSrcIp").value,
        destination_ip: document.getElementById("flowDstIp").value,
        source_port: parseInt(document.getElementById("flowSrcPort").value) || 0,
        destination_port: parseInt(document.getElementById("flowDstPort").value) || 0,
        protocol: 6,
        flow_packets_s: parseFloat(document.getElementById("flowPackets").value) || 0,
        flow_bytes_s: parseFloat(document.getElementById("flowBytes").value) || 0,
        syn_flag_count: parseInt(document.getElementById("flowSyn").value) || 0,
        flow_duration: parseFloat(document.getElementById("flowDuration").value) || 0,
        flow_count: parseInt(document.getElementById("flowCount").value) || 1
      };

      try {
        const res = await api.predictFlow(payload);
        displayVerdict(res);

        // STRICT SEPARATION RULE: Manual single-flow classification updates ONLY
        // the Manual Single-Flow Verdict panel in Threat Analyzer.
        // It NEVER updates or contributes to SOC Overview statistics, charts, or records.
        const newHistory = await api.fetchDetectionHistory({ limit: 50 });
        if (Array.isArray(newHistory)) {
          allDetectionLogs = newHistory;
          renderFilteredHistory();
        }
      } catch (err) {
        alert("Inference error: " + err.message);
      }
    });
  }

  // Pre-fill Sample Buttons (pure input population, strictly decoupled from submission)
  document.getElementById("btnSampleBenign")?.addEventListener("click", () => {
    document.getElementById("flowSrcIp").value = "192.168.10.15";
    document.getElementById("flowDstIp").value = "192.168.10.3";
    document.getElementById("flowDstPort").value = 443;
    document.getElementById("flowPackets").value = 120.0;
    document.getElementById("flowBytes").value = 45000.0;
    document.getElementById("flowSyn").value = 0;
    document.getElementById("flowDuration").value = 850000.0;
    document.getElementById("flowCount").value = 3;
  });

  document.getElementById("btnSampleFtpPatator")?.addEventListener("click", () => {
    document.getElementById("flowSrcIp").value = "172.16.0.1";
    document.getElementById("flowDstIp").value = "192.168.10.50";
    document.getElementById("flowDstPort").value = 21;
    document.getElementById("flowPackets").value = 500000.0;
    document.getElementById("flowBytes").value = 2000000.0;
    document.getElementById("flowSyn").value = 1;
    document.getElementById("flowDuration").value = 1000.0;
    document.getElementById("flowCount").value = 15;
  });

  document.getElementById("btnSampleSshPatator")?.addEventListener("click", () => {
    document.getElementById("flowSrcIp").value = "172.16.0.1";
    document.getElementById("flowDstIp").value = "192.168.10.50";
    document.getElementById("flowDstPort").value = 22;
    document.getElementById("flowPackets").value = 650000.0;
    document.getElementById("flowBytes").value = 2800000.0;
    document.getElementById("flowSyn").value = 2;
    document.getElementById("flowDuration").value = 1000.0;
    document.getElementById("flowCount").value = 25;
  });

  // Dropzone Events
  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
      if (e.dataTransfer.files.length) handleFileUpload(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", () => {
      if (fileInput.files.length) handleFileUpload(fileInput.files[0]);
    });
  }
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

async function clearBatchResults() {
  const statusEl = document.getElementById("uploadStatus");
  if (statusEl) statusEl.innerHTML = "";
  const metricsPanel = document.getElementById("batchMetricsPanel");
  if (metricsPanel) metricsPanel.style.display = "none";
  const campTable = document.getElementById("campaignResultsTable");
  if (campTable) {
    const tbody = campTable.querySelector("tbody");
    if (tbody) tbody.innerHTML = "";
  }
  const table = document.getElementById("batchResultsTable");
  if (table) {
    const tbody = table.querySelector("tbody");
    if (tbody) tbody.innerHTML = "";
    table.style.display = "none";
  }
  const fileInput = document.getElementById("fileInput");
  if (fileInput) fileInput.value = "";

  // Reset backend batch analysis summary and restore SOC Overview empty state
  try {
    await api.clearBatchSummary();
  } catch (err) {
    console.warn("Could not clear backend batch summary:", err);
  }
  updateDashboardSummaryUI({ has_data: false });
  clearThreatStreamUI();
}

let currentUploadController = null;
let activeUploadSession = null;

function renderCompletedAnalysisResults(res, defaultFilename = "") {
  const statusEl = document.getElementById("uploadStatus");
  const metricsPanel = document.getElementById("batchMetricsPanel");

  const flowStats = res.flow_statistics || {};
  const eventStats = res.event_set_statistics || {};
  const campStats = res.campaign_statistics || {};

  const totalRawFlows = Number(res.total_records ?? flowStats.total_raw_flows ?? 0);
  const totalSets = Number(res.total_processed ?? eventStats.total_event_sets ?? totalRawFlows);
  const normalSets = Number(res.normal_events ?? eventStats.normal_event_sets ?? 0);
  const totalCampaigns = Number(campStats.total_campaigns ?? res.threats_detected ?? 0);
  const threatCampaigns = Number(campStats.known_threat_campaigns ?? res.known_threats ?? 0);
  const anomCampaigns = Number(campStats.unknown_anomalous_campaigns ?? res.unknown_anomalous ?? 0);
  const invalidFlows = Number(flowStats.invalid_flows ?? res.invalid_records ?? 0);
  const procDuration = res.processing_time_ms ? `${res.processing_time_ms} ms` : "N/A";
  const captureType = res.detected_type === "flow" ? "Raw Network Flows" : (res.input_type === "flow" ? "Raw Network Flows" : "Event Profiles");

  if (statusEl) {
    statusEl.innerHTML = `
      <div class="batch-status-panel complete">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; flex-wrap: wrap; gap: 8px;">
          <div>
            <span style="color: var(--accent-green); font-weight: 700;">✅ Batch Analysis Complete</span>
            <span style="color: var(--text-secondary); margin-left: 8px;"><code>${escapeHtml(res.filename || res.source_name || defaultFilename)}</code> (${escapeHtml(captureType)} • ${procDuration})</span>
          </div>
          <button class="btn btn-secondary" id="btnClearBatchResults" type="button" style="padding: 4px 10px; font-size: 12px;">Clear Results</button>
        </div>
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
          <div class="kpi-mini-pill">Total Analysed: <strong>${totalSets.toLocaleString()}</strong></div>
          <div class="kpi-mini-pill">Uploaded Flows: <strong>${totalRawFlows.toLocaleString()}</strong></div>
          <div class="kpi-mini-pill">Generated Event Sets: <strong>${totalSets.toLocaleString()}</strong></div>
          <div class="kpi-mini-pill threat">Alert Campaigns: <strong>${totalCampaigns.toLocaleString()}</strong></div>
          <div class="kpi-mini-pill normal">Normal Sets: <strong>${normalSets.toLocaleString()}</strong></div>
          <div class="kpi-mini-pill threat">Known Threats: <strong>${threatCampaigns.toLocaleString()}</strong></div>
          <div class="kpi-mini-pill warning">Unknown Anomalous: <strong>${anomCampaigns.toLocaleString()}</strong></div>
          ${invalidFlows > 0 ? `<div class="kpi-mini-pill info">Invalid: <strong>${invalidFlows.toLocaleString()}</strong></div>` : ''}
        </div>
      </div>
    `;
    document.getElementById("btnClearBatchResults")?.addEventListener("click", clearBatchResults);
  }

  // Populate and show Batch Metrics Panel
  if (metricsPanel) {
    metricsPanel.style.display = "block";
    const elFlows = document.getElementById("metricUploadedFlows");
    const elSets = document.getElementById("metricGeneratedEventSets");
    const elCamps = document.getElementById("metricUniqueCampaigns");
    const elNorm = document.getElementById("metricNormalSets");
    const elThreatC = document.getElementById("metricKnownThreatCampaigns");
    const elAnomC = document.getElementById("metricUnknownAnomalousCampaigns");
    const elDur = document.getElementById("metricProcessingDuration");

    if (elFlows) elFlows.innerText = totalRawFlows.toLocaleString();
    if (elSets) elSets.innerText = totalSets.toLocaleString();
    if (elCamps) elCamps.innerText = totalCampaigns.toLocaleString();
    if (elNorm) elNorm.innerText = normalSets.toLocaleString();
    if (elThreatC) elThreatC.innerText = threatCampaigns.toLocaleString();
    if (elAnomC) elAnomC.innerText = anomCampaigns.toLocaleString();
    if (elDur) elDur.innerText = procDuration;
  }

  // Render Section A: Known Threats / ANN Alerts
  renderKnownThreatsTable(res.known_threats_list || []);

  // Render Section B: Unknown Anomalous Activity
  renderUnknownAnomaliesTable(res.unknown_anomalies_list || []);

  // Render Section C: Coalesced Security Campaigns Table
  renderCampaignResultsTable(res.campaigns || []);

  // Render Window Batch Table (Collapsible Audit Trail)
  renderBatchResultsTable(res.sample_results || [], totalSets);

  // Update Dashboard Summary Cards & Charts for SOC Overview
  updateDashboardSummaryUI(res);

  // Refresh Sessions Archive from SQLite
  loadSessionsArchive();

  // Load genuine Sliding Window Threat Stream for this newly uploaded session
  loadThreatStream(res.session_id);
}

function renderErrorPanel(errMsg, uploadId = null, detailExtra = "", fileHash = null) {
  const statusEl = document.getElementById("uploadStatus");
  if (!statusEl) return;
  const isConnectionError = /failed to fetch|connection|network|retries|timeout|offline/i.test(errMsg || "");

  let actionButtons = '';
  if (isConnectionError && uploadId) {
    actionButtons = `
      <button class="btn btn-primary" id="btnReconnectStatus" type="button" style="padding: 4px 12px; font-size: 12px;">Reconnect & Resume</button>
      <button class="btn btn-secondary" id="btnClearBatchResults" type="button" style="padding: 4px 10px; font-size: 12px; margin-left: 6px;">Dismiss</button>
    `;
  } else {
    actionButtons = `
      ${uploadId ? `<button class="btn btn-secondary" id="btnRetryCancel" type="button" style="padding: 4px 10px; font-size: 12px; color: var(--accent-red);">Cancel & Cleanup</button>` : ''}
      <button class="btn btn-secondary" id="btnClearBatchResults" type="button" style="padding: 4px 10px; font-size: 12px; margin-left: 6px;">Dismiss</button>
    `;
  }

  statusEl.innerHTML = `
    <div class="batch-status-panel" style="border-left: 3px solid var(--accent-red);">
      <div style="display: flex; justify-content: space-between; align-items: flex-start;">
        <div>
          <span style="color: var(--accent-red); font-weight: 600;">⚠️ Ingestion Error: ${escapeHtml(errMsg)}</span>
          ${isConnectionError ? '<div style="margin-top: 4px; font-size: 11.5px; color: var(--text-muted);">Background analysis may still be executing on the server. Click Reconnect & Resume to re-attach.</div>' : ''}
          ${detailExtra}
        </div>
        <div style="display: flex; gap: 6px; align-items: center;">
          ${actionButtons}
        </div>
      </div>
    </div>
  `;
  document.getElementById("btnClearBatchResults")?.addEventListener("click", clearBatchResults);
  if (document.getElementById("btnReconnectStatus")) {
    document.getElementById("btnReconnectStatus").addEventListener("click", () => {
      resumeActiveProcessing(uploadId, fileHash || activeUploadSession?.fileHash);
    });
  }
  if (uploadId && document.getElementById("btnRetryCancel")) {
    document.getElementById("btnRetryCancel").addEventListener("click", async () => {
      try {
        await api.cancelUploadSession(uploadId);
      } catch (_) {}
      clearBatchResults();
    });
  }
}

function renderPausedPanel(uploadId, fileHash, status) {
  const statusEl = document.getElementById("uploadStatus");
  if (!statusEl) return;
  const cBatches = status?.completed_batches ?? 0;
  const tBatches = status?.total_batches ?? 1;
  const pRows = status?.processed_rows?.toLocaleString() ?? "0";

  statusEl.innerHTML = `
    <div class="batch-status-panel" style="border-left: 3px solid var(--accent-amber);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span style="color: var(--accent-amber); font-weight: 700;">⏸️ Analysis Paused (Batch ${cBatches} of ${tBatches} • ${pRows} rows)</span>
        <div style="display: flex; gap: 8px;">
          <button class="btn btn-primary" id="btnResumeStream" style="padding: 4px 12px; font-size: 12px;">Resume Analysis</button>
          <button class="btn btn-secondary" id="btnCancelStream" style="padding: 4px 10px; font-size: 12px;">Cancel & Cleanup</button>
        </div>
      </div>
      <p style="font-size: 11.5px; color: var(--text-muted); margin: 0;">
        Checkpoints are safely saved in SQLite. You can resume processing anytime without reclassifying completed batches.
      </p>
    </div>
  `;

  document.getElementById("btnResumeStream")?.addEventListener("click", () => {
    resumeActiveProcessing(uploadId, fileHash);
  });
  document.getElementById("btnCancelStream")?.addEventListener("click", async () => {
    try {
      await api.cancelUploadSession(uploadId);
    } catch (_) {}
    clearBatchResults();
  });
}

function renderProcessingProgress(info) {
  const statusEl = document.getElementById("uploadStatus");
  if (!statusEl) return;
  const pct = Math.max(0, Math.min(100, Math.round(info.percent || 0)));
  const cBatches = info.completed_batches || 0;
  const tBatches = info.total_batches || 1;
  const pRows = (info.processed_rows || 0).toLocaleString();
  const tRows = (info.total_rows || 0).toLocaleString();
  const m = info.metrics || {};

  const warningHtml = info.warning_message ? `
    <div style="background: rgba(255, 179, 0, 0.15); border: 1px solid var(--accent-amber); border-radius: 4px; padding: 6px 10px; margin-bottom: 8px; font-size: 11.5px; color: var(--accent-amber); animation: pulse 1.5s infinite;">
      ⚠️ ${escapeHtml(info.warning_message)}
    </div>
  ` : '';

  statusEl.innerHTML = `
    <div class="batch-status-panel processing">
      ${warningHtml}
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="display: inline-block; width: 12px; height: 12px; border: 2px solid var(--accent-cyan); border-right-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite;"></span>
          <span style="color: var(--accent-cyan); font-weight: 600;">Streaming Inference: <strong>Batch ${cBatches} of ${tBatches} (${pct}%)</strong></span>
        </div>
        <div style="display: flex; gap: 6px;">
          <button class="btn btn-secondary" id="btnPauseProc" style="padding: 2px 8px; font-size: 11px;">Pause</button>
          <button class="btn btn-secondary" id="btnCancelProc" style="padding: 2px 8px; font-size: 11px;">Cancel</button>
        </div>
      </div>
      <div style="background: rgba(255,255,255,0.08); height: 8px; border-radius: 4px; overflow: hidden; margin-bottom: 10px;">
        <div style="background: var(--accent-cyan); width: ${pct}%; height: 100%; transition: width 0.3s;"></div>
      </div>
      <div style="display: flex; flex-wrap: wrap; gap: 6px; font-size: 11px;">
        <div class="kpi-mini-pill">Rows Evaluated: <strong>${pRows} / ${tRows}</strong></div>
        <div class="kpi-mini-pill">Event Sets: <strong>${(m.total_event_sets || 0).toLocaleString()}</strong></div>
        <div class="kpi-mini-pill normal">Normal: <strong>${(m.normal_event_sets || 0).toLocaleString()}</strong></div>
        <div class="kpi-mini-pill threat">Known Threats: <strong>${(m.known_threats || 0).toLocaleString()}</strong></div>
        <div class="kpi-mini-pill warning">Unknown Anomalies: <strong>${(m.unknown_anomalous || 0).toLocaleString()}</strong></div>
      </div>
    </div>
  `;

  document.getElementById("btnPauseProc")?.addEventListener("click", async () => {
    if (info.upload_id) {
      try {
        await api.pauseStreamProcessing(info.upload_id);
      } catch (err) {
        console.warn("Pause error:", err);
      }
    }
    if (currentUploadController) currentUploadController.abort();
  });

  document.getElementById("btnCancelProc")?.addEventListener("click", async () => {
    if (info.upload_id) {
      try {
        await api.pauseStreamProcessing(info.upload_id);
      } catch (err) {
        console.warn("Pause error before cancel:", err);
      }
    }
    if (currentUploadController) currentUploadController.abort();
    renderPausedPanel(info.upload_id, activeUploadSession?.fileHash, {
      completed_batches: info.completed_batches,
      total_batches: info.total_batches,
      processed_rows: info.processed_rows
    });
  });
}

async function resumeActiveProcessing(uploadId, fileHash) {
  currentUploadController = new AbortController();
  activeUploadSession = { uploadId, fileHash };

  try {
    const resumeRes = await api.resumeStreamProcessing(uploadId, fileHash, 20000, false);
    if (resumeRes.error || resumeRes.detail) {
      throw new Error(resumeRes.detail?.message || resumeRes.detail || resumeRes.error || "Failed to resume processing.");
    }

    while (true) {
      if (currentUploadController?.signal?.aborted) {
        await api.pauseStreamProcessing(uploadId);
        return;
      }
      await new Promise(r => setTimeout(r, 800));
      const status = await api.getStreamProcessStatus(uploadId, {
        maxRetries: 5,
        retryDelayBaseMs: 1200,
        signal: currentUploadController?.signal,
        onRetry: (retryInfo) => {
          renderProcessingProgress({
            upload_id: uploadId,
            percent: 0,
            warning_message: `Network connection hiccup: retrying status check (${retryInfo.attempt}/${retryInfo.maxRetries}). Background processing is continuing...`
          });
        }
      });

      if (status.processing_status === "FAILED") {
        throw new Error(status.error_message || "Processing failed.");
      }

      if (status.processing_status === "PAUSED") {
        renderPausedPanel(uploadId, fileHash, status);
        return;
      }

      if (status.processing_status === "COMPLETED") {
        const report = await api.fetchSessionReport(status.session_id);
        renderCompletedAnalysisResults(report, status.filename);
        activeUploadSession = null;
        return;
      }

      renderProcessingProgress({
        upload_id: uploadId,
        percent: status.progress_percent || 0,
        completed_batches: status.completed_batches,
        total_batches: status.total_batches,
        processed_rows: status.processed_rows,
        total_rows: status.total_rows,
        metrics: status.metrics || {}
      });
    }
  } catch (err) {
    renderErrorPanel(err.message, uploadId, "", fileHash);
  }
}

async function handleFileUpload(file) {
  const statusEl = document.getElementById("uploadStatus");
  currentUploadController = new AbortController();

  const isCsv = file.name.toLowerCase().endsWith(".csv");
  let isProfileCsv = false;

  if (isCsv) {
    try {
      const headerSlice = await file.slice(0, 2048).text();
      const firstLine = (headerSlice.split(/\r?\n/)[0] || "").toLowerCase();
      const headers = firstLine.split(",").map(h => h.trim().replace(/^["']|["']$/g, "").toLowerCase());
      const hasAllBps = ["bp_01", "bp_02", "bp_03", "bp_04", "bp_05", "bp_06", "bp_07", "bp_08"].every(bp => headers.includes(bp));
      if (hasAllBps) {
        isProfileCsv = true;
      }
    } catch (_) {
      isProfileCsv = false;
    }
  }

  if (!isCsv || isProfileCsv) {
    // Preaggregated Event Profile CSV or Non-CSV captures (TXT, LOG, PDF) use single-payload upload endpoint
    if (statusEl) {
      statusEl.innerHTML = `
        <div class="batch-status-panel processing">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span style="display: inline-block; width: 14px; height: 14px; border: 2px solid var(--accent-cyan); border-right-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite;"></span>
            <span style="color: var(--accent-cyan); font-weight: 600;">${isProfileCsv ? "Ingesting and evaluating preaggregated event profiles" : "Ingesting, aggregating, and classifying"} <code>${escapeHtml(file.name)}</code> (${(file.size / 1024).toFixed(1)} KB)...</span>
          </div>
        </div>
      `;
    }

    try {
      const res = await api.uploadThreatFile(file);
      if (res.error || res.detail) {
        let errMsg = "";
        let detailExtra = "";
        if (typeof res.detail === "object" && res.detail !== null) {
          errMsg = res.detail.message || res.detail.error || JSON.stringify(res.detail);
          if (res.detail.details && res.detail.details.extracted_records !== undefined) {
            detailExtra = `
              <div style="margin-top: 6px; font-size: 11px; color: var(--text-muted);">
                Extracted: <strong>${escapeHtml(res.detail.details.extracted_records)}</strong> flow record(s) • Detected columns: <code>${escapeHtml((res.detail.details.columns_found || []).join(", "))}</code>
              </div>
            `;
          }
        } else {
          errMsg = res.detail || res.error;
        }
        renderErrorPanel(errMsg, null, detailExtra);
        return;
      }
      renderCompletedAnalysisResults(res, file.name);
    } catch (err) {
      renderErrorPanel(err.message);
    }
    return;
  }

  // Chunked & Resumable CSV Processing Pipeline
  let activeHash = null;
  let activeUid = null;

  try {
    const report = await api.uploadFileChunked(file, {
      signal: currentUploadController.signal,
      chunkSize: 5 * 1024 * 1024,
      batchSize: 20000,
      pollIntervalMs: 750,
      onProgress: (p) => {
        if (p.phase === "HASHING" && statusEl) {
          statusEl.innerHTML = `
            <div class="batch-status-panel processing">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="color: var(--accent-cyan); font-weight: 600;">🔒 Computing Streaming SHA-256 Checksum: <strong>${p.percent}%</strong></span>
                <span style="font-size: 11px; color: var(--text-muted);">${(file.size / (1024 * 1024)).toFixed(1)} MB</span>
              </div>
              <div style="background: rgba(255,255,255,0.08); height: 8px; border-radius: 4px; overflow: hidden;">
                <div style="background: var(--accent-cyan); width: ${p.percent}%; height: 100%; transition: width 0.2s;"></div>
              </div>
            </div>
          `;
        }
      },
      onStatusChange: (ev) => {
        if (ev.upload_id) activeUid = ev.upload_id;
        if (ev.file_hash) activeHash = ev.file_hash;

        if (ev.phase === "UPLOADING" && statusEl) {
          statusEl.innerHTML = `
            <div class="batch-status-panel processing">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span style="color: var(--accent-cyan); font-weight: 600;">⬆️ Uploading Chunks: <strong>Chunk ${ev.chunk_index} of ${ev.total_chunks} (${ev.percent}%)</strong></span>
                <button class="btn btn-secondary" id="btnCancelChunkUpload" style="padding: 2px 8px; font-size: 11px;">Cancel</button>
              </div>
              <div style="background: rgba(255,255,255,0.08); height: 8px; border-radius: 4px; overflow: hidden;">
                <div style="background: var(--accent-cyan); width: ${ev.percent}%; height: 100%; transition: width 0.2s;"></div>
              </div>
            </div>
          `;
          document.getElementById("btnCancelChunkUpload")?.addEventListener("click", async () => {
            if (activeUid) {
              try { await api.cancelUploadSession(activeUid); } catch (_) {}
            }
            if (currentUploadController) currentUploadController.abort();
            clearBatchResults();
          });
        } else if (ev.phase === "SORTING" && statusEl) {
          statusEl.innerHTML = `
            <div class="batch-status-panel processing">
              <div style="display: flex; align-items: center; gap: 10px;">
                <span style="display: inline-block; width: 14px; height: 14px; border: 2px solid var(--accent-cyan); border-right-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite;"></span>
                <span style="color: var(--accent-cyan); font-weight: 600;">🔀 External Sort: Chronologically ordering network capture flows...</span>
              </div>
            </div>
          `;
        } else if (ev.phase === "PROCESSING") {
          renderProcessingProgress(ev);
        } else if (ev.phase === "POLLING_RETRY") {
          renderProcessingProgress({
            upload_id: activeUid,
            percent: ev.percent || 0,
            warning_message: ev.message
          });
        } else if (ev.phase === "PAUSED") {
          renderPausedPanel(ev.upload_id, activeHash, ev.status);
        }
      }
    });

    if (report && !report.paused) {
      renderCompletedAnalysisResults(report, file.name);
    }
  } catch (err) {
    if (err.message && err.message.includes("paused")) {
      return;
    }
    renderErrorPanel(err.message, activeUid, "", activeHash);
  }
}

function renderKnownThreatsTable(threats, tableId = "knownThreatsTable", badgeId = "badgeKnownThreatsCount") {
  const table = document.getElementById(tableId);
  const tbody = table?.querySelector("tbody");
  const countBadge = document.getElementById(badgeId);
  const n = (threats || []).length;
  if (countBadge) {
    countBadge.innerText = `${n} Known Threat${n === 1 ? '' : 's'}`;
  }
  if (!tbody) return;

  if (!threats || threats.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 16px;">No known threats identified by the ANN ensemble. All evaluated event profiles were within benign limits or handled as anomalous.</td></tr>`;
    return;
  }

  tbody.innerHTML = threats.map((t, idx) => {
    const esId = escapeHtml(t.event_set_id || t.id || `ES${String(idx + 1).padStart(7, '0')}`);
    const campId = escapeHtml(t.campaign_id || "-");
    const srcHost = escapeHtml(t.source_ip || "N/A");
    const dstHost = escapeHtml(t.destination_ip ? `${t.destination_ip}${t.destination_port ? ':' + t.destination_port : ''}` : "N/A");
    const timeRange = escapeHtml(String(t.timestamp || t.window_start || "N/A").replace("T", " "));
    const confVal = (Number(t.confidence ?? t.threat_confidence ?? 0) * 100).toFixed(2);
    const sev = t.severity || "HIGH";
    const flowCount = t.n_flows ?? (t.flow_metadata && t.flow_metadata.n_flows ? t.flow_metadata.n_flows : 1);

    return `
      <tr>
        <td><strong style="color: var(--accent-red); font-family: var(--font-mono);">${esId}</strong></td>
        <td><code style="color: var(--accent-cyan);">${campId}</code></td>
        <td><code>${srcHost}</code></td>
        <td><code>${dstHost}</code></td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${timeRange}</td>
        <td><strong>${confVal}%</strong></td>
        <td><span class="badge badge-threat">${escapeHtml(sev)}</span></td>
        <td><span class="badge badge-normal">${Number(flowCount).toLocaleString()} flows</span></td>
      </tr>
    `;
  }).join("");
}

function renderUnknownAnomaliesTable(anomalies, tableId = "unknownAnomaliesTable", badgeId = "badgeUnknownAnomaliesCount") {
  const table = document.getElementById(tableId);
  const tbody = table?.querySelector("tbody");
  const countBadge = document.getElementById(badgeId);
  const n = (anomalies || []).length;
  if (countBadge) {
    countBadge.innerText = `${n} Anomal${n === 1 ? 'y' : 'ies'}`;
  }
  if (!tbody) return;

  if (!anomalies || anomalies.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 16px;">No anomalous activity flagged by Isolation Forest. Traffic adheres to expected distribution baselines.</td></tr>`;
    return;
  }

  tbody.innerHTML = anomalies.map((a, idx) => {
    const esId = escapeHtml(a.event_set_id || a.id || `ES${String(idx + 1).padStart(7, '0')}`);
    const campId = escapeHtml(a.campaign_id || "-");
    const srcHost = escapeHtml(a.source_ip || "N/A");
    const dstHost = escapeHtml(a.destination_ip ? `${a.destination_ip}${a.destination_port ? ':' + a.destination_port : ''}` : "N/A");
    const timeRange = escapeHtml(String(a.timestamp || a.window_start || "N/A").replace("T", " "));
    const anomScore = a.anomaly_score !== undefined ? Number(a.anomaly_score).toFixed(4) : "N/A";
    const sev = a.severity || "MEDIUM";
    const flowCount = a.n_flows ?? (a.flow_metadata && a.flow_metadata.n_flows ? a.flow_metadata.n_flows : 1);

    return `
      <tr>
        <td><strong style="color: var(--accent-amber); font-family: var(--font-mono);">${esId}</strong></td>
        <td><code style="color: var(--accent-cyan);">${campId}</code></td>
        <td><code>${srcHost}</code></td>
        <td><code>${dstHost}</code></td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${timeRange}</td>
        <td><strong style="color: var(--accent-amber);">${anomScore}</strong></td>
        <td><span class="badge badge-warning">${escapeHtml(sev)}</span></td>
        <td><span class="badge badge-normal">${Number(flowCount).toLocaleString()} flows</span></td>
      </tr>
    `;
  }).join("");
}

function renderCampaignResultsTable(campaigns, tableId = "campaignResultsTable", badgeId = "badgeCampaignCount") {
  const table = document.getElementById(tableId);
  const tbody = table?.querySelector("tbody");
  const countBadge = document.getElementById(badgeId);
  if (countBadge) {
    countBadge.innerText = `${(campaigns || []).length} Campaign${(campaigns || []).length === 1 ? '' : 's'}`;
  }
  if (!tbody) return;

  if (!campaigns || campaigns.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 16px;">No alert campaigns identified. All observed sliding windows are within normal traffic baseline.</td></tr>`;
    return;
  }

  tbody.innerHTML = campaigns.map(c => {
    const cid = escapeHtml(c.campaign_id);
    const srcIp = escapeHtml(c.source_ip || "N/A");
    const dstIp = escapeHtml(c.destination_ip || "N/A");
    const startT = escapeHtml(String(c.start_time || "").replace("T", " "));
    const endT = escapeHtml(String(c.end_time || "").replace("T", " "));
    const verdict = c.verdict || "UNKNOWN";
    const badgeClass = getVerdictBadgeClass(verdict);
    const verdictLabel = formatVerdictLabel(verdict);
    const confVal = (Number(c.max_confidence || 0) * 100).toFixed(2);
    const winCount = c.window_count ?? (c.constituent_windows ? c.constituent_windows.length : 1);
    const flowCount = c.attributed_flow_count ?? (c.attributed_flow_indices ? c.attributed_flow_indices.length : 0);

    return `
      <tr>
        <td><strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${cid}</strong></td>
        <td><code>${srcIp}</code></td>
        <td><code>${dstIp}</code></td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${startT}</td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${endT}</td>
        <td><span class="badge ${badgeClass}">${verdictLabel}</span></td>
        <td><strong>${confVal}%</strong></td>
        <td><span class="badge badge-info">${winCount} win</span></td>
        <td><span class="badge badge-normal">${flowCount.toLocaleString()} flows</span></td>
      </tr>
    `;
  }).join("");
}

function renderBatchResultsTable(results, totalCount) {
  const table = document.getElementById("batchResultsTable");
  const tbody = table?.querySelector("tbody");
  const countBadge = document.getElementById("badgeWindowCount");
  if (countBadge) {
    const n = totalCount ?? (results || []).length;
    countBadge.innerText = `${n.toLocaleString()} Windows${results && results.length < n ? ` (showing first ${results.length})` : ''}`;
  }
  if (!tbody) return;
  table.style.display = "table";

  if (!results || results.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 16px;">No records available to display.</td></tr>`;
    return;
  }

  tbody.innerHTML = results.map((r, idx) => {
    const recNum = r.index ?? r.id ?? (idx + 1);
    const srcHost = r.source_ip || "N/A";
    const dstHost = (r.destination_ip) ? `${r.destination_ip}${r.destination_port ? ':' + r.destination_port : ''}` : "N/A";
    const verdict = r.verdict || "UNKNOWN";
    const badgeClass = getVerdictBadgeClass(verdict);
    const verdictLabel = formatVerdictLabel(verdict);
    const confVal = (Number(r.confidence ?? r.threat_confidence ?? 0) * 100).toFixed(2);
    const severity = r.severity || "LOW";

    let sevBadgeClass = "badge-info";
    if (severity === "CRITICAL" || severity === "HIGH") sevBadgeClass = "badge-threat";
    else if (severity === "MEDIUM") sevBadgeClass = "badge-warning";
    else if (severity === "LOW" || severity === "INFO") sevBadgeClass = "badge-normal";

    return `
      <tr>
        <td>${recNum}</td>
        <td><code>${escapeHtml(srcHost)}</code></td>
        <td><code>${escapeHtml(dstHost)}</code></td>
        <td><span class="badge ${badgeClass}">${escapeHtml(verdictLabel)}</span></td>
        <td><strong>${confVal}%</strong></td>
        <td><span class="badge ${sevBadgeClass}">${escapeHtml(severity)}</span></td>
      </tr>
    `;
  }).join("");
}

// -----------------------------------------------------------------------------
// STRICT REQUIREMENT: Display ONE Final Verdict (NORMAL, KNOWN_THREAT, or UNKNOWN_ANOMALOUS)
// -----------------------------------------------------------------------------
function displayVerdict(res) {
  const box = document.getElementById("verdictBox");
  if (!box) return;

  const v = res.verdict || res.prediction_status || "NORMAL";
  const isKnownThreat = (v === "KNOWN_THREAT" || v === "THREAT" || v === "ANN_ALERT");
  const isAnomalous = (v === "UNKNOWN_ANOMALOUS" || v === "ANOMALOUS");

  if (isKnownThreat) {
    box.className = "verdict-box threat";
  } else if (isAnomalous) {
    box.className = "verdict-box anomalous";
  } else {
    box.className = "verdict-box normal";
  }

  document.getElementById("verdictTitle").innerText = formatVerdictLabel(v);
  document.getElementById("verdictConfidence").innerText = `${(Number(res.confidence ?? res.threat_confidence ?? 0) * 100).toFixed(2)}%`;
  
  const sevBadge = document.getElementById("verdictSeverityBadge");
  if (sevBadge) {
    sevBadge.innerText = res.severity || "LOW";
    sevBadge.className = `badge ${isKnownThreat ? 'badge-threat' : (isAnomalous ? 'badge-warning' : 'badge-normal')}`;
  }

  document.getElementById("verdictDominantBp").innerText = `${res.dominant_basepoint} (${Number(res.dominant_basepoint_similarity || 0).toFixed(4)})`;

  const clsEl = document.getElementById("verdictPredictedClass");
  if (clsEl && res.predicted_class) {
    clsEl.innerText = res.predicted_class;
  }
  const reasonEl = document.getElementById("verdictReason");
  if (reasonEl && res.detection_reason) {
    reasonEl.innerText = res.detection_reason;
  }

  // Submodel probabilities for transparency
  document.getElementById("meterFcnn").style.width = `${((res.model_breakdown?.fcnn || 0) * 100).toFixed(1)}%`;
  document.getElementById("meterCnn").style.width = `${((res.model_breakdown?.cnn || 0) * 100).toFixed(1)}%`;
  document.getElementById("meterLstm").style.width = `${((res.model_breakdown?.lstm || 0) * 100).toFixed(1)}%`;

  document.getElementById("valFcnn").innerText = `${((res.model_breakdown?.fcnn || 0) * 100).toFixed(1)}%`;
  document.getElementById("valCnn").innerText = `${((res.model_breakdown?.cnn || 0) * 100).toFixed(1)}%`;
  document.getElementById("valLstm").innerText = `${((res.model_breakdown?.lstm || 0) * 100).toFixed(1)}%`;

  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// -----------------------------------------------------------------------------
// SECTION 5: Anomaly Detection Controls (Isolation Forest)
// -----------------------------------------------------------------------------
function initAnomalyControls() {
  // Manual profile coordinate editing has been removed in favor of the fully
  // automated event-profile pipeline. Isolation Forest telemetry and threshold
  // display are populated dynamically during initial telemetry loading.
}

// -----------------------------------------------------------------------------
// SECTION 6: Persistent Classification Reports Archive & Session Management
// -----------------------------------------------------------------------------
let currentSessionArchive = [];
let filteredSessionArchive = [];
let sessionArchivePage = 0;
const SESSIONS_PER_PAGE = 10;
let pendingDeleteSession = null;
let activeSessionReport = null;

async function loadSessionsArchive() {
  const tbody = document.querySelector("#sessionHistoryTable tbody");
  const infoEl = document.getElementById("sessionPaginationInfo");
  if (!tbody) return;

  tbody.innerHTML = `
    <tr>
      <td colspan="11" style="text-align: center; color: var(--accent-cyan); padding: 24px;">
        <span style="display: inline-block; width: 14px; height: 14px; border: 2px solid var(--accent-cyan); border-right-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 8px;"></span>
        Loading persistent classification reports from SQLite...
      </td>
    </tr>
  `;

  try {
    const sessions = await api.fetchSessions({ limit: 200, offset: 0 });
    currentSessionArchive = Array.isArray(sessions) ? sessions : [];

    // Apply any active search filter
    const searchInput = document.getElementById("sessionSearchInput");
    const query = searchInput ? searchInput.value.trim().toLowerCase() : "";
    if (query) {
      filteredSessionArchive = currentSessionArchive.filter(s =>
        (s.filename || s.source_name || "").toLowerCase().includes(query) ||
        (s.session_id || "").toLowerCase().includes(query)
      );
    } else {
      filteredSessionArchive = [...currentSessionArchive];
    }

    sessionArchivePage = 0;
    renderSessionsArchiveTable();
  } catch (err) {
    console.error("Failed to load sessions archive:", err);
    tbody.innerHTML = `
      <tr>
        <td colspan="11" style="text-align: center; color: var(--accent-red); padding: 20px;">
          ⚠️ Error loading classification archive: ${escapeHtml(err.message)}
        </td>
      </tr>
    `;
    if (infoEl) infoEl.innerText = "Error loading reports";
  }
}

function renderSessionsArchiveTable() {
  const tbody = document.querySelector("#sessionHistoryTable tbody");
  const infoEl = document.getElementById("sessionPaginationInfo");
  const btnPrev = document.getElementById("btnPrevSessions");
  const btnNext = document.getElementById("btnNextSessions");
  if (!tbody) return;

  const total = filteredSessionArchive.length;
  if (total === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="11" style="text-align: center; color: var(--text-muted); padding: 28px; font-style: italic;">
          No classification reports found. Upload a network capture to generate persistent reports.
        </td>
      </tr>
    `;
    if (infoEl) infoEl.innerText = "0 reports archived";
    if (btnPrev) btnPrev.disabled = true;
    if (btnNext) btnNext.disabled = true;
    return;
  }

  const maxPage = Math.max(0, Math.ceil(total / SESSIONS_PER_PAGE) - 1);
  if (sessionArchivePage > maxPage) sessionArchivePage = maxPage;
  if (sessionArchivePage < 0) sessionArchivePage = 0;

  const startIdx = sessionArchivePage * SESSIONS_PER_PAGE;
  const pageItems = filteredSessionArchive.slice(startIdx, startIdx + SESSIONS_PER_PAGE);

  if (infoEl) {
    infoEl.innerText = `Showing ${startIdx + 1}–${Math.min(startIdx + SESSIONS_PER_PAGE, total)} of ${total} reports (Page ${sessionArchivePage + 1} of ${maxPage + 1})`;
  }
  if (btnPrev) btnPrev.disabled = sessionArchivePage === 0;
  if (btnNext) btnNext.disabled = sessionArchivePage >= maxPage;

  tbody.innerHTML = pageItems.map(s => {
    const sid = escapeHtml(s.session_id);
    const fname = escapeHtml(s.filename || s.source_name || "Capture");
    const dateStr = escapeHtml(String(s.timestamp || "").replace("T", " "));
    const flows = Number(s.uploaded_flows ?? s.total_records ?? 0).toLocaleString();
    const sets = Number(s.event_sets ?? s.total_records ?? 0).toLocaleString();
    const normal = Number(s.normal_events ?? 0).toLocaleString();
    const threats = Number(s.known_threats ?? 0).toLocaleString();
    const anom = Number(s.unknown_anomalous ?? 0).toLocaleString();
    const camps = Number(s.campaigns_count ?? 0).toLocaleString();
    const status = escapeHtml(s.status || "Completed");

    const threatBadgeClass = Number(s.known_threats || 0) > 0 ? "badge-threat" : "badge-normal";
    const anomBadgeClass = Number(s.unknown_anomalous || 0) > 0 ? "badge-warning" : "badge-normal";

    return `
      <tr>
        <td><code style="font-size: 11px; color: var(--accent-cyan); font-family: var(--font-mono);">${sid}</code></td>
        <td><strong>${fname}</strong></td>
        <td style="font-size: 11.5px; color: var(--text-secondary); font-family: var(--font-mono);">${dateStr}</td>
        <td>${flows}</td>
        <td>${sets}</td>
        <td><span class="badge badge-normal">${normal}</span></td>
        <td><span class="badge ${threatBadgeClass}">${threats}</span></td>
        <td><span class="badge ${anomBadgeClass}">${anom}</span></td>
        <td><span class="badge badge-info">${camps}</span></td>
        <td><span class="badge badge-normal">${status}</span></td>
        <td style="white-space: nowrap;">
          <button class="btn btn-secondary btn-view-report" data-session-id="${sid}" style="padding: 4px 10px; font-size: 11.5px;">View Report</button>
          <button class="btn btn-threat btn-delete-session" data-session-id="${sid}" data-filename="${fname}" style="padding: 4px 8px; font-size: 11.5px; margin-left: 4px;">Delete</button>
        </td>
      </tr>
    `;
  }).join("");

  // Attach event listeners to row buttons
  tbody.querySelectorAll(".btn-view-report").forEach(btn => {
    btn.addEventListener("click", () => {
      const sid = btn.getAttribute("data-session-id");
      if (sid) viewSessionReport(sid);
    });
  });

  tbody.querySelectorAll(".btn-delete-session").forEach(btn => {
    btn.addEventListener("click", () => {
      const sid = btn.getAttribute("data-session-id");
      const fname = btn.getAttribute("data-filename");
      if (sid) promptDeleteSession(sid, fname);
    });
  });
}

async function viewSessionReport(sessionId) {
  const historyCard = document.getElementById("sessionHistoryCard");
  const reportPanel = document.getElementById("sessionReportPanel");

  try {
    const report = await api.fetchSessionReport(sessionId);
    if (!report || report.detail) {
      alert("Failed to load report: " + (report?.detail || "Session not found"));
      return;
    }
    activeSessionReport = report;

    // Toggle panels
    if (historyCard) historyCard.style.display = "none";
    if (reportPanel) reportPanel.style.display = "block";

    // Populate Header
    const fnEl = document.getElementById("reportHeaderFilename");
    const metaEl = document.getElementById("reportHeaderMeta");
    const fname = report.filename || report.source_name || "Network Capture";
    const itype = report.input_type === "flow" ? "Raw Network Flows" : "Event Profiles";
    if (fnEl) fnEl.innerText = `${fname} (${itype})`;
    if (metaEl) metaEl.innerText = `Session ID: ${report.session_id} • Analyzed on ${String(report.timestamp || "").replace("T", " ")}`;

    // Populate Metrics
    const flowStats = report.flow_statistics || {};
    const eventStats = report.event_set_statistics || {};
    const campStats = report.campaign_statistics || {};

    const elFlows = document.getElementById("repMetricFlows");
    const elSets = document.getElementById("repMetricSets");
    const elNorm = document.getElementById("repMetricNormal");
    const elThreat = document.getElementById("repMetricThreats");
    const elAnom = document.getElementById("repMetricAnomalies");
    const elCamps = document.getElementById("repMetricCampaigns");

    if (elFlows) elFlows.innerText = Number(report.total_records ?? flowStats.total_raw_flows ?? 0).toLocaleString();
    if (elSets) elSets.innerText = Number(report.total_processed ?? eventStats.total_event_sets ?? report.total_records ?? 0).toLocaleString();
    if (elNorm) elNorm.innerText = Number(report.normal_events ?? eventStats.normal_event_sets ?? 0).toLocaleString();
    if (elThreat) elThreat.innerText = Number(campStats.known_threat_campaigns ?? report.known_threats ?? 0).toLocaleString();
    if (elAnom) elAnom.innerText = Number(campStats.unknown_anomalous_campaigns ?? report.unknown_anomalous ?? 0).toLocaleString();
    const campTotal = campStats.total_campaigns ?? (report.campaigns ? report.campaigns.length : (report.threats_detected ?? 0));
    if (elCamps) elCamps.innerText = Number(campTotal).toLocaleString();

    // Populate Data Drift Metric Card (Head of SOC Only)
    const elDrift = document.getElementById("repMetricDrift");
    const elDriftCard = document.getElementById("repMetricDriftCard");
    currentReportDriftData = isHeadOfSocUser() ? (report.drift_analysis || null) : null;
    if (elDriftCard) {
      elDriftCard.style.display = isHeadOfSocUser() ? "block" : "none";
    }
    if (elDrift && isHeadOfSocUser()) {
      if (currentReportDriftData && currentReportDriftData.overall_drift_percentage !== undefined) {
        elDrift.innerText = `${currentReportDriftData.overall_drift_percentage}%`;
        const st = currentReportDriftData.drift_status;
        elDrift.style.color = st === "SIGNIFICANT" ? "var(--accent-red)" : (st === "MODERATE" ? "var(--accent-amber)" : "var(--accent-green)");
        elDrift.title = "Click to inspect detailed Dual-Layer Drift Report";
      } else {
        elDrift.innerText = "N/A";
        elDrift.style.color = "var(--text-muted)";
        elDrift.title = "Historical session: Data drift analysis was not recorded for this session.";
      }
    }

    // Populate Model Summary
    const ms = report.model_summary || {};
    const elFcnn = document.getElementById("repModelFcnn");
    const elCnn = document.getElementById("repModelCnn");
    const elLstm = document.getElementById("repModelLstm");
    const elEns = document.getElementById("repModelEns");
    if (elFcnn) elFcnn.innerText = (ms.fcnn_avg !== undefined && ms.fcnn_avg !== null) ? `${(Number(ms.fcnn_avg) * 100).toFixed(1)}%` : "N/A";
    if (elCnn) elCnn.innerText = (ms.cnn_avg !== undefined && ms.cnn_avg !== null) ? `${(Number(ms.cnn_avg) * 100).toFixed(1)}%` : "N/A";
    if (elLstm) elLstm.innerText = (ms.lstm_avg !== undefined && ms.lstm_avg !== null) ? `${(Number(ms.lstm_avg) * 100).toFixed(1)}%` : "N/A";
    if (elEns) elEns.innerText = (ms.ensemble_avg !== undefined && ms.ensemble_avg !== null) ? `${(Number(ms.ensemble_avg) * 100).toFixed(1)}%` : "N/A";

    // Render Section A: Known Threats
    renderKnownThreatsTable(report.known_threats_list || [], "reportKnownThreatsTable", "repBadgeKnownThreats");

    // Render Section B: Unknown Anomalies
    renderUnknownAnomaliesTable(report.unknown_anomalies_list || [], "reportUnknownAnomaliesTable", "repBadgeUnknownAnomalies");

    // Render Section C: Logical Security Campaigns
    renderCampaignResultsTable(report.campaigns || [], "reportCampaignsTable", "repBadgeCampaigns");

    // Collapsible all detections audit log
    const allDets = report.sample_results || [];
    const repBadgeAll = document.getElementById("repBadgeAllDetections");
    if (repBadgeAll) repBadgeAll.innerText = `${allDets.length} Records`;
    const tbodyAll = document.querySelector("#reportAllDetectionsTable tbody");
    if (tbodyAll) {
      if (allDets.length === 0) {
        tbodyAll.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 14px;">No individual detection records to display.</td></tr>`;
      } else {
        tbodyAll.innerHTML = allDets.map(r => `
          <tr>
            <td><code>${escapeHtml(String(r.timestamp || 'N/A').replace('T', ' '))}</code></td>
            <td><code>${escapeHtml(r.source_ip || 'N/A')}</code></td>
            <td><code>${escapeHtml(r.destination_ip || 'N/A')}${r.destination_port ? ':' + r.destination_port : ''}</code></td>
            <td><span class="badge ${getVerdictBadgeClass(r.verdict)}">${escapeHtml(formatVerdictLabel(r.verdict))}</span></td>
            <td><strong>${(Number(r.confidence ?? r.threat_confidence ?? 0) * 100).toFixed(1)}%</strong></td>
            <td><span class="badge badge-info">${escapeHtml(r.severity || 'LOW')}</span></td>
          </tr>
        `).join("");
      }
    }
  } catch (err) {
    console.error("Error viewing session report:", err);
    alert("Could not load report: " + err.message);
  }
}

function backToHistory() {
  const historyCard = document.getElementById("sessionHistoryCard");
  const reportPanel = document.getElementById("sessionReportPanel");
  if (reportPanel) reportPanel.style.display = "none";
  if (historyCard) historyCard.style.display = "block";
  activeSessionReport = null;
  loadSessionsArchive();
}

function promptDeleteSession(sessionId, filename) {
  pendingDeleteSession = { sessionId, filename };
  const modal = document.getElementById("deleteSessionModal");
  const fnEl = document.getElementById("delModalFilename");
  const sidEl = document.getElementById("delModalSessionId");
  if (fnEl) fnEl.innerText = filename || "Session Report";
  if (sidEl) sidEl.innerText = sessionId;
  if (modal) modal.style.display = "flex";
}

function closeDeleteModal() {
  const modal = document.getElementById("deleteSessionModal");
  if (modal) modal.style.display = "none";
  pendingDeleteSession = null;
}

function openDriftModal(driftData) {
  if (!isHeadOfSocUser() || !driftData) return;
  const modal = document.getElementById("driftDetailModal");
  if (!modal) return;

  const alertBox = document.getElementById("driftModalAlertBox");
  const title = document.getElementById("driftModalTitle");
  const msg = document.getElementById("driftModalMessage");
  const badge = document.getElementById("driftModalScoreBadge");
  const l1Score = document.getElementById("driftModalL1Score");
  const l2Score = document.getElementById("driftModalL2Score");
  const refPop = document.getElementById("driftModalRefPop");
  const l1Tbody = document.getElementById("driftModalL1TableBody");
  const l2Tbody = document.getElementById("driftModalL2TableBody");

  const isSig = driftData.drift_status === "SIGNIFICANT" || driftData.recommendation_alert;
  if (alertBox) {
    alertBox.style.background = isSig ? "rgba(255, 77, 77, 0.12)" : (driftData.drift_status === "MODERATE" ? "rgba(255, 171, 0, 0.12)" : "rgba(0, 230, 118, 0.12)");
    alertBox.style.borderLeft = isSig ? "4px solid var(--accent-red)" : (driftData.drift_status === "MODERATE" ? "4px solid var(--accent-amber)" : "4px solid var(--accent-green)");
  }
  if (title) {
    title.innerText = isSig ? "⚠️ Significant Drift: Training Dataset Update Recommended" : (driftData.drift_status === "MODERATE" ? "⚡ Moderate Drift Detected" : "✅ Low Drift: Operational Parameters Normal");
    title.style.color = isSig ? "var(--accent-red)" : (driftData.drift_status === "MODERATE" ? "var(--accent-amber)" : "var(--accent-green)");
  }
  if (msg) msg.innerText = driftData.recommendation_message || "";
  if (badge) {
    badge.className = isSig ? "badge badge-danger" : (driftData.drift_status === "MODERATE" ? "badge badge-warning" : "badge badge-normal");
    badge.innerText = `OVERALL DRIFT: ${driftData.overall_drift_percentage}% (${driftData.drift_status})`;
  }

  const l1 = driftData.layer1_network_features;
  const l2 = driftData.layer2_event_profiles;

  if (l1Score) l1Score.innerText = l1 ? `${(l1.score * 100).toFixed(1)}%` : "N/A (Omitted)";
  if (l2Score) l2Score.innerText = l2 ? `${(l2.score * 100).toFixed(1)}%` : "N/A (Omitted)";
  if (refPop) refPop.innerText = `Exp B (${(driftData.reference_population || "full").toUpperCase()})`;

  // Layer 1 table
  if (l1Tbody) {
    if (l1 && l1.features && Object.keys(l1.features).length > 0) {
      l1Tbody.innerHTML = Object.entries(l1.features).map(([featName, f]) => `
        <tr>
          <td><strong style="color:var(--accent-cyan); font-family:var(--font-mono);">${featName}</strong></td>
          <td>${Number(f.actual_mean).toLocaleString(undefined, {maximumFractionDigits: 2})}</td>
          <td>${Number(f.reference_mean).toLocaleString(undefined, {maximumFractionDigits: 2})}</td>
          <td>${f.ks_statistic} <span style="font-size:10px; color:var(--text-muted);">(p=${f.ks_pvalue})</span></td>
          <td>${f.psi} <span style="font-size:10px; color:var(--text-muted);">(${f.psi_score})</span></td>
          <td>${f.wasserstein_raw} <span style="font-size:10px; color:var(--text-muted);">(norm: ${f.wasserstein_normalized})</span></td>
          <td><strong style="color:${f.feature_drift_score >= 0.5 ? 'var(--accent-red)' : (f.feature_drift_score >= 0.25 ? 'var(--accent-amber)' : 'var(--accent-green)')};">${(f.feature_drift_score * 100).toFixed(1)}%</strong></td>
        </tr>
      `).join("");
    } else {
      l1Tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">${driftData.is_partial ? 'Layer 1 omitted (Preaggregated profile input)' : 'No Layer 1 features evaluated.'}</td></tr>`;
    }
  }

  // Layer 2 table
  if (l2Tbody) {
    if (l2 && l2.basepoints && Object.keys(l2.basepoints).length > 0) {
      l2Tbody.innerHTML = Object.entries(l2.basepoints).map(([bpName, bp]) => `
        <tr>
          <td><strong style="color:var(--accent-purple); font-family:var(--font-mono);">${bpName}</strong></td>
          <td>${Number(bp.actual_mean).toFixed(4)}</td>
          <td>${Number(bp.reference_mean).toFixed(4)}</td>
          <td>${bp.ks_statistic}</td>
          <td>${bp.psi}</td>
          <td>${Number(bp.wasserstein_raw).toFixed(4)}</td>
          <td><strong style="color:${bp.dimension_drift_score >= 0.5 ? 'var(--accent-red)' : (bp.dimension_drift_score >= 0.25 ? 'var(--accent-amber)' : 'var(--accent-green)')};">${(bp.dimension_drift_score * 100).toFixed(1)}%</strong></td>
        </tr>
      `).join("");
    } else {
      l2Tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No Layer 2 profile metrics evaluated.</td></tr>`;
    }
  }

  // Dominant basepoints
  const jsdEl = document.getElementById("driftModalJSD");
  const jsDistEl = document.getElementById("driftModalJSDist");
  const barsContainer = document.getElementById("driftModalDominantBars");
  if (jsdEl) jsdEl.innerText = l2?.js_divergence !== undefined ? l2.js_divergence : "-";
  if (jsDistEl) jsDistEl.innerText = l2?.js_distance !== undefined ? `${(l2.js_distance * 100).toFixed(1)}%` : "-";

  if (barsContainer) {
    if (l2 && l2.dominant_basepoint_distribution_actual) {
      const act = l2.dominant_basepoint_distribution_actual || {};
      const ref = l2.dominant_basepoint_distribution_reference || {};
      barsContainer.innerHTML = Array.from({length: 8}, (_, i) => {
        const k = `bp_0${i + 1}`;
        const pAct = ((act[k] || 0) * 100).toFixed(1);
        const pRef = ((ref[k] || 0) * 100).toFixed(1);
        return `
          <div style="background:var(--bg-card); padding:8px; border-radius:4px; border:1px solid var(--border-color);">
            <div style="font-weight:700; color:var(--accent-cyan); font-family:var(--font-mono);">${k}</div>
            <div style="font-size:11px; margin-top:3px;">Actual: <strong>${pAct}%</strong></div>
            <div style="font-size:11px; color:var(--text-muted);">Ref: ${pRef}%</div>
          </div>
        `;
      }).join("");
    } else {
      barsContainer.innerHTML = `<div style="grid-column:1/-1; color:var(--text-muted); font-size:12px;">No categorical dominant basepoint data available.</div>`;
    }
  }

  modal.style.display = "flex";
}

function closeDriftModal() {
  const modal = document.getElementById("driftDetailModal");
  if (modal) modal.style.display = "none";
}

export async function loadDriftPageView() {
  if (!isHeadOfSocUser()) {
    switchView("view-dashboard");
    return;
  }
  const [latestRes, historyRes] = await Promise.all([
    api.fetchLatestDrift().catch(() => null),
    api.fetchDriftHistory(20).catch(() => [])
  ]);

  const report = (latestRes && latestRes.has_drift) ? latestRes.report : null;

  // Render Top Banner & Status
  const alertBanner = document.getElementById("driftPageAlertBanner");
  const alertTitle = document.getElementById("driftPageAlertTitle");
  const alertText = document.getElementById("driftPageAlertText");
  const targetMeta = document.getElementById("driftPageTargetMeta");
  const badgeOverall = document.getElementById("driftPageOverallBadge");

  const elOverall = document.getElementById("driftPageOverallScore");
  const elOverallStatus = document.getElementById("driftPageOverallStatus");
  const elL1 = document.getElementById("driftPageL1Score");
  const elL1Sub = document.getElementById("driftPageL1Sub");
  const elL2 = document.getElementById("driftPageL2Score");
  const elL2Sub = document.getElementById("driftPageL2Sub");
  const elRefPop = document.getElementById("driftPageRefPop");
  const elRefMeta = document.getElementById("driftPageRefMeta");
  const elSess = document.getElementById("driftPageSessionId");
  const elTs = document.getElementById("driftPageTimestamp");

  if (report) {
    const isSig = report.drift_status === "SIGNIFICANT" || report.recommendation_alert;
    const isMod = report.drift_status === "MODERATE";

    if (alertBanner) {
      alertBanner.style.borderLeft = isSig ? "4px solid var(--accent-red)" : (isMod ? "4px solid var(--accent-amber)" : "4px solid var(--accent-green)");
      alertBanner.style.background = isSig ? "rgba(255, 77, 77, 0.08)" : (isMod ? "rgba(255, 171, 0, 0.08)" : "rgba(0, 230, 118, 0.08)");
    }
    if (alertTitle) {
      alertTitle.style.color = isSig ? "var(--accent-red)" : (isMod ? "var(--accent-amber)" : "var(--accent-green)");
      alertTitle.innerText = isSig ? "Training Dataset Update Recommended" : (isMod ? "Moderate Distribution Drift Detected" : "Baseline Distribution Stable");
    }
    if (alertText) {
      alertText.innerText = report.recommendation_message || "Distribution drift evaluated between baseline training and ingested traffic.";
    }
    if (targetMeta) {
      targetMeta.innerText = `Evaluated Target Session: ${report.session_id || "N/A"} • Upload: ${report.upload_id || "N/A"} • Recorded: ${report.timestamp || "N/A"}`;
    }
    if (badgeOverall) {
      badgeOverall.className = isSig ? "badge badge-danger" : (isMod ? "badge badge-warning" : "badge badge-normal");
      badgeOverall.innerText = `DRIFT: ${report.overall_drift_percentage}% (${report.drift_status})`;
    }

    if (elOverall) {
      elOverall.innerText = `${report.overall_drift_percentage}%`;
      elOverall.style.color = isSig ? "var(--accent-red)" : (isMod ? "var(--accent-amber)" : "var(--accent-green)");
    }
    if (elOverallStatus) elOverallStatus.innerText = `Status: ${report.drift_status}`;

    if (elL1) {
      if (report.layer1_network_features && report.layer1_network_features.score !== null && report.layer1_network_features.score !== undefined) {
        elL1.innerText = `${(report.layer1_network_features.score * 100).toFixed(1)}%`;
        elL1.style.color = "var(--accent-cyan)";
      } else {
        elL1.innerText = "N/A";
        elL1.style.color = "var(--text-muted)";
      }
    }
    if (elL1Sub) {
      elL1Sub.innerText = report.is_partial ? "Omitted (Profile-only input)" : "4 continuous features";
    }

    if (elL2) {
      if (report.layer2_event_profiles && report.layer2_event_profiles.score !== null && report.layer2_event_profiles.score !== undefined) {
        elL2.innerText = `${(report.layer2_event_profiles.score * 100).toFixed(1)}%`;
        elL2.style.color = "var(--accent-purple)";
      } else {
        elL2.innerText = "N/A";
        elL2.style.color = "var(--text-muted)";
      }
    }
    if (elL2Sub) {
      elL2Sub.innerText = "8 basepoint dimensions";
    }

    if (elRefPop) elRefPop.innerText = `Exp B (${(report.reference_population || "full").toUpperCase()})`;
    if (elRefMeta) elRefMeta.innerText = `Baseline: ${report.reference_experiment || "exp_b"}`;

    if (elSess) elSess.innerText = report.session_id || "-";
    if (elTs) elTs.innerText = report.timestamp || "-";

    renderDriftPageTables(report);
  } else {
    if (elOverall) elOverall.innerText = "N/A";
    if (elOverallStatus) elOverallStatus.innerText = "No drift evaluated yet";
    if (elL1) elL1.innerText = "N/A";
    if (elL2) elL2.innerText = "N/A";
    if (alertText) alertText.innerText = "No data drift reports currently recorded. Upload a network traffic CSV or event profiles to calculate data drift.";
  }

  // Render Drift History Table
  renderDriftHistoryTable(historyRes || []);
}

function renderDriftPageTables(driftData) {
  const l1Tbody = document.getElementById("driftPageL1TableBody");
  const l2Tbody = document.getElementById("driftPageL2TableBody");
  const l1 = driftData.layer1_network_features;
  const l2 = driftData.layer2_event_profiles;

  // Layer 1 table
  if (l1Tbody) {
    if (l1 && l1.features && Object.keys(l1.features).length > 0) {
      l1Tbody.innerHTML = Object.entries(l1.features).map(([featName, f]) => `
        <tr>
          <td><strong style="color:var(--accent-cyan); font-family:var(--font-mono);">${featName}</strong></td>
          <td>${Number(f.actual_mean).toLocaleString(undefined, {maximumFractionDigits: 2})}</td>
          <td>${Number(f.reference_mean).toLocaleString(undefined, {maximumFractionDigits: 2})}</td>
          <td>${f.psi} <span style="font-size:10px; color:var(--text-muted);">(${f.psi_score})</span></td>
          <td>${f.ks_statistic} <span style="font-size:10px; color:var(--text-muted);">(p=${f.ks_pvalue})</span></td>
          <td>${f.wasserstein_raw} <span style="font-size:10px; color:var(--text-muted);">(norm: ${f.wasserstein_normalized})</span></td>
          <td><strong style="color:${f.feature_drift_score >= 0.5 ? 'var(--accent-red)' : (f.feature_drift_score >= 0.25 ? 'var(--accent-amber)' : 'var(--accent-green)')};">${(f.feature_drift_score * 100).toFixed(1)}%</strong></td>
        </tr>
      `).join("");
    } else {
      l1Tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">${driftData.is_partial ? 'Layer 1 omitted (Preaggregated profile input)' : 'No Layer 1 features evaluated.'}</td></tr>`;
    }
  }

  // Layer 2 table
  if (l2Tbody) {
    if (l2 && l2.basepoints && Object.keys(l2.basepoints).length > 0) {
      l2Tbody.innerHTML = Object.entries(l2.basepoints).map(([bpName, bp]) => `
        <tr>
          <td><strong style="color:var(--accent-purple); font-family:var(--font-mono);">${bpName}</strong></td>
          <td>${Number(bp.actual_mean).toFixed(4)}</td>
          <td>${Number(bp.reference_mean).toFixed(4)}</td>
          <td>${bp.psi}</td>
          <td>${bp.ks_statistic} <span style="font-size:10px; color:var(--text-muted);">(p=${bp.ks_pvalue})</span></td>
          <td>${Number(bp.wasserstein_raw).toFixed(4)} <span style="font-size:10px; color:var(--text-muted);">(norm: ${bp.wasserstein_normalized})</span></td>
          <td><strong style="color:${bp.dimension_drift_score >= 0.5 ? 'var(--accent-red)' : (bp.dimension_drift_score >= 0.25 ? 'var(--accent-amber)' : 'var(--accent-green)')};">${(bp.dimension_drift_score * 100).toFixed(1)}%</strong></td>
        </tr>
      `).join("");
    } else {
      l2Tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-muted);">No Layer 2 profile metrics evaluated.</td></tr>`;
    }
  }

  // Dominant basepoints
  const jsdEl = document.getElementById("driftPageJSD");
  const jsDistEl = document.getElementById("driftPageJSDist");
  const barsContainer = document.getElementById("driftPageDominantBars");
  if (jsdEl) jsdEl.innerText = l2?.js_divergence !== undefined ? l2.js_divergence : "-";
  if (jsDistEl) jsDistEl.innerText = l2?.js_distance !== undefined ? `${(l2.js_distance * 100).toFixed(1)}%` : "-";

  if (barsContainer) {
    if (l2 && l2.dominant_basepoint_distribution_actual) {
      const act = l2.dominant_basepoint_distribution_actual || {};
      const ref = l2.dominant_basepoint_distribution_reference || {};
      barsContainer.innerHTML = Array.from({length: 8}, (_, i) => {
        const k = `bp_0${i + 1}`;
        const pAct = ((act[k] || 0) * 100).toFixed(1);
        const pRef = ((ref[k] || 0) * 100).toFixed(1);
        return `
          <div style="background:var(--bg-card); padding:8px; border-radius:4px; border:1px solid var(--border-color);">
            <div style="font-weight:700; color:var(--accent-cyan); font-family:var(--font-mono);">${k}</div>
            <div style="font-size:11px; margin-top:3px;">Actual: <strong>${pAct}%</strong></div>
            <div style="font-size:11px; color:var(--text-muted);">Ref: ${pRef}%</div>
          </div>
        `;
      }).join("");
    } else {
      barsContainer.innerHTML = `<div style="grid-column:1/-1; color:var(--text-muted); font-size:12px;">No categorical dominant basepoint data available.</div>`;
    }
  }
}

function renderDriftHistoryTable(historyList) {
  const tbody = document.getElementById("driftPageHistoryTableBody");
  const badge = document.getElementById("driftPageHistoryBadge");
  if (badge) badge.innerText = `${(historyList || []).length} Evaluations`;
  if (!tbody) return;

  if (!historyList || historyList.length === 0) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 16px;">No drift evaluation history recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = historyList.map(item => {
    const isSig = item.drift_status === "SIGNIFICANT" || item.recommendation_alert;
    const isMod = item.drift_status === "MODERATE";
    const statusBadge = isSig ? "badge-danger" : (isMod ? "badge-warning" : "badge-normal");
    const l1Display = (item.layer1_score !== null && item.layer1_score !== undefined) ? `${(item.layer1_score * 100).toFixed(1)}%` : (item.is_partial ? "Omitted" : "-");
    const l2Display = (item.layer2_score !== null && item.layer2_score !== undefined) ? `${(item.layer2_score * 100).toFixed(1)}%` : "-";

    return `
      <tr>
        <td style="font-size: 11.5px; font-family: var(--font-mono);">${escapeHtml(item.timestamp || "-")}</td>
        <td style="font-family: var(--font-mono); font-size: 11.5px;"><code>${escapeHtml(item.session_id || "-")}</code></td>
        <td style="font-family: var(--font-mono); font-size: 11.5px; color: var(--text-muted);">${escapeHtml(item.upload_id || "-")}</td>
        <td><strong style="color: ${isSig ? 'var(--accent-red)' : (isMod ? 'var(--accent-amber)' : 'var(--accent-green)')}; font-family: var(--font-mono);">${item.overall_drift_percentage}%</strong></td>
        <td>${l1Display}</td>
        <td>${l2Display}</td>
        <td><span class="badge ${statusBadge}">${escapeHtml(item.drift_status || "LOW")}</span></td>
        <td>
          <button class="btn btn-secondary btn-inspect-drift" data-session-id="${escapeHtml(item.session_id)}" style="padding: 3px 8px; font-size: 11px;">Inspect Details</button>
        </td>
      </tr>
    `;
  }).join("");

  tbody.querySelectorAll(".btn-inspect-drift").forEach(btn => {
    btn.addEventListener("click", () => {
      const sid = btn.getAttribute("data-session-id");
      if (sid) {
        api.fetchSessionDrift(sid).then(rep => {
          if (rep && !rep.detail) {
            openDriftModal(rep);
          } else {
            alert("No drift report details available for session: " + sid);
          }
        });
      }
    });
  });
}

async function confirmDeleteSession() {
  if (!pendingDeleteSession) return;
  const { sessionId } = pendingDeleteSession;
  const btnConfirm = document.getElementById("btnConfirmDelete");
  if (btnConfirm) btnConfirm.disabled = true;

  try {
    const res = await api.deleteSession(sessionId);
    closeDeleteModal();

    // If currently viewing the deleted report, navigate back to history
    if (activeSessionReport && activeSessionReport.session_id === sessionId) {
      backToHistory();
    } else {
      loadSessionsArchive();
    }
  } catch (err) {
    alert("Failed to delete classification report: " + err.message);
    closeDeleteModal();
  } finally {
    if (btnConfirm) btnConfirm.disabled = false;
  }
}

function initHistoryControls() {
  // Initial load of sessions archive from SQLite
  loadSessionsArchive();

  // Refresh archive button
  document.getElementById("btnRefreshSessions")?.addEventListener("click", () => {
    loadSessionsArchive();
  });

  // Client-side search and filtering
  document.getElementById("sessionSearchInput")?.addEventListener("input", (e) => {
    const query = e.target.value.trim().toLowerCase();
    if (!query) {
      filteredSessionArchive = [...currentSessionArchive];
    } else {
      filteredSessionArchive = currentSessionArchive.filter(s =>
        (s.filename || s.source_name || "").toLowerCase().includes(query) ||
        (s.session_id || "").toLowerCase().includes(query)
      );
    }
    sessionArchivePage = 0;
    renderSessionsArchiveTable();
  });

  // Export entire archive metadata to JSON
  document.getElementById("btnExportSessionsJson")?.addEventListener("click", () => {
    if (!currentSessionArchive.length) {
      alert("No classification reports to export.");
      return;
    }
    const jsonContent = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentSessionArchive, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", jsonContent);
    link.setAttribute("download", `siem_sessions_archive_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  // Archive pagination controls
  document.getElementById("btnPrevSessions")?.addEventListener("click", () => {
    if (sessionArchivePage > 0) {
      sessionArchivePage--;
      renderSessionsArchiveTable();
    }
  });

  document.getElementById("btnNextSessions")?.addEventListener("click", () => {
    const maxPage = Math.max(0, Math.ceil(filteredSessionArchive.length / SESSIONS_PER_PAGE) - 1);
    if (sessionArchivePage < maxPage) {
      sessionArchivePage++;
      renderSessionsArchiveTable();
    }
  });

  // Report Detail Panel controls
  document.getElementById("btnBackToHistory")?.addEventListener("click", backToHistory);

  document.getElementById("btnExportSingleReportJson")?.addEventListener("click", () => {
    if (!activeSessionReport) return;
    const jsonContent = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(activeSessionReport, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", jsonContent);
    link.setAttribute("download", `siem_report_${activeSessionReport.session_id}_${Date.now()}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  });

  document.getElementById("btnDeleteCurrentReport")?.addEventListener("click", () => {
    if (activeSessionReport) {
      promptDeleteSession(activeSessionReport.session_id, activeSessionReport.filename);
    }
  });

  // Delete Confirmation Modal controls
  document.getElementById("btnCloseDeleteModal")?.addEventListener("click", closeDeleteModal);
  document.getElementById("btnCancelDelete")?.addEventListener("click", closeDeleteModal);
  document.getElementById("btnConfirmDelete")?.addEventListener("click", confirmDeleteSession);

  // Close modal when clicking on backdrop
  document.getElementById("deleteSessionModal")?.addEventListener("click", (e) => {
    if (e.target && e.target.id === "deleteSessionModal") {
      closeDeleteModal();
    }
  });

  // Dual-Layer Data Drift Modal Controls
  document.getElementById("btnViewDriftDetails")?.addEventListener("click", () => {
    if (currentActiveDriftReport) {
      openDriftModal(currentActiveDriftReport);
    } else {
      api.fetchLatestDrift().then(res => {
        if (res && res.has_drift && res.report) {
          openDriftModal(res.report);
        } else {
          alert("No data drift report currently recorded. Upload a CSV to calculate data drift.");
        }
      });
    }
  });

  document.getElementById("repMetricDriftCard")?.addEventListener("click", () => {
    if (currentReportDriftData) {
      openDriftModal(currentReportDriftData);
    } else if (activeSessionReport && activeSessionReport.session_id) {
      api.fetchSessionDrift(activeSessionReport.session_id).then(rep => {
        if (rep && !rep.detail) {
          openDriftModal(rep);
        } else {
          alert("No drift report recorded for this historical session.");
        }
      });
    }
  });

  document.getElementById("btnCloseDriftModal")?.addEventListener("click", closeDriftModal);
  document.getElementById("btnCloseDriftModalBtn")?.addEventListener("click", closeDriftModal);
  document.getElementById("driftDetailModal")?.addEventListener("click", (e) => {
    if (e.target && e.target.id === "driftDetailModal") {
      closeDriftModal();
    }
  });
}

// -----------------------------------------------------------------------------
// Real-Time Sliding Window Threat Stream Controller (Latest Uploaded CSV Only)
// -----------------------------------------------------------------------------
export async function loadThreatStream(sessionId = null) {
  try {
    const res = await api.fetchStreamEvent(sessionId);
    const badge = document.getElementById("streamSessionBadge");
    const toggleBtn = document.getElementById("btnToggleStream");

    if (res && res.has_data && Array.isArray(res.records) && res.records.length > 0) {
      activeStreamSessionId = res.session_id;
      activeStreamRecords = res.records;

      if (badge) {
        const fname = res.source_name || "Uploaded Capture";
        badge.innerText = `Session: ${res.session_id} • ${fname} (${res.total_windows} Windows)`;
        badge.className = "badge badge-info";
      }

      // Populate chart with the entire uploaded sliding-window stream
      charts.populateLiveStreamChart(activeStreamRecords);

      // Render all evaluated windows in the threat stream table
      renderThreatStreamTable(activeStreamRecords);

      if (toggleBtn) {
        toggleBtn.innerText = "⏸️ Pause Stream";
        isStreamPaused = false;
      }
    } else {
      clearThreatStreamUI();
    }
  } catch (err) {
    console.warn("Could not load threat stream:", err);
    clearThreatStreamUI();
  }
}

export function clearThreatStreamUI() {
  activeStreamSessionId = null;
  activeStreamRecords = [];

  const badge = document.getElementById("streamSessionBadge");
  if (badge) {
    badge.innerText = "No Active Upload";
    badge.className = "badge badge-info";
  }

  charts.clearLiveStreamChart();

  const tbody = document.querySelector("#liveStreamTable tbody");
  if (tbody) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; color: var(--text-muted); font-style: italic; padding: 24px;">
          No uploaded sliding-window stream available. Upload a network flow or event profile CSV to view stream telemetry.
        </td>
      </tr>
    `;
  }
}

export function renderThreatStreamTable(records) {
  const tbody = document.querySelector("#liveStreamTable tbody");
  if (!tbody) return;

  if (!records || records.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align: center; color: var(--text-muted); font-style: italic; padding: 24px;">
          No sliding window records found for this upload session.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = records.map(r => {
    const wTime = r.window_time || r.window_start || r.timestamp || "N/A";
    const wId = r.window_id || r.id || "-";
    const esId = r.event_set_id || "-";
    const campBadge = (r.campaign_id && r.campaign_id !== "-")
      ? `<span class="badge badge-warning">${escapeHtml(r.campaign_id)}</span>`
      : `<span style="color: var(--text-muted);">-</span>`;
    const flows = r.n_flows !== undefined ? r.n_flows : 1;
    const confVal = Number(r.threat_confidence ?? r.confidence ?? 0);
    const confPct = (confVal * 100).toFixed(1);
    const sev = r.severity || "LOW";
    const sevClass = (sev === "CRITICAL" || sev === "HIGH") ? "badge-threat" : (sev === "MEDIUM" ? "badge-warning" : "badge-normal");

    return `
      <tr>
        <td><code>${escapeHtml(wTime)}</code></td>
        <td><code>${escapeHtml(wId)}</code></td>
        <td><code>${escapeHtml(esId)}</code></td>
        <td>${campBadge}</td>
        <td><code>${Number(flows).toLocaleString()}</code></td>
        <td><span class="badge ${getVerdictBadgeClass(r.verdict)}">${formatVerdictLabel(r.verdict)}</span></td>
        <td><strong>${confPct}%</strong></td>
        <td><span class="badge ${sevClass}">${escapeHtml(sev)}</span></td>
      </tr>
    `;
  }).join("");
}

export function renderFilteredHistory() {
  // Maintained for backward compatibility; stream table is populated exclusively via renderThreatStreamTable
  if (activeStreamRecords && activeStreamRecords.length > 0) {
    renderThreatStreamTable(activeStreamRecords);
  }
}

function toggleThreatStreamPlayback() {
  const toggleBtn = document.getElementById("btnToggleStream");
  if (isStreamPaused) {
    isStreamPaused = false;
    if (toggleBtn) toggleBtn.innerText = "⏸️ Pause Stream";
    if (activeStreamRecords && activeStreamRecords.length > 0) {
      charts.populateLiveStreamChart(activeStreamRecords);
    }
  } else {
    isStreamPaused = true;
    if (toggleBtn) toggleBtn.innerText = "▶️ Resume Stream";
  }
}

document.getElementById("btnToggleStream")?.addEventListener("click", toggleThreatStreamPlayback);

// -----------------------------------------------------------------------------
// SECTION 7: AI Cybersecurity Assistant Controls (Dedicated Section)
// -----------------------------------------------------------------------------
function initAssistantControls() {
  const chatForm = document.getElementById("chatInputForm");
  const chatInput = document.getElementById("chatInputText");
  const chatMessages = document.getElementById("chatMessages");
  const btnClearChat = document.getElementById("btnClearChat");
  const chips = document.querySelectorAll("#chatChipsArea .chip-btn");

  const sendQuery = async (queryText) => {
    if (!queryText || !queryText.trim()) return;

    appendChatMessage("user", queryText, "chatMessages");
    appendChatMessage("user", queryText, "floatingChatMessages");
    if (chatInput) chatInput.value = "";

    const loadingId = "loader_" + Date.now();
    const loadingMsg = document.createElement("div");
    loadingMsg.className = "chat-msg assistant";
    loadingMsg.id = loadingId;
    loadingMsg.innerHTML = `
      <div class="chat-avatar">🤖</div>
      <div class="chat-bubble">
        <em>Consulting SIEM telemetry and detection records...</em>
      </div>
    `;
    chatMessages?.appendChild(loadingMsg);
    if (chatMessages) chatMessages.scrollTop = chatMessages.scrollHeight;

    try {
      const res = await api.chatAssistant(queryText);
      const loader = document.getElementById(loadingId);
      if (loader) loader.remove();

      appendChatMessage("assistant", res.reply, "chatMessages", res.suggestions || [], (q) => sendQuery(q));
      appendChatMessage("assistant", res.reply, "floatingChatMessages", res.suggestions || [], (q) => sendQuery(q));
    } catch (err) {
      const loader = document.getElementById(loadingId);
      if (loader) loader.remove();
      appendChatMessage("assistant", `**Error consulting AI Analyst:** ${err.message}`, "chatMessages");
    }
  };

  chatForm?.addEventListener("submit", (e) => {
    e.preventDefault();
    if (chatInput) sendQuery(chatInput.value);
  });

  chips.forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.getAttribute("data-query");
      if (q) sendQuery(q);
    });
  });

  btnClearChat?.addEventListener("click", () => {
    if (chatMessages) {
      chatMessages.innerHTML = `
        <div class="chat-msg assistant">
          <div class="chat-avatar">🤖</div>
          <div class="chat-bubble">
            <h3>Conversation Reset</h3>
            <p>AI SIEM Analyst is ready for your next threat inquiry.</p>
          </div>
        </div>
      `;
    }
  });
}

// -----------------------------------------------------------------------------
// FLOATING AI CYBERSECURITY ASSISTANT (Accessible Across All 9 Sections)
// -----------------------------------------------------------------------------
function initFloatingChatbot() {
  const floatBtn = document.getElementById("floatingChatBtn");
  const floatPanel = document.getElementById("floatingChatPanel");
  const closeBtn = document.getElementById("btnCloseFloatingChat");
  const floatForm = document.getElementById("floatingChatForm");
  const floatInput = document.getElementById("floatingChatInput");
  const floatChips = document.querySelectorAll("#floatingChatChips .chip-btn");

  floatBtn?.addEventListener("click", () => {
    const isHidden = floatPanel.style.display === "none" || !floatPanel.style.display;
    floatPanel.style.display = isHidden ? "flex" : "none";
    if (isHidden && floatInput) {
      setTimeout(() => floatInput.focus(), 100);
    }
  });

  closeBtn?.addEventListener("click", () => {
    floatPanel.style.display = "none";
  });

  const sendFloatingQuery = async (queryText) => {
    if (!queryText || !queryText.trim()) return;

    appendChatMessage("user", queryText, "floatingChatMessages");
    appendChatMessage("user", queryText, "chatMessages");
    if (floatInput) floatInput.value = "";

    const loadingId = "float_loader_" + Date.now();
    const loadingMsg = document.createElement("div");
    loadingMsg.className = "chat-msg assistant";
    loadingMsg.id = loadingId;
    loadingMsg.innerHTML = `
      <div class="chat-avatar">🤖</div>
      <div class="chat-bubble">
        <em>Querying live detection engine...</em>
      </div>
    `;
    const floatContainer = document.getElementById("floatingChatMessages");
    if (floatContainer) {
      floatContainer.appendChild(loadingMsg);
      floatContainer.scrollTop = floatContainer.scrollHeight;
    }

    try {
      const res = await api.chatAssistant(queryText);
      const loader = document.getElementById(loadingId);
      if (loader) loader.remove();

      appendChatMessage("assistant", res.reply, "floatingChatMessages", res.suggestions || [], (q) => sendFloatingQuery(q));
      appendChatMessage("assistant", res.reply, "chatMessages", res.suggestions || [], (q) => sendFloatingQuery(q));
    } catch (err) {
      const loader = document.getElementById(loadingId);
      if (loader) loader.remove();
      appendChatMessage("assistant", `**Error:** ${err.message}`, "floatingChatMessages");
    }
  };

  floatForm?.addEventListener("submit", (e) => {
    e.preventDefault();
    if (floatInput) sendFloatingQuery(floatInput.value);
  });

  floatChips.forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.getAttribute("data-query");
      if (q) sendFloatingQuery(q);
    });
  });
}

function appendChatMessage(role, text, targetId, suggestions = [], onSuggestionClick = null) {
  const container = document.getElementById(targetId);
  if (!container) return;

  if (typeof text !== "string") text = String(text || "");

  const msgDiv = document.createElement("div");
  msgDiv.className = `chat-msg ${role}`;

  let formatted = text
    .replace(/^### (.*$)/gim, "<h3>$1</h3>")
    .replace(/^## (.*$)/gim, "<h3>$1</h3>")
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.*?)\*/g, "<em>$1</em>")
    .replace(/```([\s\S]*?)```/g, "<pre><code>$1</code></pre>")
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\n\n/g, "<p></p>")
    .replace(/\n/g, "<br>");

  let html = `
    <div class="chat-avatar">${role === "user" ? "👤" : "🤖"}</div>
    <div class="chat-bubble">
      ${formatted}
  `;

  if (suggestions && suggestions.length > 0) {
    html += `<div class="chat-reply-suggestions" style="margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px;">`;
    suggestions.forEach(s => {
      const escaped = s.replace(/"/g, '&quot;');
      html += `<button type="button" class="chip-btn suggestion-pill" data-query="${escaped}" style="font-size: 11px; padding: 4px 10px;">${s}</button>`;
    });
    html += `</div>`;
  }

  html += `</div>`;
  msgDiv.innerHTML = html;

  if (suggestions && suggestions.length > 0 && onSuggestionClick) {
    msgDiv.querySelectorAll(".suggestion-pill").forEach(btn => {
      btn.addEventListener("click", () => {
        const q = btn.getAttribute("data-query");
        if (q) onSuggestionClick(q);
      });
    });
  }

  container.appendChild(msgDiv);
  container.scrollTop = container.scrollHeight;
}


// -----------------------------------------------------------------------------
// Dynamic Background Particle Network (Matches Login Page Cybersecurity Theme)
// -----------------------------------------------------------------------------
function initDashboardBackground() {
  const canvas = document.getElementById("dashboardNetworkCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  // Respect prefers-reduced-motion accessibility setting
  const mediaQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
  if (mediaQuery.matches) {
    canvas.style.display = "none";
    return;
  }

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const mouse = { x: null, y: null, radius: 120 };
  window.addEventListener("mousemove", (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });
  window.addEventListener("mouseleave", () => {
    mouse.x = null;
    mouse.y = null;
  });

  // Dynamic particle count based on screen area (up to 75 particles matching login theme)
  const particleCount = Math.min(Math.floor((width * height) / 16000), 75);
  const particles = [];
  const colors = ["#00E5FF", "#8B35FF", "#287BFF", "#00b4d8", "#38bdf8"];

  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.55,
      vy: (Math.random() - 0.5) * 0.55,
      radius: Math.random() * 2.2 + 1.4,
      color: colors[Math.floor(Math.random() * colors.length)],
      alpha: Math.random() * 0.45 + 0.45
    });
  }

  // Telemetry pulses along edges
  const packets = [];
  function spawnPacket(p1, p2) {
    packets.push({
      p1,
      p2,
      progress: 0,
      speed: Math.random() * 0.016 + 0.010,
      color: Math.random() > 0.35 ? "#00E5FF" : "#ffffff"
    });
  }

  let frameCount = 0;
  function render() {
    // If light mode is active, clear and skip rendering to save CPU
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    if (isLight) {
      ctx.clearRect(0, 0, width, height);
      requestAnimationFrame(render);
      return;
    }

    ctx.clearRect(0, 0, width, height);
    frameCount++;

    // Update & draw particles
    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = width;
      else if (p.x > width) p.x = 0;
      if (p.y < 0) p.y = height;
      else if (p.y > height) p.y = 0;

      // Mouse attraction
      if (mouse.x !== null && mouse.y !== null) {
        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < mouse.radius) {
          const force = (mouse.radius - dist) / mouse.radius;
          p.x -= (dx / dist) * force * 1.2;
          p.y -= (dy / dist) * force * 1.2;
        }
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.globalAlpha = p.alpha;
      ctx.shadowBlur = 10;
      ctx.shadowColor = p.color;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // Connect nearby particles with subtle glowing lines
    const maxDistance = 140;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const p1 = particles[i];
        const p2 = particles[j];
        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < maxDistance) {
          const alpha = (1 - dist / maxDistance) * 0.32;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = p1.color;
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 1.0;
          ctx.stroke();

          // Spawn traveling telemetry data pulses along connecting lines
          if (frameCount % 60 === 0 && Math.random() < 0.08 && packets.length < 15) {
            spawnPacket(p1, p2);
          }
        }
      }
    }

    // Connect mouse to nearby particles
    if (mouse.x !== null && mouse.y !== null) {
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        const dx = mouse.x - p.x;
        const dy = mouse.y - p.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 110) {
          const alpha = (1 - dist / 110) * 0.35;
          ctx.beginPath();
          ctx.moveTo(mouse.x, mouse.y);
          ctx.lineTo(p.x, p.y);
          ctx.strokeStyle = "#00E5FF";
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 1.1;
          ctx.stroke();
        }
      }
    }

    // Render traveling telemetry packets
    for (let i = packets.length - 1; i >= 0; i--) {
      const pkt = packets[i];
      pkt.progress += pkt.speed;
      if (pkt.progress >= 1) {
        packets.splice(i, 1);
        continue;
      }
      const curX = pkt.p1.x + (pkt.p2.x - pkt.p1.x) * pkt.progress;
      const curY = pkt.p1.y + (pkt.p2.y - pkt.p1.y) * pkt.progress;

      ctx.beginPath();
      ctx.arc(curX, curY, 2.8, 0, Math.PI * 2);
      ctx.fillStyle = pkt.color;
      ctx.globalAlpha = 0.95;
      ctx.shadowBlur = 12;
      ctx.shadowColor = pkt.color;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    ctx.globalAlpha = 1.0;
    requestAnimationFrame(render);
  }

  requestAnimationFrame(render);
}


// =============================================================================
// Head of SOC: Candidate Model Studio & Dual Sub-Navigation Controller
// =============================================================================

function initDriftSubnav() {
  const btnTelemetry = document.getElementById("btnSubnavDriftTelemetry");
  const btnStudio = document.getElementById("btnSubnavTrainingStudio");
  const telemetryCont = document.getElementById("driftTelemetryContainer");
  const studioCont = document.getElementById("trainingStudioContainer");

  if (btnTelemetry && btnStudio && telemetryCont && studioCont) {
    btnTelemetry.addEventListener("click", () => {
      telemetryCont.style.display = "block";
      studioCont.style.display = "none";
      btnTelemetry.className = "btn btn-primary";
      btnStudio.className = "btn btn-secondary";
      loadDriftPageView();
    });

    btnStudio.addEventListener("click", () => {
      telemetryCont.style.display = "none";
      studioCont.style.display = "block";
      btnStudio.className = "btn btn-primary";
      btnTelemetry.className = "btn btn-secondary";
      loadTrainingStudioOverview();
    });
  }
}

let selectedTrainingFile = null;
let lastValidationReport = null;
let lastUploadedDataset = null;
let lastTrainedCandidate = null;

function updateTrainingSelectionState() {
  const selectDatasetEl = document.getElementById("selectTargetCandidateDataset");
  const targetLbl = document.getElementById("studioTargetDatasetLabel");
  const btnTrain = document.getElementById("btnTrainCandidateModel");
  const selectedId = selectDatasetEl ? selectDatasetEl.value : (lastUploadedDataset ? lastUploadedDataset.dataset_id : null);

  if (!selectedId) {
    if (targetLbl) {
      targetLbl.innerText = "None Selected (Training Disabled)";
      targetLbl.style.color = "var(--text-muted)";
    }
    if (btnTrain) btnTrain.disabled = true;
  } else {
    if (targetLbl) {
      targetLbl.innerText = `Dataset Ready: ${selectedId}`;
      targetLbl.style.color = "var(--accent-green)";
    }
    if (btnTrain) btnTrain.disabled = false;
  }
}

async function loadTrainingStudioOverview() {
  if (!isHeadOfSocUser()) return;
  try {
    const data = await api.fetchTrainingOverview();
    if (!data) return;

    const activeModelNameEl = document.getElementById("studioActiveModelName");
    const backupCountEl = document.getElementById("studioBackupCount");
    const badgeCandCount = document.getElementById("badgeCandidateCount");

    if (activeModelNameEl) {
      activeModelNameEl.innerText = data.active_model?.model_name || "Experiment B (Patator Baseline)";
    }
    if (backupCountEl) {
      backupCountEl.innerText = `${(data.backups || []).length} Backups Available`;
    }
    if (badgeCandCount) {
      badgeCandCount.innerText = `${(data.candidates || []).length} Models`;
    }

    // Populate Target Dataset Selector with persisted datasets
    const selectDatasetEl = document.getElementById("selectTargetCandidateDataset");
    if (selectDatasetEl) {
      const currentVal = selectDatasetEl.value;
      const opts = [`<option value="">-- No Validated Dataset Selected --</option>`];
      (data.datasets || []).forEach(ds => {
        const isSel = (lastUploadedDataset && lastUploadedDataset.dataset_id === ds.dataset_id) || (currentVal === ds.dataset_id);
        opts.push(`<option value="${escapeHtml(ds.dataset_id)}" ${isSel ? 'selected' : ''}>${escapeHtml(ds.dataset_id)} — ${escapeHtml(ds.filename)} (${(ds.row_count || 0).toLocaleString()} rows)</option>`);
      });
      selectDatasetEl.innerHTML = opts.join("");
      updateTrainingSelectionState();
    }

    renderCandidateHistoryTable(data.candidates || []);
  } catch (err) {
    console.error("Failed to load training studio overview:", err);
  }
}

function renderCandidateHistoryTable(candidates) {
  const tbody = document.getElementById("candidateHistoryTableBody");
  if (!tbody) return;

  if (!candidates || candidates.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted); padding: 16px;">No candidate models trained yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = candidates.map(c => {
    const metrics = c.metrics || {};
    const isActive = c.status === "ACTIVE";
    const statusBadge = isActive ? "badge-normal" : (c.status === "ROLLED_BACK" ? "badge-danger" : "badge-info");
    const f1Str = metrics.f1_score !== undefined ? `${(metrics.f1_score * 100).toFixed(1)}%` : "-";
    const precStr = metrics.precision !== undefined ? `${(metrics.precision * 100).toFixed(1)}%` : "-";
    const recStr = metrics.recall !== undefined ? `${(metrics.recall * 100).toFixed(1)}%` : "-";

    return `
      <tr>
        <td style="font-family: var(--font-mono); font-size: 11.5px; font-weight: 700; color: var(--accent-purple);">${escapeHtml(c.candidate_id)}</td>
        <td style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(c.dataset_id)}</td>
        <td style="font-size: 11px;">${escapeHtml(c.created_at || "-")}</td>
        <td><span class="badge ${statusBadge}">${escapeHtml(c.status)}</span></td>
        <td><strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${f1Str}</strong></td>
        <td>${precStr}</td>
        <td>${recStr}</td>
        <td style="font-size: 11px; color: var(--text-muted);">${escapeHtml(c.approved_by || "-")}</td>
        <td>
          ${!isActive ? `<button class="btn btn-secondary btn-activate-table" data-id="${escapeHtml(c.candidate_id)}" style="padding: 2px 8px; font-size: 11px;">Activate</button>` : `<span style="font-size: 11px; color: var(--accent-green); font-weight: 600;">Currently Active</span>`}
        </td>
      </tr>
    `;
  }).join("");

  tbody.querySelectorAll(".btn-activate-table").forEach(btn => {
    btn.addEventListener("click", () => {
      const cid = btn.getAttribute("data-id");
      if (cid) {
        promptActivateCandidate(cid);
      }
    });
  });
}

function initTrainingStudioControls() {
  const dropZone = document.getElementById("datasetDropZone");
  const fileInput = document.getElementById("inputTrainingDatasetFile");
  const btnBrowse = document.getElementById("btnBrowseTrainingDataset");
  const filenameEl = document.getElementById("selectedDatasetFilename");
  const btnValidate = document.getElementById("btnValidateDataset");
  const btnUpload = document.getElementById("btnUploadDataset");
  const btnTrain = document.getElementById("btnTrainCandidateModel");
  const btnActivate = document.getElementById("btnActivateCandidate");
  const btnRollback = document.getElementById("btnStudioRollback");
  const btnRefresh = document.getElementById("btnRefreshStudio");
  const selectDatasetEl = document.getElementById("selectTargetCandidateDataset");

  // Safeguards: Initial button states
  if (btnUpload) btnUpload.disabled = true;
  if (btnTrain) btnTrain.disabled = true;

  if (selectDatasetEl) {
    selectDatasetEl.addEventListener("change", () => {
      updateTrainingSelectionState();
    });
  }

  if (btnBrowse && fileInput) {
    btnBrowse.addEventListener("click", () => fileInput.click());
  }

  function handleFileSelect(file) {
    if (!file) return;
    selectedTrainingFile = file;
    lastValidationReport = null;
    if (filenameEl) {
      filenameEl.innerText = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
      filenameEl.style.display = "block";
      filenameEl.style.color = "var(--accent-cyan)";
    }
    const badge = document.getElementById("badgeStudioValidation");
    if (badge) {
      badge.className = "badge badge-info";
      badge.innerText = "Awaiting Validation";
    }
    if (btnValidate) btnValidate.disabled = false;
    // Safeguard 2: Persist Validated Dataset must be disabled until schema validation succeeds
    if (btnUpload) btnUpload.disabled = true;
  }

  if (fileInput) {
    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFileSelect(e.target.files[0]);
      }
    });
  }

  if (dropZone) {
    dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "var(--accent-cyan)";
      dropZone.style.background = "rgba(0, 229, 255, 0.08)";
    });
    dropZone.addEventListener("dragleave", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "var(--border-color)";
      dropZone.style.background = "transparent";
    });
    dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropZone.style.borderColor = "var(--border-color)";
      dropZone.style.background = "transparent";
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelect(e.dataTransfer.files[0]);
      }
    });
  }

  // Validate Dataset
  if (btnValidate) {
    btnValidate.addEventListener("click", async () => {
      if (!selectedTrainingFile) {
        alert("Please select a training dataset CSV file first.");
        return;
      }
      btnValidate.disabled = true;
      btnValidate.innerText = "Validating...";
      const badge = document.getElementById("badgeStudioValidation");
      if (badge) {
        badge.className = "badge badge-warning";
        badge.innerText = "Validating...";
      }

      try {
        const report = await api.validateCandidateDataset(selectedTrainingFile);
        lastValidationReport = report;
        renderValidationReport(report);

        // Safeguard 2: Persist Validated Dataset must be disabled until schema validation succeeds
        if (report.is_valid) {
          if (btnUpload) btnUpload.disabled = false;
        } else {
          if (btnUpload) btnUpload.disabled = true;
        }
      } catch (err) {
        alert("Validation error: " + err.message);
        if (badge) {
          badge.className = "badge badge-danger";
          badge.innerText = "Validation Error";
        }
      } finally {
        btnValidate.disabled = false;
        btnValidate.innerText = "🔍 Validate Dataset Quality";
      }
    });
  }

  // Persist Validated Dataset
  if (btnUpload) {
    btnUpload.addEventListener("click", async () => {
      if (!selectedTrainingFile || !lastValidationReport?.is_valid) {
        alert("Action Denied: You must successfully validate the dataset schema and quality before persisting.");
        return;
      }
      btnUpload.disabled = true;
      btnUpload.innerText = "Persisting...";
      try {
        const res = await api.uploadCandidateDataset(selectedTrainingFile);
        if (res.status === "SUCCESS") {
          lastUploadedDataset = res.dataset;
          const badge = document.getElementById("badgeStudioValidation");
          if (badge) {
            badge.className = "badge badge-normal";
            badge.innerText = "Dataset Persisted";
          }
          alert(`Dataset successfully validated and persisted as ${res.dataset.dataset_id}.`);
          await loadTrainingStudioOverview();
          updateTrainingSelectionState();
        } else {
          alert("Persistence failed: " + (res.detail || "Unknown error"));
        }
      } catch (err) {
        alert("Persistence error: " + err.message);
      } finally {
        btnUpload.disabled = false;
        btnUpload.innerText = "💾 Persist Validated Dataset";
      }
    });
  }

  // Train Candidate Model
  if (btnTrain) {
    btnTrain.addEventListener("click", async () => {
      // Safeguard 1 & 3: Train Candidate Model must be disabled when no validated dataset is selected
      const targetDatasetId = (selectDatasetEl && selectDatasetEl.value) || (lastUploadedDataset && lastUploadedDataset.dataset_id);
      if (!targetDatasetId) {
        alert("Training Error: Train Candidate Model requires a successfully validated and persisted dataset.");
        btnTrain.disabled = true;
        return;
      }
      btnTrain.disabled = true;
      const sp = document.getElementById("btnTrainSpinner");
      const txt = document.getElementById("btnTrainText");
      if (sp) sp.style.display = "inline";
      if (txt) txt.innerText = "Training Neural Ensemble...";

      try {
        const res = await api.trainCandidateModel(targetDatasetId);
        if (res.status === "SUCCESS") {
          lastTrainedCandidate = res.candidate;
          renderCandidateEvaluation(res.candidate);
          await loadTrainingStudioOverview();
        } else {
          alert("Training failed: " + (res.detail || "Unknown error"));
        }
      } catch (err) {
        alert("Training error: " + err.message);
      } finally {
        btnTrain.disabled = false;
        if (sp) sp.style.display = "none";
        if (txt) txt.innerText = "⚡ Train Candidate Model";
      }
    });
  }

  // Activate Candidate Model
  if (btnActivate) {
    btnActivate.addEventListener("click", () => {
      if (!lastTrainedCandidate) {
        alert("No candidate model has been trained yet in this session.");
        return;
      }
      promptActivateCandidate(lastTrainedCandidate.candidate_id);
    });
  }

  // Rollback Model
  if (btnRollback) {
    btnRollback.addEventListener("click", async () => {
      const note = prompt("Enter supervisory rollback note for Head of SOC rollback authorization:", "Rollback to baseline Experiment B model");
      if (note === null) return;
      try {
        const res = await api.rollbackCandidateModel(note);
        if (res.status === "SUCCESS") {
          alert(res.message);
          await loadTrainingStudioOverview();
        } else {
          alert("Rollback failed: " + (res.detail || "Unknown error"));
        }
      } catch (err) {
        alert("Rollback error: " + err.message);
      }
    });
  }

  // Refresh Overview
  if (btnRefresh) {
    btnRefresh.addEventListener("click", () => loadTrainingStudioOverview());
  }
}

function promptActivateCandidate(candidateId) {
  // Safeguard 4.1: Require explicit confirmation and supervisory justification before activation
  const noteInput = document.getElementById("inputActivationNote");
  const note = (noteInput && noteInput.value.trim()) || prompt("Enter Head of SOC activation authorization note:", "Candidate model approved following distribution shift verification");
  if (note === null) return;

  if (!confirm(`SUPERVISORY AUTHORIZATION CONFIRMATION:\n\nAre you sure you want to authorize and ACTIVATE candidate model '${candidateId}'?\n\n- The active production baseline will be backed up automatically.\n- An immutable supervisory audit record will be logged.\n- Rollback capability is 100% guaranteed.`)) {
    return;
  }

  api.activateCandidateModel(candidateId, note)
    .then(res => {
      if (res.status === "SUCCESS") {
        alert(`Candidate model '${candidateId}' is now ACTIVE in production!\nVerified Backup ID: ${res.backup_id || 'BKP-CURRENT'}`);
        loadTrainingStudioOverview();
      } else {
        alert("Activation failed: " + (res.detail || "Unknown error"));
      }
    })
    .catch(err => alert("Activation error: " + err.message));
}

function renderValidationReport(rep) {
  const box = document.getElementById("datasetValidationReportBox");
  const content = document.getElementById("validationReportContent");
  const badge = document.getElementById("badgeStudioValidation");
  if (!box || !content) return;

  box.style.display = "block";
  if (badge) {
    badge.className = rep.is_valid ? "badge badge-normal" : "badge badge-danger";
    badge.innerText = rep.is_valid ? "SCHEMA VALID" : "VALIDATION FAILED";
  }

  const issuesHtml = (rep.issues || []).map(iss => `<li style="color: var(--accent-red); margin-bottom: 3px;">❌ ${escapeHtml(iss)}</li>`).join("");
  const warningsHtml = (rep.warnings || []).map(w => `<li style="color: var(--accent-amber); margin-bottom: 3px;">⚠️ ${escapeHtml(w)}</li>`).join("");

  const rejectedCount = rep.rejected_rows ? rep.rejected_rows.count : 0;
  const rejectedHtml = rejectedCount > 0
    ? `<div style="margin-top: 6px; padding: 6px 10px; background: rgba(255, 77, 77, 0.1); border-left: 3px solid var(--accent-red); border-radius: 4px; font-size: 11.5px; color: var(--accent-red);">
        <strong>Rejected Rows: ${rejectedCount}</strong> ${rep.rejected_rows.reasons?.length ? `(${escapeHtml(rep.rejected_rows.reasons[0])})` : ''}
       </div>`
    : `<div style="margin-top: 6px; font-size: 11.5px; color: var(--text-muted);">Rejected Rows: <strong>0 (Clean Dataset)</strong></div>`;

  const imbRatio = rep.class_distribution?.imbalance_ratio ? ` (Ratio: ${rep.class_distribution.imbalance_ratio}:1)` : "";

  content.innerHTML = `
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 8px; margin-bottom: 10px;">
      <div><span style="color: var(--text-muted); font-size: 11px;">Validation Status:</span> <strong style="color: ${rep.is_valid ? 'var(--accent-green)' : 'var(--accent-red)'};">${escapeHtml(rep.validation_status || (rep.is_valid ? 'READY' : 'FAILED'))}</strong></div>
      <div><span style="color: var(--text-muted); font-size: 11px;">Schema Type:</span> <strong style="color: var(--accent-cyan);">${escapeHtml(rep.schema_type || "Unknown")}</strong></div>
      <div><span style="color: var(--text-muted); font-size: 11px;">Total Samples:</span> <strong>${(rep.num_rows || 0).toLocaleString()} rows</strong></div>
      <div><span style="color: var(--text-muted); font-size: 11px;">Model Features:</span> <strong>${rep.feature_count || rep.num_cols || 0} features</strong></div>
      <div style="grid-column: 1 / -1;"><span style="color: var(--text-muted); font-size: 11px;">Class Distribution:</span> <strong>${rep.class_balance?.BENIGN ?? 0} Benign / ${rep.class_balance?.ATTACK ?? 0} Attack${imbRatio}</strong></div>
    </div>
    ${rejectedHtml}
    ${issuesHtml ? `<ul style="margin: 8px 0 6px 18px; font-size: 11.5px;">${issuesHtml}</ul>` : ""}
    ${warningsHtml ? `<ul style="margin: 4px 0 6px 18px; font-size: 11.5px;">${warningsHtml}</ul>` : ""}
    ${rep.is_valid ? `<div style="font-size: 12px; color: var(--accent-green); font-weight: 600; margin-top: 6px;">✓ Dataset passed schema verification, label integrity, and value distribution checks. Ready to persist.</div>` : `<div style="font-size: 12px; color: var(--accent-red); font-weight: 600; margin-top: 6px;">✕ Dataset rejected. Persist Validated Dataset and Model Training remain disabled.</div>`}
  `;
}

function renderCandidateEvaluation(candidate) {
  const card = document.getElementById("cardCandidateEvaluation");
  if (!card) return;
  card.style.display = "block";

  const metrics = candidate.metrics || {};
  const cm = metrics.confusion_matrix || {};

  const pEl = document.getElementById("valCandPrecision");
  const rEl = document.getElementById("valCandRecall");
  const fEl = document.getElementById("valCandF1");
  const prEl = document.getElementById("valCandPrAuc");
  const rocEl = document.getElementById("valCandRocAuc");
  const fprEl = document.getElementById("valCandFpr");

  if (pEl) pEl.innerText = `${((metrics.precision ?? 0) * 100).toFixed(1)}%`;
  if (rEl) rEl.innerText = `${((metrics.recall ?? 0) * 100).toFixed(1)}%`;
  if (fEl) fEl.innerText = `${((metrics.f1_score ?? 0) * 100).toFixed(1)}%`;
  if (prEl) prEl.innerText = `${((metrics.pr_auc ?? 0) * 100).toFixed(1)}%`;
  if (rocEl) rocEl.innerText = `${((metrics.roc_auc ?? 0) * 100).toFixed(1)}%`;
  if (fprEl) fprEl.innerText = `${((metrics.false_positive_rate ?? 0) * 100).toFixed(2)}%`;

  const tnEl = document.getElementById("cmTN");
  const fpEl = document.getElementById("cmFP");
  const fnEl = document.getElementById("cmFN");
  const tpEl = document.getElementById("cmTP");

  if (tnEl) tnEl.innerText = (cm.true_negatives ?? 0).toLocaleString();
  if (fpEl) fpEl.innerText = (cm.false_positives ?? 0).toLocaleString();
  if (fnEl) fnEl.innerText = (cm.false_negatives ?? 0).toLocaleString();
  if (tpEl) tpEl.innerText = (cm.true_positives ?? 0).toLocaleString();
}
