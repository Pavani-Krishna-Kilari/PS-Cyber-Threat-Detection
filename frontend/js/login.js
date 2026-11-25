/**
 * AI-SIEM SOC - PREMIUM INTERACTIVE LOGIN CONTROLLER
 * Pure Vanilla JavaScript ES6+ Module
 * Handles:
 *   1. Full-screen interactive particle network canvas
 *   2. 3D digital wireframe cyber globe rendering
 *   3. Credential validation & REST API authentication
 *   4. Google Workspace SSO enterprise flow
 *   5. Password recovery protocol modal
 *   6. Contact administrator clearance ticket request
 *   7. Show/Hide password toggle & Quick-fill demo credentials
 */

const API_BASE = "";

document.addEventListener("DOMContentLoaded", () => {
  initParticleNetwork();
  initCyberGlobe();
  initInputInteractions();
  initPasswordToggle();
  initLoginForm();
  initModals();
  checkRememberedUser();
});

// -----------------------------------------------------------------------------
// 1. FULL-SCREEN INTERACTIVE NEURAL PARTICLE NETWORK CANVAS
// -----------------------------------------------------------------------------
function initParticleNetwork() {
  const canvas = document.getElementById("networkCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const mouse = { x: null, y: null, radius: 140 };

  window.addEventListener("mousemove", (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
  });

  window.addEventListener("mouseleave", () => {
    mouse.x = null;
    mouse.y = null;
  });

  const particleCount = Math.min(Math.floor((width * height) / 18000), 75);
  const particles = [];
  const colors = ["#00E5FF", "#8B35FF", "#287BFF", "#00b4d8"];

  for (let i = 0; i < particleCount; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.65,
      vy: (Math.random() - 0.5) * 0.65,
      radius: Math.random() * 2.2 + 1.2,
      color: colors[Math.floor(Math.random() * colors.length)],
      alpha: Math.random() * 0.5 + 0.3
    });
  }

  // Animated packets traversing network edges
  const packets = [];
  function spawnPacket(p1, p2) {
    packets.push({
      p1, p2, progress: 0, speed: Math.random() * 0.015 + 0.01
    });
  }

  let frameCount = 0;

  function renderNetwork() {
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
          p.x -= (dx / dist) * force * 1.5;
          p.y -= (dy / dist) * force * 1.5;
        }
      }

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.globalAlpha = p.alpha;
      ctx.shadowBlur = 8;
      ctx.shadowColor = p.color;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // Connect nearby particles with glowing lines
    const maxDistance = 135;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const p1 = particles[i];
        const p2 = particles[j];
        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < maxDistance) {
          const alpha = (1 - dist / maxDistance) * 0.22;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = p1.color;
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 1;
          ctx.stroke();

          // Occasionally spawn a telemetry packet
          if (frameCount % 180 === 0 && Math.random() < 0.08 && packets.length < 15) {
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
        if (dist < 120) {
          const alpha = (1 - dist / 120) * 0.45;
          ctx.beginPath();
          ctx.moveTo(mouse.x, mouse.y);
          ctx.lineTo(p.x, p.y);
          ctx.strokeStyle = "#00E5FF";
          ctx.globalAlpha = alpha;
          ctx.lineWidth = 1.2;
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
      ctx.fillStyle = "#ffffff";
      ctx.globalAlpha = 0.9;
      ctx.shadowBlur = 10;
      ctx.shadowColor = "#00E5FF";
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    ctx.globalAlpha = 1.0;
    requestAnimationFrame(renderNetwork);
  }

  requestAnimationFrame(renderNetwork);
}

// -----------------------------------------------------------------------------
// 2. 3D DIGITAL WIREFRAME CYBER GLOBE CANVAS
// -----------------------------------------------------------------------------
function initCyberGlobe() {
  const canvas = document.getElementById("globeCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  let rect = canvas.getBoundingClientRect();
  let dpr = window.devicePixelRatio || 1;
  let cx = rect.width / 2;
  let cy = rect.height + 40;
  let R = Math.min(rect.width * 0.65, 230);

  function resizeGlobe() {
    rect = canvas.getBoundingClientRect();
    dpr = window.devicePixelRatio || 1;
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.scale(dpr, dpr);
    cx = rect.width / 2;
    cy = rect.height + 40;
    R = Math.min(rect.width * 0.65, 230);
  }

  resizeGlobe();
  window.addEventListener("resize", resizeGlobe);

  let rotation = 0;
  let targetTilt = 0.22;
  let currentTilt = 0.22;

  // Key global threat telemetry hub nodes (latitude, longitude in radians)
  const hubs = [
    { lat: 0.70, lon: -1.29, name: "US-EAST" },
    { lat: 0.90, lon: -2.13, name: "US-WEST" },
    { lat: 0.90, lon: 0.00, name: "EU-CENTRAL" },
    { lat: 0.62, lon: 0.65, name: "MIDEAST" },
    { lat: 0.62, lon: 1.35, name: "ASIA-SOUTH" },
    { lat: 0.61, lon: 2.43, name: "ASIA-EAST" },
    { lat: 0.23, lon: 1.81, name: "ASIA-SE" },
    { lat: -0.59, lon: 2.64, name: "OCEANIA" }
  ];

  // Animated telemetry arcs connecting hubs
  const arcs = [
    { from: 0, to: 2, progress: 0.1, speed: 0.007 },
    { from: 2, to: 5, progress: 0.4, speed: 0.009 },
    { from: 1, to: 5, progress: 0.7, speed: 0.006 },
    { from: 2, to: 4, progress: 0.25, speed: 0.008 }
  ];

  function project(lat, lon, rot, tilt) {
    const cosLat = Math.cos(lat);
    const sinLat = Math.sin(lat);
    const cosLon = Math.cos(lon + rot);
    const sinLon = Math.sin(lon + rot);

    // 3D coordinates on sphere
    const x = R * cosLat * sinLon;
    const y0 = -R * sinLat;
    const z0 = R * cosLat * cosLon;

    // Apply pitch tilt
    const y = y0 * Math.cos(tilt) - z0 * Math.sin(tilt);
    const z = y0 * Math.sin(tilt) + z0 * Math.cos(tilt);

    return {
      x: cx + x,
      y: cy + y,
      z: z,
      visible: z > -R * 0.2
    };
  }

  function renderGlobe() {
    ctx.clearRect(0, 0, rect.width, rect.height);

    rotation += 0.006;
    currentTilt += (targetTilt - currentTilt) * 0.05;

    // Outer atmospheric rim glow
    const rimGrad = ctx.createRadialGradient(cx, cy, R * 0.75, cx, cy, R * 1.08);
    rimGrad.addColorStop(0, "rgba(0, 229, 255, 0.0)");
    rimGrad.addColorStop(0.85, "rgba(0, 229, 255, 0.12)");
    rimGrad.addColorStop(1, "rgba(139, 53, 255, 0.0)");

    ctx.fillStyle = rimGrad;
    ctx.beginPath();
    ctx.arc(cx, cy, R * 1.1, 0, Math.PI * 2);
    ctx.fill();

    // 1. Draw Latitude Rings
    const latAngles = [-0.8, -0.4, 0, 0.4, 0.8];
    for (const lat of latAngles) {
      ctx.beginPath();
      let started = false;
      for (let lon = 0; lon <= Math.PI * 2 + 0.1; lon += 0.15) {
        const pt = project(lat, lon, rotation, currentTilt);
        if (pt.visible) {
          if (!started) {
            ctx.moveTo(pt.x, pt.y);
            started = true;
          } else {
            ctx.lineTo(pt.x, pt.y);
          }
        } else {
          started = false;
        }
      }
      ctx.strokeStyle = lat === 0 ? "rgba(0, 229, 255, 0.35)" : "rgba(0, 229, 255, 0.14)";
      ctx.lineWidth = lat === 0 ? 1.5 : 0.8;
      ctx.stroke();
    }

    // 2. Draw Longitude Meridians
    const meridians = 12;
    for (let m = 0; m < meridians; m++) {
      const lon = (m * Math.PI * 2) / meridians;
      ctx.beginPath();
      let started = false;
      for (let lat = -Math.PI / 2; lat <= Math.PI / 2; lat += 0.12) {
        const pt = project(lat, lon, rotation, currentTilt);
        if (pt.visible) {
          if (!started) {
            ctx.moveTo(pt.x, pt.y);
            started = true;
          } else {
            ctx.lineTo(pt.x, pt.y);
          }
        } else {
          started = false;
        }
      }
      ctx.strokeStyle = "rgba(40, 123, 255, 0.16)";
      ctx.lineWidth = 0.8;
      ctx.stroke();
    }

    // 3. Draw Hub Nodes
    const projectedHubs = hubs.map(h => project(h.lat, h.lon, rotation, currentTilt));

    for (let i = 0; i < projectedHubs.length; i++) {
      const pt = projectedHubs[i];
      if (pt.visible && pt.z > 0) {
        const alpha = Math.min(1.0, (pt.z / R) * 1.2);

        // Pulsing radar ring
        ctx.beginPath();
        const pulseSize = 4 + (Math.sin(rotation * 5 + i) + 1) * 2.5;
        ctx.arc(pt.x, pt.y, pulseSize, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 229, 255, ${alpha * 0.6})`;
        ctx.lineWidth = 1;
        ctx.stroke();

        // Center beacon dot
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = "#ffffff";
        ctx.shadowBlur = 8;
        ctx.shadowColor = "#00E5FF";
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }

    // 4. Draw Traveling Arcs
    for (const arc of arcs) {
      const p1 = projectedHubs[arc.from];
      const p2 = projectedHubs[arc.to];

      if (p1.visible && p2.visible && (p1.z > -10 || p2.z > -10)) {
        arc.progress = (arc.progress + arc.speed) % 1.0;

        // Elevated control point for 3D curved arc
        const midX = (p1.x + p2.x) / 2;
        const midY = (p1.y + p2.y) / 2 - 25;

        // Draw faint base arc line
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.quadraticCurveTo(midX, midY, p2.x, p2.y);
        ctx.strokeStyle = "rgba(139, 53, 255, 0.25)";
        ctx.lineWidth = 1;
        ctx.stroke();

        // Draw animated traveling projectile packet
        const t = arc.progress;
        const arcX = (1 - t) * (1 - t) * p1.x + 2 * (1 - t) * t * midX + t * t * p2.x;
        const arcY = (1 - t) * (1 - t) * p1.y + 2 * (1 - t) * t * midY + t * t * p2.y;

        ctx.beginPath();
        ctx.arc(arcX, arcY, 3, 0, Math.PI * 2);
        ctx.fillStyle = "#00E5FF";
        ctx.shadowBlur = 10;
        ctx.shadowColor = "#00E5FF";
        ctx.fill();
        ctx.shadowBlur = 0;
      }
    }

    requestAnimationFrame(renderGlobe);
  }

  requestAnimationFrame(renderGlobe);
}

// -----------------------------------------------------------------------------
// 3. INPUT FOCUS & INTERACTIVE UI ENHANCEMENTS
// -----------------------------------------------------------------------------
function initInputInteractions() {
  const inputs = document.querySelectorAll(".form-input");
  inputs.forEach(input => {
    const container = input.closest(".input-container");
    if (!container) return;

    input.addEventListener("focus", () => {
      container.classList.add("focused");
    });

    input.addEventListener("blur", () => {
      container.classList.remove("focused");
    });
  });
}

// -----------------------------------------------------------------------------
// 4. SHOW / HIDE PASSWORD TOGGLE
// -----------------------------------------------------------------------------
function initPasswordToggle() {
  const btnToggle = document.getElementById("btnTogglePassword");
  const inputPw = document.getElementById("inputPassword");
  const iconEye = document.getElementById("iconEye");
  const iconEyeOff = document.getElementById("iconEyeOff");

  if (!btnToggle || !inputPw) return;

  btnToggle.addEventListener("click", () => {
    const isPw = inputPw.getAttribute("type") === "password";
    if (isPw) {
      inputPw.setAttribute("type", "text");
      if (iconEye) iconEye.style.display = "none";
      if (iconEyeOff) iconEyeOff.style.display = "block";
      btnToggle.setAttribute("title", "Hide Password");
    } else {
      inputPw.setAttribute("type", "password");
      if (iconEye) iconEye.style.display = "block";
      if (iconEyeOff) iconEyeOff.style.display = "none";
      btnToggle.setAttribute("title", "Show Password");
    }
    inputPw.focus();
  });
}

// -----------------------------------------------------------------------------
// 5. LOGIN FORM VALIDATION & REST API AUTHENTICATION
// -----------------------------------------------------------------------------
function showAlert(message, type = "error") {
  const box = document.getElementById("alertBox");
  const msgEl = document.getElementById("alertMessage");
  const iconEl = document.getElementById("alertIcon");
  if (!box || !msgEl) return;

  box.className = `alert-box ${type} show`;
  msgEl.innerText = message;
  if (iconEl) {
    if (type === "error") iconEl.innerText = "⛔";
    else if (type === "success") iconEl.innerText = "🛡️";
    else iconEl.innerText = "ℹ️";
  }
}

function hideAlert() {
  const box = document.getElementById("alertBox");
  if (box) box.className = "alert-box";
}

function setBtnLoading(isLoading) {
  const btn = document.getElementById("btnLogin");
  const textEl = document.getElementById("btnLoginText");
  const spinEl = document.getElementById("btnLoginSpinner");
  if (!btn) return;

  btn.disabled = isLoading;
  if (textEl) textEl.style.display = isLoading ? "none" : "flex";
  if (spinEl) spinEl.style.display = isLoading ? "block" : "none";
}

function initLoginForm() {
  const form = document.getElementById("loginForm");
  const emailInput = document.getElementById("inputEmail");
  const pwInput = document.getElementById("inputPassword");
  const remCheckbox = document.getElementById("checkRememberMe");
  const quickFillBtn = document.getElementById("btnQuickFill");
  const quickFillAnalystBtn = document.getElementById("btnQuickFillAnalyst");

  // Restrict demo credentials bar: only show if backend explicitly allows demo accounts and not in production
  fetch("/api/auth/config")
    .then(r => r.json())
    .then(cfg => {
      const demoBar = document.getElementById("demoCredentialsBar");
      if (demoBar && (!cfg.demo_mode || cfg.is_production)) {
        demoBar.style.display = "none";
      }
    })
    .catch(() => {});

  // Quick-Fill Head of SOC Demo Credentials Button
  if (quickFillBtn) {
    quickFillBtn.addEventListener("click", () => {
      emailInput.value = "admin@soc.ai";
      pwInput.value = "CyberShield2026!";
      showAlert("Demo credentials populated: admin@soc.ai (Head of SOC)", "info");
      emailInput.closest(".input-container")?.classList.add("focused");
      setTimeout(() => {
        emailInput.closest(".input-container")?.classList.remove("focused");
      }, 600);
    });
  }

  // Quick-Fill Regular Security Analyst Demo Credentials Button
  if (quickFillAnalystBtn) {
    quickFillAnalystBtn.addEventListener("click", () => {
      emailInput.value = "analyst@soc.ai";
      pwInput.value = "ThreatHunter2026!";
      showAlert("Demo credentials populated: analyst@soc.ai (Regular Security Analyst)", "info");
      emailInput.closest(".input-container")?.classList.add("focused");
      setTimeout(() => {
        emailInput.closest(".input-container")?.classList.remove("focused");
      }, 600);
    });
  }

  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (isTransitioning) return;
    hideAlert();

    const email = emailInput.value.trim();
    const password = pwInput.value;
    const rememberMe = remCheckbox ? remCheckbox.checked : false;

    // Client-side validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!email || !emailRegex.test(email)) {
      showAlert("Please enter a valid SOC operator work email address.");
      emailInput.focus();
      return;
    }

    if (!password) {
      showAlert("Please enter your security access password.");
      pwInput.focus();
      return;
    }

    setBtnLoading(true);

    try {
      const resp = await fetch(`${API_BASE}/api/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password, remember_me: rememberMe })
      });

      const data = await resp.json();

      if (!resp.ok) {
        throw new Error(data.detail || data.message || "Authentication failed.");
      }

      // Success: store session
      if (rememberMe) {
        localStorage.setItem("siem_auth_token", data.session_token);
        localStorage.setItem("siem_operator", JSON.stringify(data.user));
        localStorage.setItem("siem_remembered_email", email);
      } else {
        sessionStorage.setItem("siem_auth_token", data.session_token);
        sessionStorage.setItem("siem_operator", JSON.stringify(data.user));
        localStorage.removeItem("siem_auth_token");
      }

      showAlert(data.message || "Security clearance granted. Initiating secure SOC transition...", "success");

      // Play exact 3-second reference transition animation and redirect automatically on ended
      playSuccessTransitionAndRedirect();

    } catch (err) {
      showAlert(err.message || "Security clearance verification failed.");
      setBtnLoading(false);
    }
  });
}

let isTransitioning = false;

function playSuccessTransitionAndRedirect() {
  if (isTransitioning) return;
  isTransitioning = true;

  const glassCard = document.querySelector(".login-glass-card");
  const overlay = document.getElementById("loginSuccessOverlay");
  const video = document.getElementById("loginSuccessVideo");
  const stageContainer = document.getElementById("dashboardStage");
  const stageFrame = document.getElementById("dashboardStageFrame");

  // Smoothly fade out the login card
  if (glassCard) {
    glassCard.style.opacity = "0";
    glassCard.style.transform = "scale(0.96)";
    glassCard.style.transition = "all 0.35s ease-out";
  }

  let isDashboardLoaded = false;
  let isFadeThresholdReached = false;
  let hasRevealed = false;
  let hasFinalized = false;
  let rafId = null;

  // Reveal the dashboard underneath the fading video
  function revealDashboard() {
    if (hasRevealed) return;
    hasRevealed = true;

    // 1. Gradually fade the video overlay out with subtle blur and gentle expansion
    if (overlay) {
      overlay.classList.add("cinematic-fade-out");
    }

    // 2. Make the fully-loaded dashboard appear underneath with smooth opacity transition
    if (stageContainer) {
      stageContainer.classList.add("revealed");
    }
  }

  // Finalize transition when video playback concludes
  function finalizeTransition() {
    if (hasFinalized) return;
    hasFinalized = true;

    clearTimeout(fallbackTimer);
    clearTimeout(fadeTimer);
    if (rafId) cancelAnimationFrame(rafId);

    revealDashboard();

    // Clean up overlay visibility after fade-out transition concludes
    setTimeout(() => {
      if (overlay) {
        overlay.classList.remove("active");
        overlay.classList.remove("cinematic-fade-out");
        overlay.style.display = "none";
        overlay.setAttribute("aria-hidden", "true");
      }
    }, 400);

    // Enable interactive pointer events on dashboard stage
    if (stageContainer) {
      stageContainer.classList.add("revealed");
      stageContainer.style.pointerEvents = "all";
    }

    // Seamlessly synchronize address bar to / without triggering browser page reload
    try {
      window.history.replaceState({}, document.title, "/");
      if (stageFrame && stageFrame.contentWindow) {
        stageFrame.contentWindow.focus();
      }
    } catch (_) {}
  }

  // Graceful fallback if video playback encounters decode errors or autoplay restriction
  function handlePlaybackFallback() {
    clearTimeout(fallbackTimer);
    clearTimeout(fadeTimer);
    if (rafId) cancelAnimationFrame(rafId);

    if (isDashboardLoaded && stageContainer) {
      revealDashboard();
      finalizeTransition();
    } else {
      window.location.replace("/");
    }
  }

  // Preload the authenticated dashboard in stage iframe (ensures dashboard is loaded before reveal)
  if (stageFrame) {
    stageFrame.addEventListener("load", () => {
      isDashboardLoaded = true;
      if (stageContainer) {
        stageContainer.classList.add("loaded");
      }
      // If playback already reached the final 300-400ms threshold, reveal now
      if (isFadeThresholdReached && !hasRevealed) {
        revealDashboard();
      }
    }, { once: true });

    stageFrame.src = "/";
  }

  // Safety fallback timer (2.6s maximum) ensures user is never stranded
  const fallbackTimer = setTimeout(handlePlaybackFallback, 2600);

  // Synchronized fade timer (triggers fade at ~1620ms, final 380ms of 2.0s video)
  const fadeTimer = setTimeout(() => {
    isFadeThresholdReached = true;
    if (isDashboardLoaded && !hasRevealed) {
      revealDashboard();
    }
  }, 1620);

  if (overlay && video) {
    overlay.classList.remove("cinematic-fade-out");
    overlay.style.display = "flex";
    overlay.classList.add("active");
    overlay.setAttribute("aria-hidden", "false");
    video.currentTime = 0;
    video.loop = false;

    // Precise progress monitoring for the final 300-400ms (1.62s threshold)
    const FADE_THRESHOLD = 1.62;

    function checkVideoProgress() {
      if (video.currentTime >= FADE_THRESHOLD && !isFadeThresholdReached) {
        isFadeThresholdReached = true;
        if (isDashboardLoaded && !hasRevealed) {
          revealDashboard();
        }
      }
      if (!hasFinalized) {
        rafId = requestAnimationFrame(checkVideoProgress);
      }
    }
    rafId = requestAnimationFrame(checkVideoProgress);

    video.addEventListener("timeupdate", () => {
      if (video.currentTime >= FADE_THRESHOLD && !isFadeThresholdReached) {
        isFadeThresholdReached = true;
        if (isDashboardLoaded && !hasRevealed) {
          revealDashboard();
        }
      }
    });

    // Coordinated ended event
    video.addEventListener("ended", () => {
      if (isDashboardLoaded) {
        finalizeTransition();
      } else {
        // Wait briefly for dashboard to complete loading
        const waitTimer = setTimeout(finalizeTransition, 450);
        stageFrame?.addEventListener("load", () => {
          clearTimeout(waitTimer);
          finalizeTransition();
        }, { once: true });
      }
    }, { once: true });

    video.addEventListener("error", () => {
      handlePlaybackFallback();
    }, { once: true });

    const playPromise = video.play();
    if (playPromise !== undefined) {
      playPromise.catch((err) => {
        console.warn("Autoplay was prevented or video failed to play:", err);
        handlePlaybackFallback();
      });
    }
  } else {
    handlePlaybackFallback();
  }
}

function checkRememberedUser() {
  const remembered = localStorage.getItem("siem_remembered_email");
  const emailInput = document.getElementById("inputEmail");
  if (remembered && emailInput) {
    emailInput.value = remembered;
  }
}

// -----------------------------------------------------------------------------
// 6. MODALS CONTROLLER (FORGOT PASSWORD, CONTACT ADMIN, GOOGLE SSO)
// -----------------------------------------------------------------------------
function initModals() {
  // Modal Elements
  const modalForgot = document.getElementById("modalForgotPassword");
  const modalContact = document.getElementById("modalContactAdmin");
  const modalGoogle = document.getElementById("modalGoogleSSO");

  // Triggers
  document.getElementById("linkForgotPassword")?.addEventListener("click", (e) => {
    e.preventDefault();
    openModal(modalForgot);
  });

  document.getElementById("linkContactAdmin")?.addEventListener("click", (e) => {
    e.preventDefault();
    openModal(modalContact);
  });

  document.getElementById("btnGoogleLogin")?.addEventListener("click", () => {
    openModal(modalGoogle);
  });

  // Close Buttons
  document.getElementById("btnCloseForgotModal")?.addEventListener("click", () => closeModal(modalForgot));
  document.getElementById("btnCancelForgot")?.addEventListener("click", () => closeModal(modalForgot));

  document.getElementById("btnCloseContactModal")?.addEventListener("click", () => closeModal(modalContact));
  document.getElementById("btnCancelContact")?.addEventListener("click", () => closeModal(modalContact));

  document.getElementById("btnCloseGoogleModal")?.addEventListener("click", () => closeModal(modalGoogle));
  document.getElementById("btnCancelGoogle")?.addEventListener("click", () => closeModal(modalGoogle));

  // Backdrop click closes modal
  [modalForgot, modalContact, modalGoogle].forEach(m => {
    if (!m) return;
    m.addEventListener("click", (e) => {
      if (e.target === m) closeModal(m);
    });
  });

  function openModal(m) {
    if (m) m.classList.add("open");
  }

  function closeModal(m) {
    if (m) m.classList.remove("open");
  }

  // --- 1. Forgot Password & Reset Lifecycle ---
  document.getElementById("btnSubmitForgot")?.addEventListener("click", async () => {
    const email = document.getElementById("inputForgotEmail")?.value.trim();
    const resultBox = document.getElementById("forgotResultBox");
    const submitBtn = document.getElementById("btnSubmitForgot");
    const resetStep = document.getElementById("resetPasswordStep");
    const resetTokenInput = document.getElementById("inputResetToken");

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = "Please enter a valid work email address.";
      }
      return;
    }

    if (submitBtn) submitBtn.disabled = true;

    try {
      const resp = await fetch(`${API_BASE}/api/auth/forgot-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email })
      });
      const data = await resp.json();

      if (!resp.ok) throw new Error(data.detail || "Dispatch failed.");

      if (resultBox) {
        resultBox.className = "alert-box success show";
        resultBox.innerHTML = `
          <div>
            <strong>✓ Recovery Protocol Dispatched:</strong><br>
            ${data.message}<br>
            ${data.recovery_token ? `<em>(Dev Mode Token: <code>${data.recovery_token}</code>)</em>` : ''}
          </div>
        `;
      }
      if (submitBtn) submitBtn.innerText = "Dispatched";

      // Reveal step 2: apply new password with token
      if (resetStep) {
        resetStep.style.display = "block";
        if (data.recovery_token && resetTokenInput) {
          resetTokenInput.value = data.recovery_token;
        }
      }
    } catch (err) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = err.message;
      }
      if (submitBtn) submitBtn.disabled = false;
    }
  });

  // Step 2: Apply new password with token
  document.getElementById("btnApplyNewPassword")?.addEventListener("click", async () => {
    const token = document.getElementById("inputResetToken")?.value.trim();
    const newPassword = document.getElementById("inputNewPassword")?.value;
    const resultBox = document.getElementById("forgotResultBox");
    const applyBtn = document.getElementById("btnApplyNewPassword");

    if (!token) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = "Please enter your recovery authorization token.";
      }
      return;
    }

    if (!newPassword || newPassword.length < 8) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = "New password must be at least 8 characters long.";
      }
      return;
    }

    if (applyBtn) applyBtn.disabled = true;

    try {
      const resp = await fetch(`${API_BASE}/api/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, new_password: newPassword })
      });
      const data = await resp.json();

      if (!resp.ok) throw new Error(data.detail || "Password reset failed.");

      if (resultBox) {
        resultBox.className = "alert-box success show";
        resultBox.innerHTML = `<div><strong>✓ Password Updated:</strong> ${data.message}</div>`;
      }

      // Prepopulate login form
      const loginEmail = document.getElementById("inputEmail");
      const loginPw = document.getElementById("inputPassword");
      if (loginEmail && data.email) loginEmail.value = data.email;
      if (loginPw) loginPw.value = newPassword;

      setTimeout(() => {
        closeModal(modalForgot);
        showAlert("Password reset successful. You may now log in.", "success");
      }, 1500);

    } catch (err) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = err.message;
      }
      if (applyBtn) applyBtn.disabled = false;
    }
  });

  // --- 2. Contact Administrator Submission ---
  document.getElementById("btnSubmitContact")?.addEventListener("click", async () => {
    const name = document.getElementById("inputContactName")?.value.trim();
    const email = document.getElementById("inputContactEmail")?.value.trim();
    const clearance = document.getElementById("selectClearance")?.value;
    const reason = document.getElementById("inputContactReason")?.value.trim();
    const resultBox = document.getElementById("contactResultBox");
    const submitBtn = document.getElementById("btnSubmitContact");

    if (!name || name.length < 2) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = "Please enter your full name.";
      }
      return;
    }

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = "Please enter a valid corporate work email address.";
      }
      return;
    }

    if (!reason || reason.length < 10) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = "Please enter a justification of at least 10 characters.";
      }
      return;
    }

    if (submitBtn) submitBtn.disabled = true;

    try {
      const resp = await fetch(`${API_BASE}/api/auth/contact-admin`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, clearance_level: clearance, reason })
      });
      const data = await resp.json();

      if (!resp.ok) throw new Error(data.detail || "Request submission failed.");

      if (resultBox) {
        resultBox.className = "alert-box success show";
        resultBox.innerHTML = `
          <div>
            <strong>✓ Access Clearance Ticket Created:</strong><br>
            Ticket ID: <code>${data.ticket_id}</code><br>
            Notification forwarded to SOC Operations Supervisor.
          </div>
        `;
      }
      if (submitBtn) submitBtn.innerText = "Submitted";
    } catch (err) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = err.message;
      }
      if (submitBtn) submitBtn.disabled = false;
    }
  });

  // --- 3. Google Workspace SSO Handler with OAuth 2.0 Inspection ---
  // When Google button is clicked, check live OAuth configuration
  document.getElementById("btnGoogleLogin")?.addEventListener("click", async () => {
    try {
      const resp = await fetch(`${API_BASE}/api/auth/oauth/google/url`);
      const data = await resp.json();
      const badgeText = document.getElementById("googleConfigBadgeText");
      const descEl = document.getElementById("googleModalDescription");
      const confirmBtn = document.getElementById("btnConfirmGoogleSSO");

      if (data.is_configured) {
        if (badgeText) badgeText.innerText = "OAuth 2.0 Status: Live Google Cloud Connected";
        if (descEl) descEl.innerText = "Google Workspace enterprise integration is active. You will be redirected to Google for secure single sign-on.";
        if (confirmBtn) {
          confirmBtn.innerText = "Proceed to Google Sign-In";
          confirmBtn.onclick = () => { window.location.href = data.auth_url; };
        }
      } else {
        if (badgeText) badgeText.innerText = "OAuth 2.0 Status: Sandbox Simulation Mode";
        if (descEl) descEl.innerText = "Google Client credentials are unconfigured in environment (GOOGLE_CLIENT_ID). Click below to launch a transparent developer sandbox demo session tagged [DEMO SIMULATION].";
        if (confirmBtn) {
          confirmBtn.innerText = "Launch Sandbox Demo ([DEMO SIMULATION])";
        }
      }
    } catch (_) {}
  });

  document.getElementById("btnConfirmGoogleSSO")?.addEventListener("click", async () => {
    const resultBox = document.getElementById("googleResultBox");
    const confirmBtn = document.getElementById("btnConfirmGoogleSSO");

    if (confirmBtn) confirmBtn.disabled = true;

    try {
      const resp = await fetch(`${API_BASE}/api/auth/google`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ requested_email: "analyst.google@soc-siem.cloud" })
      });
      const data = await resp.json();

      if (!resp.ok) throw new Error(data.detail || "Google SSO authorization failed.");

      // Store session
      sessionStorage.setItem("siem_auth_token", data.session_token);
      sessionStorage.setItem("siem_operator", JSON.stringify(data.user));

      if (resultBox) {
        resultBox.className = "alert-box success show";
        resultBox.innerHTML = `<div><strong>✓ ${data.status === 'DEMO_SIMULATION' ? 'Sandbox Demo Session Active:' : 'Google SSO Verified:'}</strong> ${data.message}</div>`;
      }

      setTimeout(() => {
        const modalGoogle = document.getElementById("modalGoogleSSO");
        if (modalGoogle) modalGoogle.classList.remove("open");
        playSuccessTransitionAndRedirect();
      }, 700);

    } catch (err) {
      if (resultBox) {
        resultBox.className = "alert-box error show";
        resultBox.innerText = err.message;
      }
      if (confirmBtn) confirmBtn.disabled = false;
    }
  });
}
