/**
 * CYBERSHIELD — Frontend Script
 * Handles file upload, scan progress, results display
 * Professional UI with real data population
 * No alerts — toast notifications throughout
 */

document.addEventListener("DOMContentLoaded", () => {

  // ─── STATE ──────────────────────────────────────────────────────────────────

  let chartInstance  = null;
  let gaugeInstance  = null;
  let currentScanData = null;


  // ─── DOM REFS ────────────────────────────────────────────────────────────────

  const uploadArea     = document.getElementById("uploadArea");
  const fileInput      = document.getElementById("fileInput");
  const results        = document.getElementById("results");
  const loader         = document.getElementById("scanLoader");
  const scanStatus     = document.getElementById("scanStatus");
  const scanSubStatus  = document.getElementById("scanSubStatus");
  const progressBar    = document.getElementById("progressBar");
  const progressFill   = document.getElementById("progressFill");


  // ─── FIX: Ensure browse button works ─────────────────────────────────────────
  
  // Method 1: Re-attach click handler to browse button
  const browseBtn = document.querySelector('.upload-btn');
  if (browseBtn && fileInput) {
    // Remove any existing inline onclick
    browseBtn.removeAttribute('onclick');
    // Add proper event listener
    browseBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      fileInput.click();
    });
  }
  
  // Also make the entire upload area clickable
  if (uploadArea && fileInput) {
    uploadArea.addEventListener('click', (e) => {
      // Don't trigger if clicking on the button (already handled)
      if (e.target.closest('.upload-btn')) return;
      fileInput.click();
    });
  }


  // ─── TOAST NOTIFICATION SYSTEM ───────────────────────────────────────────────

  function showToast(message, type = "info", duration = 4000) {

    const container = document.getElementById("toastContainer") ||
      (() => {
        const el = document.createElement("div");
        el.id = "toastContainer";
        el.style.cssText = `
          position: fixed;
          top: 80px;
          right: 20px;
          z-index: 9999;
          display: flex;
          flex-direction: column;
          gap: 10px;
          max-width: 360px;
        `;
        document.body.appendChild(el);
        return el;
      })();

    const colors = {
      success: "#00f5a0",
      error:   "#ff3b5c",
      warning: "#ffb700",
      info:    "#00d4ff"
    };

    const icons = {
      success: "✓",
      error:   "✕",
      warning: "⚠",
      info:    "ℹ"
    };

    const toast = document.createElement("div");
    toast.style.cssText = `
      background: #0d1117;
      border: 1px solid ${colors[type]};
      border-left: 4px solid ${colors[type]};
      color: #ccd6f6;
      padding: 12px 16px;
      border-radius: 8px;
      font-family: 'Rajdhani', sans-serif;
      font-size: 14px;
      display: flex;
      align-items: flex-start;
      gap: 10px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.5);
      animation: slideIn 0.3s ease;
      max-width: 360px;
      word-break: break-word;
    `;

    toast.innerHTML = `
      <span style="color:${colors[type]};font-weight:bold;font-size:16px;flex-shrink:0">
        ${icons[type]}
      </span>
      <span>${message}</span>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.animation = "slideOut 0.3s ease forwards";
      setTimeout(() => toast.remove(), 300);
    }, duration);

  }


  // ─── PROGRESS STEPS ──────────────────────────────────────────────────────────

  const SCAN_STEPS = [
    { message: "Uploading APK file...",           subMessage: "Preparing for analysis",                   progress: 5  },
    { message: "Validating APK format...",         subMessage: "Checking file integrity",                  progress: 12 },
    { message: "Parsing Android Manifest...",      subMessage: "Extracting permissions and metadata",      progress: 22 },
    { message: "Running Static Analysis...",       subMessage: "Scanning APIs, strings and code patterns", progress: 35 },
    { message: "Analyzing Permissions...",         subMessage: "Checking for dangerous permission combos", progress: 45 },
    { message: "Detecting Malware Patterns...",    subMessage: "Matching against 22 malware signatures",   progress: 55 },
    { message: "Scanning for Secrets...",          subMessage: "Looking for hardcoded credentials",        progress: 63 },
    { message: "Analyzing URLs & Domains...",      subMessage: "Checking against threat intelligence",     progress: 70 },
    { message: "Running Threat Intelligence...",   subMessage: "Querying VirusTotal & MalwareBazaar",      progress: 80 },
    { message: "Classifying Malware Type...",      subMessage: "Running classification engine",            progress: 88 },
    { message: "Analyzing Certificate...",         subMessage: "Validating signing certificate",           progress: 92 },
    { message: "Generating Security Report...",    subMessage: "Building PDF report",                      progress: 97 },
    { message: "Scan Complete",                    subMessage: "Results ready",                            progress: 100 }
  ];

  let stepIndex    = 0;
  let stepInterval = null;


  function startProgressSteps() {
    stepIndex = 0;
    updateStep(0);

    stepInterval = setInterval(() => {
      stepIndex++;
      if (stepIndex < SCAN_STEPS.length - 1) {
        updateStep(stepIndex);
      }
    }, 1800);
  }


  function updateStep(index) {
    const step = SCAN_STEPS[index];
    if (!step) return;

    if (scanStatus)    scanStatus.innerText    = step.message;
    if (scanSubStatus) scanSubStatus.innerText = step.subMessage;

    if (progressFill) {
      progressFill.style.width      = step.progress + "%";
      progressFill.style.transition = "width 0.8s ease";
    }
  }


  function stopProgressSteps() {
    if (stepInterval) {
      clearInterval(stepInterval);
      stepInterval = null;
    }
    updateStep(SCAN_STEPS.length - 1);
  }


  // ─── FILE VALIDATION ─────────────────────────────────────────────────────────

  function validateFile(file) {

    if (!file) {
      showToast("Please select an APK file", "error");
      return false;
    }

    if (!file.name.toLowerCase().endsWith(".apk")) {
      showToast("Invalid file type. Please upload an APK file.", "error");
      return false;
    }

    const maxSize = 100 * 1024 * 1024; // 100MB
    if (file.size > maxSize) {
      showToast("File too large. Maximum size is 100MB.", "error");
      return false;
    }

    if (file.size < 1000) {
      showToast("File is too small to be a valid APK.", "error");
      return false;
    }

    return true;

  }


  // ─── DRAG & DROP ─────────────────────────────────────────────────────────────

  // File input change handler
  fileInput.addEventListener("change", () => {
    if (fileInput.files && fileInput.files[0]) {
      handleFileUpload(fileInput.files[0]);
    }
  });

  // Drag and drop handlers
  if (uploadArea) {
    uploadArea.addEventListener("dragover", (e) => {
      e.preventDefault();
      uploadArea.classList.add("drag-active");
    });

    uploadArea.addEventListener("dragleave", (e) => {
      if (!uploadArea.contains(e.relatedTarget)) {
        uploadArea.classList.remove("drag-active");
      }
    });

    uploadArea.addEventListener("drop", (e) => {
      e.preventDefault();
      uploadArea.classList.remove("drag-active");
      const file = e.dataTransfer.files[0];
      if (file) handleFileUpload(file);
    });
  }


  // ─── MAIN UPLOAD + SCAN HANDLER ──────────────────────────────────────────────

  async function handleFileUpload(file) {

    if (!validateFile(file)) return;

    // Hide results, show loader
    if (results) results.classList.remove("visible");
    if (uploadArea) uploadArea.style.display = "none";

    if (loader) {
      loader.style.display = "flex";
    }

    startProgressSteps();

    const formData = new FormData();
    formData.append("apk", file);

    try {

      const response = await fetch("/scan", {
        method: "POST",
        body:   formData
      });

      stopProgressSteps();

      const data = await response.json();

      if (!response.ok || data.error) {
        throw new Error(data.message || data.error || "Scan failed");
      }

      // Hide loader
      if (loader) loader.style.display = "none";

      currentScanData = data;

      displayResults(data);

      showToast(
        `Scan complete — ${data.classification}`,
        data.classification === "SAFE"
          ? "success"
          : data.classification === "SUSPICIOUS"
            ? "warning"
            : "error",
        5000
      );

    } catch (err) {

      stopProgressSteps();

      if (loader) loader.style.display = "none";

      if (uploadArea) uploadArea.style.display = "block";

      console.error("Scan error:", err);
      showToast(err.message || "Scan failed. Please try again.", "error", 6000);

    }

  }


  // ─── RESULTS DISPLAY ─────────────────────────────────────────────────────────

  function displayResults(data) {

    if (results) results.classList.add("visible");

    // Scroll to results
    setTimeout(() => {
      if (results) results.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 300);

    populateScoreGauge(data);
    populateAppInfo(data);
    populateScoreBreakdown(data);
    populatePermissions(data);
    populateStaticAnalysis(data);
    populateMalwareAnalysis(data);
    populateMLClassification(data);
    populateDynamicAnalysis(data);
    populateThreatIntel(data);
    populateSecretScan(data);
    populateCertificateAnalysis(data);
    populateFakeAppAnalysis(data);
    populateURLAnalysis(data);
    setupReportButton(data);

  }


  // ─── SCORE GAUGE ─────────────────────────────────────────────────────────────

  function populateScoreGauge(data) {

    const score          = data.finalRiskScore || 0;
    const classification = data.classification || "SAFE";

    const colorMap = {
      SAFE:       "#00f5a0",
      SUSPICIOUS: "#ffb700",
      DANGEROUS:  "#ff3b5c"
    };

    const color = colorMap[classification] || "#00d4ff";

    // Animated score counter
    const scoreValueEl = document.querySelector(".score-value");
    const scoreLabelEl = document.querySelector(".score-label");

    if (scoreValueEl) {
      scoreValueEl.className = "score-value";
      scoreValueEl.classList.add(`score-${classification.toLowerCase()}`);

      let current = 0;
      const interval = setInterval(() => {
        current += Math.ceil(score / 30);
        if (current >= score) {
          current = score;
          clearInterval(interval);
        }
        scoreValueEl.innerText = current + "%";
      }, 40);
    }

    if (scoreLabelEl) {
      scoreLabelEl.innerText = classification;
      scoreLabelEl.style.color = color;
    }

    // Gauge chart
    const gaugeCanvas = document.getElementById("riskGauge");
    if (gaugeCanvas) {

      if (gaugeInstance) gaugeInstance.destroy();

      gaugeInstance = new Chart(gaugeCanvas, {
        type: "doughnut",
        data: {
          datasets: [{
            data: [score, 100 - score],
            backgroundColor: [color, "#1a1a2e"],
            borderWidth: 0
          }]
        },
        options: {
          cutout:   "78%",
          rotation: -90,
          plugins:  { legend: { display: false }, tooltip: { enabled: false } },
          animation: { animateRotate: true, duration: 1000 }
        }
      });

    }

  }


  // ─── APP INFO ────────────────────────────────────────────────────────────────

  function populateAppInfo(data) {

    setText("appName",      data.appName         || "Unknown");
    setText("packageName",  data.packageName      || "Unknown");
    setText("apkVersion",   data.version          || "Unknown");
    setText("minSdk",       data.minSdk           || "Unknown");
    setText("targetSdk",    data.targetSdk        || "Unknown");
    setText("apkSize",      data.fileSizeFormatted || "Unknown");
    setText("apkFileName",  data.fileName         || "Unknown");
    setText("totalPermissions", data.totalPermissions || 0);
    setText("scanId",       data.scanId           || "N/A");

    // Hashes with copy buttons
    if (data.hashes) {
      setHashWithCopy("hashMd5",    data.hashes.md5);
      setHashWithCopy("hashSha1",   data.hashes.sha1);
      setHashWithCopy("hashSha256", data.hashes.sha256);
    }

    // Trusted package badge
    const trustedBadge = document.getElementById("trustedBadge");
    if (trustedBadge) {
      if (data.isTrustedPackage) {
        trustedBadge.innerHTML = `<span class="badge badge-safe">✓ Trusted Package</span>`;
      } else {
        trustedBadge.innerHTML = `<span class="badge badge-warning">⚠ Unverified Package</span>`;
      }
    }

  }


  // ─── SCORE BREAKDOWN CHART ────────────────────────────────────────────────────

  function populateScoreBreakdown(data) {

    const ctx = document.getElementById("riskChart");
    if (!ctx || !data.scores) return;

    if (chartInstance) chartInstance.destroy();

    const scores = data.scores;

    const labels = [
      "Permissions",
      "Static Code",
      "Malware Patterns",
      "Dynamic Behavior",
      "URLs",
      "Threat Intel",
      "Secrets",
      "Certificate",
      "Fake App"
    ];

    const values = [
      scores.permissionScore || 0,
      scores.staticScore     || 0,
      scores.malwareScore    || 0,
      scores.dynamicScore    || 0,
      scores.urlScore        || 0,
      scores.threatScore     || 0,
      scores.secretScore     || 0,
      scores.certScore       || 0,
      scores.fakeAppScore    || 0
    ];

    const backgroundColors = values.map(v =>
      v >= 70 ? "#ff3b5c44" :
      v >= 40 ? "#ffb70044" :
                "#00f5a044"
    );

    const borderColors = values.map(v =>
      v >= 70 ? "#ff3b5c" :
      v >= 40 ? "#ffb700" :
                "#00f5a0"
    );

    chartInstance = new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          label:           "Risk Score",
          data:            values,
          backgroundColor: backgroundColors,
          borderColor:     borderColors,
          borderWidth:     2,
          borderRadius:    4
        }]
      },
      options: {
        responsive:          true,
        maintainAspectRatio: true,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: ctx => ` Score: ${ctx.raw}/100`
            }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            max:         100,
            ticks: {
              color:     "#8892b0",
              font:      { size: 10 }
            },
            grid: {
              color: "#1a1a2e"
            }
          },
          x: {
            ticks: {
              color:     "#8892b0",
              font:      { size: 9 },
              maxRotation: 45
            },
            grid: { display: false }
          }
        }
      }
    });

  }


  // ─── PERMISSIONS ─────────────────────────────────────────────────────────────

  function populatePermissions(data) {

    const permList = document.getElementById("permissionList");
    if (!permList) return;

    permList.innerHTML = "";

    // Flagged permissions
    if (data.flaggedPermissions?.length > 0) {

      data.flaggedPermissions.forEach(perm => {
        const name     = typeof perm === "string" ? perm : perm.permission;
        const severity = typeof perm === "object" ? perm.severity : "HIGH";
        permList.appendChild(createFindingItem(name, severity));
      });

    } else {
      permList.appendChild(createEmptyItem("No dangerous permissions detected"));
    }

    // Dangerous combos
    const comboList = document.getElementById("comboList");
    if (comboList) {
      comboList.innerHTML = "";
      if (data.comboFindings?.length > 0) {
        data.comboFindings.forEach(combo => {
          comboList.appendChild(createFindingItem(combo.label, combo.severity));
        });
      } else {
        comboList.appendChild(createEmptyItem("No dangerous permission combinations"));
      }
    }

  }


  // ─── STATIC ANALYSIS ─────────────────────────────────────────────────────────

  function populateStaticAnalysis(data) {

    const sa = data.staticAnalysis;
    if (!sa) return;

    // APIs by category
    const apiList = document.getElementById("apiList");
    if (apiList) {
      apiList.innerHTML = "";
      if (sa.detectedAPIs?.length > 0) {
        sa.detectedAPIs.forEach(api => {
          const label = `${api.api} — ${api.category}`;
          apiList.appendChild(createFindingItem(label, api.severity));
        });
      } else {
        apiList.appendChild(createEmptyItem("No suspicious APIs detected"));
      }
    }

    // String findings
    const stringList = document.getElementById("stringFindingsList");
    if (stringList) {
      stringList.innerHTML = "";
      if (sa.stringFindings?.length > 0) {
        sa.stringFindings.forEach(f => {
          stringList.appendChild(createFindingItem(f.label, f.severity));
        });
      } else {
        stringList.appendChild(createEmptyItem("No suspicious string patterns"));
      }
    }

    // Obfuscation
    const obfList = document.getElementById("obfuscationList");
    if (obfList) {
      obfList.innerHTML = "";
      if (sa.obfuscationIndicators?.length > 0) {
        sa.obfuscationIndicators.forEach(o => {
          obfList.appendChild(createFindingItem(o, "HIGH"));
        });
      } else {
        obfList.appendChild(createEmptyItem("No obfuscation indicators"));
      }
    }

    // Suspicious domains
    const domainList = document.getElementById("domainList");
    if (domainList) {
      domainList.innerHTML = "";
      if (sa.suspiciousDomains?.length > 0) {
        sa.suspiciousDomains.forEach(d => {
          domainList.appendChild(createFindingItem(d, "HIGH"));
        });
      } else {
        domainList.appendChild(createEmptyItem("No suspicious domains found"));
      }
    }

  }


  // ─── MALWARE ANALYSIS ────────────────────────────────────────────────────────

  function populateMalwareAnalysis(data) {

    const ma = data.malwareAnalysis;
    if (!ma) return;

    const malwareList = document.getElementById("malwareList");
    if (malwareList) {
      malwareList.innerHTML = "";
      if (ma.findings?.length > 0) {
        ma.findings.forEach(f => {
          malwareList.appendChild(createFindingItem(f.label, f.severity));
        });
      } else {
        malwareList.appendChild(createEmptyItem("No malware patterns detected"));
      }
    }

    // Verdict badge
    const verdictEl = document.getElementById("malwareVerdict");
    if (verdictEl) {
      const verdictColors = {
        NONE:          "safe",
        POSSIBLE:      "warning",
        LIKELY:        "danger",
        HIGHLY_LIKELY: "danger"
      };
      verdictEl.innerHTML = createBadgeHTML(
        ma.malwareVerdict || "NONE",
        verdictColors[ma.malwareVerdict] || "safe"
      );
    }

  }


  // ─── ML CLASSIFICATION ───────────────────────────────────────────────────────

  function populateMLClassification(data) {

    const ml = data.mlClassification;
    if (!ml) return;

    setText("mlPrimaryType",        ml.primaryLabel       || "Clean");
    setText("mlPrimaryDescription", ml.primaryDescription || "No threats detected");
    setText("mlPrimaryScore",       (ml.primaryScore || 0) + "/100");
    setText("mlConfidence",         ml.primaryConfidence  || "UNLIKELY");
    setText("mlMultiThreat",        ml.isMultiThreat ? "YES — Multiple threat types detected" : "No");

    // Confidence badge
    const confBadge = document.getElementById("mlConfidenceBadge");
    if (confBadge) {
      const confColors = {
        UNLIKELY:  "safe",
        POSSIBLE:  "warning",
        LIKELY:    "danger",
        CONFIRMED: "danger"
      };
      confBadge.innerHTML = createBadgeHTML(
        ml.primaryConfidence || "UNLIKELY",
        confColors[ml.primaryConfidence] || "safe"
      );
    }

    // All detected types
    const mlTypesList = document.getElementById("mlDetectedTypes");
    if (mlTypesList) {
      mlTypesList.innerHTML = "";
      if (ml.detectedTypes?.length > 0) {
        ml.detectedTypes.forEach(t => {
          const li = document.createElement("li");
          li.style.cssText = "padding: 8px 0; border-bottom: 1px solid #1a1a2e;";
          li.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
              <span style="color:#ccd6f6;font-weight:600">${t.label}</span>
              ${createBadgeHTML(t.confidence, t.score >= 75 ? "danger" : t.score >= 50 ? "warning" : "info")}
            </div>
            <div style="color:#8892b0;font-size:12px">${t.description}</div>
            <div style="color:#00d4ff;font-size:11px;margin-top:2px">Score: ${t.score}/100</div>
          `;
          mlTypesList.appendChild(li);
        });
      } else {
        mlTypesList.appendChild(createEmptyItem("No malware types classified"));
      }
    }

  }


  // ─── DYNAMIC ANALYSIS ────────────────────────────────────────────────────────

  function populateDynamicAnalysis(data) {

    const da = data.dynamicAnalysis;
    if (!da) return;

    const dynamicList = document.getElementById("dynamicList");
    if (dynamicList) {
      dynamicList.innerHTML = "";
      if (da.behaviors?.length > 0) {
        da.behaviors.forEach(b => {
          const item = createFindingItem(
            `${b.label} — ${b.description}`,
            b.severity
          );
          dynamicList.appendChild(item);
        });
      } else {
        dynamicList.appendChild(createEmptyItem("No suspicious behaviors predicted"));
      }
    }

    // Verdict
    const verdictEl = document.getElementById("dynamicVerdict");
    if (verdictEl) {
      const verdictColors = {
        CLEAN:           "safe",
        LOW_RISK:        "info",
        SUSPICIOUS:      "warning",
        MALICIOUS:       "danger",
        HIGHLY_MALICIOUS:"danger"
      };
      verdictEl.innerHTML = createBadgeHTML(
        da.behaviorVerdict || "CLEAN",
        verdictColors[da.behaviorVerdict] || "safe"
      );
    }

    // Analysis note
    const noteEl = document.getElementById("dynamicNote");
    if (noteEl && da.analysisNote) {
      noteEl.innerText  = da.analysisNote;
      noteEl.style.display = "block";
    }

  }


  // ─── THREAT INTELLIGENCE ─────────────────────────────────────────────────────

  function populateThreatIntel(data) {

    const ti = data.threatIntel;
    if (!ti) return;

    const threatList = document.getElementById("threatIntelList");
    if (threatList) {
      threatList.innerHTML = "";
      if (ti.findings?.length > 0) {
        ti.findings.forEach(f => {
          const item = createFindingItem(f.label, f.severity);
          if (f.link) {
            const a = document.createElement("a");
            a.href   = f.link;
            a.target = "_blank";
            a.style.cssText = "color:#00d4ff;font-size:11px;margin-left:8px";
            a.innerText = "View Report →";
            item.appendChild(a);
          }
          threatList.appendChild(item);
        });
      } else {
        threatList.appendChild(createEmptyItem("No threat intelligence matches"));
      }
    }

    // VT Status
    const vtStatus = document.getElementById("vtStatus");
    if (vtStatus && ti.summary) {
      const status = ti.summary.virusTotalStatus;
      const color  = status === "detected" ? "danger" : status === "clean" ? "safe" : "info";
      vtStatus.innerHTML = createBadgeHTML(
        status === "detected"
          ? `DETECTED — ${ti.summary.vtDetectionRate}`
          : status === "clean"
            ? "Clean"
            : "Unavailable",
        color
      );
    }

    // MB Status
    const mbStatus = document.getElementById("mbStatus");
    if (mbStatus && ti.summary) {
      const status = ti.summary.malwareBazaarStatus;
      const color  = status === "detected" ? "danger" : status === "clean" ? "safe" : "info";
      mbStatus.innerHTML = createBadgeHTML(
        status === "detected" ? "DETECTED" : status === "clean" ? "Clean" : "Unavailable",
        color
      );
    }

    // VT Link
    const vtLink = document.getElementById("vtLink");
    if (vtLink && ti.summary?.vtPermalink) {
      vtLink.href        = ti.summary.vtPermalink;
      vtLink.style.display = "inline-block";
    }

  }


  // ─── SECRET SCAN ─────────────────────────────────────────────────────────────

  function populateSecretScan(data) {

    const ss = data.secretScan;
    if (!ss) return;

    const secretList = document.getElementById("secretList");
    if (secretList) {
      secretList.innerHTML = "";
      if (ss.findings?.length > 0) {
        ss.findings.forEach(f => {
          const item = createFindingItem(
            `${f.label} — Sample: ${f.sample}`,
            f.severity
          );
          secretList.appendChild(item);
        });
      } else {
        secretList.appendChild(createEmptyItem("No hardcoded secrets detected"));
      }
    }

    setText("secretCritical", ss.criticalCount || 0);
    setText("secretHigh",     ss.highCount     || 0);
    setText("secretTotal",    ss.totalSecrets  || 0);

    // Credential leak warning
    const leakWarning = document.getElementById("credLeakWarning");
    if (leakWarning) {
      leakWarning.style.display = ss.hasCredentialLeak ? "block" : "none";
    }

  }


  // ─── CERTIFICATE ANALYSIS ────────────────────────────────────────────────────

  function populateCertificateAnalysis(data) {

    const cert = data.certificateAnalysis;
    if (!cert) return;

    const certList = document.getElementById("certFindingsList");
    if (certList) {
      certList.innerHTML = "";
      if (cert.findings?.length > 0) {
        cert.findings.forEach(f => {
          certList.appendChild(createFindingItem(f.label, f.severity));
        });
      } else {
        certList.appendChild(createEmptyItem("Certificate appears normal"));
      }
    }

    if (cert.certDetails) {
      setText("certCommonName",   cert.certDetails.commonName    || "Unknown");
      setText("certOrganization", cert.certDetails.organization  || "Unknown");
      setText("certCountry",      cert.certDetails.country       || "Unknown");
      setText("certV2Signature",  cert.certDetails.hasV2Signature ? "Present ✓" : "Not found ✗");
      setText("certSigningType",  cert.certDetails.signingBlockType || "Unknown");

      if (cert.certDetails.validityYears) {
        setText("certValidity",
          `${cert.certDetails.validityYears.from} — ${cert.certDetails.validityYears.to}`
        );
      }
    }

  }


  // ─── FAKE APP ANALYSIS ───────────────────────────────────────────────────────

  function populateFakeAppAnalysis(data) {

    const fa = data.fakeAppAnalysis;
    if (!fa) return;

    const fakeList = document.getElementById("fakeAppList");
    if (fakeList) {
      fakeList.innerHTML = "";
      if (fa.fakeAppFindings?.length > 0) {
        fa.fakeAppFindings.forEach(f => {
          fakeList.appendChild(createFindingItem(
            f.label || f,
            f.severity || "HIGH"
          ));
        });
      } else {
        fakeList.appendChild(createEmptyItem("No brand impersonation detected"));
      }
    }

    // Brand matches
    const brandEl = document.getElementById("brandMatches");
    if (brandEl) {
      if (fa.brandMatches?.length > 0) {
        brandEl.innerHTML = fa.brandMatches
          .map(b => createBadgeHTML(b, "danger"))
          .join(" ");
      } else {
        brandEl.innerHTML = createBadgeHTML("None", "safe");
      }
    }

  }


  // ─── URL ANALYSIS ────────────────────────────────────────────────────────────

  function populateURLAnalysis(data) {

    const ua = data.urlAnalysis;
    if (!ua) return;

    const urlList = document.getElementById("urlList");
    if (urlList) {
      urlList.innerHTML = "";
      if (ua.suspiciousUrls?.length > 0) {
        ua.suspiciousUrls.forEach(urlObj => {
          const url      = typeof urlObj === "string" ? urlObj : urlObj.url;
          const urlScore = typeof urlObj === "object"  ? urlObj.riskScore : 0;
          const severity = urlScore >= 25 ? "HIGH" : "MEDIUM";

          const li = createFindingItem(url, severity);

          // Show per-URL findings
          if (urlObj.findings?.length > 0) {
            const sub = document.createElement("div");
            sub.style.cssText = "font-size:11px;color:#8892b0;margin-top:3px;padding-left:12px";
            sub.innerText = urlObj.findings.map(f => f.label).join(" · ");
            li.appendChild(sub);
          }

          urlList.appendChild(li);
        });
      } else {
        urlList.appendChild(createEmptyItem("No suspicious URLs detected"));
      }
    }

    setText("urlTotal",      ua.totalUrlsAnalyzed || 0);
    setText("urlSuspicious", ua.totalSuspicious   || 0);

  }


  // ─── REPORT BUTTON ───────────────────────────────────────────────────────────

  function setupReportButton(data) {

    const btn = document.getElementById("downloadReport");
    if (!btn) return;

    if (data.report) {
      btn.onclick = () => window.open(data.report, "_blank");
      btn.disabled = false;
      btn.innerText = "Download Full Report";
    } else {
      btn.disabled  = true;
      btn.innerText = "Report unavailable";
    }

  }


  // ─── SCAN ANOTHER ────────────────────────────────────────────────────────────

  const scanAnotherBtn = document.getElementById("scanAnotherBtn");
  if (scanAnotherBtn) {
    scanAnotherBtn.addEventListener("click", () => {
      if (results) results.classList.remove("visible");
      if (uploadArea) uploadArea.style.display = "block";
      if (fileInput) fileInput.value = "";
      currentScanData = null;
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }


  // ─── UI HELPERS ──────────────────────────────────────────────────────────────

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.innerText = String(value ?? "N/A");
  }

  function setHashWithCopy(id, value) {
    const el = document.getElementById(id);
    if (!el || !value) return;

    el.innerHTML = `
      <span style="font-family:monospace;font-size:11px;word-break:break-all">${value}</span>
      <button onclick="window.copyToClipboard('${value}')"
        style="
          margin-left:8px;
          background:transparent;
          border:1px solid #00d4ff;
          color:#00d4ff;
          padding:2px 8px;
          border-radius:3px;
          cursor:pointer;
          font-size:10px;
          font-family:'Rajdhani',sans-serif
        ">
        Copy
      </button>
    `;
  }

  function createFindingItem(label, severity = "INFO") {

    const colors = {
      CRITICAL: "#ff3b5c",
      HIGH:     "#ff6b35",
      MEDIUM:   "#ffb700",
      LOW:      "#00f5a0",
      INFO:     "#00d4ff"
    };

    const color = colors[severity?.toUpperCase()] || colors.INFO;

    const li = document.createElement("li");
    li.style.cssText = `
      padding: 8px 6px;
      border-bottom: 1px solid #0d1117;
      display: flex;
      align-items: flex-start;
      gap: 8px;
      font-size: 13px;
      line-height: 1.4;
    `;

    li.innerHTML = `
      <span style="
        background:${color}22;
        color:${color};
        border:1px solid ${color}44;
        padding:1px 6px;
        border-radius:3px;
        font-size:10px;
        font-weight:700;
        white-space:nowrap;
        margin-top:1px;
        flex-shrink:0
      ">${severity}</span>
      <span style="color:#ccd6f6;word-break:break-word">${label}</span>
    `;

    return li;
  }

  function createEmptyItem(message) {
    const li = document.createElement("li");
    li.style.cssText = "padding:8px 6px;color:#00f5a0;font-size:13px";
    li.innerHTML = `<span style="margin-right:6px">✓</span>${message}`;
    return li;
  }

  function createBadgeHTML(text, type = "info") {
    const colors = {
      safe:    { bg: "#00f5a022", border: "#00f5a044", text: "#00f5a0" },
      warning: { bg: "#ffb70022", border: "#ffb70044", text: "#ffb700" },
      danger:  { bg: "#ff3b5c22", border: "#ff3b5c44", text: "#ff3b5c" },
      info:    { bg: "#00d4ff22", border: "#00d4ff44", text: "#00d4ff" }
    };
    const c = colors[type] || colors.info;
    return `<span style="
      background:${c.bg};
      color:${c.text};
      border:1px solid ${c.border};
      padding:2px 8px;
      border-radius:3px;
      font-size:11px;
      font-weight:700
    ">${text}</span>`;
  }


  // ─── GLOBAL CLIPBOARD ────────────────────────────────────────────────────────

  window.copyToClipboard = function(text) {
    navigator.clipboard.writeText(text).then(() => {
      showToast("Copied to clipboard", "success", 2000);
    }).catch(() => {
      showToast("Copy failed", "error", 2000);
    });
  };

});