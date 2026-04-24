/**
 * REPORT GENERATOR
 * Generates professional PDF security report
 * Uses PDFKit with proper styling, colors, sections
 * Fully async — waits for PDF to finish before resolving
 */

const PDFDocument = require("pdfkit");
const fs          = require("fs");
const path        = require("path");

// ─── COLOR PALETTE ────────────────────────────────────────────────────────────

const COLORS = {
  // Backgrounds
  pageBg:       "#0a0e17",
  cardBg:       "#0d1117",
  headerBg:     "#0d1117",

  // Brand
  primary:      "#00ccff",
  secondary:    "#8a2be2",
  accent:       "#ff00ff",

  // Status
  critical:     "#ff073a",
  high:         "#ff6b35",
  medium:       "#ffb300",
  low:          "#00cc88",
  safe:         "#00ff9d",
  info:         "#00ccff",

  // Text
  textPrimary:  "#ccd6f6",
  textSecondary:"#8892b0",
  textMuted:    "#495670",

  // Classification
  dangerous:    "#ff073a",
  suspicious:   "#ffb300",
  safeColor:    "#00ff9d"
};


// ─── HELPERS ──────────────────────────────────────────────────────────────────

function getSeverityColor(severity = "") {
  switch (severity.toUpperCase()) {
    case "CRITICAL": return COLORS.critical;
    case "HIGH":     return COLORS.high;
    case "MEDIUM":   return COLORS.medium;
    case "LOW":      return COLORS.low;
    default:         return COLORS.info;
  }
}

function getClassificationColor(classification = "") {
  switch (classification.toUpperCase()) {
    case "DANGEROUS":  return COLORS.dangerous;
    case "SUSPICIOUS": return COLORS.suspicious;
    case "SAFE":       return COLORS.safeColor;
    default:           return COLORS.info;
  }
}

function formatDate(date = new Date()) {
  return new Date(date).toLocaleString("en-IN", {
    timeZone:    "Asia/Kolkata",
    year:        "numeric",
    month:       "long",
    day:         "numeric",
    hour:        "2-digit",
    minute:      "2-digit"
  });
}

function truncate(str = "", max = 80) {
  if (!str) return "N/A";
  return str.length > max ? str.slice(0, max) + "..." : str;
}


// ─── DRAWING HELPERS ──────────────────────────────────────────────────────────

function drawPageBackground(doc) {
  doc.rect(0, 0, doc.page.width, doc.page.height)
     .fill(COLORS.pageBg);
}

function drawSectionHeader(doc, title, y = null) {
  const yPos = y || doc.y;

  // Background bar
  doc.rect(40, yPos, doc.page.width - 80, 28)
     .fill(COLORS.cardBg);

  // Left accent line
  doc.rect(40, yPos, 4, 28)
     .fill(COLORS.primary);

  // Title text
  doc.fillColor(COLORS.primary)
     .font("Helvetica-Bold")
     .fontSize(11)
     .text(title.toUpperCase(), 52, yPos + 8, {
       width:  doc.page.width - 100,
       lineBreak: false
     });

  doc.moveDown(0.3);
  return yPos + 35;
}

function drawDivider(doc) {
  doc.moveDown(0.3);
  doc.moveTo(40, doc.y)
     .lineTo(doc.page.width - 40, doc.y)
     .strokeColor(COLORS.textMuted)
     .lineWidth(0.5)
     .stroke();
  doc.moveDown(0.3);
}

function drawKeyValue(doc, key, value, options = {}) {
  const {
    keyColor   = COLORS.textSecondary,
    valueColor = COLORS.textPrimary,
    fontSize   = 9,
    indent     = 50
  } = options;

  doc.font("Helvetica-Bold")
     .fontSize(fontSize)
     .fillColor(keyColor)
     .text(key + ":", indent, doc.y, { continued: true, width: 160 });

  doc.font("Helvetica")
     .fontSize(fontSize)
     .fillColor(valueColor)
     .text(" " + truncate(String(value || "N/A"), 100), {
       width: doc.page.width - indent - 60
     });
}

function drawBadge(doc, text, color, x, y) {
  const padding = 6;
  const textWidth = text.length * 6;

  doc.rect(x, y - 2, textWidth + padding * 2, 14)
     .fill(color);

  doc.fillColor("#ffffff")
     .font("Helvetica-Bold")
     .fontSize(7)
     .text(text, x + padding, y, {
       width:     textWidth + padding,
       lineBreak: false
     });

  return x + textWidth + padding * 2 + 8;
}

function drawFindingItem(doc, finding, indent = 50) {

  const severity = finding.severity || "INFO";
  const color    = getSeverityColor(severity);
  const label    = finding.label || finding.description || String(finding);

  // Check if we need a new page
  if (doc.y > doc.page.height - 80) {
    doc.addPage();
    drawPageBackground(doc);
    doc.y = 40;
  }

  // Severity dot
  doc.circle(indent + 4, doc.y + 5, 4)
     .fill(color);

  // Severity label
  doc.font("Helvetica-Bold")
     .fontSize(8)
     .fillColor(color)
     .text(`[${severity}]`, indent + 12, doc.y, {
       continued: true,
       width:     60
     });

  // Finding text
  doc.font("Helvetica")
     .fontSize(8)
     .fillColor(COLORS.textPrimary)
     .text(" " + truncate(label, 120), {
       width: doc.page.width - indent - 70
     });

  doc.moveDown(0.2);
}

function ensureSpace(doc, needed = 60) {
  if (doc.y > doc.page.height - needed) {
    doc.addPage();
    drawPageBackground(doc);
    doc.y = 40;
  }
}


// ─── SCORE GAUGE (text-based) ─────────────────────────────────────────────────

function drawScoreGauge(doc, score, classification) {

  const color = getClassificationColor(classification);
  const cx    = doc.page.width / 2;
  const cy    = doc.y + 60;
  const r     = 45;

  // Outer ring
  doc.circle(cx, cy, r + 4)
     .fill(COLORS.cardBg);

  // Track circle
  doc.circle(cx, cy, r)
     .lineWidth(6)
     .strokeColor(COLORS.textMuted)
     .stroke();

  // Score arc simulation using filled circle overlay
  doc.circle(cx, cy, r)
     .lineWidth(6)
     .strokeColor(color)
     .stroke();

  // Score number
  doc.font("Helvetica-Bold")
     .fontSize(28)
     .fillColor(color)
     .text(score + "%", cx - 28, cy - 16, {
       width:     56,
       align:     "center",
       lineBreak: false
     });

  // Classification label
  doc.font("Helvetica-Bold")
     .fontSize(10)
     .fillColor(color)
     .text(classification, cx - 50, cy + 18, {
       width: 100,
       align: "center"
     });

  doc.y = cy + r + 20;

}


// ─── SCORE BAR ────────────────────────────────────────────────────────────────

function drawScoreBar(doc, label, score, maxScore = 100) {

  ensureSpace(doc, 30);

  const barX     = 160;
  const barY     = doc.y + 2;
  const barW     = doc.page.width - barX - 80;
  const barH     = 8;
  const fillW    = Math.round((Math.min(score, maxScore) / maxScore) * barW);
  const color    = score >= 70
    ? COLORS.critical
    : score >= 40
      ? COLORS.medium
      : COLORS.safe;

  // Label
  doc.font("Helvetica")
     .fontSize(8)
     .fillColor(COLORS.textSecondary)
     .text(truncate(label, 30), 50, doc.y, {
       width:     105,
       lineBreak: false
     });

  // Track
  doc.rect(barX, barY, barW, barH)
     .fill(COLORS.textMuted);

  // Fill
  if (fillW > 0) {
    doc.rect(barX, barY, fillW, barH)
       .fill(color);
  }

  // Score text
  doc.font("Helvetica-Bold")
     .fontSize(8)
     .fillColor(color)
     .text(score + "/100", barX + barW + 8, barY - 1, {
       width:     40,
       lineBreak: false
     });

  doc.moveDown(0.8);
}


// ─── MAIN FUNCTION ────────────────────────────────────────────────────────────

async function generateReport(data, outputPath) {

  // Ensure reports directory exists
  const reportsDir = path.dirname(outputPath);
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }

  return new Promise((resolve, reject) => {

    try {

      const doc = new PDFDocument({
        size:    "A4",
        margins: { top: 40, bottom: 40, left: 40, right: 40 },
        info: {
          Title:    "CyberShield Security Report",
          Author:   "CyberShield APK Scanner",
          Subject:  `Security analysis of ${data.appName || "Unknown App"}`,
          Keywords: "malware, APK, Android, security"
        }
      });

      const stream = fs.createWriteStream(outputPath);
      doc.pipe(stream);

      stream.on("error", reject);
      stream.on("finish", resolve);


      // ════════════════════════════════════════════════════════════
      // PAGE 1 — COVER & SUMMARY
      // ════════════════════════════════════════════════════════════

      drawPageBackground(doc);


      // ── Header bar ───────────────────────────────────────────────
      doc.rect(0, 0, doc.page.width, 70)
         .fill(COLORS.headerBg);

      doc.rect(0, 0, doc.page.width, 4)
         .fill(COLORS.primary);

      // Logo text
      doc.font("Helvetica-Bold")
         .fontSize(22)
         .fillColor(COLORS.primary)
         .text("CYBERSHIELD", 40, 15, { lineBreak: false });

      doc.font("Helvetica")
         .fontSize(10)
         .fillColor(COLORS.textSecondary)
         .text("APK Security Analysis Report", 40, 42);

      // Date top-right
      doc.font("Helvetica")
         .fontSize(8)
         .fillColor(COLORS.textSecondary)
         .text(formatDate(), doc.page.width - 200, 30, {
           width: 160,
           align: "right"
         });


      // ── Classification banner ────────────────────────────────────
      const classColor = getClassificationColor(data.classification);

      doc.rect(0, 70, doc.page.width, 50)
         .fill(classColor + "22");  // transparent tint

      doc.rect(0, 70, doc.page.width, 3)
         .fill(classColor);

      doc.font("Helvetica-Bold")
         .fontSize(16)
         .fillColor(classColor)
         .text(
           `⚠  CLASSIFICATION: ${data.classification}`,
           40, 83, {
             width: doc.page.width - 80,
             align: "center"
           }
         );


      // ── Risk score gauge ─────────────────────────────────────────
      doc.y = 135;
      drawScoreGauge(doc, data.finalRiskScore, data.classification);


      // ── App information ──────────────────────────────────────────
      doc.y += 10;
      drawSectionHeader(doc, "Application Information");
      doc.moveDown(0.3);

      drawKeyValue(doc, "App Name",        data.appName         || "Unknown");
      drawKeyValue(doc, "Package Name",    data.packageName     || "Unknown");
      drawKeyValue(doc, "File Name",       data.fileName        || "Unknown");
      drawKeyValue(doc, "File Size",       data.fileSizeFormatted || "Unknown");
      drawKeyValue(doc, "Version",         data.version         || "Unknown");
      drawKeyValue(doc, "Min SDK",         data.minSdk          || "Unknown");
      drawKeyValue(doc, "Target SDK",      data.targetSdk       || "Unknown");
      drawKeyValue(doc, "Scan Date",       formatDate());


      // ── Cryptographic hashes ─────────────────────────────────────
      doc.moveDown(0.5);
      drawSectionHeader(doc, "Cryptographic Hashes");
      doc.moveDown(0.3);

      drawKeyValue(doc, "MD5",    data.hashes?.md5    || "N/A");
      drawKeyValue(doc, "SHA1",   data.hashes?.sha1   || "N/A");
      drawKeyValue(doc, "SHA256", data.hashes?.sha256 || "N/A");


      // ── Risk score breakdown ─────────────────────────────────────
      doc.moveDown(0.5);
      drawSectionHeader(doc, "Risk Score Breakdown");
      doc.moveDown(0.5);

      drawScoreBar(doc, "Permission Risk",     data.scores?.permissionScore  || 0);
      drawScoreBar(doc, "Static Analysis",     data.scores?.staticScore      || 0);
      drawScoreBar(doc, "Malware Patterns",    data.scores?.malwareScore     || 0);
      drawScoreBar(doc, "Dynamic Behavior",    data.scores?.dynamicScore     || 0);
      drawScoreBar(doc, "URL Analysis",        data.scores?.urlScore         || 0);
      drawScoreBar(doc, "Threat Intelligence", data.scores?.threatScore      || 0);
      drawScoreBar(doc, "Secret Leaks",        data.scores?.secretScore      || 0);
      drawScoreBar(doc, "Certificate",         data.scores?.certScore        || 0);
      drawScoreBar(doc, "Fake App Detection",  data.scores?.fakeAppScore     || 0);


      // ════════════════════════════════════════════════════════════
      // PAGE 2 — PERMISSIONS & STATIC ANALYSIS
      // ════════════════════════════════════════════════════════════

      doc.addPage();
      drawPageBackground(doc);
      doc.y = 40;


      // ── Flagged permissions ──────────────────────────────────────
      drawSectionHeader(doc, `Flagged Permissions (${data.flaggedPermissions?.length || 0} found)`);
      doc.moveDown(0.3);

      if (data.flaggedPermissions?.length > 0) {

        data.flaggedPermissions.forEach(perm => {
          drawFindingItem(doc, {
            label:    typeof perm === "string" ? perm : perm.permission,
            severity: typeof perm === "object" ? perm.severity : "HIGH"
          });
        });

      } else {
        doc.font("Helvetica").fontSize(9)
           .fillColor(COLORS.safe)
           .text("  ✓ No dangerous permissions detected", 50, doc.y);
        doc.moveDown(0.5);
      }


      // ── Permission combinations ──────────────────────────────────
      if (data.comboFindings?.length > 0) {
        ensureSpace(doc, 60);
        doc.moveDown(0.3);
        drawSectionHeader(doc, `Dangerous Permission Combinations (${data.comboFindings.length} found)`);
        doc.moveDown(0.3);

        data.comboFindings.forEach(combo => {
          drawFindingItem(doc, {
            label:    combo.label,
            severity: combo.severity
          });
        });
      }


      // ── Static analysis ──────────────────────────────────────────
      ensureSpace(doc, 60);
      doc.moveDown(0.3);
      drawSectionHeader(doc, `Static Analysis — Suspicious APIs (${data.staticAnalysis?.detectedAPIs?.length || 0} found)`);
      doc.moveDown(0.3);

      if (data.staticAnalysis?.detectedAPIs?.length > 0) {

        data.staticAnalysis.detectedAPIs.forEach(api => {
          drawFindingItem(doc, {
            label:    `${api.api} — ${api.category}`,
            severity: api.severity
          });
        });

      } else {
        doc.font("Helvetica").fontSize(9)
           .fillColor(COLORS.safe)
           .text("  ✓ No suspicious APIs detected", 50, doc.y);
        doc.moveDown(0.5);
      }


      // ── String findings ──────────────────────────────────────────
      if (data.staticAnalysis?.stringFindings?.length > 0) {
        ensureSpace(doc, 60);
        doc.moveDown(0.3);
        drawSectionHeader(doc, "Static Analysis — Suspicious String Patterns");
        doc.moveDown(0.3);

        data.staticAnalysis.stringFindings.forEach(f => {
          drawFindingItem(doc, f);
        });
      }


      // ── Obfuscation ──────────────────────────────────────────────
      if (data.staticAnalysis?.obfuscationIndicators?.length > 0) {
        ensureSpace(doc, 60);
        doc.moveDown(0.3);
        drawSectionHeader(doc, "Obfuscation Indicators");
        doc.moveDown(0.3);

        data.staticAnalysis.obfuscationIndicators.forEach(o => {
          drawFindingItem(doc, { label: o, severity: "HIGH" });
        });
      }


      // ════════════════════════════════════════════════════════════
      // PAGE 3 — MALWARE & BEHAVIOR ANALYSIS
      // ════════════════════════════════════════════════════════════

      doc.addPage();
      drawPageBackground(doc);
      doc.y = 40;


      // ── Malware patterns ─────────────────────────────────────────
      drawSectionHeader(doc, `Malware Pattern Analysis — ${data.malwareAnalysis?.malwareVerdict || "NONE"}`);
      doc.moveDown(0.3);

      if (data.malwareAnalysis?.findings?.length > 0) {

        data.malwareAnalysis.findings.forEach(f => {
          drawFindingItem(doc, f);
        });

      } else {
        doc.font("Helvetica").fontSize(9)
           .fillColor(COLORS.safe)
           .text("  ✓ No malware patterns detected", 50, doc.y);
        doc.moveDown(0.5);
      }


      // ── ML Classification ────────────────────────────────────────
      ensureSpace(doc, 80);
      doc.moveDown(0.3);
      drawSectionHeader(doc, "Threat Classification");
      doc.moveDown(0.3);

      const ml = data.mlClassification;

      if (ml) {

        drawKeyValue(doc, "Primary Type",   ml.primaryLabel       || "Clean");
        drawKeyValue(doc, "Confidence",     ml.primaryConfidence  || "UNLIKELY");
        drawKeyValue(doc, "Score",          (ml.primaryScore || 0) + "/100");
        drawKeyValue(doc, "Multi-Threat",   ml.isMultiThreat ? "YES" : "NO");

        if (ml.detectedTypes?.length > 0) {
          doc.moveDown(0.3);
          doc.font("Helvetica-Bold")
             .fontSize(8)
             .fillColor(COLORS.textSecondary)
             .text("  Detected Threat Types:", 50, doc.y);
          doc.moveDown(0.2);

          ml.detectedTypes.forEach(t => {
            drawFindingItem(doc, {
              label:    `${t.label} — Score: ${t.score}/100 — ${t.confidence}`,
              severity: t.score >= 75 ? "CRITICAL" : t.score >= 50 ? "HIGH" : "MEDIUM"
            });
          });
        }

      }


      // ── Dynamic behavior ─────────────────────────────────────────
      ensureSpace(doc, 60);
      doc.moveDown(0.3);
      drawSectionHeader(doc, `Predicted Runtime Behaviors — ${data.dynamicAnalysis?.behaviorVerdict || "CLEAN"}`);
      doc.moveDown(0.3);

      if (data.dynamicAnalysis?.behaviors?.length > 0) {

        data.dynamicAnalysis.behaviors.forEach(b => {
          drawFindingItem(doc, {
            label:    `${b.label} — ${b.description}`,
            severity: b.severity
          });
        });

      } else {
        doc.font("Helvetica").fontSize(9)
           .fillColor(COLORS.safe)
           .text("  ✓ No suspicious runtime behaviors predicted", 50, doc.y);
        doc.moveDown(0.5);
      }

      if (data.dynamicAnalysis?.analysisNote) {
        doc.moveDown(0.2);
        doc.font("Helvetica-Oblique")
           .fontSize(7)
           .fillColor(COLORS.textMuted)
           .text("  Note: " + data.dynamicAnalysis.analysisNote, 50, doc.y, {
             width: doc.page.width - 100
           });
      }


      // ════════════════════════════════════════════════════════════
      // PAGE 4 — THREAT INTEL, URLS, SECRETS
      // ════════════════════════════════════════════════════════════

      doc.addPage();
      drawPageBackground(doc);
      doc.y = 40;


      // ── Threat intelligence ──────────────────────────────────────
      drawSectionHeader(doc, "Threat Intelligence");
      doc.moveDown(0.3);

      const ti = data.threatIntel;

      if (ti) {

        drawKeyValue(doc, "VirusTotal",
          ti.summary?.virusTotalStatus === "detected"
            ? `DETECTED — ${ti.summary.vtDetectionRate}`
            : ti.summary?.virusTotalStatus === "clean"
              ? "Clean — not in database"
              : "API unavailable"
        );

        drawKeyValue(doc, "MalwareBazaar",
          ti.summary?.malwareBazaarStatus === "detected"
            ? "DETECTED in MalwareBazaar"
            : ti.summary?.malwareBazaarStatus === "clean"
              ? "Clean — not in database"
              : "Unavailable"
        );

        drawKeyValue(doc, "Domain Matches",  String(ti.summary?.domainMatches  || 0));
        drawKeyValue(doc, "Package Match",   ti.summary?.packageMatch ? "YES — Known malware package" : "No");

        if (ti.summary?.vtPermalink) {
          doc.moveDown(0.2);
          doc.font("Helvetica")
             .fontSize(8)
             .fillColor(COLORS.info)
             .text("  VT Report: " + ti.summary.vtPermalink, 50, doc.y, {
               width: doc.page.width - 100
             });
        }

        doc.moveDown(0.3);

        if (ti.findings?.length > 0) {
          ti.findings.forEach(f => drawFindingItem(doc, f));
        } else {
          doc.font("Helvetica").fontSize(9)
             .fillColor(COLORS.safe)
             .text("  ✓ No threat intelligence matches", 50, doc.y);
          doc.moveDown(0.5);
        }

      }


      // ── Certificate analysis ─────────────────────────────────────
      ensureSpace(doc, 80);
      doc.moveDown(0.3);
      drawSectionHeader(doc, "Certificate Analysis");
      doc.moveDown(0.3);

      const cert = data.certificateAnalysis;

      if (cert) {

        drawKeyValue(doc, "Common Name",    cert.certDetails?.commonName    || "Unknown");
        drawKeyValue(doc, "Organization",   cert.certDetails?.organization  || "Unknown");
        drawKeyValue(doc, "Country",        cert.certDetails?.country       || "Unknown");
        drawKeyValue(doc, "V2 Signature",   cert.certDetails?.hasV2Signature ? "Present" : "Not found");
        drawKeyValue(doc, "Signing Type",   cert.certDetails?.signingBlockType || "Unknown");

        if (cert.certDetails?.validityYears) {
          drawKeyValue(doc, "Valid Period",
            `${cert.certDetails.validityYears.from} — ${cert.certDetails.validityYears.to}`
          );
        }

        doc.moveDown(0.3);

        if (cert.findings?.length > 0) {
          cert.findings.forEach(f => drawFindingItem(doc, f));
        } else {
          doc.font("Helvetica").fontSize(9)
             .fillColor(COLORS.safe)
             .text("  ✓ Certificate appears normal", 50, doc.y);
          doc.moveDown(0.5);
        }

      }


      // ── URL analysis ─────────────────────────────────────────────
      ensureSpace(doc, 60);
      doc.moveDown(0.3);
      drawSectionHeader(doc, `URL Analysis (${data.urlAnalysis?.totalSuspicious || 0} suspicious of ${data.urlAnalysis?.totalUrlsAnalyzed || 0} found)`);
      doc.moveDown(0.3);

      if (data.urlAnalysis?.suspiciousUrls?.length > 0) {

        data.urlAnalysis.suspiciousUrls.slice(0, 15).forEach(urlObj => {
          const url      = typeof urlObj === "string" ? urlObj : urlObj.url;
          const urlScore = typeof urlObj === "object" ? urlObj.riskScore : 0;

          drawFindingItem(doc, {
            label:    truncate(url, 80),
            severity: urlScore >= 25 ? "HIGH" : "MEDIUM"
          });
        });

      } else {
        doc.font("Helvetica").fontSize(9)
           .fillColor(COLORS.safe)
           .text("  ✓ No suspicious URLs detected", 50, doc.y);
        doc.moveDown(0.5);
      }


      // ── Secret scan ──────────────────────────────────────────────
      ensureSpace(doc, 60);
      doc.moveDown(0.3);
      drawSectionHeader(doc, `Secret & Credential Leak Scan (${data.secretScan?.totalSecrets || 0} found)`);
      doc.moveDown(0.3);

      if (data.secretScan?.findings?.length > 0) {

        data.secretScan.findings.forEach(f => {
          drawFindingItem(doc, {
            label:    `${f.label} — Sample: ${f.sample}`,
            severity: f.severity
          });
        });

      } else {
        doc.font("Helvetica").fontSize(9)
           .fillColor(COLORS.safe)
           .text("  ✓ No hardcoded secrets detected", 50, doc.y);
        doc.moveDown(0.5);
      }


      // ════════════════════════════════════════════════════════════
      // PAGE 5 — FAKE APP & RECOMMENDATIONS
      // ════════════════════════════════════════════════════════════

      doc.addPage();
      drawPageBackground(doc);
      doc.y = 40;


      // ── Fake app detection ───────────────────────────────────────
      drawSectionHeader(doc, "Fake App Detection");
      doc.moveDown(0.3);

      if (data.fakeAppAnalysis?.fakeAppFindings?.length > 0) {

        data.fakeAppAnalysis.fakeAppFindings.forEach(f => {
          drawFindingItem(doc, {
            label:    f.label || f,
            severity: f.severity || "HIGH"
          });
        });

      } else {
        doc.font("Helvetica").fontSize(9)
           .fillColor(COLORS.safe)
           .text("  ✓ No brand impersonation detected", 50, doc.y);
        doc.moveDown(0.5);
      }


      // ── Recommendations ──────────────────────────────────────────
      ensureSpace(doc, 100);
      doc.moveDown(0.3);
      drawSectionHeader(doc, "Security Recommendations");
      doc.moveDown(0.3);

      const recommendations = buildRecommendations(data);

      recommendations.forEach((rec, i) => {
        ensureSpace(doc, 30);

        doc.font("Helvetica-Bold")
           .fontSize(9)
           .fillColor(COLORS.primary)
           .text(`${i + 1}. `, 50, doc.y, { continued: true, width: 20 });

        doc.font("Helvetica")
           .fontSize(9)
           .fillColor(COLORS.textPrimary)
           .text(rec, { width: doc.page.width - 100 });

        doc.moveDown(0.3);
      });


      // ── Footer ───────────────────────────────────────────────────
      ensureSpace(doc, 80);
      doc.moveDown(1);
      drawDivider(doc);

      doc.font("Helvetica")
         .fontSize(8)
         .fillColor(COLORS.textMuted)
         .text(
           "This report was generated by CyberShield APK Security Scanner. " +
           "Results are based on static analysis and heuristic detection. " +
           "For definitive malware analysis, consult a professional cybersecurity expert.",
           40, doc.y, {
             width: doc.page.width - 80,
             align: "center"
           }
         );

      doc.moveDown(0.5);

      doc.font("Helvetica-Bold")
         .fontSize(8)
         .fillColor(COLORS.primary)
         .text("CyberShield | LNCT University, Bhopal", 40, doc.y, {
           width: doc.page.width - 80,
           align: "center"
         });


      doc.end();

    } catch (err) {
      reject(err);
    }

  });

}


// ─── RECOMMENDATION BUILDER ───────────────────────────────────────────────────

function buildRecommendations(data) {

  const recs = [];

  if (data.classification === "DANGEROUS") {
    recs.push("Do NOT install this application. Immediately delete the APK file.");
    recs.push("If already installed, uninstall immediately and run a full device scan.");
    recs.push("Change all passwords and banking credentials if app was previously installed.");
  }

  if (data.classification === "SUSPICIOUS") {
    recs.push("Exercise extreme caution before installing this application.");
    recs.push("Only install apps from official sources like Google Play Store.");
  }

  if (data.malwareAnalysis?.findings?.length > 0) {
    recs.push("Malware patterns detected — report this APK to your cybersecurity team.");
  }

  if (data.threatIntel?.summary?.hasRealDetection) {
    recs.push("This file has been flagged by antivirus engines. Do not install.");
  }

  if (data.secretScan?.hasCredentialLeak) {
    recs.push("Hardcoded credentials found — these keys may already be compromised.");
  }

  if (data.fakeAppAnalysis?.brandMatches?.length > 0) {
    recs.push(
      `This app impersonates: ${data.fakeAppAnalysis.brandMatches.join(", ")}. ` +
      "Download only from official app stores."
    );
  }

  if (data.certificateAnalysis?.findings?.length > 0) {
    recs.push("Certificate anomalies detected — verify app authenticity before installing.");
  }

  if (data.urlAnalysis?.highRiskUrls?.length > 0) {
    recs.push("High-risk URLs detected — app may communicate with malicious servers.");
  }

  if (recs.length === 0) {
    recs.push("No critical issues found. Always download apps from trusted sources.");
    recs.push("Keep your Android device and security software updated.");
    recs.push("Review app permissions before granting access.");
  }

  return recs;

}


module.exports = { generateReport };