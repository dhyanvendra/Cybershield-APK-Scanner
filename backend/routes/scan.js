/**
 * SCAN ROUTE
 * Complete async pipeline — file read ONCE, buffer passed to all services
 * Proper weighted scoring — no double counting
 * Full error handling with meaningful messages
 */

const express  = require("express");
const multer   = require("multer");
const ApkReader = require("adbkit-apkreader");
const path     = require("path");
const fs       = require("fs");
const crypto   = require("crypto");

const { generateApkHash }       = require("../services/hashAnalyzer");
const { analyzeRisk }           = require("../services/riskEngine");
const { analyzeStaticCode }     = require("../services/staticAnalyzer");
const { analyzeMalwarePatterns } = require("../services/malwareAnalyzer");
const { analyzeUrls }           = require("../services/urlAnalyzer");
const { scanSecrets }           = require("../services/secretScanner");
const { analyzeCertificate }    = require("../services/certificateAnalyzer");
const { classifyMalware }       = require("../services/mlClassifier");
const { analyzeDynamicBehavior } = require("../services/dynamicAnalyzer");
const { analyzeThreatIntel }    = require("../services/threatIntel");
const { detectFakeApps }        = require("../services/fakeAppDetector");
const { generateReport }        = require("../services/reportGenerator");

const router = express.Router();


// ─── ENSURE DIRECTORIES EXIST ────────────────────────────────────────────────

const UPLOAD_DIR  = path.join(__dirname, "../uploads");
const REPORTS_DIR = path.join(__dirname, "../reports");

[UPLOAD_DIR, REPORTS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});


// ─── MULTER CONFIG ────────────────────────────────────────────────────────────

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename:    (req, file, cb) => {
    const unique = Date.now() + "-" + crypto.randomBytes(6).toString("hex");
    cb(null, unique + ".apk");
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB
  fileFilter: (req, file, cb) => {

    // Validate file extension
    if (!file.originalname.toLowerCase().endsWith(".apk")) {
      return cb(new Error("Only APK files are allowed"), false);
    }

    cb(null, true);
  }
});


// ─── APK MAGIC BYTES VALIDATOR ────────────────────────────────────────────────
// APK files are ZIP files — magic bytes are PK\x03\x04

function isValidApk(buffer) {
  if (buffer.length < 4) return false;
  return (
    buffer[0] === 0x50 &&  // P
    buffer[1] === 0x4B &&  // K
    buffer[2] === 0x03 &&
    buffer[3] === 0x04
  );
}


// ─── WEIGHTED FINAL SCORE CALCULATOR ─────────────────────────────────────────

function calculateFinalScore(scores) {

  // Weights must add up to 100
  const weights = {
    permissionScore:  20,   // Most reliable signal
    staticScore:      15,   // Code-level evidence
    malwareScore:     20,   // Pattern-based detection
    dynamicScore:     10,   // Behavior prediction
    urlScore:         8,    // Network indicators
    threatScore:      12,   // External intelligence
    secretScore:      8,    // Credential leaks
    certScore:        4,    // Certificate issues
    fakeAppScore:     3     // Brand impersonation
  };

  let weightedSum = 0;

  Object.entries(weights).forEach(([key, weight]) => {
    const score = Math.min(scores[key] || 0, 100);
    weightedSum += (score * weight) / 100;
  });

  return Math.min(Math.round(weightedSum), 100);

}


// ─── MANIFEST METADATA EXTRACTOR ─────────────────────────────────────────────

function extractMetadata(manifest) {
  return {
    appName:     manifest.application?.label     || "Unknown",
    packageName: manifest.package                || "Unknown",
    version:     manifest.versionName            || manifest.versionCode?.toString() || "Unknown",
    minSdk:      manifest.usesSdk?.minSdkVersion?.toString() || "Unknown",
    targetSdk:   manifest.usesSdk?.targetSdkVersion?.toString() || "Unknown",
    permissions: manifest.usesPermissions        || []
  };
}


// ─── CLEANUP HELPER ──────────────────────────────────────────────────────────

async function cleanupFile(filePath) {
  try {
    if (filePath && fs.existsSync(filePath)) {
      await fs.promises.unlink(filePath);
    }
  } catch {
    // Silent cleanup failure — non-critical
  }
}


// ─── SCAN ROUTE ───────────────────────────────────────────────────────────────

router.post("/", upload.single("apk"), async (req, res) => {

  let filePath = null;

  try {

    // ── 1. File validation ───────────────────────────────────────────────────
    if (!req.file) {
      return res.status(400).json({
        error:   "No file uploaded",
        message: "Please upload an APK file"
      });
    }

    filePath = req.file.path;


    // ── 2. Hash + single file read ────────────────────────────────────────────
    const hashResult = await generateApkHash(filePath);
    const { buffer } = hashResult;


    // ── 3. Magic bytes validation ─────────────────────────────────────────────
    if (!isValidApk(buffer)) {
      await cleanupFile(filePath);
      return res.status(400).json({
        error:   "Invalid file format",
        message: "File does not appear to be a valid APK (ZIP) file"
      });
    }


    // ── 4. APK Manifest parsing ───────────────────────────────────────────────
    let metadata;

    try {
      const reader   = await ApkReader.open(filePath);
      const manifest = await reader.readManifest();
      metadata       = extractMetadata(manifest);
    } catch (manifestErr) {
      // Manifest parse failure — still run all other analysis
      console.warn("Manifest parse warning:", manifestErr.message);
      metadata = {
        appName:     req.file.originalname.replace(".apk", "") || "Unknown",
        packageName: "Unknown",
        version:     "Unknown",
        minSdk:      "Unknown",
        targetSdk:   "Unknown",
        permissions: []
      };
    }


    // ── 5. Run all analysis modules in parallel where possible ────────────────

    // Static analysis first — provides APIs + URLs for other modules
    const staticResult = analyzeStaticCode(buffer);

    // Run independent modules in parallel
    const [
      riskResult,
      secretResult,
      certResult,
      fakeAppResult
    ] = await Promise.all([
      Promise.resolve(analyzeRisk(metadata.packageName, metadata.permissions)),
      Promise.resolve(scanSecrets(buffer)),
      analyzeCertificate(buffer),
      Promise.resolve(detectFakeApps(
        metadata.packageName,
        metadata.appName
      ))
    ]);


    // Modules that depend on static results
    const malwareResult  = analyzeMalwarePatterns(
      metadata.permissions,
      staticResult.detectedAPIs
    );

    const urlResult = analyzeUrls(staticResult.extractedUrls);

    const mlResult = classifyMalware(
      metadata.permissions,
      staticResult.detectedAPIs,
      malwareResult.findings
    );

    const dynamicResult = analyzeDynamicBehavior(
      metadata.permissions,
      staticResult.detectedAPIs,
      staticResult.stringFindings,
      secretResult.hasCredentialLeak
    );

    // Threat intel — async (external API calls)
    const threatResult = await analyzeThreatIntel(
      hashResult.sha256,
      staticResult.extractedUrls,
      metadata.packageName
    );


    // ── 6. Weighted final score ───────────────────────────────────────────────

    const scores = {
      permissionScore: riskResult.riskScore,
      staticScore:     staticResult.staticScore,
      malwareScore:    malwareResult.malwareScore,
      dynamicScore:    dynamicResult.dynamicScore,
      urlScore:        urlResult.urlScore,
      threatScore:     threatResult.threatScore,
      secretScore:     secretResult.secretScore,
      certScore:       certResult.certScore,
      fakeAppScore:    fakeAppResult.fakeAppScore
    };

    const finalRiskScore = calculateFinalScore(scores);


    // ── 7. Boost score for critical findings ──────────────────────────────────

    let boostedScore = finalRiskScore;

    // Real AV detection — serious signal
    if (threatResult.hasRealDetection) {
      boostedScore = Math.min(boostedScore + 20, 100);
    }

    // Critical malware verdict
    if (malwareResult.malwareVerdict === "HIGHLY_LIKELY") {
      boostedScore = Math.min(boostedScore + 15, 100);
    }

    // Credential leak
    if (secretResult.hasCredentialLeak) {
      boostedScore = Math.min(boostedScore + 10, 100);
    }

    // Device admin abuse
    if (dynamicResult.behaviors.some(b => b.id === "PERSIST_ADMIN")) {
      boostedScore = Math.min(boostedScore + 15, 100);
    }

    const normalizedScore = Math.min(Math.round(boostedScore), 100);


    // ── 8. Classification ─────────────────────────────────────────────────────

    let classification = "SAFE";
    if      (normalizedScore >= 65) classification = "DANGEROUS";
    else if (normalizedScore >= 30) classification = "SUSPICIOUS";


    // ── 9. Generate PDF report ────────────────────────────────────────────────

    const reportFileName = `report-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.pdf`;
    const reportPath     = path.join(REPORTS_DIR, reportFileName);
    const reportUrl      = `/reports/${reportFileName}`;

    try {
      await generateReport({

        // App info
        appName:          metadata.appName,
        packageName:      metadata.packageName,
        fileName:         hashResult.fileName,
        fileSizeFormatted: hashResult.fileSizeFormatted,
        version:          metadata.version,
        minSdk:           metadata.minSdk,
        targetSdk:        metadata.targetSdk,

        // Classification
        finalRiskScore:   normalizedScore,
        classification,

        // Hashes
        hashes: {
          md5:    hashResult.md5,
          sha1:   hashResult.sha1,
          sha256: hashResult.sha256
        },

        // Module scores for breakdown chart
        scores,

        // Analysis results
        flaggedPermissions:  riskResult.flaggedPermissions,
        comboFindings:       riskResult.comboFindings,
        staticAnalysis:      staticResult,
        malwareAnalysis:     malwareResult,
        mlClassification:    mlResult,
        dynamicAnalysis:     dynamicResult,
        urlAnalysis:         urlResult,
        threatIntel:         threatResult,
        secretScan:          secretResult,
        certificateAnalysis: certResult,
        fakeAppAnalysis:     fakeAppResult

      }, reportPath);

    } catch (reportErr) {
      // Report generation failure — non-fatal, continue with response
      console.error("Report generation error:", reportErr.message);
    }


    // ── 10. Send response ─────────────────────────────────────────────────────

    res.json({

      // ── Core result ──────────────────────────────────────────────
      finalRiskScore:  normalizedScore,
      classification,
      scanId:          crypto.randomBytes(8).toString("hex"),

      // ── App metadata ─────────────────────────────────────────────
      appName:         metadata.appName,
      packageName:     metadata.packageName,
      fileName:        hashResult.fileName,
      fileSize:        hashResult.fileSize,
      fileSizeFormatted: hashResult.fileSizeFormatted,
      version:         metadata.version,
      minSdk:          metadata.minSdk,
      targetSdk:       metadata.targetSdk,

      // ── Hashes ───────────────────────────────────────────────────
      hashes: {
        md5:    hashResult.md5,
        sha1:   hashResult.sha1,
        sha256: hashResult.sha256
      },

      // ── Score breakdown ───────────────────────────────────────────
      scores,

      // ── Permissions ───────────────────────────────────────────────
      permissions:        metadata.permissions,
      flaggedPermissions: riskResult.flaggedPermissions,
      comboFindings:      riskResult.comboFindings,
      totalPermissions:   riskResult.totalPermissions,
      allPermissions:     riskResult.allPermissions,
      isTrustedPackage:   riskResult.isTrustedPackage,

      // ── Static analysis ───────────────────────────────────────────
      staticAnalysis: {
        detectedAPIs:           staticResult.detectedAPIs,
        apisByCategory:         staticResult.apisByCategory,
        suspiciousDomains:      staticResult.suspiciousDomains,
        urlShorteners:          staticResult.urlShorteners,
        stringFindings:         staticResult.stringFindings,
        obfuscationIndicators:  staticResult.obfuscationIndicators,
        staticScore:            staticResult.staticScore,
        totalUrlsFound:         staticResult.totalUrlsFound
      },

      // ── Malware analysis ──────────────────────────────────────────
      malwareAnalysis: {
        malwareScore:    malwareResult.malwareScore,
        malwareVerdict:  malwareResult.malwareVerdict,
        findings:        malwareResult.findings,
        detectedTypes:   malwareResult.detectedTypes,
        totalPatterns:   malwareResult.totalPatterns
      },

      // ── ML Classification ─────────────────────────────────────────
      mlClassification: {
        primaryType:          mlResult.primaryType,
        primaryLabel:         mlResult.primaryLabel,
        primaryDescription:   mlResult.primaryDescription,
        primaryScore:         mlResult.primaryScore,
        primaryConfidence:    mlResult.primaryConfidence,
        detectedTypes:        mlResult.detectedTypes,
        allScores:            mlResult.allScores,
        isMultiThreat:        mlResult.isMultiThreat,
        totalThreatsDetected: mlResult.totalThreatsDetected
      },

      // ── Dynamic analysis ──────────────────────────────────────────
      dynamicAnalysis: {
        dynamicScore:    dynamicResult.dynamicScore,
        behaviorVerdict: dynamicResult.behaviorVerdict,
        behaviors:       dynamicResult.behaviors,
        byCategory:      dynamicResult.byCategory,
        criticalCount:   dynamicResult.criticalCount,
        highCount:       dynamicResult.highCount,
        mediumCount:     dynamicResult.mediumCount,
        totalBehaviors:  dynamicResult.totalBehaviors,
        analysisNote:    dynamicResult.analysisNote
      },

      // ── URL analysis ──────────────────────────────────────────────
      urlAnalysis: {
        urlScore:          urlResult.urlScore,
        suspiciousUrls:    urlResult.suspiciousUrls,
        highRiskUrls:      urlResult.highRiskUrls,
        mediumRiskUrls:    urlResult.mediumRiskUrls,
        totalUrlsAnalyzed: urlResult.totalUrlsAnalyzed,
        totalSuspicious:   urlResult.totalSuspicious
      },

      // ── Threat intelligence ───────────────────────────────────────
      threatIntel: {
        threatScore:      threatResult.threatScore,
        findings:         threatResult.findings,
        summary:          threatResult.summary,
        hasRealDetection: threatResult.hasRealDetection,
        totalFindings:    threatResult.totalFindings
      },

      // ── Secret scan ───────────────────────────────────────────────
      secretScan: {
        secretScore:        secretResult.secretScore,
        findings:           secretResult.findings,
        byCategory:         secretResult.byCategory,
        criticalCount:      secretResult.criticalCount,
        highCount:          secretResult.highCount,
        totalSecrets:       secretResult.totalSecrets,
        hasCredentialLeak:  secretResult.hasCredentialLeak
      },

      // ── Certificate ───────────────────────────────────────────────
      certificateAnalysis: {
        certScore:     certResult.certScore,
        findings:      certResult.findings,
        certDetails:   certResult.certDetails,
        isSuspicious:  certResult.isSuspicious,
        totalFindings: certResult.totalFindings
      },

      // ── Fake app detection ────────────────────────────────────────
      fakeAppAnalysis: {
        fakeAppScore:    fakeAppResult.fakeAppScore,
        fakeAppFindings: fakeAppResult.fakeAppFindings,
        isTrustedApp:    fakeAppResult.isTrustedApp,
        brandMatches:    fakeAppResult.brandMatches,
        totalFindings:   fakeAppResult.totalFindings
      },

      // ── Report ────────────────────────────────────────────────────
      report: reportUrl

    });


  } catch (error) {

    console.error("SCAN ERROR:", error);

    // Meaningful error messages
    if (error.message?.includes("multer")) {
      return res.status(400).json({
        error:   "File upload failed",
        message: error.message
      });
    }

    if (error.message?.includes("APK")) {
      return res.status(400).json({
        error:   "APK parsing failed",
        message: "Could not parse APK file — file may be corrupted"
      });
    }

    res.status(500).json({
      error:   "Scan failed",
      message: "An error occurred during analysis. Please try again."
    });

  } finally {
    // Always cleanup uploaded file
    await cleanupFile(filePath);
  }

});


// ─── MULTER ERROR HANDLER ────────────────────────────────────────────────────

router.use((err, req, res, next) => {

  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({
      error:   "File too large",
      message: "APK file must be under 100MB"
    });
  }

  if (err.message === "Only APK files are allowed") {
    return res.status(400).json({
      error:   "Invalid file type",
      message: "Only APK files are accepted"
    });
  }

  next(err);

});


module.exports = router;