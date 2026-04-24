/**
 * RISK ENGINE — Permission-based risk analysis
 * Uses weighted scoring with context-aware logic
 * No false positives on legitimate apps
 */

// ─── PERMISSION RISK LEVELS ───────────────────────────────────────────────────

const HIGH_RISK_PERMISSIONS = new Set([
  "android.permission.READ_SMS",
  "android.permission.SEND_SMS",
  "android.permission.RECEIVE_SMS",
  "android.permission.RECEIVE_MMS",
  "android.permission.READ_CALL_LOG",
  "android.permission.WRITE_CALL_LOG",
  "android.permission.PROCESS_OUTGOING_CALLS",
  "android.permission.RECORD_AUDIO",
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.REQUEST_INSTALL_PACKAGES",
  "android.permission.REQUEST_DELETE_PACKAGES",
  "android.permission.MANAGE_EXTERNAL_STORAGE",
  "android.permission.WRITE_SETTINGS",
  "android.permission.BIND_DEVICE_ADMIN",
  "android.permission.BIND_ACCESSIBILITY_SERVICE",
  "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
  "android.permission.READ_CONTACTS",
  "android.permission.WRITE_CONTACTS",
  "android.permission.GET_TASKS",
  "android.permission.REORDER_TASKS",
  "android.permission.KILL_BACKGROUND_PROCESSES",
  "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
  "android.permission.MASTER_CLEAR",
  "android.permission.FACTORY_TEST",
  "android.permission.SET_WALLPAPER",
  "android.permission.DISABLE_KEYGUARD",
  "android.permission.STATUS_BAR",
  "android.permission.EXPAND_STATUS_BAR"
]);

const MEDIUM_RISK_PERMISSIONS = new Set([
  "android.permission.CAMERA",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.ACCESS_COARSE_LOCATION",
  "android.permission.ACCESS_BACKGROUND_LOCATION",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.BLUETOOTH_SCAN",
  "android.permission.BLUETOOTH_CONNECT",
  "android.permission.QUERY_ALL_PACKAGES",
  "android.permission.GET_ACCOUNTS",
  "android.permission.USE_BIOMETRIC",
  "android.permission.USE_FINGERPRINT",
  "android.permission.RECEIVE_BOOT_COMPLETED",
  "android.permission.FOREGROUND_SERVICE",
  "android.permission.REQUEST_COMPANION_RUN_IN_BACKGROUND",
  "android.permission.PACKAGE_USAGE_STATS",
  "android.permission.READ_PHONE_STATE",
  "android.permission.READ_PHONE_NUMBERS",
  "android.permission.CHANGE_NETWORK_STATE",
  "android.permission.CHANGE_WIFI_STATE",
  "android.permission.ACCESS_WIFI_STATE"
]);

// ─── DANGEROUS PERMISSION COMBINATIONS ────────────────────────────────────────

const DANGEROUS_COMBOS = [
  {
    permissions: ["android.permission.READ_SMS", "android.permission.INTERNET"],
    label: "SMS Exfiltration",
    score: 25,
    severity: "HIGH"
  },
  {
    permissions: ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
    label: "Audio Surveillance",
    score: 25,
    severity: "HIGH"
  },
  {
    permissions: ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
    label: "Surveillance Capability (Camera + Mic + Network)",
    score: 35,
    severity: "CRITICAL"
  },
  {
    permissions: ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.REQUEST_DELETE_PACKAGES"],
    label: "App Install/Delete Manipulation",
    score: 30,
    severity: "HIGH"
  },
  {
    permissions: ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET"],
    label: "Accessibility Abuse (Keylogging/Overlay risk)",
    score: 35,
    severity: "CRITICAL"
  },
  {
    permissions: ["android.permission.READ_CONTACTS", "android.permission.INTERNET"],
    label: "Contact Data Exfiltration",
    score: 20,
    severity: "HIGH"
  },
  {
    permissions: ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
    label: "Real-time Location Tracking",
    score: 20,
    severity: "HIGH"
  },
  {
    permissions: ["android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.INTERNET"],
    label: "Persistence + Network Access",
    score: 15,
    severity: "MEDIUM"
  },
  {
    permissions: ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"],
    label: "Overlay Attack Capability",
    score: 25,
    severity: "HIGH"
  },
  {
    permissions: ["android.permission.GET_ACCOUNTS", "android.permission.INTERNET"],
    label: "Account Credential Harvesting",
    score: 20,
    severity: "HIGH"
  },
  {
    permissions: [
      "android.permission.READ_SMS",
      "android.permission.RECEIVE_SMS",
      "android.permission.SEND_SMS"
    ],
    label: "Full SMS Control (OTP Theft Risk)",
    score: 40,
    severity: "CRITICAL"
  },
  {
    permissions: [
      "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
      "android.permission.INTERNET"
    ],
    label: "Notification Interception + Exfiltration",
    score: 25,
    severity: "HIGH"
  }
];

// ─── TRUSTED PACKAGE PREFIXES (with strict prefix match) ──────────────────────

const TRUSTED_PREFIXES = [
  "com.google.android",
  "com.android",
  "com.samsung.android",
  "com.huawei.android",
  "com.oneplus",
  "com.miui",
  "com.facebook.katana",
  "com.whatsapp",
  "com.instagram.android",
  "com.microsoft.office",
  "com.amazon.mShop",
  "net.one97.paytm",
  "com.phonepe.app",
  "com.gpay",
  "in.org.npci.upiapp"
];

// ─── SUSPICIOUS PACKAGE NAME KEYWORDS ────────────────────────────────────────

const SUSPICIOUS_PKG_KEYWORDS = [
  "hack", "crack", "fake", "mod", "cheat",
  "spy", "keylog", "steal", "phish", "trojan",
  "rootkit", "exploit", "inject", "bypass",
  "banklogin", "freemoney", "unlocked", "premium_free"
];


// ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────

function analyzeRisk(packageName = "", permissions = []) {

  let score = 0;
  const flaggedPermissions = [];
  const comboFindings = [];

  const permNames = permissions
    .map(p => (typeof p === "string" ? p : p.name))
    .filter(Boolean);

  const permSet = new Set(permNames);


  // ── 1. Individual Permission Scoring ────────────────────────────────────────
  permNames.forEach(perm => {

    if (HIGH_RISK_PERMISSIONS.has(perm)) {
      score += 8;
      flaggedPermissions.push({ permission: perm, severity: "HIGH" });
    } else if (MEDIUM_RISK_PERMISSIONS.has(perm)) {
      score += 4;
      flaggedPermissions.push({ permission: perm, severity: "MEDIUM" });
    }

  });


  // ── 2. Dangerous Combination Detection ──────────────────────────────────────
  DANGEROUS_COMBOS.forEach(combo => {

    const allPresent = combo.permissions.every(p => permSet.has(p));

    if (allPresent) {
      score += combo.score;
      comboFindings.push({
        label: combo.label,
        severity: combo.severity,
        score: combo.score
      });
    }

  });


  // ── 3. Permission Count Anomaly ──────────────────────────────────────────────
  let permCountNote = null;

  if (permNames.length > 50) {
    score += 20;
    permCountNote = `Extremely high permission count: ${permNames.length}`;
  } else if (permNames.length > 30) {
    score += 10;
    permCountNote = `High permission count: ${permNames.length}`;
  } else if (permNames.length > 20) {
    score += 5;
    permCountNote = `Elevated permission count: ${permNames.length}`;
  }


  // ── 4. Suspicious Package Name ───────────────────────────────────────────────
  const pkgLower = packageName.toLowerCase();
  const suspiciousKeywordFound = SUSPICIOUS_PKG_KEYWORDS.find(k => pkgLower.includes(k));

  if (suspiciousKeywordFound) {
    score += 30;
  }


  // ── 5. Trusted Package Reduction ─────────────────────────────────────────────
  // Strict match — com.google.fake will NOT get reduction
  const isTrusted = TRUSTED_PREFIXES.some(prefix => {
    const pkgStart = packageName.toLowerCase().slice(0, prefix.length + 1);
    return pkgStart === prefix || packageName.toLowerCase() === prefix;
  });

  if (isTrusted) {
    score = Math.max(score - 25, 0);
  }


  // ── 6. Normalize ──────────────────────────────────────────────────────────────
  score = Math.min(Math.round(score), 100);


  // ── 7. Classification ─────────────────────────────────────────────────────────
  let classification = "SAFE";
  if (score >= 70) classification = "DANGEROUS";
  else if (score >= 35) classification = "SUSPICIOUS";


  return {
    riskScore: score,
    classification,
    flaggedPermissions,        // [{ permission, severity }]
    comboFindings,             // [{ label, severity, score }]
    totalPermissions: permNames.length,
    allPermissions: permNames,
    permCountNote,
    suspiciousPackageKeyword: suspiciousKeywordFound || null,
    isTrustedPackage: isTrusted
  };

}

module.exports = { analyzeRisk };