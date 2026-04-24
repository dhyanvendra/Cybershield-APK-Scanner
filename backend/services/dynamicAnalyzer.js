/**
 * DYNAMIC BEHAVIOR ANALYZER
 * Predicts runtime behaviors based on permission + API + static evidence
 * Clearly labeled as STATIC-BASED BEHAVIOR PREDICTION (not actual dynamic analysis)
 * No overlap with malwareAnalyzer — focuses on WHAT the app will DO at runtime
 * Each behavior has severity, category and evidence trail
 */

// ─── BEHAVIOR DEFINITIONS ─────────────────────────────────────────────────────

const BEHAVIOR_DEFINITIONS = [

  // ── Network & Data Exfiltration ──────────────────────────────────────────────
  {
    id: "NET_DATA_EXFIL",
    label: "Network Data Exfiltration",
    description: "App likely transmits collected sensitive data to remote server",
    category: "Network",
    severity: "CRITICAL",
    score: 30,
    requires: {
      anyPermission: ["android.permission.INTERNET"],
      anyAPI: [
        "getDeviceId", "getSubscriberId",
        "getAccounts(", "AccountManager",
        "getLastKnownLocation"
      ]
    }
  },
  {
    id: "NET_UNENCRYPTED",
    label: "Unencrypted Network Communication",
    description: "App communicates over HTTP — data transmitted in plaintext",
    category: "Network",
    severity: "HIGH",
    score: 15,
    requires: {
      anyStringFinding: ["Unencrypted HTTP connection"]
    }
  },
  {
    id: "NET_C2_COMM",
    label: "Command & Control Communication",
    description: "App shows indicators of C2 server communication",
    category: "Network",
    severity: "CRITICAL",
    score: 35,
    requires: {
      anyPermission: ["android.permission.INTERNET"],
      anyAPI: ["Runtime.exec", "ProcessBuilder", "DexClassLoader"]
    }
  },

  // ── Persistence ──────────────────────────────────────────────────────────────
  {
    id: "PERSIST_BOOT",
    label: "Boot Persistence",
    description: "App auto-starts on device boot — maintains persistent presence",
    category: "Persistence",
    severity: "HIGH",
    score: 20,
    requires: {
      allPermissions: ["android.permission.RECEIVE_BOOT_COMPLETED"]
    }
  },
  {
    id: "PERSIST_ADMIN",
    label: "Device Administrator Persistence",
    description: "App requests device admin rights — extremely difficult to uninstall",
    category: "Persistence",
    severity: "CRITICAL",
    score: 40,
    requires: {
      anyPermission: ["android.permission.BIND_DEVICE_ADMIN"],
      anyAPI: ["DevicePolicyManager"]
    }
  },
  {
    id: "PERSIST_FOREGROUND",
    label: "Foreground Service Persistence",
    description: "App runs as foreground service — stays active in background",
    category: "Persistence",
    severity: "MEDIUM",
    score: 10,
    requires: {
      allPermissions: [
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.RECEIVE_BOOT_COMPLETED"
      ]
    }
  },

  // ── Overlay & UI Attacks ─────────────────────────────────────────────────────
  {
    id: "UI_OVERLAY",
    label: "Screen Overlay Attack",
    description: "App can draw over other apps — used for phishing and credential theft",
    category: "UI Attack",
    severity: "CRITICAL",
    score: 35,
    requires: {
      allPermissions: ["android.permission.SYSTEM_ALERT_WINDOW"],
      anyPermission: ["android.permission.INTERNET"]
    }
  },
  {
    id: "UI_ACCESSIBILITY_ABUSE",
    label: "Accessibility Service Abuse",
    description: "App uses accessibility API to read screen content and simulate user input",
    category: "UI Attack",
    severity: "CRITICAL",
    score: 40,
    requires: {
      anyPermission: ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
      anyAPI: [
        "findAccessibilityNodeInfosByText",
        "performGlobalAction",
        "AccessibilityService"
      ]
    }
  },
  {
    id: "UI_NOTIFICATION_INTERCEPT",
    label: "Notification Interception",
    description: "App intercepts all device notifications including OTPs and messages",
    category: "UI Attack",
    severity: "CRITICAL",
    score: 35,
    requires: {
      anyPermission: [
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
      ]
    }
  },

  // ── Surveillance ─────────────────────────────────────────────────────────────
  {
    id: "SURV_AUDIO",
    label: "Covert Audio Recording",
    description: "App can record audio without visible user interaction",
    category: "Surveillance",
    severity: "CRITICAL",
    score: 35,
    requires: {
      anyPermission: ["android.permission.RECORD_AUDIO"],
      anyAPI: ["AudioRecord", "MediaRecorder"],
      anyPermissionAlso: ["android.permission.INTERNET"]
    }
  },
  {
    id: "SURV_SCREEN",
    label: "Screen Capture / Recording",
    description: "App can capture device screen content in real time",
    category: "Surveillance",
    severity: "CRITICAL",
    score: 40,
    requires: {
      anyAPI: ["MediaProjection", "createVirtualDisplay"]
    }
  },
  {
    id: "SURV_LOCATION",
    label: "Continuous Background Location Tracking",
    description: "App tracks precise device location even when not in use",
    category: "Surveillance",
    severity: "HIGH",
    score: 25,
    requires: {
      allPermissions: [
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION"
      ]
    }
  },
  {
    id: "SURV_CAMERA",
    label: "Covert Camera Access",
    description: "App can access camera silently in background",
    category: "Surveillance",
    severity: "CRITICAL",
    score: 35,
    requires: {
      allPermissions: [
        "android.permission.CAMERA",
        "android.permission.INTERNET"
      ],
      anyAPI: ["MediaRecorder"]
    }
  },
  {
    id: "SURV_CLIPBOARD",
    label: "Clipboard Monitoring",
    description: "App monitors clipboard — can steal passwords and crypto wallet addresses",
    category: "Surveillance",
    severity: "HIGH",
    score: 25,
    requires: {
      anyAPI: ["ClipboardManager", "getPrimaryClip"],
      anyPermission: ["android.permission.INTERNET"]
    }
  },
  {
    id: "SURV_KEYLOG",
    label: "Keystroke Capture",
    description: "App captures keystrokes via accessibility or input monitoring",
    category: "Surveillance",
    severity: "CRITICAL",
    score: 40,
    requires: {
      anyAPI: ["onKeyEvent", "KeyEvent"],
      anyPermission: ["android.permission.BIND_ACCESSIBILITY_SERVICE"]
    }
  },

  // ── SMS & Call Abuse ─────────────────────────────────────────────────────────
  {
    id: "SMS_INTERCEPT",
    label: "SMS Interception",
    description: "App intercepts incoming SMS messages including OTPs",
    category: "SMS/Call Abuse",
    severity: "CRITICAL",
    score: 35,
    requires: {
      anyPermission: [
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS"
      ]
    }
  },
  {
    id: "SMS_SEND_SILENT",
    label: "Silent SMS Sending",
    description: "App sends SMS messages without user knowledge",
    category: "SMS/Call Abuse",
    severity: "CRITICAL",
    score: 35,
    requires: {
      anyPermission: ["android.permission.SEND_SMS"],
      anyAPI: ["sendTextMessage", "SmsManager"]
    }
  },
  {
    id: "CALL_MONITOR",
    label: "Call Monitoring",
    description: "App monitors and logs incoming and outgoing phone calls",
    category: "SMS/Call Abuse",
    severity: "HIGH",
    score: 25,
    requires: {
      anyPermission: [
        "android.permission.READ_CALL_LOG",
        "android.permission.PROCESS_OUTGOING_CALLS"
      ]
    }
  },

  // ── Code Execution ───────────────────────────────────────────────────────────
  {
    id: "CODE_DYNAMIC_LOAD",
    label: "Dynamic Code Loading",
    description: "App loads additional code at runtime — can download malicious payloads",
    category: "Code Execution",
    severity: "CRITICAL",
    score: 35,
    requires: {
      anyAPI: [
        "DexClassLoader",
        "BaseDexClassLoader",
        "InMemoryDexClassLoader",
        "loadDex"
      ]
    }
  },
  {
    id: "CODE_REMOTE_EXEC",
    label: "Remote Command Execution",
    description: "App executes shell commands — high risk of privilege escalation",
    category: "Code Execution",
    severity: "CRITICAL",
    score: 40,
    requires: {
      anyAPI: ["Runtime.exec", "ProcessBuilder", "exec("]
    }
  },
  {
    id: "CODE_REFLECTION",
    label: "Reflection-Based Code Execution",
    description: "App uses Java reflection to call hidden/obfuscated methods",
    category: "Code Execution",
    severity: "HIGH",
    score: 20,
    requires: {
      anyAPI: ["getDeclaredMethod", "setAccessible", "invoke("]
    }
  },
  {
    id: "CODE_NATIVE",
    label: "Native Code Execution",
    description: "App loads native libraries — may contain undetectable malicious code",
    category: "Code Execution",
    severity: "MEDIUM",
    score: 15,
    requires: {
      anyAPI: ["System.loadLibrary", "System.load("]
    }
  },

  // ── Credential & Data Theft ──────────────────────────────────────────────────
  {
    id: "CRED_ACCOUNT_HARVEST",
    label: "Account Credential Harvesting",
    description: "App accesses device accounts to harvest login credentials",
    category: "Credential Theft",
    severity: "CRITICAL",
    score: 35,
    requires: {
      anyAPI: ["getAccounts(", "AccountManager"],
      anyPermission: [
        "android.permission.GET_ACCOUNTS",
        "android.permission.INTERNET"
      ]
    }
  },
  {
    id: "CRED_CONTACT_HARVEST",
    label: "Contact Data Harvesting",
    description: "App reads and likely exfiltrates device contacts",
    category: "Credential Theft",
    severity: "HIGH",
    score: 20,
    requires: {
      allPermissions: [
        "android.permission.READ_CONTACTS",
        "android.permission.INTERNET"
      ]
    }
  },
  {
    id: "CRED_DEVICE_ID",
    label: "Device Fingerprinting",
    description: "App collects unique device identifiers for tracking",
    category: "Credential Theft",
    severity: "HIGH",
    score: 20,
    requires: {
      anyAPI: [
        "getDeviceId",
        "getSubscriberId",
        "getSimSerialNumber",
        "getImei"
      ]
    }
  },
  {
    id: "CRED_SECRET_LEAK",
    label: "Hardcoded Credentials Detected",
    description: "App contains hardcoded API keys, tokens or passwords",
    category: "Credential Theft",
    severity: "HIGH",
    score: 25,
    requires: {
      hasSecrets: true
    }
  },

  // ── Package & System Abuse ───────────────────────────────────────────────────
  {
    id: "PKG_INSTALL",
    label: "Silent App Installation",
    description: "App can silently install additional applications",
    category: "System Abuse",
    severity: "CRITICAL",
    score: 35,
    requires: {
      anyPermission: ["android.permission.REQUEST_INSTALL_PACKAGES"],
      anyAPI: ["installPackage", "DexClassLoader"]
    }
  },
  {
    id: "PKG_ENUM",
    label: "Installed Package Enumeration",
    description: "App scans all installed apps — used for targeted attacks on banking apps",
    category: "System Abuse",
    severity: "HIGH",
    score: 20,
    requires: {
      anyAPI: ["getInstalledPackages", "getInstalledApplications"]
    }
  },
  {
    id: "PKG_WEBVIEW_INJECT",
    label: "WebView JavaScript Injection",
    description: "App injects JavaScript into WebView — risk of credential theft",
    category: "System Abuse",
    severity: "HIGH",
    score: 20,
    requires: {
      anyAPI: ["addJavascriptInterface", "setJavaScriptEnabled"]
    }
  },
  {
    id: "PKG_ROOT",
    label: "Root Access Attempt",
    description: "App attempts to gain root/superuser access",
    category: "System Abuse",
    severity: "CRITICAL",
    score: 45,
    requires: {
      anyStringFinding: [
        "Root Access",
        "Filesystem Remount Attempt",
        "Ownership Change to Root",
        "File Permission Change (chmod)"
      ]
    }
  }

];


// ─── HELPER: Check if behavior conditions are met ────────────────────────────

function checkBehavior(behavior, permSet, apiSet, stringFindings, hasSecrets) {

  const req = behavior.requires;

  // allPermissions — ALL must be present
  if (req.allPermissions) {
    if (!req.allPermissions.every(p => permSet.has(p))) return false;
  }

  // anyPermission — at least ONE must be present
  if (req.anyPermission) {
    if (!req.anyPermission.some(p => permSet.has(p))) return false;
  }

  // anyPermissionAlso — additional ANY check (AND logic with above)
  if (req.anyPermissionAlso) {
    if (!req.anyPermissionAlso.some(p => permSet.has(p))) return false;
  }

  // anyAPI — at least ONE must be present
  if (req.anyAPI) {
    if (!req.anyAPI.some(a => apiSet.has(a))) return false;
  }

  // allAPIs — ALL must be present
  if (req.allAPIs) {
    if (!req.allAPIs.every(a => apiSet.has(a))) return false;
  }

  // anyStringFinding — at least ONE label must match
  if (req.anyStringFinding) {
    const findingLabels = stringFindings.map(f =>
      typeof f === "string" ? f : f.label
    );
    if (!req.anyStringFinding.some(s =>
      findingLabels.some(fl => fl.includes(s))
    )) return false;
  }

  // hasSecrets — secret scan must have found something
  if (req.hasSecrets) {
    if (!hasSecrets) return false;
  }

  return true;

}


// ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────

function analyzeDynamicBehavior(
  permissions  = [],
  detectedAPIs = [],
  stringFindings = [],
  hasSecrets   = false
) {

  const permNames = permissions
    .map(p => (typeof p === "string" ? p : p.name))
    .filter(Boolean);

  const apiNames = detectedAPIs
    .map(a => (typeof a === "string" ? a : a.api))
    .filter(Boolean);

  const permSet = new Set(permNames);
  const apiSet  = new Set(apiNames);

  const behaviors      = [];
  const byCategory     = {};
  let   dynamicScore   = 0;


  // ── Evaluate each behavior ───────────────────────────────────────────────────
  BEHAVIOR_DEFINITIONS.forEach(behavior => {

    const matched = checkBehavior(
      behavior, permSet, apiSet, stringFindings, hasSecrets
    );

    if (!matched) return;

    behaviors.push({
      id:          behavior.id,
      label:       behavior.label,
      description: behavior.description,
      category:    behavior.category,
      severity:    behavior.severity,
      score:       behavior.score
    });

    // Group by category
    if (!byCategory[behavior.category]) {
      byCategory[behavior.category] = [];
    }
    byCategory[behavior.category].push(behavior.label);

    dynamicScore += behavior.score;

  });


  // ── Smart score normalization ────────────────────────────────────────────────
  if (behaviors.length > 1) {
    const sorted = behaviors
      .map(b => b.score)
      .sort((a, b) => b - a);

    const primary = sorted[0];
    const rest    = sorted
      .slice(1)
      .reduce((sum, s) => sum + s * 0.25, 0);

    dynamicScore = Math.round(primary + rest);
  }

  dynamicScore = Math.min(dynamicScore, 100);


  // ── Severity breakdown ───────────────────────────────────────────────────────
  const criticalBehaviors = behaviors.filter(b => b.severity === "CRITICAL");
  const highBehaviors     = behaviors.filter(b => b.severity === "HIGH");
  const mediumBehaviors   = behaviors.filter(b => b.severity === "MEDIUM");


  // ── Overall behavior verdict ─────────────────────────────────────────────────
  let behaviorVerdict = "CLEAN";

  if      (criticalBehaviors.length >= 3) behaviorVerdict = "HIGHLY_MALICIOUS";
  else if (criticalBehaviors.length >= 1) behaviorVerdict = "MALICIOUS";
  else if (highBehaviors.length     >= 2) behaviorVerdict = "SUSPICIOUS";
  else if (highBehaviors.length     >= 1) behaviorVerdict = "LOW_RISK";


  return {
    dynamicScore,
    behaviorVerdict,
    behaviors,
    byCategory,
    criticalCount:  criticalBehaviors.length,
    highCount:      highBehaviors.length,
    mediumCount:    mediumBehaviors.length,
    totalBehaviors: behaviors.length,
    // Analysis note — honest about what this is
    analysisNote: "Behavior prediction based on static evidence. Actual runtime behavior may vary."
  };

}

module.exports = { analyzeDynamicBehavior };