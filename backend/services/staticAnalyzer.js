const path = require("path");

/**
 * STATIC ANALYZER
 * Receives buffer from hashAnalyzer — NO file re-read
 * Performs deep string-level analysis on APK binary
 */

// ─── SUSPICIOUS API SIGNATURES ────────────────────────────────────────────────

const SUSPICIOUS_APIS = [

  // Device Identification
  { api: "getDeviceId",           category: "Device Fingerprinting",  severity: "HIGH",   score: 12 },
  { api: "getSubscriberId",       category: "Device Fingerprinting",  severity: "HIGH",   score: 12 },
  { api: "getSimSerialNumber",    category: "Device Fingerprinting",  severity: "HIGH",   score: 10 },
  { api: "getImei",               category: "Device Fingerprinting",  severity: "HIGH",   score: 12 },
  { api: "getLine1Number",        category: "Device Fingerprinting",  severity: "HIGH",   score: 10 },
  { api: "getSIMCountryIso",      category: "Device Fingerprinting",  severity: "MEDIUM", score: 6  },

  // Code Execution
  { api: "Runtime.exec",          category: "Code Execution",         severity: "CRITICAL", score: 20 },
  { api: "ProcessBuilder",        category: "Code Execution",         severity: "CRITICAL", score: 20 },
  { api: "exec(",                 category: "Code Execution",         severity: "HIGH",     score: 15 },

  // Dynamic Code Loading
  { api: "DexClassLoader",        category: "Dynamic Code Loading",   severity: "CRITICAL", score: 25 },
  { api: "BaseDexClassLoader",    category: "Dynamic Code Loading",   severity: "CRITICAL", score: 25 },
  { api: "PathClassLoader",       category: "Dynamic Code Loading",   severity: "HIGH",     score: 18 },
  { api: "ClassLoader",           category: "Dynamic Code Loading",   severity: "MEDIUM",   score: 8  },
  { api: "loadDex",               category: "Dynamic Code Loading",   severity: "HIGH",     score: 18 },
  { api: "InMemoryDexClassLoader",category: "Dynamic Code Loading",   severity: "CRITICAL", score: 25 },

  // Reflection
  { api: "getDeclaredMethod",     category: "Reflection",             severity: "HIGH",     score: 12 },
  { api: "getDeclaredField",      category: "Reflection",             severity: "MEDIUM",   score: 8  },
  { api: "setAccessible",         category: "Reflection",             severity: "HIGH",     score: 10 },
  { api: "invoke(",               category: "Reflection",             severity: "MEDIUM",   score: 6  },

  // Native Code
  { api: "System.loadLibrary",    category: "Native Code",            severity: "MEDIUM",   score: 8  },
  { api: "System.load(",          category: "Native Code",            severity: "HIGH",     score: 12 },

  // Crypto Abuse
  { api: "Cipher.getInstance",    category: "Encryption",             severity: "MEDIUM",   score: 6  },
  { api: "SecretKeySpec",         category: "Encryption",             severity: "MEDIUM",   score: 6  },
  { api: "IvParameterSpec",       category: "Encryption",             severity: "MEDIUM",   score: 5  },

  // Package Management
  { api: "getInstalledPackages",  category: "Package Enumeration",    severity: "MEDIUM",   score: 8  },
  { api: "getInstalledApplications", category: "Package Enumeration", severity: "MEDIUM",   score: 8  },
  { api: "installPackage",        category: "Package Manipulation",   severity: "CRITICAL", score: 20 },
  { api: "deletePackage",         category: "Package Manipulation",   severity: "CRITICAL", score: 20 },

  // Account Access
  { api: "getAccounts(",          category: "Account Access",         severity: "HIGH",     score: 14 },
  { api: "AccountManager",        category: "Account Access",         severity: "HIGH",     score: 12 },

  // SMS / Telephony
  { api: "sendTextMessage",       category: "SMS Abuse",              severity: "CRITICAL", score: 20 },
  { api: "sendMultipartTextMessage", category: "SMS Abuse",           severity: "CRITICAL", score: 20 },
  { api: "SmsManager",            category: "SMS Abuse",              severity: "HIGH",     score: 15 },

  // Network / WebView
  { api: "addJavascriptInterface",category: "WebView Injection",      severity: "HIGH",     score: 15 },
  { api: "setJavaScriptEnabled",  category: "WebView Config",         severity: "MEDIUM",   score: 6  },

  // Accessibility Abuse
  { api: "AccessibilityService",  category: "Accessibility Abuse",    severity: "CRITICAL", score: 20 },
  { api: "performGlobalAction",   category: "Accessibility Abuse",    severity: "CRITICAL", score: 20 },
  { api: "findAccessibilityNodeInfosByText", category: "Accessibility Abuse", severity: "HIGH", score: 15 },

  // Keylogging
  { api: "onKeyEvent",            category: "Input Capture",          severity: "HIGH",     score: 15 },
  { api: "KeyEvent",              category: "Input Capture",          severity: "MEDIUM",   score: 6  },

  // Camera / Mic
  { api: "MediaRecorder",         category: "Media Recording",        severity: "HIGH",     score: 14 },
  { api: "AudioRecord",           category: "Audio Recording",        severity: "HIGH",     score: 14 },

  // Clipboard
  { api: "ClipboardManager",      category: "Clipboard Access",       severity: "MEDIUM",   score: 8  },
  { api: "getPrimaryClip",        category: "Clipboard Access",       severity: "MEDIUM",   score: 8  },

  // Screen Capture
  { api: "MediaProjection",       category: "Screen Capture",         severity: "CRITICAL", score: 20 },
  { api: "createVirtualDisplay",  category: "Screen Capture",         severity: "CRITICAL", score: 20 },

  // Location
  { api: "getLastKnownLocation",  category: "Location Tracking",      severity: "HIGH",     score: 10 },
  { api: "requestLocationUpdates",category: "Location Tracking",      severity: "HIGH",     score: 10 },

  // Admin / Root
  { api: "DevicePolicyManager",   category: "Device Admin",           severity: "CRITICAL", score: 22 },
  { api: "setDeviceOwner",        category: "Device Admin",           severity: "CRITICAL", score: 25 },
  { api: "su\n",                  category: "Root Access",            severity: "CRITICAL", score: 25 },
  { api: "/system/bin/su",        category: "Root Access",            severity: "CRITICAL", score: 25 },

  // Obfuscation Indicators
  { api: "Base64.decode",         category: "Obfuscation",            severity: "MEDIUM",   score: 8  },
  { api: "base64_decode",         category: "Obfuscation",            severity: "MEDIUM",   score: 8  },
  { api: "Obfuscated",            category: "Obfuscation",            severity: "HIGH",     score: 10 },

];


// ─── SUSPICIOUS TLDs ──────────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".ru", ".cn", ".tk",
  ".ml", ".ga", ".cf", ".work", ".click",
  ".site", ".online", ".pw", ".cc",
  ".biz", ".info", ".ws", ".su",
  ".to", ".in.net", ".rest"
];


// ─── URL SHORTENERS ───────────────────────────────────────────────────────────

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl",
  "t.co", "ow.ly", "short.io",
  "rb.gy", "cutt.ly", "is.gd"
];


// ─── KNOWN MALICIOUS PATTERNS IN STRINGS ─────────────────────────────────────

const MALICIOUS_STRING_PATTERNS = [
  { pattern: /\/data\/data\/[a-z.]+\/databases/i, label: "Database File Access Path",         severity: "HIGH"   },
  { pattern: /\/proc\/net\/tcp/i,                 label: "Network Socket Enumeration",         severity: "HIGH"   },
  { pattern: /\/proc\/self\/maps/i,               label: "Memory Map Access",                  severity: "HIGH"   },
  { pattern: /chmod\s+[0-9]+/i,                   label: "File Permission Change (chmod)",     severity: "CRITICAL"},
  { pattern: /chown\s+root/i,                     label: "Ownership Change to Root",           severity: "CRITICAL"},
  { pattern: /mount\s+-o\s+remount/i,             label: "Filesystem Remount Attempt",         severity: "CRITICAL"},
  { pattern: /\/system\/app\//i,                  label: "System App Directory Access",        severity: "HIGH"   },
  { pattern: /content:\/\/sms/i,                  label: "SMS Content Provider Access",        severity: "HIGH"   },
  { pattern: /content:\/\/contacts/i,             label: "Contacts Content Provider Access",   severity: "HIGH"   },
  { pattern: /TelephonyManager/i,                 label: "Telephony Manager Usage",            severity: "MEDIUM" },
  { pattern: /WifiManager/i,                      label: "WiFi Manager Access",                severity: "LOW"    },
  { pattern: /getRunningTasks/i,                  label: "Running Task Enumeration",           severity: "MEDIUM" },
  { pattern: /ActivityManager/i,                  label: "Activity Manager Access",            severity: "LOW"    },
];


// ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────

function analyzeStaticCode(buffer) {

  // Use buffer directly — no file read
  const content = buffer.toString("latin1");

  const detectedAPIs     = [];
  const suspiciousDomains = [];
  const urlShorteners    = [];
  const stringFindings   = [];

  let staticScore = 0;
  const seenAPIs = new Set();


  // ── 1. Suspicious API Detection ─────────────────────────────────────────────
  SUSPICIOUS_APIS.forEach(entry => {

    if (!seenAPIs.has(entry.api) && content.includes(entry.api)) {

      seenAPIs.add(entry.api);

      detectedAPIs.push({
        api:      entry.api,
        category: entry.category,
        severity: entry.severity,
        score:    entry.score
      });

      staticScore += entry.score;
    }

  });


  // ── 2. URL Extraction ────────────────────────────────────────────────────────
  const urlRegex = /(https?:\/\/[^\s"'<>\x00-\x1f]{6,200})/g;
  const rawUrls  = [...new Set(content.match(urlRegex) || [])];


  // ── 3. Suspicious TLD Detection ──────────────────────────────────────────────
  rawUrls.forEach(url => {

    const lower = url.toLowerCase();

    const isSuspiciousTLD = SUSPICIOUS_TLDS.some(tld => {
      try {
        const hostname = new URL(url).hostname;
        return hostname.endsWith(tld);
      } catch {
        return lower.includes(tld);
      }
    });

    if (isSuspiciousTLD) {
      suspiciousDomains.push(url);
      staticScore += 12;
    }

    // URL Shortener Detection
    if (URL_SHORTENERS.some(s => lower.includes(s))) {
      urlShorteners.push(url);
      staticScore += 10;
    }

  });


  // ── 4. Malicious String Pattern Detection ────────────────────────────────────
  MALICIOUS_STRING_PATTERNS.forEach(entry => {

    if (entry.pattern.test(content)) {

      stringFindings.push({
        label:    entry.label,
        severity: entry.severity
      });

      const severityScore = {
        CRITICAL: 15,
        HIGH:     10,
        MEDIUM:   6,
        LOW:      2
      }[entry.severity] || 5;

      staticScore += severityScore;
    }

  });


  // ── 5. Obfuscation Indicators ────────────────────────────────────────────────
  const obfuscationIndicators = [];

  // Very short class names (common in obfuscated APKs)
  const shortClassRegex = /L[a-z]{1,2}\/[a-z]{1,2}\/[a-z]{1,2};/g;
  const shortClassMatches = content.match(shortClassRegex) || [];

  if (shortClassMatches.length > 50) {
    obfuscationIndicators.push("Heavy class name obfuscation detected");
    staticScore += 15;
  }

  // High entropy strings (potential encrypted payloads)
  const base64BlockRegex = /[A-Za-z0-9+/]{60,}={0,2}/g;
  const base64Blocks = content.match(base64BlockRegex) || [];

  if (base64Blocks.length > 10) {
    obfuscationIndicators.push("Multiple large base64/encrypted blocks detected");
    staticScore += 10;
  }


  // ── 6. Normalize Score ───────────────────────────────────────────────────────
  staticScore = Math.min(Math.round(staticScore), 100);


  // ── 7. Group APIs by category for cleaner output ─────────────────────────────
  const apisByCategory = {};

  detectedAPIs.forEach(entry => {
    if (!apisByCategory[entry.category]) {
      apisByCategory[entry.category] = [];
    }
    apisByCategory[entry.category].push(entry);
  });


  return {
    staticScore,
    detectedAPIs,
    apisByCategory,
    suspiciousDomains,
    urlShorteners,
    stringFindings,
    obfuscationIndicators,
    totalUrlsFound: rawUrls.length,
    extractedUrls: rawUrls.slice(0, 20)  // pass to urlAnalyzer
  };

}

module.exports = { analyzeStaticCode };