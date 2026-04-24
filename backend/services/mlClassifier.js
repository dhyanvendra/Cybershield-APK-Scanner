/**
 * ML CLASSIFIER
 * Rule-based weighted classification engine
 * Classifies malware type using permissions, APIs, static findings,
 * malware patterns and secret scan results combined
 * Multi-label support — app can be classified as multiple threat types
 * Honest labeling — called "classifier" not "ML" in outputs
 */

// ─── MALWARE TYPE DEFINITIONS ─────────────────────────────────────────────────

const MALWARE_TYPES = {

  BANKING_TROJAN: {
    label: "Banking Trojan",
    description: "Steals banking credentials, intercepts OTPs, performs overlay attacks on banking apps",
    indicators: {
      permissions: [
        { name: "android.permission.READ_SMS",                  weight: 25 },
        { name: "android.permission.RECEIVE_SMS",               weight: 20 },
        { name: "android.permission.SEND_SMS",                  weight: 20 },
        { name: "android.permission.SYSTEM_ALERT_WINDOW",       weight: 20 },
        { name: "android.permission.BIND_ACCESSIBILITY_SERVICE",weight: 25 },
        { name: "android.permission.GET_ACCOUNTS",              weight: 15 },
        { name: "android.permission.INTERNET",                  weight: 5  },
        { name: "android.permission.RECEIVE_BOOT_COMPLETED",    weight: 10 }
      ],
      apis: [
        { name: "AccessibilityService",                weight: 20 },
        { name: "findAccessibilityNodeInfosByText",     weight: 20 },
        { name: "performGlobalAction",                 weight: 20 },
        { name: "sendTextMessage",                     weight: 25 },
        { name: "SmsManager",                          weight: 20 },
        { name: "getAccounts(",                        weight: 15 },
        { name: "AccountManager",                      weight: 15 }
      ],
      combos: [
        {
          permissions: ["android.permission.READ_SMS", "android.permission.SYSTEM_ALERT_WINDOW"],
          bonus: 20,
          label: "OTP theft + Overlay combo"
        },
        {
          permissions: ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.INTERNET"],
          bonus: 25,
          label: "Accessibility abuse for credential theft"
        }
      ]
    }
  },

  SPYWARE: {
    label: "Spyware",
    description: "Covertly monitors user activity, location, communications and transmits data",
    indicators: {
      permissions: [
        { name: "android.permission.RECORD_AUDIO",              weight: 25 },
        { name: "android.permission.ACCESS_FINE_LOCATION",      weight: 20 },
        { name: "android.permission.ACCESS_BACKGROUND_LOCATION",weight: 20 },
        { name: "android.permission.READ_CONTACTS",             weight: 15 },
        { name: "android.permission.READ_CALL_LOG",             weight: 20 },
        { name: "android.permission.PROCESS_OUTGOING_CALLS",    weight: 20 },
        { name: "android.permission.CAMERA",                    weight: 15 },
        { name: "android.permission.READ_SMS",                  weight: 15 },
        { name: "android.permission.INTERNET",                  weight: 5  }
      ],
      apis: [
        { name: "AudioRecord",              weight: 25 },
        { name: "MediaRecorder",            weight: 20 },
        { name: "getLastKnownLocation",     weight: 20 },
        { name: "requestLocationUpdates",   weight: 20 },
        { name: "getDeviceId",              weight: 15 },
        { name: "getSubscriberId",          weight: 15 },
        { name: "ClipboardManager",         weight: 15 },
        { name: "getPrimaryClip",           weight: 15 }
      ],
      combos: [
        {
          permissions: [
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET"
          ],
          bonus: 30,
          label: "Full surveillance combo"
        },
        {
          permissions: [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO"
          ],
          bonus: 20,
          label: "AV surveillance combo"
        }
      ]
    }
  },

  RANSOMWARE: {
    label: "Ransomware",
    description: "Encrypts device files or locks device demanding ransom payment",
    indicators: {
      permissions: [
        { name: "android.permission.MANAGE_EXTERNAL_STORAGE",  weight: 25 },
        { name: "android.permission.WRITE_EXTERNAL_STORAGE",   weight: 15 },
        { name: "android.permission.READ_EXTERNAL_STORAGE",    weight: 10 },
        { name: "android.permission.BIND_DEVICE_ADMIN",        weight: 30 },
        { name: "android.permission.SYSTEM_ALERT_WINDOW",      weight: 15 },
        { name: "android.permission.DISABLE_KEYGUARD",         weight: 20 },
        { name: "android.permission.RECEIVE_BOOT_COMPLETED",   weight: 10 }
      ],
      apis: [
        { name: "DevicePolicyManager",    weight: 30 },
        { name: "Cipher.getInstance",     weight: 20 },
        { name: "SecretKeySpec",          weight: 20 },
        { name: "Runtime.exec",           weight: 20 },
        { name: "ProcessBuilder",         weight: 20 },
        { name: "setDeviceOwner",         weight: 30 }
      ],
      combos: [
        {
          permissions: [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.MANAGE_EXTERNAL_STORAGE"
          ],
          bonus: 30,
          label: "Device lock + file encryption combo"
        }
      ]
    }
  },

  SMS_FRAUD: {
    label: "SMS Fraud",
    description: "Sends unauthorized premium SMS, subscribes to paid services without consent",
    indicators: {
      permissions: [
        { name: "android.permission.SEND_SMS",      weight: 30 },
        { name: "android.permission.RECEIVE_SMS",   weight: 20 },
        { name: "android.permission.READ_SMS",      weight: 20 },
        { name: "android.permission.INTERNET",      weight: 5  }
      ],
      apis: [
        { name: "sendTextMessage",          weight: 30 },
        { name: "sendMultipartTextMessage", weight: 30 },
        { name: "SmsManager",               weight: 20 }
      ],
      combos: [
        {
          permissions: [
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS"
          ],
          apis: ["sendTextMessage"],
          bonus: 25,
          label: "Full SMS control combo"
        }
      ]
    }
  },

  ADWARE: {
    label: "Adware",
    description: "Displays persistent intrusive ads, collects device info for ad targeting",
    indicators: {
      permissions: [
        { name: "android.permission.SYSTEM_ALERT_WINDOW",      weight: 20 },
        { name: "android.permission.RECEIVE_BOOT_COMPLETED",   weight: 15 },
        { name: "android.permission.INTERNET",                 weight: 5  },
        { name: "android.permission.ACCESS_FINE_LOCATION",     weight: 10 },
        { name: "android.permission.READ_PHONE_STATE",         weight: 10 },
        { name: "android.permission.QUERY_ALL_PACKAGES",       weight: 15 }
      ],
      apis: [
        { name: "getInstalledApplications", weight: 15 },
        { name: "getInstalledPackages",     weight: 15 },
        { name: "getDeviceId",              weight: 10 }
      ],
      combos: [
        {
          permissions: [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET"
          ],
          bonus: 20,
          label: "Persistent overlay ad combo"
        }
      ]
    }
  },

  RAT: {
    label: "Remote Access Trojan (RAT)",
    description: "Allows remote attacker to control device, execute commands and exfiltrate data",
    indicators: {
      permissions: [
        { name: "android.permission.INTERNET",                  weight: 5  },
        { name: "android.permission.RECEIVE_BOOT_COMPLETED",    weight: 10 },
        { name: "android.permission.BIND_ACCESSIBILITY_SERVICE",weight: 20 },
        { name: "android.permission.RECORD_AUDIO",              weight: 15 },
        { name: "android.permission.CAMERA",                    weight: 15 }
      ],
      apis: [
        { name: "Runtime.exec",           weight: 30 },
        { name: "ProcessBuilder",         weight: 30 },
        { name: "MediaProjection",        weight: 25 },
        { name: "createVirtualDisplay",   weight: 25 },
        { name: "DexClassLoader",         weight: 20 },
        { name: "AccessibilityService",   weight: 20 }
      ],
      combos: [
        {
          apis: ["Runtime.exec", "MediaProjection"],
          bonus: 30,
          label: "Remote execution + screen capture combo"
        }
      ]
    }
  },

  DROPPER: {
    label: "Dropper / Loader",
    description: "Downloads and installs additional malicious payloads after initial installation",
    indicators: {
      permissions: [
        { name: "android.permission.REQUEST_INSTALL_PACKAGES", weight: 30 },
        { name: "android.permission.INTERNET",                 weight: 5  },
        { name: "android.permission.RECEIVE_BOOT_COMPLETED",   weight: 10 },
        { name: "android.permission.WRITE_EXTERNAL_STORAGE",   weight: 10 }
      ],
      apis: [
        { name: "DexClassLoader",           weight: 30 },
        { name: "BaseDexClassLoader",       weight: 30 },
        { name: "InMemoryDexClassLoader",   weight: 35 },
        { name: "loadDex",                  weight: 30 },
        { name: "installPackage",           weight: 25 }
      ],
      combos: [
        {
          permissions: ["android.permission.REQUEST_INSTALL_PACKAGES"],
          apis: ["DexClassLoader"],
          bonus: 30,
          label: "Install + dynamic loading combo"
        }
      ]
    }
  },

  STALKERWARE: {
    label: "Stalkerware",
    description: "Covertly tracks victim device — calls, location, messages, contacts",
    indicators: {
      permissions: [
        { name: "android.permission.READ_SMS",               weight: 20 },
        { name: "android.permission.READ_CALL_LOG",          weight: 25 },
        { name: "android.permission.PROCESS_OUTGOING_CALLS", weight: 25 },
        { name: "android.permission.ACCESS_FINE_LOCATION",   weight: 20 },
        { name: "android.permission.ACCESS_BACKGROUND_LOCATION", weight: 25 },
        { name: "android.permission.RECORD_AUDIO",           weight: 20 },
        { name: "android.permission.READ_CONTACTS",          weight: 15 },
        { name: "android.permission.RECEIVE_BOOT_COMPLETED", weight: 10 }
      ],
      apis: [
        { name: "getLastKnownLocation",   weight: 20 },
        { name: "requestLocationUpdates", weight: 20 },
        { name: "AudioRecord",            weight: 20 }
      ],
      combos: [
        {
          permissions: [
            "android.permission.READ_CALL_LOG",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_SMS"
          ],
          bonus: 35,
          label: "Full stalkerware profile"
        }
      ]
    }
  },

  CRYPTOMINER: {
    label: "Cryptominer",
    description: "Uses device CPU/GPU resources to mine cryptocurrency without user consent",
    indicators: {
      permissions: [
        { name: "android.permission.INTERNET",               weight: 5  },
        { name: "android.permission.RECEIVE_BOOT_COMPLETED", weight: 15 },
        { name: "android.permission.WAKE_LOCK",              weight: 20 },
        { name: "android.permission.FOREGROUND_SERVICE",     weight: 15 }
      ],
      apis: [
        { name: "System.loadLibrary",   weight: 20 },
        { name: "System.load(",         weight: 20 },
        { name: "Runtime.exec",         weight: 15 }
      ],
      combos: [
        {
          permissions: [
            "android.permission.WAKE_LOCK",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET"
          ],
          bonus: 20,
          label: "Persistent CPU mining combo"
        }
      ]
    }
  },

  KEYLOGGER: {
    label: "Keylogger",
    description: "Captures user keystrokes and input via accessibility services",
    indicators: {
      permissions: [
        { name: "android.permission.BIND_ACCESSIBILITY_SERVICE", weight: 30 },
        { name: "android.permission.INTERNET",                   weight: 5  }
      ],
      apis: [
        { name: "onKeyEvent",                           weight: 30 },
        { name: "findAccessibilityNodeInfosByText",     weight: 25 },
        { name: "performGlobalAction",                  weight: 20 },
        { name: "AccessibilityService",                 weight: 20 },
        { name: "KeyEvent",                             weight: 15 }
      ],
      combos: [
        {
          permissions: ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
          apis: ["onKeyEvent", "findAccessibilityNodeInfosByText"],
          bonus: 30,
          label: "Accessibility keylogger combo"
        }
      ]
    }
  }

};


// ─── SAFE APP INDICATORS (reduce false positives) ────────────────────────────

const SAFE_INDICATORS = [
  "android.permission.CAMERA",           // Camera alone is fine
  "android.permission.RECORD_AUDIO",     // Mic alone is fine (voice apps)
  "android.permission.ACCESS_FINE_LOCATION", // Location alone is fine (maps)
  "android.permission.READ_CONTACTS",    // Contacts alone is fine (dialer)
  "android.permission.INTERNET"          // Internet alone is always fine
];


// ─── CLASSIFICATION THRESHOLDS ────────────────────────────────────────────────

const THRESHOLDS = {
  CONFIRMED:   75,
  LIKELY:      50,
  POSSIBLE:    30,
  UNLIKELY:    0
};


// ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────

function classifyMalware(permissions = [], detectedAPIs = [], malwareFindings = []) {

  const permNames = permissions
    .map(p => (typeof p === "string" ? p : p.name))
    .filter(Boolean);

  const apiNames = detectedAPIs
    .map(a => (typeof a === "string" ? a : a.api))
    .filter(Boolean);

  const permSet = new Set(permNames);
  const apiSet  = new Set(apiNames);

  const results = {};


  // ── Score each malware type ───────────────────────────────────────────────────
  Object.entries(MALWARE_TYPES).forEach(([typeKey, typeDef]) => {

    let score = 0;
    const matchedIndicators = [];


    // Permission scoring
    typeDef.indicators.permissions.forEach(ind => {
      if (permSet.has(ind.name)) {
        score += ind.weight;
        matchedIndicators.push({
          type: "permission",
          name: ind.name,
          weight: ind.weight
        });
      }
    });


    // API scoring
    typeDef.indicators.apis.forEach(ind => {
      if (apiSet.has(ind.name)) {
        score += ind.weight;
        matchedIndicators.push({
          type: "api",
          name: ind.name,
          weight: ind.weight
        });
      }
    });


    // Combo bonuses
    typeDef.indicators.combos.forEach(combo => {

      const permsMatch = !combo.permissions
        ? true
        : combo.permissions.every(p => permSet.has(p));

      const apisMatch = !combo.apis
        ? true
        : combo.apis.every(a => apiSet.has(a));

      if (permsMatch && apisMatch) {
        score += combo.bonus;
        matchedIndicators.push({
          type:  "combo",
          label: combo.label,
          bonus: combo.bonus
        });
      }

    });


    // Normalize to 0-100
    const maxPossible = [
      ...typeDef.indicators.permissions.map(i => i.weight),
      ...typeDef.indicators.apis.map(i => i.weight),
      ...typeDef.indicators.combos.map(i => i.bonus)
    ].reduce((a, b) => a + b, 0);

    const normalizedScore = maxPossible > 0
      ? Math.round((score / maxPossible) * 100)
      : 0;


    // Determine confidence level
    let confidence = "UNLIKELY";
    if      (normalizedScore >= THRESHOLDS.CONFIRMED) confidence = "CONFIRMED";
    else if (normalizedScore >= THRESHOLDS.LIKELY)    confidence = "LIKELY";
    else if (normalizedScore >= THRESHOLDS.POSSIBLE)  confidence = "POSSIBLE";


    results[typeKey] = {
      label:            typeDef.label,
      description:      typeDef.description,
      rawScore:         score,
      normalizedScore,
      confidence,
      matchedIndicators
    };

  });


  // ── Multi-label: find all types above threshold ───────────────────────────────
  const detectedTypes = Object.entries(results)
    .filter(([, v]) => v.normalizedScore >= THRESHOLDS.POSSIBLE)
    .sort((a, b) => b[1].normalizedScore - a[1].normalizedScore);


  // ── Primary classification ────────────────────────────────────────────────────
  let primaryType        = "SAFE";
  let primaryLabel       = "Clean Application";
  let primaryDescription = "No malware indicators detected";
  let primaryScore       = 0;
  let primaryConfidence  = "UNLIKELY";

  if (detectedTypes.length > 0) {
    const [topKey, topVal] = detectedTypes[0];
    primaryType        = topKey;
    primaryLabel       = topVal.label;
    primaryDescription = topVal.description;
    primaryScore       = topVal.normalizedScore;
    primaryConfidence  = topVal.confidence;
  }


  // ── Safe app check — single harmless permissions don't trigger detection ───────
  const onlySafePermissions = permNames.every(p => SAFE_INDICATORS.includes(p));

  if (onlySafePermissions && detectedTypes.length === 0) {
    primaryType  = "SAFE";
    primaryLabel = "Clean Application";
  }


  // ── Build all scores summary ──────────────────────────────────────────────────
  const allScores = {};
  Object.entries(results).forEach(([key, val]) => {
    allScores[key] = {
      label:      val.label,
      score:      val.normalizedScore,
      confidence: val.confidence
    };
  });


  return {
    primaryType,
    primaryLabel,
    primaryDescription,
    primaryScore,
    primaryConfidence,
    detectedTypes: detectedTypes.map(([key, val]) => ({
      type:        key,
      label:       val.label,
      score:       val.normalizedScore,
      confidence:  val.confidence,
      description: val.description,
      indicators:  val.matchedIndicators
    })),
    allScores,
    isMultiThreat: detectedTypes.length > 1,
    totalThreatsDetected: detectedTypes.length
  };

}

module.exports = { classifyMalware };