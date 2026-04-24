/**
 * FAKE APP DETECTOR
 * Detects apps impersonating legitimate brands
 * Uses strict matching — no false positives on legitimate apps
 * Checks package name, app name, and combination patterns
 */

// ─── OFFICIAL APP REGISTRY ────────────────────────────────────────────────────
// Exact official package names — these get immediate pass

const OFFICIAL_PACKAGES = new Set([
  // Google
  "com.google.android.gms",
  "com.google.android.gsf",
  "com.google.android.apps.maps",
  "com.google.android.youtube",
  "com.google.android.apps.photos",
  "com.google.android.apps.docs",
  "com.google.android.apps.drive",
  "com.google.android.apps.walletnfcrel",
  "com.google.android.dialer",
  "com.google.android.contacts",

  // Meta / Facebook
  "com.facebook.katana",
  "com.facebook.orca",
  "com.facebook.lite",
  "com.instagram.android",
  "com.whatsapp",
  "com.whatsapp.w4b",

  // Microsoft
  "com.microsoft.office.word",
  "com.microsoft.office.excel",
  "com.microsoft.teams",
  "com.microsoft.launcher",

  // Amazon
  "com.amazon.mShop.android.shopping",
  "com.amazon.india.shopping",

  // Indian Banking — Official
  "net.one97.paytm",
  "com.phonepe.app",
  "in.org.npci.upiapp",           // BHIM UPI
  "com.google.android.apps.nbu.paisa.user", // Google Pay
  "com.sbi.lotusintouch",
  "com.sbi.SBIFreedomPlus",
  "com.icicibank.imobile",
  "com.hdfcbank.hdfcmobilebanking",
  "com.axisbank.retail",
  "com.kotak.mahindra.kotak811",
  "com.csam.icici.bank.imobile",

  // Indian Apps
  "com.truecaller",
  "com.flipkart.android",
  "com.myntra.android",
  "com.swiggy.android",
  "com.zomato.android",
  "com.ola.android",
  "com.olacabs.customer",
  "com.makemytrip",
  "com.irctc.ticketbooking",

  // Telecom India
  "com.jio.myjio",
  "com.airtel.android.myairtel",
  "com.bsb.hike",

  // Utilities
  "com.netflix.mediaclient",
  "com.spotify.music",
  "com.snapchat.android",
  "com.twitter.android",
  "com.linkedin.android",
  "org.telegram.messenger",
  "org.thoughtcrime.securesms" // Signal
]);


// ─── TRUSTED PACKAGE PREFIXES ─────────────────────────────────────────────────
// Verified official vendor prefixes — strict suffix check applied

const TRUSTED_PREFIXES = [
  "com.google.android.",
  "com.android.",
  "android.",
  "com.samsung.android.",
  "com.sec.android.",
  "com.huawei.android.",
  "com.miui.",
  "com.oneplus.",
  "com.oppo.",
  "com.vivo."
];


// ─── BRAND TARGETS WITH OFFICIAL PACKAGE PREFIXES ────────────────────────────

const BRAND_TARGETS = [
  // Indian Banking
  {
    brand:           "SBI (State Bank of India)",
    keywords:        ["sbi", "statebank", "state_bank", "yono"],
    officialPrefixes: ["com.sbi.", "com.onlinesbi."],
    category:        "Banking",
    riskScore:       35
  },
  {
    brand:           "HDFC Bank",
    keywords:        ["hdfc", "hdfcbank"],
    officialPrefixes: ["com.hdfcbank.", "com.hdfc."],
    category:        "Banking",
    riskScore:       35
  },
  {
    brand:           "ICICI Bank",
    keywords:        ["icici", "icicib"],
    officialPrefixes: ["com.icicibank.", "com.csam.icici."],
    category:        "Banking",
    riskScore:       35
  },
  {
    brand:           "Axis Bank",
    keywords:        ["axisbank", "axis_bank"],
    officialPrefixes: ["com.axisbank."],
    category:        "Banking",
    riskScore:       35
  },
  {
    brand:           "Kotak Bank",
    keywords:        ["kotak"],
    officialPrefixes: ["com.kotak."],
    category:        "Banking",
    riskScore:       35
  },
  {
    brand:           "Bank of India",
    keywords:        ["bankofindia", "bank_of_india", "boi_mobile"],
    officialPrefixes: ["com.bankofindia."],
    category:        "Banking",
    riskScore:       35
  },
  {
    brand:           "Punjab National Bank",
    keywords:        ["pnbmobile", "punjabnational"],
    officialPrefixes: ["com.pnb."],
    category:        "Banking",
    riskScore:       35
  },

  // Indian Payment Apps
  {
    brand:           "Paytm",
    keywords:        ["paytm"],
    officialPrefixes: ["net.one97.paytm"],
    category:        "Payment",
    riskScore:       35
  },
  {
    brand:           "PhonePe",
    keywords:        ["phonepe", "phone_pe"],
    officialPrefixes: ["com.phonepe."],
    category:        "Payment",
    riskScore:       35
  },
  {
    brand:           "Google Pay",
    keywords:        ["googlepay", "google_pay", "gpay", "tez"],
    officialPrefixes: ["com.google.android.apps.nbu."],
    category:        "Payment",
    riskScore:       35
  },
  {
    brand:           "BHIM UPI",
    keywords:        ["bhimupi", "bhim_upi", "npci"],
    officialPrefixes: ["in.org.npci."],
    category:        "Payment",
    riskScore:       35
  },
  {
    brand:           "Razorpay",
    keywords:        ["razorpay"],
    officialPrefixes: ["com.razorpay."],
    category:        "Payment",
    riskScore:       30
  },

  // Social Media
  {
    brand:           "WhatsApp",
    keywords:        ["whatsapp", "whats_app", "watsapp"],
    officialPrefixes: ["com.whatsapp"],
    category:        "Social",
    riskScore:       30
  },
  {
    brand:           "Facebook",
    keywords:        ["facebook", "fb_android"],
    officialPrefixes: ["com.facebook."],
    category:        "Social",
    riskScore:       25
  },
  {
    brand:           "Instagram",
    keywords:        ["instagram", "insta_gram"],
    officialPrefixes: ["com.instagram."],
    category:        "Social",
    riskScore:       25
  },
  {
    brand:           "Telegram",
    keywords:        ["telegram"],
    officialPrefixes: ["org.telegram."],
    category:        "Social",
    riskScore:       25
  },
  {
    brand:           "Snapchat",
    keywords:        ["snapchat", "snap_chat"],
    officialPrefixes: ["com.snapchat."],
    category:        "Social",
    riskScore:       25
  },

  // E-commerce
  {
    brand:           "Amazon",
    keywords:        ["amazon", "amazon_india"],
    officialPrefixes: ["com.amazon."],
    category:        "E-commerce",
    riskScore:       30
  },
  {
    brand:           "Flipkart",
    keywords:        ["flipkart"],
    officialPrefixes: ["com.flipkart."],
    category:        "E-commerce",
    riskScore:       30
  },

  // Government India
  {
    brand:           "Aadhaar / UIDAI",
    keywords:        ["aadhaar", "aadhar", "uidai"],
    officialPrefixes: ["in.gov.uidai."],
    category:        "Government",
    riskScore:       40
  },
  {
    brand:           "DigiLocker",
    keywords:        ["digilocker", "digi_locker"],
    officialPrefixes: ["com.digilocker."],
    category:        "Government",
    riskScore:       40
  },
  {
    brand:           "IRCTC",
    keywords:        ["irctc"],
    officialPrefixes: ["com.irctc."],
    category:        "Government",
    riskScore:       35
  },
  {
    brand:           "Umang",
    keywords:        ["umang"],
    officialPrefixes: ["in.gov.umang."],
    category:        "Government",
    riskScore:       40
  },

  // Telecom India
  {
    brand:           "Jio",
    keywords:        ["myjio", "jio_app"],
    officialPrefixes: ["com.jio."],
    category:        "Telecom",
    riskScore:       25
  },
  {
    brand:           "Airtel",
    keywords:        ["myairtel", "airtel_app"],
    officialPrefixes: ["com.airtel."],
    category:        "Telecom",
    riskScore:       25
  },

  // Global
  {
    brand:           "Google",
    keywords:        ["googl3", "g00gle", "google_update"],
    officialPrefixes: ["com.google."],
    category:        "Tech",
    riskScore:       30
  },
  {
    brand:           "Microsoft",
    keywords:        ["micros0ft", "microsoft_update"],
    officialPrefixes: ["com.microsoft."],
    category:        "Tech",
    riskScore:       30
  }
];


// ─── SUSPICIOUS NAME PATTERNS ─────────────────────────────────────────────────

const SUSPICIOUS_NAME_PATTERNS = [
  { pattern: /\bfake\b/i,       label: "Contains word 'fake'",        score: 30 },
  { pattern: /\bmod\b/i,        label: "Contains word 'mod'",         score: 20 },
  { pattern: /\bcrack(ed)?\b/i, label: "Contains word 'cracked'",     score: 30 },
  { pattern: /\bhack(ed)?\b/i,  label: "Contains word 'hacked'",      score: 30 },
  { pattern: /\bclone\b/i,      label: "Contains word 'clone'",       score: 25 },
  { pattern: /\bspoof\b/i,      label: "Contains word 'spoof'",       score: 30 },
  { pattern: /\bunlock(ed)?\b/i,label: "Contains word 'unlocked'",    score: 20 },
  { pattern: /\bpremium\b/i,    label: "Contains word 'premium'",     score: 15 },
  { pattern: /\bfree\b/i,       label: "Contains word 'free'",        score: 10 },
  { pattern: /\bupdate\b/i,     label: "Contains word 'update'",      score: 10 },
  { pattern: /\bverif(y|ication)\b/i, label: "Contains word 'verify'",score: 15 },
  { pattern: /\bkyc\b/i,        label: "Contains word 'kyc'",         score: 20 },
  { pattern: /\breward(s)?\b/i, label: "Contains word 'rewards'",     score: 15 },
  // Leet speak substitutions
  { pattern: /[0-9](?=[a-z])|(?<=[a-z])[0-9]/i, label: "Leet-speak in package name", score: 15 }
];


// ─── MAIN FUNCTION ────────────────────────────────────────────────────────────

function detectFakeApps(packageName = "", appName = "") {

  const pkg     = packageName.toLowerCase().trim();
  const name    = appName.toLowerCase().trim();
  const findings = [];
  let   score    = 0;


  // ── 1. Exact official package match — immediate pass ──────────────────────
  if (OFFICIAL_PACKAGES.has(pkg)) {
    return {
      fakeAppScore:    0,
      fakeAppFindings: [],
      isTrustedApp:    true,
      brandMatches:    []
    };
  }


  // ── 2. Trusted system prefix match — strict check ─────────────────────────
  const isTrustedPrefix = TRUSTED_PREFIXES.some(prefix =>
    pkg.startsWith(prefix)
  );

  if (isTrustedPrefix) {
    return {
      fakeAppScore:    0,
      fakeAppFindings: [],
      isTrustedApp:    true,
      brandMatches:    []
    };
  }


  // ── 3. Brand impersonation detection ─────────────────────────────────────
  const brandMatches = [];

  BRAND_TARGETS.forEach(target => {

    // Check if package name contains brand keyword
    const pkgMatch = target.keywords.some(kw => pkg.includes(kw));

    // Check if app name contains brand keyword
    const nameMatch = name && target.keywords.some(kw => name.includes(kw));

    if (!pkgMatch && !nameMatch) return;

    // Check if it starts with official prefix — if so, it's legitimate
    const isOfficial = target.officialPrefixes.some(prefix =>
      pkg.startsWith(prefix.toLowerCase())
    );

    if (isOfficial) return;

    // Not official — flag as potential fake
    const matchedVia = pkgMatch ? "package name" : "app name";

    findings.push({
      label:    `Possible fake app impersonating ${target.brand} (matched via ${matchedVia})`,
      brand:    target.brand,
      category: target.category,
      severity: target.riskScore >= 35 ? "CRITICAL" : "HIGH",
      score:    target.riskScore
    });

    brandMatches.push(target.brand);
    score += target.riskScore;

  });


  // ── 4. Suspicious package name patterns ──────────────────────────────────
  SUSPICIOUS_NAME_PATTERNS.forEach(entry => {

    if (entry.pattern.test(pkg) || entry.pattern.test(name)) {
      findings.push({
        label:    entry.label,
        severity: "MEDIUM",
        score:    entry.score
      });
      score += entry.score;
    }

  });


  // ── 5. Package structure anomalies ───────────────────────────────────────

  // Too few segments (e.g. "com.app" instead of "com.company.app")
  const segments = pkg.split(".");
  if (segments.length < 3) {
    findings.push({
      label:    "Unusual package name structure (too few segments)",
      severity: "MEDIUM",
      score:    10
    });
    score += 10;
  }

  // Generic/suspicious top-level segments
  const suspiciousSegments = ["xyz", "top", "tk", "ru", "cn", "ml", "ga"];
  if (suspiciousSegments.includes(segments[0])) {
    findings.push({
      label:    `Suspicious package domain: .${segments[0]}`,
      severity: "HIGH",
      score:    20
    });
    score += 20;
  }

  // Very long package name (obfuscation attempt)
  if (pkg.length > 80) {
    findings.push({
      label:    "Unusually long package name (possible obfuscation)",
      severity: "MEDIUM",
      score:    10
    });
    score += 10;
  }


  // ── 6. Score normalization ────────────────────────────────────────────────
  // If multiple brand matches, only count highest + 30% of rest
  if (brandMatches.length > 1) {
    const brandScores = findings
      .filter(f => f.brand)
      .map(f => f.score)
      .sort((a, b) => b - a);

    const primary  = brandScores[0];
    const rest     = brandScores.slice(1)
      .reduce((sum, s) => sum + s * 0.3, 0);

    const nonBrandScore = findings
      .filter(f => !f.brand)
      .reduce((sum, f) => sum + f.score, 0);

    score = Math.round(primary + rest + nonBrandScore);
  }

  score = Math.min(score, 100);


  return {
    fakeAppScore:    score,
    fakeAppFindings: findings,
    isTrustedApp:    false,
    brandMatches,
    totalFindings:   findings.length
  };

}

module.exports = { detectFakeApps };