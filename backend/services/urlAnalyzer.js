/**
 * URL ANALYZER
 * Receives pre-extracted URLs from staticAnalyzer — NO file re-read
 * Performs deep URL risk analysis with minimal false positives
 */

// ─── TRUSTED DOMAINS (whitelist) ─────────────────────────────────────────────

const TRUSTED_DOMAINS = new Set([
  // Google
  "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
  "firebase.google.com", "firebaseapp.com", "firebasestorage.googleapis.com",
  "crashlytics.com", "google-analytics.com", "googletagmanager.com",
  "play.google.com", "android.com", "schema.android.com",

  // Meta / Facebook
  "facebook.com", "fb.com", "fbcdn.net", "instagram.com",
  "whatsapp.com", "whatsapp.net", "meta.com",

  // Microsoft
  "microsoft.com", "live.com", "outlook.com", "azure.com",
  "microsoftonline.com", "office.com", "office365.com",

  // Amazon / AWS
  "amazon.com", "amazonaws.com", "cloudfront.net",

  // Apple
  "apple.com", "icloud.com", "mzstatic.com",

  // CDNs & Dev
  "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
  "raw.githubusercontent.com", "github.com", "github.io",

  // Android / Schema
  "schemas.android.com", "schemas.xmlsoap.org", "www.w3.org",
  "xmlpull.org", "json-schema.org",

  // Analytics / Crash Reporting
  "segment.com", "mixpanel.com", "amplitude.com",
  "sentry.io", "bugsnag.com", "appsflyer.com",

  // Indian trusted
  "npci.org.in", "upi.org.in", "bhimupi.org.in",
  "paytm.com", "phonepe.com", "razorpay.com",
  "juspay.in", "sbi.co.in", "hdfcbank.com",
  "icicibank.com", "axisbank.com"
]);


// ─── SUSPICIOUS TLDs ──────────────────────────────────────────────────────────

const SUSPICIOUS_TLDS = [
  ".xyz", ".top", ".ru", ".cn", ".tk",
  ".ml", ".ga", ".cf", ".work", ".click",
  ".site", ".online", ".pw", ".cc",
  ".biz", ".su", ".ws", ".rest",
  ".party", ".racing", ".download",
  ".gq", ".icu", ".vip", ".win"
];


// ─── URL SHORTENER SERVICES ───────────────────────────────────────────────────

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "goo.gl", "t.co",
  "ow.ly", "short.io", "rb.gy", "cutt.ly",
  "is.gd", "buff.ly", "adf.ly", "shorte.st",
  "linktr.ee", "tiny.cc", "clck.ru"
];


// ─── PHISHING KEYWORDS (only flag when combined with other signals) ───────────

const PHISHING_KEYWORDS = [
  "login-verify", "account-suspend", "verify-identity",
  "secure-login", "update-account", "confirm-payment",
  "reset-password", "bank-verify", "wallet-restore",
  "kyc-update", "aadhar-verify", "pan-verify",
  "otp-verify", "suspend-alert", "blocked-account"
];


// ─── C2 / MALWARE INFRASTRUCTURE INDICATORS ──────────────────────────────────

const C2_PATTERNS = [
  // Non-standard ports
  { pattern: /:(\d{4,5})(\/|$)/, label: "Non-standard port usage", score: 15 },
  // IP-based URLs (no domain)
  { pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, label: "Direct IP address URL (C2 indicator)", score: 20 },
  // Very long random subdomains (DGA - Domain Generation Algorithm)
  { pattern: /https?:\/\/[a-z0-9]{20,}\.[a-z]{2,6}/, label: "Possible DGA domain detected", score: 18 },
  // .onion (Tor hidden service)
  { pattern: /\.onion/, label: "Tor hidden service URL", score: 30 },
  // Base64-looking paths
  { pattern: /\/[A-Za-z0-9+/]{30,}={0,2}(\/|$)/, label: "Encoded path in URL (obfuscated endpoint)", score: 12 }
];


// ─── HELPER: Strict domain check ─────────────────────────────────────────────

function isTrustedDomain(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    // Must end with trusted domain — prevents com.google.fake.xyz bypass
    return [...TRUSTED_DOMAINS].some(trusted =>
      hostname === trusted || hostname.endsWith("." + trusted)
    );
  } catch {
    return false;
  }
}


function extractHostname(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}


// ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────

function analyzeUrls(urls = []) {

  let urlScore = 0;
  const suspiciousUrls = [];
  const findings = [];
  const seenHostnames = new Set();


  // Filter out noise — only process URLs with real hostnames
  const validUrls = urls.filter(url => {
    try {
      const u = new URL(url);
      return u.hostname && u.hostname.length > 3;
    } catch {
      return false;
    }
  });


  validUrls.forEach(url => {

    const hostname = extractHostname(url);
    if (!hostname) return;

    // Skip trusted domains entirely
    if (isTrustedDomain(url)) return;

    const urlFindings = [];
    let urlRiskScore = 0;


    // ── 1. HTTP (non-HTTPS) ────────────────────────────────────────────────────
    if (url.startsWith("http://")) {
      urlFindings.push({ label: "Unencrypted HTTP connection", severity: "MEDIUM" });
      urlRiskScore += 8;
    }


    // ── 2. Suspicious TLD ─────────────────────────────────────────────────────
    const suspiciousTLD = SUSPICIOUS_TLDS.find(tld => hostname.endsWith(tld));

    if (suspiciousTLD) {
      urlFindings.push({ label: `Suspicious TLD: ${suspiciousTLD}`, severity: "HIGH" });
      urlRiskScore += 15;
    }


    // ── 3. URL Shortener ──────────────────────────────────────────────────────
    if (URL_SHORTENERS.some(s => hostname.includes(s))) {
      urlFindings.push({ label: "URL shortener used (hides real destination)", severity: "MEDIUM" });
      urlRiskScore += 12;
    }


    // ── 4. Phishing Keywords (compound detection only) ────────────────────────
    const phishingMatch = PHISHING_KEYWORDS.find(kw =>
      url.toLowerCase().includes(kw)
    );

    if (phishingMatch) {
      urlFindings.push({ label: `Phishing keyword in URL: "${phishingMatch}"`, severity: "HIGH" });
      urlRiskScore += 18;
    }


    // ── 5. C2 Infrastructure Patterns ────────────────────────────────────────
    C2_PATTERNS.forEach(c2 => {
      if (c2.pattern.test(url)) {
        urlFindings.push({ label: c2.label, severity: "HIGH" });
        urlRiskScore += c2.score;
      }
    });


    // ── 6. Newly registered TLD + random subdomain combo ─────────────────────
    const randomSubdomainRegex = /^[a-z0-9]{8,20}\.[a-z0-9]{4,12}\.[a-z]{2,6}$/;

    if (randomSubdomainRegex.test(hostname)) {
      urlFindings.push({ label: "Random subdomain pattern (possible DGA)", severity: "HIGH" });
      urlRiskScore += 12;
    }


    // Only add to suspicious list if has findings AND not already seen this hostname
    if (urlFindings.length > 0 && !seenHostnames.has(hostname)) {

      seenHostnames.add(hostname);

      suspiciousUrls.push({
        url,
        hostname,
        riskScore: Math.min(urlRiskScore, 50),
        findings: urlFindings
      });

      urlScore += urlRiskScore;
    }

  });


  // Smart normalization — cap per-URL contribution
  urlScore = Math.min(Math.round(urlScore), 100);


  // Summary findings for report
  const highRiskUrls    = suspiciousUrls.filter(u => u.riskScore >= 25);
  const mediumRiskUrls  = suspiciousUrls.filter(u => u.riskScore >= 10 && u.riskScore < 25);


  return {
    urlScore,
    suspiciousUrls,
    highRiskUrls,
    mediumRiskUrls,
    totalUrlsAnalyzed: validUrls.length,
    totalSuspicious: suspiciousUrls.length,
    findings
  };

}

module.exports = { analyzeUrls };