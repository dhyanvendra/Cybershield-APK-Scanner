/**
 * SECRET SCANNER
 * Receives buffer from hashAnalyzer — NO file re-read
 * Detects hardcoded credentials, API keys, tokens with context validation
 * Severity-weighted scoring to avoid false positives
 */

// ─── SECRET PATTERN DEFINITIONS ──────────────────────────────────────────────

const SECRET_PATTERNS = [

  // ── Cloud Provider Keys ──────────────────────────────────────────────────────
  {
    id: "AWS_ACCESS_KEY",
    label: "AWS Access Key ID",
    category: "Cloud Credentials",
    severity: "CRITICAL",
    score: 30,
    pattern: /AKIA[0-9A-Z]{16}/g,
    validate: (match) => match.length === 20
  },
  {
    id: "AWS_SECRET_KEY",
    label: "AWS Secret Access Key",
    category: "Cloud Credentials",
    severity: "CRITICAL",
    score: 30,
    pattern: /(?:aws_secret_access_key|AWS_SECRET)[^a-zA-Z0-9][a-zA-Z0-9/+]{40}/gi,
    validate: null
  },
  {
    id: "GOOGLE_API_KEY",
    label: "Google API Key",
    category: "Cloud Credentials",
    severity: "HIGH",
    score: 20,
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    validate: (match) => match.length === 39
  },
  {
    id: "GOOGLE_OAUTH",
    label: "Google OAuth Client Secret",
    category: "Cloud Credentials",
    severity: "CRITICAL",
    score: 30,
    pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    validate: null
  },
  {
    id: "AZURE_KEY",
    label: "Azure Subscription Key",
    category: "Cloud Credentials",
    severity: "CRITICAL",
    score: 30,
    pattern: /[a-f0-9]{32}(?:[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/g,
    validate: null
  },

  // ── Payment Keys ─────────────────────────────────────────────────────────────
  {
    id: "STRIPE_SECRET",
    label: "Stripe Secret Key (Live)",
    category: "Payment Credentials",
    severity: "CRITICAL",
    score: 35,
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    validate: null
  },
  {
    id: "STRIPE_RESTRICTED",
    label: "Stripe Restricted Key",
    category: "Payment Credentials",
    severity: "CRITICAL",
    score: 35,
    pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
    validate: null
  },
  {
    id: "RAZORPAY_KEY",
    label: "Razorpay Live Secret Key",
    category: "Payment Credentials",
    severity: "CRITICAL",
    score: 35,
    pattern: /rzp_live_[0-9a-zA-Z]{14,}/g,
    validate: null
  },
  {
    id: "PAYPAL_SECRET",
    label: "PayPal Client Secret",
    category: "Payment Credentials",
    severity: "CRITICAL",
    score: 35,
    pattern: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g,
    validate: null
  },

  // ── Firebase ─────────────────────────────────────────────────────────────────
  {
    id: "FIREBASE_URL",
    label: "Firebase Realtime Database URL",
    category: "Firebase",
    severity: "MEDIUM",
    score: 10,
    pattern: /https:\/\/[a-zA-Z0-9\-]+\.firebaseio\.com/g,
    validate: null
  },
  {
    id: "FIREBASE_DB_APP",
    label: "Firebase Database App URL",
    category: "Firebase",
    severity: "MEDIUM",
    score: 10,
    pattern: /https:\/\/[a-zA-Z0-9\-]+\.firebasedatabase\.app/g,
    validate: null
  },
  {
    id: "FIREBASE_SERVER_KEY",
    label: "Firebase Server Key (FCM Push)",
    category: "Firebase",
    severity: "HIGH",
    score: 20,
    pattern: /AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}/g,
    validate: null
  },

  // ── Source Control & CI ───────────────────────────────────────────────────────
  {
    id: "GITHUB_PAT",
    label: "GitHub Personal Access Token",
    category: "Source Control",
    severity: "CRITICAL",
    score: 30,
    pattern: /ghp_[A-Za-z0-9]{36}/g,
    validate: null
  },
  {
    id: "GITHUB_OAUTH",
    label: "GitHub OAuth Token",
    category: "Source Control",
    severity: "CRITICAL",
    score: 30,
    pattern: /gho_[A-Za-z0-9]{36}/g,
    validate: null
  },
  {
    id: "GITLAB_TOKEN",
    label: "GitLab Personal Access Token",
    category: "Source Control",
    severity: "CRITICAL",
    score: 30,
    pattern: /glpat-[A-Za-z0-9\-_]{20}/g,
    validate: null
  },

  // ── Communication Services ────────────────────────────────────────────────────
  {
    id: "TWILIO_SID",
    label: "Twilio Account SID",
    category: "Communication",
    severity: "HIGH",
    score: 20,
    pattern: /AC[a-zA-Z0-9]{32}/g,
    validate: null
  },
  {
    id: "TWILIO_TOKEN",
    label: "Twilio Auth Token",
    category: "Communication",
    severity: "CRITICAL",
    score: 30,
    pattern: /SK[a-zA-Z0-9]{32}/g,
    validate: null
  },
  {
    id: "SENDGRID_KEY",
    label: "SendGrid API Key",
    category: "Communication",
    severity: "HIGH",
    score: 20,
    pattern: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g,
    validate: null
  },
  {
    id: "SLACK_WEBHOOK",
    label: "Slack Incoming Webhook URL",
    category: "Communication",
    severity: "HIGH",
    score: 20,
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    validate: null
  },
  {
    id: "SLACK_TOKEN",
    label: "Slack Bot/User Token",
    category: "Communication",
    severity: "CRITICAL",
    score: 30,
    pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}/g,
    validate: null
  },

  // ── Authentication Tokens ─────────────────────────────────────────────────────
  {
    id: "JWT_TOKEN",
    label: "JWT Token (with valid structure)",
    category: "Authentication",
    severity: "HIGH",
    score: 15,
    // Strict JWT — must have 3 parts each 10+ chars, starting with eyJ
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    validate: (match) => {
      // Extra validation — all 3 parts must be non-trivial
      const parts = match.split(".");
      return parts.length === 3 && parts.every(p => p.length >= 10);
    }
  },
  {
    id: "BEARER_TOKEN",
    label: "Hardcoded Bearer Token",
    category: "Authentication",
    severity: "HIGH",
    score: 15,
    pattern: /Bearer\s+[A-Za-z0-9\-_\.]{32,}/g,
    validate: null
  },
  {
    id: "BASIC_AUTH",
    label: "Hardcoded Basic Auth Credentials",
    category: "Authentication",
    severity: "CRITICAL",
    score: 30,
    pattern: /Basic\s+[A-Za-z0-9+/]{20,}={0,2}/g,
    validate: (match) => {
      // Try to decode and check if it looks like user:pass
      try {
        const decoded = Buffer.from(
          match.replace("Basic ", ""), "base64"
        ).toString("utf8");
        return decoded.includes(":");
      } catch {
        return false;
      }
    }
  },

  // ── Crypto & Wallets ──────────────────────────────────────────────────────────
  {
    id: "PRIVATE_KEY_PEM",
    label: "RSA/EC Private Key (PEM format)",
    category: "Cryptographic Keys",
    severity: "CRITICAL",
    score: 40,
    pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g,
    validate: null
  },
  {
    id: "BTC_PRIVATE_KEY",
    label: "Bitcoin Private Key (WIF format)",
    category: "Cryptographic Keys",
    severity: "CRITICAL",
    score: 35,
    pattern: /[5KL][1-9A-HJ-NP-Za-km-z]{50,51}/g,
    validate: (match) => match.length >= 51 && match.length <= 52
  },
  {
    id: "ETH_PRIVATE_KEY",
    label: "Ethereum Private Key",
    category: "Cryptographic Keys",
    severity: "CRITICAL",
    score: 35,
    pattern: /(?:0x)?[0-9a-fA-F]{64}/g,
    validate: (match) => {
      // Must be exactly 64 hex chars (or 66 with 0x)
      const cleaned = match.startsWith("0x") ? match.slice(2) : match;
      return cleaned.length === 64;
    }
  },
  {
    id: "MNEMONIC_PHRASE",
    label: "Crypto Wallet Mnemonic Phrase",
    category: "Cryptographic Keys",
    severity: "CRITICAL",
    score: 40,
    pattern: /\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse)\b.{0,200}\b(zoo|zone|zero|year|young)\b/gi,
    validate: null
  },

  // ── Database Credentials ──────────────────────────────────────────────────────
  {
    id: "MONGODB_URI",
    label: "MongoDB Connection String with Credentials",
    category: "Database",
    severity: "CRITICAL",
    score: 35,
    pattern: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@[^\s"']+/g,
    validate: null
  },
  {
    id: "MYSQL_URI",
    label: "MySQL Connection String with Credentials",
    category: "Database",
    severity: "CRITICAL",
    score: 35,
    pattern: /mysql:\/\/[^:]+:[^@]+@[^\s"']+/g,
    validate: null
  },
  {
    id: "POSTGRES_URI",
    label: "PostgreSQL Connection String with Credentials",
    category: "Database",
    severity: "CRITICAL",
    score: 35,
    pattern: /postgres(ql)?:\/\/[^:]+:[^@]+@[^\s"']+/g,
    validate: null
  },
  {
    id: "HARDCODED_PASSWORD",
    label: "Hardcoded Password in Code",
    category: "Authentication",
    severity: "HIGH",
    score: 20,
    // Must have quotes and non-trivial value (min 8 chars)
    pattern: /(?:password|passwd|pwd|secret|api_secret)\s*[=:]\s*["'][^"']{8,}["']/gi,
    validate: (match) => {
      // Exclude obvious placeholders
      const lower = match.toLowerCase();
      const placeholders = [
        "password", "your_password", "changeme",
        "placeholder", "example", "xxxxxxxx",
        "12345678", "testtest", "password123"
      ];
      return !placeholders.some(p => lower.includes(p));
    }
  },

];


// ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────

function scanSecrets(buffer) {

  const content = buffer.toString("latin1");

  const findings = [];
  const seenIds  = new Set();
  let secretScore = 0;


  SECRET_PATTERNS.forEach(secret => {

    // Reset regex lastIndex for global patterns
    secret.pattern.lastIndex = 0;

    const matches = content.match(secret.pattern);

    if (!matches || matches.length === 0) return;

    // Run validation if defined
    const validMatches = matches.filter(m =>
      secret.validate ? secret.validate(m) : true
    );

    if (validMatches.length === 0) return;

    // Deduplicate by ID — only report each secret type once
    if (seenIds.has(secret.id)) return;
    seenIds.add(secret.id);

    // Redact actual secret value — show only first 6 chars
    const redacted = validMatches[0].slice(0, 6) + "****[REDACTED]";

    findings.push({
      id:        secret.id,
      label:     secret.label,
      category:  secret.category,
      severity:  secret.severity,
      score:     secret.score,
      sample:    redacted,
      count:     validMatches.length
    });

    secretScore += secret.score;

  });


  // Smart normalization — critical secrets dominate score
  if (findings.length > 1) {
    const sorted = findings.map(f => f.score).sort((a, b) => b - a);
    const primary = sorted[0];
    const rest = sorted.slice(1).reduce((sum, s) => sum + s * 0.25, 0);
    secretScore = Math.round(primary + rest);
  }

  secretScore = Math.min(secretScore, 100);


  // Group by category
  const byCategory = {};
  findings.forEach(f => {
    if (!byCategory[f.category]) byCategory[f.category] = [];
    byCategory[f.category].push(f);
  });


  // Severity summary
  const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;
  const highCount     = findings.filter(f => f.severity === "HIGH").length;


  return {
    secretScore,
    findings,
    byCategory,
    criticalCount,
    highCount,
    totalSecrets: findings.length,
    hasCredentialLeak: criticalCount > 0
  };

}

module.exports = { scanSecrets };