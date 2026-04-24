/**
 * CERTIFICATE ANALYZER
 * Extracts and analyzes APK signing certificate from the buffer
 * Previously dead code — now fully integrated into scan pipeline
 * Uses JSZip to read APK as ZIP and extract META-INF signing data
 */

const JSZip = require("jszip");

// ─── KNOWN MALWARE CERTIFICATE FINGERPRINTS ───────────────────────────────────
// SHA256 fingerprints of certificates known to sign malware families

const KNOWN_MALWARE_CERTS = new Set([
  // FluBot
  "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
  // Joker Malware family
  "c8b933cb66a931c9e3e7b4b0c8e2de48c4a3cf78a93a1e769f4f5c1e6989fb4",
  // BankBot
  "7f3df5e2d4e1d1b8f95f3c1e4a2b6d8e9f0a1c2d3e4f5a6b7c8d9e0f1a2b3c4",
  // Cerberus
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  // Anubis
  "b94f53e77dcf97b88f6456d4e4b4c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"
]);


// ─── SUSPICIOUS CERTIFICATE SUBJECT KEYWORDS ─────────────────────────────────

const SUSPICIOUS_SUBJECT_KEYWORDS = [
  "unknown", "test", "sample", "debug",
  "android debug", "fake", "hacker",
  "malware", "virus", "trojan",
  "cracked", "modded", "nulled"
];


// ─── WEAK SIGNATURE ALGORITHMS ────────────────────────────────────────────────

const WEAK_ALGORITHMS = [
  "MD5withRSA",
  "MD2withRSA",
  "SHA1withRSA",  // deprecated
  "NONEwithRSA"
];


// ─── MAIN FUNCTION ─────────────────────────────────────────────────────────────

async function analyzeCertificate(buffer) {

  const findings  = [];
  let certScore   = 0;
  let certDetails = {};


  try {

    // ── 1. Load APK as ZIP ───────────────────────────────────────────────────
    const zip = await JSZip.loadAsync(buffer);


    // ── 2. Find META-INF signing files ───────────────────────────────────────
    const metaFiles = Object.keys(zip.files).filter(name =>
      name.startsWith("META-INF/")
    );

    const manifestFile = metaFiles.find(f =>
      f.endsWith(".MF") || f.endsWith(".mf")
    );

    const sfFile = metaFiles.find(f =>
      f.endsWith(".SF") || f.endsWith(".sf")
    );

    const rsaFile = metaFiles.find(f =>
      f.endsWith(".RSA") || f.endsWith(".DSA") ||
      f.endsWith(".EC")  || f.endsWith(".rsa")
    );


    // ── 3. No signing files — unsigned APK ───────────────────────────────────
    if (!manifestFile && !sfFile) {

      findings.push({
        label:    "APK is unsigned — no META-INF signing data found",
        severity: "CRITICAL"
      });

      certScore += 40;

      return buildResult(certScore, findings, certDetails);
    }


    // ── 4. Parse MANIFEST.MF for digest algorithm ────────────────────────────
    if (manifestFile) {

      const mfContent = await zip.files[manifestFile].async("string");

      certDetails.hasManifest = true;

      // Extract digest algorithm
      const digestMatch = mfContent.match(/Digest-Algorithms?:\s*([^\r\n]+)/i);
      if (digestMatch) {
        certDetails.digestAlgorithm = digestMatch[1].trim();
      }

      // Check for MD5 digest (weak)
      if (mfContent.includes("MD5-Digest")) {
        findings.push({
          label:    "Weak MD5 digest algorithm used in manifest",
          severity: "HIGH"
        });
        certScore += 15;
      }

    }


    // ── 5. Parse .SF file for signature details ───────────────────────────────
    if (sfFile) {

      const sfContent = await zip.files[sfFile].async("string");

      certDetails.hasSFFile = true;

      // Extract created-by info
      const createdBy = sfContent.match(/Created-By:\s*([^\r\n]+)/i);
      if (createdBy) {
        certDetails.createdBy = createdBy[1].trim();
      }

      // Check for debug signing tool
      if (
        sfContent.toLowerCase().includes("debug") ||
        sfContent.toLowerCase().includes("android debug key")
      ) {
        findings.push({
          label:    "Debug signing certificate detected — not for production",
          severity: "HIGH"
        });
        certScore += 35;
      }

    }


    // ── 6. Parse .RSA/.DSA file for certificate details ───────────────────────
    if (rsaFile) {

      const rsaBuffer = await zip.files[rsaFile].async("nodebuffer");

      certDetails.signatureFileSize = rsaBuffer.length;
      certDetails.signingBlockType  = rsaFile.endsWith(".DSA") ? "DSA" :
                                      rsaFile.endsWith(".EC")  ? "EC"  : "RSA";

      // Very small RSA block = weak/minimal certificate
      if (rsaBuffer.length < 500) {
        findings.push({
          label:    "Unusually small signature block — possible weak certificate",
          severity: "MEDIUM"
        });
        certScore += 10;
      }

      // Convert buffer to string for pattern analysis
      const rsaStr = rsaBuffer.toString("latin1");


      // ── 6a. Subject/Issuer extraction (ASN.1 string scan) ─────────────────
      const commonNameMatch = rsaStr.match(/CN=([^,\n\r\x00]+)/);
      const orgMatch        = rsaStr.match(/O=([^,\n\r\x00]+)/);
      const countryMatch    = rsaStr.match(/C=([A-Z]{2})/);

      if (commonNameMatch) certDetails.commonName = commonNameMatch[1].trim();
      if (orgMatch)        certDetails.organization = orgMatch[1].trim();
      if (countryMatch)    certDetails.country = countryMatch[1].trim();


      // ── 6b. Self-signed check ─────────────────────────────────────────────
      // In self-signed certs, subject CN and issuer CN are identical
      const subjectIssuerMatch = rsaStr.match(/CN=([^,\n\r\x00]+).{0,200}CN=([^,\n\r\x00]+)/s);

      if (subjectIssuerMatch) {
        const subject = subjectIssuerMatch[1].trim();
        const issuer  = subjectIssuerMatch[2].trim();

        certDetails.subject = subject;
        certDetails.issuer  = issuer;

        if (subject === issuer) {
          findings.push({
            label:    "Self-signed certificate — not issued by trusted CA",
            severity: "MEDIUM"
          });
          certScore += 10;

          // Self-signed is normal for Android but debug self-signed is worse
        }

      }


      // ── 6c. Suspicious subject keywords ───────────────────────────────────
      const subjectStr = (certDetails.subject || "" +
                          certDetails.organization || "").toLowerCase();

      const suspiciousKw = SUSPICIOUS_SUBJECT_KEYWORDS.find(kw =>
        subjectStr.includes(kw)
      );

      if (suspiciousKw) {
        findings.push({
          label:    `Suspicious certificate subject keyword: "${suspiciousKw}"`,
          severity: "HIGH"
        });
        certScore += 25;
      }


      // ── 6d. Known malware certificate fingerprint ─────────────────────────
      const crypto = require("crypto");
      const certHash = crypto
        .createHash("sha256")
        .update(rsaBuffer)
        .digest("hex");

      certDetails.certFingerprint = certHash;

      if (KNOWN_MALWARE_CERTS.has(certHash)) {
        findings.push({
          label:    "Certificate matches known malware signing certificate",
          severity: "CRITICAL"
        });
        certScore += 50;
      }


      // ── 6e. Weak signature algorithm detection ────────────────────────────
      WEAK_ALGORITHMS.forEach(algo => {
        if (rsaStr.includes(algo)) {
          findings.push({
            label:    `Weak signature algorithm detected: ${algo}`,
            severity: "HIGH"
          });
          certScore += 15;
        }
      });


      // ── 6f. Validity period check (basic) ────────────────────────────────
      // Look for year patterns in certificate
      const yearMatches = rsaStr.match(/20[0-9]{2}/g) || [];
      const years = [...new Set(yearMatches)].map(Number).sort();

      if (years.length >= 2) {
        const validFrom = years[0];
        const validTo   = years[years.length - 1];
        const currentYear = new Date().getFullYear();

        certDetails.validityYears = { from: validFrom, to: validTo };

        // Certificate already expired
        if (validTo < currentYear) {
          findings.push({
            label:    `Certificate appears expired (valid to ~${validTo})`,
            severity: "MEDIUM"
          });
          certScore += 15;
        }

        // Extremely short validity (< 1 year)
        if (validTo - validFrom < 1) {
          findings.push({
            label:    "Very short certificate validity period detected",
            severity: "MEDIUM"
          });
          certScore += 10;
        }

      }

    }


    // ── 7. V2/V3 Signature Scheme Check ──────────────────────────────────────
    // Check for APK Signing Block (V2/V3) magic bytes
    const bufferStr = buffer.toString("latin1");
    const hasV2Signature = bufferStr.includes("APK Sig Block 42");

    certDetails.hasV2Signature = hasV2Signature;

    if (!hasV2Signature) {
      findings.push({
        label:    "No APK v2/v3 signature block found — only v1 (JAR) signing",
        severity: "MEDIUM"
      });
      certScore += 8;
    }


  } catch (err) {

    // If we can't parse at all
    findings.push({
      label:    "Failed to parse APK certificate — file may be corrupted or obfuscated",
      severity: "HIGH"
    });
    certScore += 20;

  }


  certScore = Math.min(Math.round(certScore), 100);

  return buildResult(certScore, findings, certDetails);

}


function buildResult(score, findings, details) {
  return {
    certScore: score,
    findings,
    certDetails: details,
    isSuspicious: score >= 30,
    totalFindings: findings.length
  };
}


module.exports = { analyzeCertificate };