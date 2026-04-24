const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

/**
 * Reads APK file once and generates MD5, SHA1, SHA256 hashes.
 * Returns buffer so all other services reuse it — NO double file reads.
 */
async function generateApkHash(filePath) {

  // Validate file exists
  if (!fs.existsSync(filePath)) {
    throw new Error("APK file not found at path: " + filePath);
  }

  // Read file ONCE — buffer shared across all services
  const fileBuffer = await fs.promises.readFile(filePath);

  const md5    = crypto.createHash("md5").update(fileBuffer).digest("hex");
  const sha1   = crypto.createHash("sha1").update(fileBuffer).digest("hex");
  const sha256 = crypto.createHash("sha256").update(fileBuffer).digest("hex");

  // File size in human readable form
  const bytes = fileBuffer.length;
  const fileSizeFormatted = formatBytes(bytes);

  // File name
  const fileName = path.basename(filePath);

  return {
    md5,
    sha1,
    sha256,
    fileSize: bytes,
    fileSizeFormatted,
    fileName,
    buffer: fileBuffer   // <-- passed to ALL other services
  };

}


function formatBytes(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}


module.exports = { generateApkHash };