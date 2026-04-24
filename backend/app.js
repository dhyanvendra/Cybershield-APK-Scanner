/**
 * CYBERSHIELD — Main Application Entry Point
 * Production-grade Express server
 * Rate limiting, security headers, logging, error handling
 */

require("dotenv").config();

const express      = require("express");
const cors         = require("cors");
const path         = require("path");
const fs           = require("fs");
const helmet       = require("helmet");
const rateLimit    = require("express-rate-limit");
const morgan       = require("morgan");

const scanRoutes   = require("./routes/scan");

const app = express();


// ─── ENSURE DIRECTORIES EXIST ────────────────────────────────────────────────

const DIRS = [
  path.join(__dirname, "uploads"),
  path.join(__dirname, "reports"),
  path.join(__dirname, "logs")
];

DIRS.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});


// ─── LOGGING SETUP ───────────────────────────────────────────────────────────

// Access log stream
const accessLogStream = fs.createWriteStream(
  path.join(__dirname, "logs", "access.log"),
  { flags: "a" }
);

// Console + file logging
app.use(morgan("combined", { stream: accessLogStream }));
app.use(morgan("dev"));  // Console output during development


// ─── SECURITY HEADERS ────────────────────────────────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "fonts.googleapis.com"],
      styleSrc:    ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
      fontSrc:     ["'self'", "fonts.gstatic.com"],
      imgSrc:      ["'self'", "data:", "blob:"],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false  // Allow PDF viewing in browser
}));


// ─── CORS ────────────────────────────────────────────────────────────────────

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || "*",
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));


// ─── BODY PARSING ────────────────────────────────────────────────────────────

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));


// ─── RATE LIMITING ───────────────────────────────────────────────────────────

// Global rate limit
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max:      100,              // 100 requests per window
  standardHeaders: true,
  legacyHeaders:   false,
  message: {
    error:   "Too many requests",
    message: "Please wait before making more requests"
  }
});

// Strict scan rate limit — prevent abuse
const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max:      10,               // 10 scans per 15 minutes
  standardHeaders: true,
  legacyHeaders:   false,
  message: {
    error:   "Scan limit reached",
    message: "Maximum 10 scans per 15 minutes. Please wait before scanning again."
  }
});

app.use(globalLimiter);
app.use("/scan", scanLimiter);


// ─── STATIC FILES ────────────────────────────────────────────────────────────

// Reports — with cache headers
app.use("/reports", express.static(
  path.join(__dirname, "reports"),
  {
    maxAge:      "1h",
    etag:        true,
    lastModified: true
  }
));

// Uploads — no public access to uploads
// (intentionally not serving uploads directory)


// ─── API ROUTES ───────────────────────────────────────────────────────────────

app.use("/scan", scanRoutes);


// ─── HEALTH CHECK ────────────────────────────────────────────────────────────

app.get("/api/health", (req, res) => {
  res.json({
    status:    "operational",
    service:   "CyberShield APK Scanner",
    version:   "2.0.0",
    timestamp: new Date().toISOString(),
    uptime:    Math.round(process.uptime()) + "s",
    environment: process.env.NODE_ENV || "development",
    vtApiConfigured: !!process.env.VT_API_KEY
  });
});


// ─── SERVE FRONTEND ───────────────────────────────────────────────────────────

const FRONTEND_DIR = path.join(__dirname, "../frontend");

if (fs.existsSync(FRONTEND_DIR)) {
  // Serve static files from frontend directory
  app.use(express.static(FRONTEND_DIR, {
    maxAge: "1h",
    etag:   true
  }));

  // SPA fallback - FIXED for Express 5.x (no wildcard "*" support)
  // Using middleware instead of app.get("*")
  app.use((req, res, next) => {
    // Skip API routes
    if (req.path.startsWith("/api") ||
        req.path.startsWith("/scan") ||
        req.path.startsWith("/reports")) {
      return next();
    }
    
    // Skip if requesting a static file with extension (css, js, images, etc.)
    // This ensures express.static handles them properly
    if (path.extname(req.path) !== '') {
      return next();
    }
    
    // For all other routes, serve index.html (SPA routing)
    res.sendFile(path.join(FRONTEND_DIR, "index.html"));
  });
}


// ─── GLOBAL ERROR HANDLER ─────────────────────────────────────────────────────

app.use((err, req, res, next) => {

  // Log full error
  console.error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.error("SERVER ERROR:", err.message);
  console.error("Stack:", err.stack);
  console.error("Path:", req.path);
  console.error("Method:", req.method);
  console.error("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  // Multer errors
  if (err.code === "LIMIT_FILE_SIZE") {
    return res.status(400).json({
      error:   "File too large",
      message: "APK file must be under 100MB"
    });
  }

  // Don't leak error details in production
  const isDev = process.env.NODE_ENV !== "production";

  res.status(err.status || 500).json({
    error:   "Internal Server Error",
    message: isDev ? err.message : "Something went wrong. Please try again.",
    ...(isDev && { stack: err.stack })
  });

});


// ─── 404 HANDLER ─────────────────────────────────────────────────────────────

app.use((req, res) => {
  res.status(404).json({
    error:   "Not Found",
    message: `Route ${req.method} ${req.path} does not exist`
  });
});


// ─── STARTUP ─────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 8000;

const server = app.listen(PORT, () => {

  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  🛡️  CyberShield APK Scanner v2.0.0");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log(`  🚀 Server     : http://localhost:${PORT}`);
  console.log(`  🌍 Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`  🔑 VT API     : ${process.env.VT_API_KEY ? "✅ Configured" : "❌ Not configured"}`);
  console.log(`  📁 Reports    : ${path.join(__dirname, "reports")}`);
  console.log(`  📋 Logs       : ${path.join(__dirname, "logs")}`);
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

});


// ─── GRACEFUL SHUTDOWN ────────────────────────────────────────────────────────

process.on("SIGTERM", () => {
  console.log("SIGTERM received — shutting down gracefully");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("\nSIGINT received — shutting down gracefully");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});


module.exports = app;