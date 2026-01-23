const express = require("express");
const path = require("path");
const fs = require("fs");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const { runSQLInjectionTest } = require("./utils/sqlInjectionTest");
const { runLoadTest } = require("./utils/ddostest");
const { logMaliciousIP } = require("./utils/ipLogger");
const { spawn } = require("child_process");

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));

// MySQL Connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "security_scanner"
});

db.connect((err) => {
  if (err) {
    console.error("MySQL Connection Error:", err.message);
    console.log("Continuing without database connection...");
  } else {
    console.log("MySQL Connected");
  }
});

// ------------------------------------------
// API: SQL Injection Test
// ------------------------------------------
app.post("/scan/sql", async (req, res) => {
  const { url } = req.body;
  const result = await runSQLInjectionTest(url);
  res.json(result);
});

// ------------------------------------------
// API: DDoS Attack Simulation Test
// ------------------------------------------
app.post("/scan/ddos", async (req, res) => {
  const { url } = req.body;
  try {
    const result = await runLoadTest(url, { duration: 10, connections: 50 });
    
    if (result.vulnerability.score > 50) {
      logMaliciousIP(db, "127.0.0.1");
    }
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ------------------------------------------
// API: Fetch Malicious IP Entries
// ------------------------------------------
app.get("/malicious-ips", (req, res) => {
  db.query("SELECT * FROM malicious_ips", (err, rows) => {
    if (err) {
      console.error("Database error:", err.message);
      return res.status(500).json({ error: "Database query failed" });
    }
    res.json(rows);
  });
});

// ------------------------------------------
// API: Delete all Malicious IP Entries
// ------------------------------------------
app.delete("/malicious-ips", (req, res) => {
  if (!db || typeof db.query !== 'function') {
    return res.status(503).json({ error: 'Database not available' });
  }

  db.query("DELETE FROM malicious_ips", (err, result) => {
    if (err) {
      console.error("Database delete error:", err.message);
      return res.status(500).json({ error: 'Failed to clear malicious IPs' });
    }

    res.json({ deleted: result.affectedRows || 0 });
  });
});

// ------------------------------------------
// Route: Serve microfinance demo (for testing)
// ------------------------------------------
app.get("/demo", (req, res) => {
  const demoPath = path.join("C:\\Users\\user\\OneDrive\\Desktop\\microfinance-demo\\index.html");
  if (fs.existsSync(demoPath)) {
    res.sendFile(demoPath);
  } else {
    res.status(404).json({ error: "Demo file not found" });
  }
});

// ------------------------------------------
// API: ML-Based Anomaly Detection
// ------------------------------------------
app.post("/analyze/anomalies", (req, res) => {
  const { url } = req.body;
  const script = path.join(__dirname, "ml", "anomalydetector.py");
  const pythonExe = path.join(__dirname, ".venv", "Scripts", "python.exe");
  
  // Build arguments: if URL is provided, pass --url and --sample arguments
  const args = [];
  if (url) {
    args.push("--url", url, "--sample", "50");
  } else {
    args.push("--sample", "50");
  }

  const process = spawn(pythonExe, [script, ...args]);

  let output = "";
  let errorOutput = "";

  process.stdout.on("data", (data) => (output += data.toString()));
  process.stderr.on("data", (data) => {
    errorOutput += data.toString();
    console.error("Python Error:", data.toString());
  });

  process.on("close", (code) => {
    try {
      if (code !== 0 && !output) {
        res.status(500).json({ error: "ML script failed", details: errorOutput });
      } else {
        res.json(JSON.parse(output));
      }
    } catch (e) {
      res.status(500).json({ error: "Failed to parse ML output", details: e.message });
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));