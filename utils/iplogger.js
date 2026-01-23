function logMaliciousIP(db, ip) {
  if (!ip) return;

  db.query(
    "INSERT INTO malicious_ips(ip_address, detected_at) VALUES (?, NOW())",
    [ip]
  );
}

module.exports = { logMaliciousIP };

