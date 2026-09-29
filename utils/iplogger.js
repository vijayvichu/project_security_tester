/**
 * IP Logger with In-Memory Fallback
 * Logs malicious IPs with automatic fallback to in-memory storage if MySQL is unavailable
 */

// In-memory storage for when database is not available
const memoryIPLog = [];
const MAX_MEMORY_ENTRIES = 1000;

/**
 * Log a malicious IP address
 * @param {Object} db - MySQL database connection (optional)
 * @param {string} ip - IP address to log
 * @param {string} reason - Reason for flagging (optional)
 */
function logMaliciousIP(db, ip, reason = 'Suspicious Activity') {
  if (!ip) return;
  
  const entry = {
    id: memoryIPLog.length + 1,
    ip_address: ip,
    detected_at: new Date().toISOString(),
    reason: reason
  };
  
  // Try database first
  if (db && typeof db.query === 'function') {
    try {
      // Check if table exists first
      db.query(
        "INSERT INTO malicious_ips (ip_address, detected_at, reason) VALUES (?, NOW(), ?)",
        [ip, reason],
        (err) => {
          if (err) {
            console.warn('Database logging failed, using memory fallback:', err.message);
            addToMemoryLog(entry);
          }
        }
      );
    } catch (e) {
      console.warn('Database error, using memory fallback:', e.message);
      addToMemoryLog(entry);
    }
  } else {
    // No database, use memory
    addToMemoryLog(entry);
  }
}

/**
 * Add entry to memory log
 */
function addToMemoryLog(entry) {
  // Remove duplicates
  const existingIndex = memoryIPLog.findIndex(e => e.ip_address === entry.ip_address);
  if (existingIndex !== -1) {
    // Update existing entry
    memoryIPLog[existingIndex] = entry;
  } else {
    // Add new entry
    memoryIPLog.push(entry);
  }
  
  // Limit memory log size
  if (memoryIPLog.length > MAX_MEMORY_ENTRIES) {
    memoryIPLog.shift();
  }
}

/**
 * Get all logged IPs
 * @param {Object} db - MySQL database connection (optional)
 * @returns {Promise<Array>} - Array of logged IPs
 */
async function getLoggedIPs(db) {
  if (db && typeof db.query === 'function') {
    try {
      return await Promise.race([
        new Promise((resolve, reject) => {
          db.query("SELECT * FROM malicious_ips ORDER BY detected_at DESC LIMIT 100", (err, results) => {
            if (err) {
              console.warn('Database query failed, using memory fallback:', err.message);
              resolve([...memoryIPLog]);
            } else {
              resolve(results);
            }
          });
        }),
        new Promise((resolve) => {
          setTimeout(() => {
            console.warn('Database query timeout, using memory fallback');
            resolve([...memoryIPLog]);
          }, 1000);
        })
      ]);
    } catch (e) {
      console.warn('Database error, using memory fallback:', e.message);
    }
  }
  return [...memoryIPLog];
}

/**
 * Clear all logged IPs
 * @param {Object} db - MySQL database connection (optional)
 */
async function clearLoggedIPs(db) {
  // Clear memory
  memoryIPLog.length = 0;
  
  // Try database
  if (db && typeof db.query === 'function') {
    try {
      await Promise.race([
        new Promise((resolve, reject) => {
          db.query("DELETE FROM malicious_ips", (err) => {
            if (err) {
              console.warn('Database clear failed:', err.message);
            }
            resolve();
          });
        }),
        new Promise((resolve) => {
          setTimeout(() => {
            console.warn('Database clear timeout');
            resolve();
          }, 1000);
        })
      ]);
    } catch (e) {
      console.warn('Database error:', e.message);
    }
  }
}

/**
 * Get count of logged IPs
 * @returns {number}
 */
function getLoggedIPCount() {
  return memoryIPLog.length;
}

module.exports = { 
  logMaliciousIP, 
  getLoggedIPs, 
  clearLoggedIPs,
  getLoggedIPCount,
  memoryIPLog 
};
