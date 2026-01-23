
function out(msg) {
  document.getElementById("output").textContent =
    JSON.stringify(msg, null, 2);
}

async function runSQLTest() {
  const url = document.getElementById("url").value;
  const res = await fetch("/scan/sql", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });
  out(await res.json());
}

async function runDDOSTest() {
  const url = document.getElementById("url").value;
  const res = await fetch("/scan/ddos", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });
  out(await res.json());
}

async function fetchMaliciousIPs() {
  const res = await fetch("/malicious-ips");
  out(await res.json());
}

async function runML() {
  const url = document.getElementById("url").value;
  const res = await fetch("/analyze/anomalies", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });
  out(await res.json());
}
