/**
 * Password Hashing & Key Stretching Educational Lab Module.
 * Calls POST /api/demo-hash to compare fast vs slow cryptographic hashing.
 */

function initHashingLab() {
  const runBtn = document.getElementById("run-hash-demo-btn");
  const inputEl = document.getElementById("hash-demo-input");
  const iterEl = document.getElementById("hash-iterations");
  const resultsArea = document.getElementById("hash-results-area");

  if (!runBtn) return;

  runBtn.addEventListener("click", async () => {
    const password = inputEl ? inputEl.value : "SyntheticDemoPassword42!";
    const iterations = iterEl ? parseInt(iterEl.value, 10) : 100000;

    runBtn.textContent = "Deriving Cryptographic Keys...";
    runBtn.disabled = true;

    try {
      const res = await fetch("/api/demo-hash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password, iterations })
      });
      const json = await res.json();
      if (json.status === "success") {
        renderHashingResults(json.data);
        if (resultsArea) resultsArea.style.display = "block";
      }
    } catch (e) {
      console.error("Hashing demo error", e);
    } finally {
      runBtn.textContent = "Execute Cryptographic Pipeline";
      runBtn.disabled = false;
    }
  });
}

function renderHashingResults(data) {
  // Fast Hash (SHA-256)
  const fast = data.fast_hash || {};
  const fastValEl = document.getElementById("fast-hash-val");
  const fastTimeEl = document.getElementById("fast-hash-time");
  if (fastValEl) fastValEl.textContent = fast.output || "---";
  if (fastTimeEl) fastTimeEl.textContent = `${fast.duration_ms} ms (Fast)`;

  // Slow Hash (PBKDF2)
  const slow = data.slow_hash || {};
  const slowValEl = document.getElementById("slow-hash-val");
  const slowTimeEl = document.getElementById("slow-hash-time");
  if (slowValEl) slowValEl.textContent = slow.output || "---";
  if (slowTimeEl) slowTimeEl.textContent = `${slow.duration_ms} ms (Stretched)`;

  // Salt & Storage String
  const saltEl = document.getElementById("demo-salt-hex");
  if (saltEl) saltEl.textContent = data.salt_hex || "---";
}
