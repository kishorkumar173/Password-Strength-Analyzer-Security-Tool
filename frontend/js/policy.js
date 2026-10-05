/**
 * Enterprise Password Policy Evaluator Module.
 * Connects frontend configuration with POST /api/check-policy.
 */

function initPolicyChecker() {
  const checkBtn = document.getElementById("run-policy-check-btn");
  const testInput = document.getElementById("policy-test-password");

  if (!checkBtn) return;

  checkBtn.addEventListener("click", async () => {
    const password = testInput ? testInput.value : "";
    if (!password) {
      alert("Please enter a candidate password to evaluate.");
      return;
    }

    const minLength = parseInt(document.getElementById("policy-min-len").value, 10);
    const maxLength = parseInt(document.getElementById("policy-max-len").value, 10);
    const rejectCommon = document.getElementById("policy-reject-common").checked;
    const allowSpaces = document.getElementById("policy-allow-spaces").checked;
    const rejectContext = document.getElementById("policy-reject-context").checked;

    const reqLower = document.getElementById("policy-req-lower").checked;
    const reqUpper = document.getElementById("policy-req-upper").checked;
    const reqDigits = document.getElementById("policy-req-digits").checked;
    const reqSymbols = document.getElementById("policy-req-symbols").checked;

    const payload = {
      password: password,
      policy: {
        min_length: minLength,
        max_length: maxLength,
        require_lowercase: reqLower,
        require_uppercase: reqUpper,
        require_digits: reqDigits,
        require_symbols: reqSymbols,
        reject_common: rejectCommon,
        allow_spaces: allowSpaces,
        reject_personal_context: rejectContext
      }
    };

    try {
      const res = await fetch("/api/check-policy", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const json = await res.json();
      if (json.status === "success") {
        renderPolicyVerdict(json.data);
      }
    } catch (err) {
      console.error("Policy check failed", err);
    }
  });
}

function renderPolicyVerdict(data) {
  const badgeEl = document.getElementById("policy-verdict-badge");
  const bannerEl = document.getElementById("policy-verdict-banner");
  const rulesListEl = document.getElementById("policy-rules-list");
  const nistTextEl = document.getElementById("nist-compliance-text");

  const passed = data.passed;

  // 1. Badge & Banner
  if (badgeEl) {
    badgeEl.textContent = passed ? "POLICY PASS" : "POLICY FAIL";
    badgeEl.className = `badge ${passed ? "badge-success" : "badge-danger"}`;
  }

  if (bannerEl) {
    if (passed) {
      bannerEl.style.backgroundColor = "rgba(16, 185, 129, 0.15)";
      bannerEl.style.border = "1px solid rgba(16, 185, 129, 0.3)";
      bannerEl.innerHTML = `
        <h3 style="color:var(--color-very-strong);">✓ Password Conforms to Active Policy</h3>
        <p>All ${data.total_rules} configured organizational and security rules satisfied.</p>
      `;
    } else {
      bannerEl.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
      bannerEl.style.border = "1px solid rgba(239, 68, 68, 0.3)";
      bannerEl.innerHTML = `
        <h3 style="color:var(--color-very-weak);">❌ Password Violated Policy Rules</h3>
        <p>Failed ${data.failed_count} rule(s): <strong>${data.failed_rules.join(", ")}</strong></p>
      `;
    }
  }

  // 2. Rules Breakdown Table
  if (rulesListEl) {
    const rules = data.rules || [];
    rulesListEl.innerHTML = rules.map(r => `
      <div style="display:flex; justify-content:space-between; align-items:center; padding:0.6rem 0; border-bottom:1px solid var(--border-color); font-size:0.85rem;">
        <div>
          <strong>${r.rule}</strong>
          <div style="font-size:0.75rem; color:var(--text-secondary);">${r.detail} (${r.threshold})</div>
        </div>
        <span class="badge ${r.status === 'PASS' ? 'badge-success' : 'badge-danger'}">${r.status}</span>
      </div>
    `).join("");
  }

  // 3. NIST commentary
  if (nistTextEl && data.nist_guidance) {
    const nist = data.nist_guidance;
    nistTextEl.innerHTML = `
      <strong>NIST SP 800-63B Alignment: ${nist.sp800_63b_compliant ? '✅ COMPLIANT' : '⚠️ NON-RECOMMENDED LEGACY RESTRICTIONS DETECTED'}</strong><br>
      ${nist.commentary}
    `;
  }
}
