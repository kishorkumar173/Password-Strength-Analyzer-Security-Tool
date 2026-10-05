/**
 * Real-Time Password Strength Meter & Interactive Analyzer Module.
 * - Listens for input changes with debouncing
 * - Calls POST /api/analyze transiently
 * - Updates DOM (progress bar, score gauge, findings, suggestions, checklist)
 * - Safe Show/Hide password toggle without console logging
 */

let analyzeDebounceTimer = null;

function initPasswordMeter() {
  const passwordInput = document.getElementById("password-input");
  const toggleBtn = document.getElementById("toggle-password-btn");
  const firstNameInput = document.getElementById("first-name-input");
  const birthYearInput = document.getElementById("birth-year-input");
  const orgInput = document.getElementById("organization-input");

  if (!passwordInput) return;

  // 1. Real-time typing listener with 150ms debounce
  passwordInput.addEventListener("input", () => {
    updateClientChecklist(passwordInput.value);
    clearTimeout(analyzeDebounceTimer);
    analyzeDebounceTimer = setTimeout(() => {
      triggerAnalysis();
    }, 150);
  });

  // Re-trigger analysis if context fields change
  [firstNameInput, birthYearInput, orgInput].forEach((input) => {
    if (input) {
      input.addEventListener("input", () => {
        clearTimeout(analyzeDebounceTimer);
        analyzeDebounceTimer = setTimeout(() => {
          triggerAnalysis();
        }, 200);
      });
    }
  });

  // 2. Show / Hide Password toggle
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const isPassword = passwordInput.getAttribute("type") === "password";
      passwordInput.setAttribute("type", isPassword ? "text" : "password");
      toggleBtn.querySelector(".eye-icon").textContent = isPassword ? "🙈" : "👁️";
    });
  }

  // 3. Synthetic preset buttons
  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      const preset = chip.getAttribute("data-pwd");
      passwordInput.value = preset;
      updateClientChecklist(preset);
      triggerAnalysis();
    });
  });
}

/**
 * Instant client-side visual checklist update
 */
function updateClientChecklist(pwd) {
  const checkLength = document.getElementById("check-length");
  const checkLower = document.getElementById("check-lowercase");
  const checkUpper = document.getElementById("check-uppercase");
  const checkDigits = document.getElementById("check-digits");
  const checkSymbols = document.getElementById("check-symbols");
  const checkUnique = document.getElementById("check-uniqueness");

  const len = pwd ? pwd.length : 0;
  const hasLower = /[a-z]/.test(pwd);
  const hasUpper = /[A-Z]/.test(pwd);
  const hasDigits = /[0-9]/.test(pwd);
  const hasSymbols = /[^a-zA-Z0-9\s]/.test(pwd);
  const uniqueCount = new Set(pwd).size;
  const uniqueRatio = len > 0 ? uniqueCount / len : 0;

  toggleCheckItem(checkLength, len >= 12);
  toggleCheckItem(checkLower, hasLower);
  toggleCheckItem(checkUpper, hasUpper);
  toggleCheckItem(checkDigits, hasDigits);
  toggleCheckItem(checkSymbols, hasSymbols);
  toggleCheckItem(checkUnique, uniqueRatio >= 0.7 && len >= 8);
}

function toggleCheckItem(el, isValid) {
  if (!el) return;
  if (isValid) {
    el.classList.add("valid");
    el.querySelector(".check-icon").textContent = "✓";
  } else {
    el.classList.remove("valid");
    el.querySelector(".check-icon").textContent = "○";
  }
}

/**
 * Executes transient POST /api/analyze request
 */
async function triggerAnalysis() {
  const passwordInput = document.getElementById("password-input");
  const firstNameInput = document.getElementById("first-name-input");
  const birthYearInput = document.getElementById("birth-year-input");
  const orgInput = document.getElementById("organization-input");

  const password = passwordInput ? passwordInput.value : "";
  const firstName = firstNameInput ? firstNameInput.value : "";
  const birthYear = birthYearInput ? birthYearInput.value : "";
  const organization = orgInput ? orgInput.value : "";

  if (!password) {
    resetMeterToEmpty();
    return;
  }

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        password: password,
        first_name: firstName,
        birth_year: birthYear,
        organization: organization
      })
    });

    if (!response.ok) throw new Error("Analysis failed");
    const json = await response.json();
    renderAnalysisResults(json.data);
  } catch (err) {
    // In defensive mode, silently fail or display generic error
    console.warn("Analysis communication error (input preserved safely).");
  }
}

/**
 * Updates UI elements with analysis results
 */
function renderAnalysisResults(data) {
  if (!data) return;

  const score = data.score;
  const classification = data.classification;
  const color = data.color || "#ef4444";
  const metrics = data.metrics || {};
  const findings = data.findings || [];
  const suggestions = data.suggestions || [];
  const breakdown = data.score_breakdown || {};

  // 1. Score & Classification Text
  const scoreNumEl = document.getElementById("score-number");
  const classTitleEl = document.getElementById("meter-classification-title");
  const classBadgeEl = document.getElementById("classification-badge");
  const progressBarEl = document.getElementById("progress-bar");
  const summaryEl = document.getElementById("score-summary-text");

  if (scoreNumEl) {
    scoreNumEl.textContent = score;
    scoreNumEl.style.color = color;
  }
  if (classTitleEl) {
    classTitleEl.textContent = classification;
    classTitleEl.style.color = color;
  }
  if (classBadgeEl) {
    classBadgeEl.textContent = classification;
    classBadgeEl.style.backgroundColor = `${color}25`;
    classBadgeEl.style.color = color;
    classBadgeEl.style.border = `1px solid ${color}`;
  }
  if (progressBarEl) {
    progressBarEl.style.width = `${Math.max(5, score)}%`;
    progressBarEl.style.backgroundColor = color;
  }
  if (summaryEl) {
    summaryEl.textContent = data.summary;
  }

  // 2. Metrics Box
  setText("metric-length", metrics.length || 0);
  setText("metric-length-band", metrics.length_band || "Empty");
  setText("metric-unique", metrics.unique_character_count || 0);
  setText("metric-unique-ratio", `${Math.round((metrics.unique_character_ratio || 0) * 100)}%`);
  setText("metric-theor-entropy", `${metrics.theoretical_entropy_bits || 0} b`);
  setText("metric-pool-size", metrics.pool_size || 0);
  setText("metric-eff-entropy", `${metrics.effective_entropy_bits || 0} b`);
  setText("metric-entropy-rating", metrics.entropy_rating || "Zero");

  // Guess resistance
  setText("resistance-offline", metrics.crack_resistance_offline || "Instantaneous");
  setText("resistance-online", metrics.crack_resistance_online || "Instantaneous");

  // 3. Render Findings
  const findingsContainer = document.getElementById("findings-container");
  if (findingsContainer) {
    if (findings.length === 0) {
      findingsContainer.innerHTML = '<div class="empty-state">No weaknesses or warnings detected.</div>';
    } else {
      findingsContainer.innerHTML = findings.map(f => `
        <div class="finding-item ${f.severity}">
          <span class="finding-icon">${f.type === 'POSITIVE' ? '✓' : '⚠️'}</span>
          <div>
            <strong>${f.title}</strong>
            <p>${f.description}</p>
          </div>
        </div>
      `).join("");
    }
  }

  // 4. Render Suggestions
  const suggestionsContainer = document.getElementById("suggestions-container");
  if (suggestionsContainer) {
    if (suggestions.length === 0) {
      suggestionsContainer.innerHTML = '<div class="empty-state">No immediate suggestions.</div>';
    } else {
      suggestionsContainer.innerHTML = suggestions.map(s => `
        <div class="suggestion-card">
          <div class="suggestion-header">
            <span class="suggestion-title">${s.title}</span>
            <span class="badge badge-${s.priority.toLowerCase()}">${s.priority}</span>
          </div>
          <div class="suggestion-body">${s.description}</div>
          <div class="suggestion-action">&rarr; Recommended Action: ${s.action}</div>
        </div>
      `).join("");
    }
  }

  // 5. Render Transparent Score Audit Breakdown
  const breakdownContainer = document.getElementById("scoring-breakdown-container");
  if (breakdownContainer) {
    const additions = breakdown.additions || [];
    const deductions = breakdown.deductions || [];

    let html = '<div style="font-size:0.8rem;">';
    html += '<p style="color:var(--color-very-strong); font-weight:700; margin-bottom:0.4rem;">+ Positive Factor Contributions:</p>';
    if (additions.length > 0) {
      html += additions.map(a => `
        <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem;">
          <span>• ${a.category} (${a.detail})</span>
          <strong style="color:var(--color-very-strong);">+${a.points}</strong>
        </div>
      `).join("");
    } else {
      html += '<p class="empty-state">No positive additions.</p>';
    }

    html += '<p style="color:var(--color-very-weak); font-weight:700; margin-top:0.8rem; margin-bottom:0.4rem;">- Pattern Penalties & Deductions:</p>';
    if (deductions.length > 0) {
      html += deductions.map(d => `
        <div style="display:flex; justify-content:space-between; margin-bottom:0.25rem;">
          <span>• ${d.category} (${d.detail})</span>
          <strong style="color:var(--color-very-weak);">${d.points}</strong>
        </div>
      `).join("");
    } else {
      html += '<p style="color:var(--text-secondary); font-size:0.75rem;">None! Excellent pattern resistance.</p>';
    }

    html += `<div style="border-top:1px solid var(--border-color); margin-top:0.6rem; padding-top:0.4rem; display:flex; justify-content:space-between; font-weight:800;">
      <span>Final Clamped Score (0-100):</span>
      <span style="color:${color};">${score}/100</span>
    </div>`;

    html += '</div>';
    breakdownContainer.innerHTML = html;
  }
}

function resetMeterToEmpty() {
  setText("score-number", "0");
  setText("meter-classification-title", "VERY WEAK");
  const scoreNumEl = document.getElementById("score-number");
  const classTitleEl = document.getElementById("meter-classification-title");
  const progressBarEl = document.getElementById("progress-bar");
  const classBadgeEl = document.getElementById("classification-badge");

  if (scoreNumEl) scoreNumEl.style.color = "var(--color-very-weak)";
  if (classTitleEl) classTitleEl.style.color = "var(--color-very-weak)";
  if (progressBarEl) {
    progressBarEl.style.width = "0%";
    progressBarEl.style.backgroundColor = "var(--color-very-weak)";
  }
  if (classBadgeEl) {
    classBadgeEl.textContent = "AWAITING INPUT";
    classBadgeEl.className = "badge badge-default";
    classBadgeEl.style = "";
  }

  setText("score-summary-text", "Type a password above to begin defensive multi-vector strength analysis.");
  setText("metric-length", "0");
  setText("metric-length-band", "Empty");
  setText("metric-unique", "0");
  setText("metric-unique-ratio", "0%");
  setText("metric-theor-entropy", "0.0 b");
  setText("metric-pool-size", "0");
  setText("metric-eff-entropy", "0.0 b");
  setText("metric-entropy-rating", "Zero");
  setText("resistance-offline", "Instantaneous");
  setText("resistance-online", "Instantaneous");

  const findingsContainer = document.getElementById("findings-container");
  if (findingsContainer) {
    findingsContainer.innerHTML = '<div class="empty-state">No analysis performed yet.</div>';
  }
  const suggestionsContainer = document.getElementById("suggestions-container");
  if (suggestionsContainer) {
    suggestionsContainer.innerHTML = '<div class="empty-state">Recommendations will appear based on detected weaknesses.</div>';
  }
  const breakdownContainer = document.getElementById("scoring-breakdown-container");
  if (breakdownContainer) {
    breakdownContainer.innerHTML = '';
  }
}

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}
