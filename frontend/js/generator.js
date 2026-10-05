/**
 * Secure Password & Diceware Passphrase Generator Module.
 * Calls backend CSPRNG endpoints and enables instant testing in the real-time analyzer.
 */

function initPasswordGenerator() {
  const lenSlider = document.getElementById("gen-length-slider");
  const lenVal = document.getElementById("gen-length-val");
  const genBtn = document.getElementById("generate-password-btn");
  const pwdOutput = document.getElementById("generated-password-output");
  const copyPwdBtn = document.getElementById("copy-password-btn");
  const testPwdBtn = document.getElementById("test-in-analyzer-btn");

  const wordsSlider = document.getElementById("passphrase-words-slider");
  const wordsVal = document.getElementById("passphrase-words-val");
  const genPassphraseBtn = document.getElementById("generate-passphrase-btn");
  const passphraseOutput = document.getElementById("generated-passphrase-output");
  const copyPassphraseBtn = document.getElementById("copy-passphrase-btn");
  const testPassphraseBtn = document.getElementById("test-passphrase-btn");
  const separatorSelect = document.getElementById("passphrase-separator");

  // 1. Password Slider Sync
  if (lenSlider && lenVal) {
    lenSlider.addEventListener("input", () => {
      lenVal.textContent = lenSlider.value;
    });
  }

  // 2. Generate Random CSPRNG Password
  if (genBtn) {
    genBtn.addEventListener("click", async () => {
      const length = parseInt(lenSlider.value, 10);
      const uppercase = document.getElementById("gen-upper").checked;
      const lowercase = document.getElementById("gen-lower").checked;
      const digits = document.getElementById("gen-digits").checked;
      const symbols = document.getElementById("gen-symbols").checked;

      try {
        const res = await fetch("/api/generate-password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ length, uppercase, lowercase, digits, symbols })
        });
        const json = await res.json();
        if (json.status === "success") {
          pwdOutput.value = json.data.password;
        }
      } catch (e) {
        console.error("Generator request failed", e);
      }
    });
  }

  // 3. Copy Generated Password
  if (copyPwdBtn && pwdOutput) {
    copyPwdBtn.addEventListener("click", () => {
      if (pwdOutput.value) {
        navigator.clipboard.writeText(pwdOutput.value);
        showToast("Generated password copied to clipboard!");
      }
    });
  }

  // 4. Test in Analyzer
  if (testPwdBtn && pwdOutput) {
    testPwdBtn.addEventListener("click", () => {
      if (pwdOutput.value) {
        switchToAnalyzerWithPassword(pwdOutput.value);
      }
    });
  }

  // 5. Passphrase Words Slider Sync
  if (wordsSlider && wordsVal) {
    wordsSlider.addEventListener("input", () => {
      wordsVal.textContent = wordsSlider.value;
    });
  }

  // 6. Generate Diceware Passphrase
  if (genPassphraseBtn) {
    genPassphraseBtn.addEventListener("click", async () => {
      const wordCount = parseInt(wordsSlider.value, 10);
      const separator = separatorSelect ? separatorSelect.value : "-";

      try {
        const res = await fetch("/api/generate-passphrase", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ word_count: wordCount, separator })
        });
        const json = await res.json();
        if (json.status === "success") {
          passphraseOutput.value = json.data.passphrase;
          const infoEl = document.getElementById("passphrase-entropy-info");
          if (infoEl) {
            infoEl.textContent = `Estimated entropy: ~${json.data.estimated_bits} bits (${json.data.word_count} words). Long physical character length.`;
          }
        }
      } catch (e) {
        console.error("Passphrase generation failed", e);
      }
    });
  }

  // 7. Copy Passphrase
  if (copyPassphraseBtn && passphraseOutput) {
    copyPassphraseBtn.addEventListener("click", () => {
      if (passphraseOutput.value) {
        navigator.clipboard.writeText(passphraseOutput.value);
        showToast("Passphrase copied to clipboard!");
      }
    });
  }

  // 8. Test Passphrase in Analyzer
  if (testPassphraseBtn && passphraseOutput) {
    testPassphraseBtn.addEventListener("click", () => {
      if (passphraseOutput.value) {
        switchToAnalyzerWithPassword(passphraseOutput.value);
      }
    });
  }
}

function switchToAnalyzerWithPassword(pwd) {
  // Switch tab
  const analyzerTabBtn = document.querySelector('.nav-tab[data-tab="analyzer"]');
  if (analyzerTabBtn) analyzerTabBtn.click();

  // Populate input & trigger evaluation
  const pwdInput = document.getElementById("password-input");
  if (pwdInput) {
    pwdInput.value = pwd;
    updateClientChecklist(pwd);
    triggerAnalysis();
    pwdInput.scrollIntoView({ behavior: "smooth" });
  }
}
