/**
 * Core Application Initialization & Tab Coordinator.
 */

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initPasswordMeter();
  initPasswordGenerator();
  initPolicyChecker();
  initHashingLab();
  initSecurityDashboard();
});

function initTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  const panes = document.querySelectorAll(".tab-pane");

  tabs.forEach(tab => {
    tab.addEventListener("click", () => {
      const targetId = `tab-${tab.getAttribute("data-tab")}`;

      tabs.forEach(t => t.classList.remove("active"));
      panes.forEach(p => p.classList.remove("active"));

      tab.classList.add("active");
      const targetPane = document.getElementById(targetId);
      if (targetPane) {
        targetPane.classList.add("active");
      }

      // If switching to dashboard, refresh charts
      if (tab.getAttribute("data-tab") === "dashboard") {
        fetchDashboardTelemetry();
      }
    });
  });
}

function showToast(message) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.add("show");
  setTimeout(() => {
    toast.classList.remove("show");
  }, 2500);
}
