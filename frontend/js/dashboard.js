/**
 * Security Analytics Dashboard Module.
 * Renders Chart.js defensive telemetry charts and manages aggregate statistics.
 * Strictly anonymous metadata - ZERO password display or storage.
 */

let chartStrength = null;
let chartWeaknesses = null;
let chartScoreHist = null;
let chartLengthDist = null;

function initSecurityDashboard() {
  const refreshBtn = document.getElementById("refresh-dashboard-btn");
  const seedBtn = document.getElementById("seed-demo-btn");
  const resetBtn = document.getElementById("reset-analytics-btn");

  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => fetchDashboardTelemetry());
  }

  if (seedBtn) {
    seedBtn.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/dashboard/seed-demo", { method: "POST" });
        if (res.ok) {
          showToast("Sample telemetry seeded successfully!");
          fetchDashboardTelemetry();
        }
      } catch (e) {
        console.error("Failed to seed sample data", e);
      }
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener("click", async () => {
      if (confirm("Reset all test telemetry in SQLite? (Zero credentials exist anyway).")) {
        try {
          const res = await fetch("/api/dashboard/reset", { method: "POST" });
          if (res.ok) {
            showToast("Telemetry database reset.");
            fetchDashboardTelemetry();
          }
        } catch (e) {
          console.error("Failed to reset telemetry", e);
        }
      }
    });
  }

  // Initial load
  fetchDashboardTelemetry();
}

async function fetchDashboardTelemetry() {
  try {
    const res = await fetch("/api/dashboard/stats");
    if (!res.ok) throw new Error("Stats request failed");
    const json = await res.json();
    if (json.status === "success") {
      updateDashboardUI(json.data);
    }
  } catch (err) {
    console.warn("Could not load dashboard statistics:", err);
  }
}

function updateDashboardUI(data) {
  // 1. KPI Cards
  const total = data.total_analyses || 0;
  const avgScore = data.average_score || 0;
  const avgLen = data.average_length || 0;
  const classCounts = data.classification_counts || {};

  const weakCount = (classCounts["VERY WEAK"] || 0) + (classCounts["WEAK"] || 0);
  const highRiskRate = total > 0 ? Math.round((weakCount / total) * 100) : 0;

  setText("kpi-total-analyses", total);
  setText("kpi-average-score", avgScore);
  setText("kpi-average-length", avgLen);
  setText("kpi-high-risk-rate", `${highRiskRate}%`);

  // 2. Charts (using Chart.js if available)
  if (typeof Chart !== "undefined") {
    renderCharts(data);
  }

  // 3. Telemetry Table
  renderTelemetryTable(data.recent_analyses || []);
}

function renderCharts(data) {
  const chartTextColor = "#94a3b8";
  const chartGridColor = "#1e293b";

  // Chart 1: Strength Classification Distribution (Doughnut)
  const strengthCanvas = document.getElementById("chart-strength-distribution");
  if (strengthCanvas) {
    const counts = data.classification_counts || {};
    const labels = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"];
    const values = labels.map(l => counts[l] || 0);

    if (chartStrength) chartStrength.destroy();
    chartStrength = new Chart(strengthCanvas, {
      type: "doughnut",
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#10b981"],
          borderColor: "#111827",
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: chartTextColor, font: { family: "Plus Jakarta Sans" } } }
        }
      }
    });
  }

  // Chart 2: Weakness Frequencies (Horizontal Bar)
  const weakCanvas = document.getElementById("chart-weaknesses");
  if (weakCanvas) {
    const freq = data.weakness_frequency || {};
    const labels = Object.keys(freq);
    const values = Object.values(freq);

    if (chartWeaknesses) chartWeaknesses.destroy();
    chartWeaknesses = new Chart(weakCanvas, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Detections",
          data: values,
          backgroundColor: "rgba(239, 68, 68, 0.75)",
          borderColor: "#ef4444",
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: chartTextColor, precision: 0 }, grid: { color: chartGridColor } },
          y: { ticks: { color: chartTextColor }, grid: { display: false } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  // Chart 3: Score Distribution Histogram (Bar)
  const scoreCanvas = document.getElementById("chart-score-hist");
  if (scoreCanvas) {
    const ranges = data.score_ranges || {};
    const labels = Object.keys(ranges);
    const values = Object.values(ranges);

    if (chartScoreHist) chartScoreHist.destroy();
    chartScoreHist = new Chart(scoreCanvas, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Passwords in Range",
          data: values,
          backgroundColor: "rgba(59, 130, 246, 0.75)",
          borderColor: "#3b82f6",
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: chartTextColor }, grid: { display: false } },
          y: { ticks: { color: chartTextColor, precision: 0 }, grid: { color: chartGridColor } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }

  // Chart 4: Length Distribution (Bar)
  const lenCanvas = document.getElementById("chart-length-dist");
  if (lenCanvas) {
    const dist = data.length_distribution || {};
    const labels = Object.keys(dist);
    const values = Object.values(dist);

    if (chartLengthDist) chartLengthDist.destroy();
    chartLengthDist = new Chart(lenCanvas, {
      type: "bar",
      data: {
        labels: labels,
        datasets: [{
          label: "Count by Length",
          data: values,
          backgroundColor: "rgba(6, 182, 212, 0.75)",
          borderColor: "#06b6d4",
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: chartTextColor }, grid: { display: false } },
          y: { ticks: { color: chartTextColor, precision: 0 }, grid: { color: chartGridColor } }
        },
        plugins: { legend: { display: false } }
      }
    });
  }
}

function renderTelemetryTable(recentList) {
  const tbody = document.getElementById("telemetry-table-body");
  if (!tbody) return;

  if (recentList.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center empty-state">No telemetry recorded yet. Test a password above to view anonymous telemetry.</td></tr>';
    return;
  }

  tbody.innerHTML = recentList.map(r => {
    let colorClass = "badge-default";
    if (r.classification === "VERY WEAK") colorClass = "badge-danger";
    else if (r.classification === "WEAK") colorClass = "badge-warning";
    else if (r.classification === "MODERATE") colorClass = "badge-warning";
    else if (r.classification === "STRONG") colorClass = "badge-primary";
    else if (r.classification === "VERY STRONG") colorClass = "badge-success";

    return `
      <tr>
        <td>#${r.id}</td>
        <td><strong>${r.score}/100</strong></td>
        <td><span class="badge ${colorClass}">${r.classification}</span></td>
        <td>${r.length} chars</td>
        <td>${r.weaknesses} detected</td>
        <td><small style="color:var(--text-muted);">${r.created_at || 'Just now'}</small></td>
      </tr>
    `;
  }).join("");
}
