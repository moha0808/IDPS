/* ==========================================================================
   IDPS SOC DASHBOARD REAL-TIME CONTROLLER
   ========================================================================== */

let trafficChart = null;
let protocolChart = null;

document.addEventListener("DOMContentLoaded", () => {
    initCharts();
    updateDashboard();
    // Live update every 2 seconds
    setInterval(updateDashboard, 2000);
});

function initCharts() {
    // 1. Traffic Volume Line Chart
    const ctxTraffic = document.getElementById("trafficChart");
    if (ctxTraffic) {
        trafficChart = new Chart(ctxTraffic.getContext("2d"), {
            type: "line",
            data: {
                labels: [],
                datasets: [{
                    label: "Packets / Min",
                    data: [],
                    borderColor: "#00f2ff",
                    backgroundColor: "rgba(0, 242, 255, 0.1)",
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: "#00f2ff"
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { color: "#9ca3af" }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: "rgba(255, 255, 255, 0.05)" },
                        ticks: { color: "#9ca3af" }
                    }
                }
            }
        });
    }

    // 2. Protocol Distribution Donut Chart
    const ctxProtocol = document.getElementById("protocolChart");
    if (ctxProtocol) {
        protocolChart = new Chart(ctxProtocol.getContext("2d"), {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP", "ICMP", "Other"],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ["#3b82f6", "#8b5cf6", "#ffab00", "#6b7280"],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: { color: "#f3f4f6", padding: 15 }
                    }
                },
                cutout: "70%"
            }
        });
    }
}

async function updateDashboard() {
    try {
        // Fetch stats & chart analytics
        const resStats = await fetch("/api/stats");
        const dataStats = await resStats.json();
        
        if (dataStats.status === "success") {
            const stats = dataStats.stats;
            document.getElementById("stat-packets").innerText = stats.total_packets.toLocaleString();
            document.getElementById("stat-sources").innerText = stats.unique_sources.toLocaleString();
            document.getElementById("stat-alerts").innerText = stats.total_alerts.toLocaleString();
            document.getElementById("stat-high-risk").innerText = stats.high_risk.toLocaleString();
            document.getElementById("stat-blocked").innerText = stats.total_blocked.toLocaleString();

            // Update Timeline Chart
            const timeline = dataStats.charts.timeline || [];
            if (trafficChart) {
                trafficChart.data.labels = timeline.map(t => t.time);
                trafficChart.data.datasets[0].data = timeline.map(t => t.count);
                trafficChart.update("none");
            }

            // Update Protocol Donut Chart
            const pDist = dataStats.charts.protocol_distribution || {};
            if (protocolChart) {
                protocolChart.data.datasets[0].data = [
                    pDist.TCP || 0,
                    pDist.UDP || 0,
                    pDist.ICMP || 0,
                    pDist.IP || 0
                ];
                protocolChart.update("none");
            }
        }

        // Fetch recent alerts for dashboard table
        const resAlerts = await fetch("/api/alerts?limit=8");
        const dataAlerts = await resAlerts.json();

        if (dataAlerts.status === "success" && document.getElementById("alerts-tbody")) {
            const tbody = document.getElementById("alerts-tbody");
            const alerts = dataAlerts.alerts || [];

            if (alerts.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">Listening for security events...</td></tr>`;
            } else {
                tbody.innerHTML = alerts.map(a => {
                    const sevClass = (a.severity || 'LOW').toLowerCase();
                    return `
                        <tr>
                            <td>${a.time_str}</td>
                            <td style="color: var(--accent-cyan);">${a.src_ip}</td>
                            <td><strong>${a.alert_type}</strong></td>
                            <td><span class="badge badge-info">${a.protocol}</span></td>
                            <td><span class="badge badge-${sevClass}">${a.severity}</span></td>
                            <td><strong style="color: ${a.risk_score >= 80 ? 'var(--sev-critical)' : a.risk_score >= 50 ? 'var(--sev-medium)' : 'var(--sev-low)'}">${a.risk_score}</strong></td>
                            <td><span class="badge badge-${a.status ? a.status.toLowerCase() : 'open'}">${a.status || 'Open'}</span></td>
                            <td>
                                <button class="btn btn-sm btn-danger" onclick="quickBlockIP('${a.src_ip}')"><i class="fa-solid fa-ban"></i> Block</button>
                            </td>
                        </tr>
                    `;
                }).join("");
            }
        }

    } catch (err) {
        console.error("Error updating dashboard:", err);
    }
}

async function triggerSimulation(type) {
    try {
        const res = await fetch("/api/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ type: type })
        });
        const data = await res.json();
        if (data.status === "success") {
            // Immediate update call
            setTimeout(updateDashboard, 300);
        }
    } catch(err) {
        console.error("Simulation trigger failed:", err);
    }
}

async function quickBlockIP(ip) {
    if (!confirm(`Block IP ${ip} in lab firewall?`)) return;
    await fetch("/api/prevention/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip, reason: "Manual SOC Block from Dashboard" })
    });
    updateDashboard();
}
