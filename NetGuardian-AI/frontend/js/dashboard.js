/**
 * NetGuardian AI - Overview Dashboard View Controller
 * Page 1 - Overview SOC Telemetry & Real-time Metrics
 */

const DashboardView = {
    trafficChart: null,
    alertChart: null,
    trafficInterval: null,

    init() {
        this.updateKPIs();
        this.renderMiniTopology();
        this.renderCriticalIncidents();
        this.renderUserActivity();
        this.renderRecentEvents();
        this.initTrafficChart();
        this.initAlertOverviewChart();
        this.bindEvents();

        // Subscribe to store updates
        window.NetGuardianStore.subscribe((event, payload) => {
            this.updateKPIs();
            this.renderMiniTopology();
            this.renderCriticalIncidents();
            this.renderRecentEvents();
            this.updateAlertOverviewChart();
        });
    },

    bindEvents() {
        const gotoTopoBtn = document.getElementById('btn-goto-topology');
        if (gotoTopoBtn) {
            gotoTopoBtn.addEventListener('click', () => {
                if (window.NetGuardianApp) {
                    window.NetGuardianApp.switchView('topology');
                }
            });
        }
    },

    updateKPIs() {
        const metrics = window.NetGuardianStore.getMetrics();
        const elTotal = document.getElementById('kpi-total-devices');
        const elOnline = document.getElementById('kpi-online-devices');
        const elOffline = document.getElementById('kpi-offline-devices');
        const elSuspicious = document.getElementById('kpi-suspicious-devices');
        const elThreats = document.getElementById('kpi-active-threats');
        const elHealth = document.getElementById('kpi-network-health');
        const elRecoveries = document.getElementById('kpi-recoveries');

        if (elTotal) elTotal.textContent = metrics.totalDevices;
        if (elOnline) elOnline.textContent = metrics.onlineDevices;
        if (elOffline) elOffline.textContent = metrics.offlineDevices;
        if (elSuspicious) elSuspicious.textContent = metrics.suspiciousDevices;
        if (elThreats) elThreats.textContent = metrics.activeThreats;
        if (elHealth) {
            let healthGrade = 'Optimal Mesh Tolerance';
            let healthColor = 'var(--green-bright)';
            if (metrics.networkHealth < 75) {
                healthGrade = 'Degraded Outage Warning';
                healthColor = 'var(--red-bright)';
            } else if (metrics.networkHealth < 90) {
                healthGrade = 'Elevated AI Vigilance';
                healthColor = 'var(--amber)';
            }
            elHealth.innerHTML = `<span style="color: ${healthColor};">${metrics.networkHealth}</span><span class="kpi-unit">%</span>`;
            const healthCard = elHealth.closest('.kpi-card');
            if (healthCard) {
                const footer = healthCard.querySelector('.kpi-footer');
                if (footer) footer.innerHTML = `<span class="pulse-dot ${metrics.networkHealth < 75 ? 'dot-red' : (metrics.networkHealth < 90 ? 'dot-purple' : '')}"></span> ${healthGrade}`;
            }
        }
        if (elRecoveries) elRecoveries.textContent = metrics.successfulRecoveries;

        // Update Defcon badge
        const defconText = document.getElementById('top-defcon-text');
        const defconPill = document.getElementById('top-threat-pill');
        if (defconText && defconPill) {
            if (metrics.offlineDevices > 1 || metrics.networkHealth < 75) {
                defconText.textContent = `DEFCON: RED ALERT (${metrics.offlineDevices} OFFLINE)`;
                defconPill.className = 'soc-pill pill-defcon';
                defconPill.style.borderColor = 'var(--red-bright)';
                defconPill.style.color = 'var(--red-bright)';
            } else if (metrics.activeThreats > 0) {
                defconText.textContent = `DEFCON: ELEVATED (${metrics.activeThreats} THREATS)`;
                defconPill.className = 'soc-pill pill-defcon';
                defconPill.style.borderColor = 'rgba(0, 240, 255, 0.35)';
                defconPill.style.color = 'var(--cyan)';
            } else {
                defconText.textContent = `DEFCON: NORMAL (SECURED)`;
                defconPill.className = 'soc-pill pill-live';
                defconPill.style.borderColor = 'rgba(16, 185, 129, 0.3)';
                defconPill.style.color = '#a7f3d0';
            }
        }
    },

    renderMiniTopology() {
        const svg = document.getElementById('mini-topology-svg');
        if (!svg) return;

        const { nodes, links } = window.NetGuardianStore.getTopology();
        const devices = window.NetGuardianStore.getDevices();

        // Build node status lookup
        const devStatusMap = {};
        devices.forEach(d => devStatusMap[d.id] = d.status);

        // Coordinates scaled for mini viewBox (900 x 460)
        let linksHtml = '';
        links.forEach(l => {
            const source = nodes.find(n => n.id === l.from);
            const target = nodes.find(n => n.id === l.to);
            if (!source || !target) return;

            let linkClass = 'topo-link link-active';
            if (l.status === 'inactive') linkClass = 'topo-link link-failed';
            else if (l.status === 'suspicious') linkClass = 'topo-link link-threat';
            else if (l.status === 'rerouted-active') linkClass = 'topo-link link-rerouted';
            else if (l.status === 'standby') linkClass = 'topo-link link-redundant';

            linksHtml += `<line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" class="${linkClass}" />`;
        });

        let nodesHtml = '';
        nodes.forEach(n => {
            const status = devStatusMap[n.id] || 'online';
            let statusClass = 'node-healthy';
            let iconText = '🖥️';
            if (n.type === 'router') iconText = '🌐';
            else if (n.type === 'server') iconText = '🗄️';
            else if (n.type === 'firewall') iconText = '🛡️';

            if (status === 'offline') statusClass = 'node-failed';
            else if (status === 'suspicious') statusClass = 'node-suspicious';
            else if (status === 'recovering') statusClass = 'node-suspicious';

            nodesHtml += `
                <g class="topo-node ${statusClass}" transform="translate(${n.x}, ${n.y})" onclick="DashboardView.onMiniNodeClick('${n.id}')">
                    <circle class="node-pulse" r="28" fill="none" stroke-width="1.5" />
                    <circle class="node-core" r="22" />
                    <text y="5" text-anchor="middle" font-size="12" fill="#fff">${iconText}</text>
                    <text class="node-text-title" y="38">${n.name}</text>
                    <text class="node-text-ip" y="50">${n.ip}</text>
                </g>
            `;
        });

        svg.innerHTML = `
            <defs>
                <linearGradient id="link-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stop-color="#00f0ff" stop-opacity="0.8" />
                    <stop offset="100%" stop-color="#0077fe" stop-opacity="0.4" />
                </linearGradient>
            </defs>
            <g id="mini-links">${linksHtml}</g>
            <g id="mini-nodes">${nodesHtml}</g>
        `;
    },

    onMiniNodeClick(nodeId) {
        if (window.NetGuardianApp) {
            window.NetGuardianApp.openDeviceModal(nodeId);
        }
    },

    renderCriticalIncidents() {
        const container = document.getElementById('dashboard-critical-incidents-list');
        if (!container) return;

        const incidents = window.NetGuardianStore.state.criticalIncidents;
        const badge = document.getElementById('incident-count-badge');
        if (badge) badge.textContent = `${incidents.length} ALERTS`;

        if (incidents.length === 0) {
            container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem; padding: 10px 0;">No active critical incidents. System nominal.</div>';
            return;
        }

        container.innerHTML = incidents.slice(0, 3).map(inc => {
            const isCrit = inc.severity === 'CRITICAL';
            const badgeClass = isCrit ? 'badge-red' : 'badge-amber';
            return `
                <div class="incident-item" style="cursor: pointer;" onclick="NetGuardianApp.switchView('alerts')">
                    <div class="incident-info">
                        <div class="incident-title" style="display: flex; align-items: center; gap: 6px;">
                            <span class="pulse-dot ${isCrit ? 'dot-red' : 'dot-purple'}"></span>
                            <span>${inc.title}</span>
                        </div>
                        <div class="incident-target">${inc.target} • ${inc.time}</div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span class="badge ${badgeClass}">${inc.status}</span>
                        <button class="btn btn-outline btn-sm" style="padding: 2px 6px; font-size: 0.68rem;" onclick="event.stopPropagation(); NetGuardianApp.switchView('alerts')">
                            Resolve
                        </button>
                    </div>
                </div>
            `;
        }).join('');
    },

    renderUserActivity() {
        const tbody = document.getElementById('dashboard-user-activity-body');
        if (!tbody) return;

        const activities = window.NetGuardianStore.state.userActivity;
        tbody.innerHTML = activities.map(item => {
            let statusStyle = 'color: var(--green-bright);';
            if (item.status === 'Blocked') statusStyle = 'color: var(--red-bright);';
            if (item.status === 'Flagged') statusStyle = 'color: var(--purple-light);';

            return `
                <tr>
                    <td>
                        <strong style="color: #fff;">${item.user}</strong>
                        <div style="font-size: 0.68rem; color: var(--text-muted);">${item.role}</div>
                    </td>
                    <td style="font-family: var(--font-mono); font-size: 0.72rem;">${item.ip}</td>
                    <td>${item.action}</td>
                    <td style="${statusStyle} font-family: var(--font-mono); font-weight: 600;">${item.status}</td>
                </tr>
            `;
        }).join('');
    },

    renderRecentEvents() {
        const container = document.getElementById('dashboard-recent-events-list');
        if (!container) return;

        const events = window.NetGuardianStore.state.recentEvents;
        container.innerHTML = events.slice(0, 8).map(e => {
            let itemClass = 'event-ticker-item';
            if (e.type.includes('ALERT') || e.type.includes('FAILURE') || e.type.includes('WARN')) {
                itemClass += ' event-alert';
            } else if (e.type.includes('AI') || e.type.includes('THREAT')) {
                itemClass += ' event-ai';
            } else if (e.type.includes('RECOVER') || e.type.includes('OK')) {
                itemClass += ' event-recover';
            }

            return `
                <div class="${itemClass}">
                    <span>${e.msg}</span>
                    <span style="color: var(--text-dim); white-space: nowrap;">${e.time}</span>
                </div>
            `;
        }).join('');
    },

    initTrafficChart() {
        const ctx = document.getElementById('dashboard-traffic-chart');
        if (!ctx) return;

        const context = ctx.getContext('2d');
        const rxGrad = context.createLinearGradient(0, 0, 0, 220);
        rxGrad.addColorStop(0, 'rgba(0, 240, 255, 0.35)');
        rxGrad.addColorStop(1, 'rgba(0, 240, 255, 0.01)');

        const txGrad = context.createLinearGradient(0, 0, 0, 220);
        txGrad.addColorStop(0, 'rgba(168, 85, 247, 0.28)');
        txGrad.addColorStop(1, 'rgba(168, 85, 247, 0.01)');

        const labels = ['-50s', '-45s', '-40s', '-35s', '-30s', '-25s', '-20s', '-15s', '-10s', '-5s', 'Now'];
        const rxData = [390, 410, 435, 420, 480, 510, 495, 470, 520, 482, 490];
        const txData = [320, 340, 360, 350, 395, 420, 405, 390, 430, 410, 415];

        this.trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels,
                datasets: [
                    {
                        label: 'Inbound Rx (Mbps)',
                        data: rxData,
                        borderColor: '#00f0ff',
                        backgroundColor: rxGrad,
                        borderWidth: 2.5,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 3.5,
                        pointBackgroundColor: '#00f0ff',
                        pointHoverRadius: 6,
                        pointHoverBackgroundColor: '#ffffff'
                    },
                    {
                        label: 'Outbound Tx (Mbps)',
                        data: txData,
                        borderColor: '#a855f7',
                        backgroundColor: txGrad,
                        borderWidth: 2.5,
                        tension: 0.4,
                        fill: true,
                        pointRadius: 3.5,
                        pointBackgroundColor: '#a855f7',
                        pointHoverRadius: 6,
                        pointHoverBackgroundColor: '#ffffff'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 600 },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.04)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.06)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } },
                        suggestedMin: 200,
                        suggestedMax: 600
                    }
                },
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                    },
                    tooltip: {
                        backgroundColor: '#0d1527',
                        borderColor: 'rgba(0, 240, 255, 0.35)',
                        borderWidth: 1,
                        titleColor: '#fff',
                        bodyColor: '#94a3b8',
                        padding: 10,
                        displayColors: true
                    }
                }
            }
        });

        // Live simulated pulse tick every 3.5s
        if (this.trafficInterval) clearInterval(this.trafficInterval);
        this.trafficInterval = setInterval(() => {
            if (!this.trafficChart) return;
            const rxBase = 460 + Math.floor(Math.random() * 80) - 40;
            const txBase = 380 + Math.floor(Math.random() * 60) - 30;

            const rxData = this.trafficChart.data.datasets[0].data;
            const txData = this.trafficChart.data.datasets[1].data;

            rxData.shift();
            rxData.push(rxBase);
            txData.shift();
            txData.push(txBase);

            this.trafficChart.update('none');

            const badge = document.getElementById('live-throughput-badge');
            if (badge) {
                badge.textContent = `RX: ${rxBase} Mbps | TX: ${txBase} Mbps`;
            }
        }, 3500);
    },

    initAlertOverviewChart() {
        const ctx = document.getElementById('chart-alert-overview');
        if (!ctx) return;

        // Only count active/in-progress alerts so resolved alerts do not show as active threats
        const alerts = window.NetGuardianStore.getAlerts().filter(a => a.status === 'ACTIVE' || a.status === 'IN_PROGRESS');
        const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        alerts.forEach(a => { if (counts[a.severity] !== undefined) counts[a.severity]++; });

        this.alertChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW],
                    backgroundColor: [
                        '#ef4444',
                        '#f59e0b',
                        '#a855f7',
                        '#10b981'
                    ],
                    borderColor: '#0d1527',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { size: 10, family: 'Inter' } }
                    }
                }
            }
        });
    },

    updateAlertOverviewChart() {
        if (!this.alertChart) return;
        // Only count active/in-progress alerts so resolved alerts do not show as active threats
        const alerts = window.NetGuardianStore.getAlerts().filter(a => a.status === 'ACTIVE' || a.status === 'IN_PROGRESS');
        const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        alerts.forEach(a => { if (counts[a.severity] !== undefined) counts[a.severity]++; });

        this.alertChart.data.datasets[0].data = [counts.CRITICAL, counts.HIGH, counts.MEDIUM, counts.LOW];
        this.alertChart.update();
    }
};

window.DashboardView = DashboardView;
