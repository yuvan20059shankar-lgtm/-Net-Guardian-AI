/**
 * NetGuardian AI - Analytics & History View Controller
 * Page 7 - Long-term SOC Telemetry & Machine Learning Analytics
 */

const AnalyticsView = {
    trafficHistoryChart: null,
    deviceAvailChart: null,
    threatHistoryChart: null,
    recoveryOpsChart: null,
    activeRange: '24h',

    init() {
        this.bindEvents();
    },

    onViewActivated() {
        // Render charts once the view tab is made visible so dimensions calculate accurately
        setTimeout(() => {
            this.renderAllCharts();
        }, 50);
    },

    bindEvents() {
        const rangeBtns = document.querySelectorAll('#view-analytics .tab-pill');
        rangeBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                rangeBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.activeRange = btn.getAttribute('data-range');
                this.renderAllCharts();
                if (window.NetGuardianApp) {
                    window.NetGuardianApp.showToast(`Analytics filtered to ${btn.textContent}`, 'cyan');
                }
            });
        });
    },

    async renderAllCharts() {
        let dataset = null;
        if (window.NetGuardianAPI && typeof window.NetGuardianAPI.getAnalytics === 'function') {
            try {
                dataset = await window.NetGuardianAPI.getAnalytics(this.activeRange);
            } catch (err) {
                console.warn('Backend /api/analytics call failed, falling back to local store:', err);
            }
        }
        if (!dataset) {
            dataset = this.getActiveDataset();
        }
        this._currentData = dataset;

        this.renderTrafficHistoryChart(dataset);
        this.renderDeviceAvailabilityChart(dataset);
        this.renderThreatHistoryChart(dataset);
        this.renderRecoveryOpsChart(dataset);
    },

    getActiveDataset() {
        if (window.NetGuardianStore && typeof window.NetGuardianStore.getAnalytics === 'function') {
            return window.NetGuardianStore.getAnalytics(this.activeRange);
        }
        const storeData = window.NetGuardianStore.state.analyticsData;
        return storeData[this.activeRange] || storeData['24h'];
    },

    // 1. Network Traffic History (Multi-line with scrubbed malicious traffic)
    renderTrafficHistoryChart(dataset) {
        const ctx = document.getElementById('chart-traffic-history');
        if (!ctx) return;

        if (this.trafficHistoryChart) {
            this.trafficHistoryChart.destroy();
        }

        const activeData = dataset || this._currentData || this.getActiveDataset();
        const data = activeData.trafficHistory;

        this.trafficHistoryChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: data.labels,
                datasets: [
                    {
                        label: 'Inbound Rx (Mbps)',
                        data: data.inbound,
                        borderColor: '#00f0ff',
                        backgroundColor: 'rgba(0, 240, 255, 0.1)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2
                    },
                    {
                        label: 'Outbound Tx (Mbps)',
                        data: data.outbound,
                        borderColor: '#a855f7',
                        backgroundColor: 'rgba(168, 85, 247, 0.08)',
                        fill: true,
                        tension: 0.35,
                        borderWidth: 2
                    },
                    {
                        label: 'Scrubbed Malicious Packets (kpps)',
                        data: data.maliciousScrubbed,
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.2)',
                        borderWidth: 2,
                        borderDash: [4, 4],
                        pointRadius: 4,
                        pointBackgroundColor: '#ef4444'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    }
                },
                plugins: {
                    legend: { labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' } } }
                }
            }
        });
    },

    // 2. Device Availability & Uptime (%)
    renderDeviceAvailabilityChart(dataset) {
        const ctx = document.getElementById('chart-device-availability');
        if (!ctx) return;

        if (this.deviceAvailChart) {
            this.deviceAvailChart.destroy();
        }

        const activeData = dataset || this._currentData || this.getActiveDataset();
        const data = activeData.deviceAvailability;

        this.deviceAvailChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.devices,
                datasets: [{
                    label: 'Availability SLA (%)',
                    data: data.uptimePercentages,
                    backgroundColor: data.uptimePercentages.map(p => {
                        if (p >= 99.5) return 'rgba(16, 185, 129, 0.8)';
                        if (p >= 96.0) return 'rgba(0, 240, 255, 0.8)';
                        return 'rgba(239, 68, 68, 0.8)';
                    }),
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        min: 90,
                        max: 100,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#f1f5f9', font: { size: 10, family: 'Inter' } }
                    }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
    },

    // 3. Threat Detection History (Stacked bar chart)
    renderThreatHistoryChart(dataset) {
        const ctx = document.getElementById('chart-threat-history');
        if (!ctx) return;

        if (this.threatHistoryChart) {
            this.threatHistoryChart.destroy();
        }

        const activeData = dataset || this._currentData || this.getActiveDataset();
        const data = activeData.threatHistory;

        this.threatHistoryChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.labels,
                datasets: [
                    {
                        label: 'Critical',
                        data: data.critical,
                        backgroundColor: '#ef4444'
                    },
                    {
                        label: 'High',
                        data: data.high,
                        backgroundColor: '#f59e0b'
                    },
                    {
                        label: 'Medium',
                        data: data.medium,
                        backgroundColor: '#a855f7'
                    },
                    {
                        label: 'Low',
                        data: data.low,
                        backgroundColor: '#10b981'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        stacked: true,
                        grid: { display: false },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        stacked: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    }
                },
                plugins: {
                    legend: { labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' } } }
                }
            }
        });
    },

    // 4. Recovery Operations & Auto-Heal Speed
    renderRecoveryOpsChart(dataset) {
        const ctx = document.getElementById('chart-recovery-ops');
        if (!ctx) return;

        if (this.recoveryOpsChart) {
            this.recoveryOpsChart.destroy();
        }

        const activeData = dataset || this._currentData || this.getActiveDataset();
        const data = activeData.recoveryOperations;

        this.recoveryOpsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: data.labels,
                datasets: [
                    {
                        type: 'bar',
                        label: 'Autonomous Self-Healed Outages',
                        data: data.autoHealed,
                        backgroundColor: 'rgba(0, 240, 255, 0.65)',
                        borderColor: '#00f0ff',
                        borderWidth: 1,
                        borderRadius: 4,
                        yAxisID: 'y'
                    },
                    {
                        type: 'line',
                        label: 'Average Failover Time (Seconds)',
                        data: data.avgTimeSeconds,
                        borderColor: '#a855f7',
                        pointBackgroundColor: '#c084fc',
                        pointRadius: 5,
                        tension: 0.3,
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y: {
                        position: 'left',
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { family: 'JetBrains Mono', size: 10 } }
                    },
                    y1: {
                        position: 'right',
                        grid: { display: false },
                        ticks: { color: '#a855f7', font: { family: 'JetBrains Mono', size: 10 } },
                        suggestedMax: 5
                    }
                },
                plugins: {
                    legend: { labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' } } }
                }
            }
        });
    }
};

window.AnalyticsView = AnalyticsView;
