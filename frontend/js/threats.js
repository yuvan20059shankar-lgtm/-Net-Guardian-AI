/**
 * NetGuardian AI - AI Threat Detection View Controller
 * Page 4 - Machine Learning Anomaly Inspector & Threat Mitigation
 */

const ThreatsView = {
    searchQuery: '',
    severityFilter: 'all',

    init() {
        this.renderThreats();
        this.bindEvents();

        // Subscribe to store updates
        window.NetGuardianStore.subscribe((event, payload) => {
            this.renderThreats();
        });
    },

    bindEvents() {
        const searchInput = document.getElementById('threat-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchQuery = e.target.value.toLowerCase().trim();
                this.renderThreats();
            });
        }

        const severityPills = document.querySelectorAll('#threat-severity-pill-group .tab-pill');
        severityPills.forEach(pill => {
            pill.addEventListener('click', () => {
                severityPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                this.severityFilter = pill.getAttribute('data-threat-severity');
                this.renderThreats();
            });
        });
    },

    renderThreats() {
        const container = document.getElementById('ai-threats-container');
        if (!container) return;

        const allThreats = window.NetGuardianStore.getThreats();

        // Update nav badge count
        const activeCount = allThreats.filter(t => t.status === 'ACTIVE' || t.status === 'INVESTIGATING').length;
        const navBadge = document.getElementById('nav-threats-badge');
        if (navBadge) {
            navBadge.textContent = `${activeCount} ACTIVE`;
            if (activeCount === 0) {
                navBadge.className = 'nav-badge badge-purple';
                navBadge.textContent = 'SECURED';
            } else {
                navBadge.className = 'nav-badge badge-red';
            }
        }

        // Filter by search and severity
        const filtered = allThreats.filter(t => {
            const matchesSearch = !this.searchQuery ||
                t.id.toLowerCase().includes(this.searchQuery) ||
                t.threatType.toLowerCase().includes(this.searchQuery) ||
                t.affectedDeviceName.toLowerCase().includes(this.searchQuery) ||
                t.affectedIp.toLowerCase().includes(this.searchQuery) ||
                t.explanation.toLowerCase().includes(this.searchQuery);

            const matchesSeverity = this.severityFilter === 'all' || t.severity === this.severityFilter;
            return matchesSearch && matchesSeverity;
        });

        const countBadge = document.getElementById('threats-filtered-count');
        if (countBadge) {
            countBadge.textContent = `${filtered.length} of ${allThreats.length} Records`;
        }

        if (filtered.length === 0) {
            container.innerHTML = `
                <div class="soc-card" style="padding: 40px; text-align: center; color: var(--text-muted);">
                    <i data-lucide="shield-check" style="width: 48px; height: 48px; color: var(--green-bright); margin-bottom: 12px;"></i>
                    <h3 style="color: #fff; margin-bottom: 6px;">No Threats Match Filter</h3>
                    <p style="font-size: 0.85rem;">No anomaly records match the selected severity category (${this.severityFilter.toUpperCase()}) or search term.</p>
                </div>
            `;
            if (window.lucide) window.lucide.createIcons();
            return;
        }

        container.innerHTML = filtered.map(threat => {
            let severityBadge = '';
            let cardBorderClass = '';

            if (threat.severity === 'CRITICAL') {
                severityBadge = '<span class="badge badge-red">CRITICAL SEVERITY</span>';
                cardBorderClass = 'glow-red';
            } else if (threat.severity === 'HIGH') {
                severityBadge = '<span class="badge badge-amber">HIGH SEVERITY</span>';
            } else if (threat.severity === 'MEDIUM') {
                severityBadge = '<span class="badge badge-purple">MEDIUM SEVERITY</span>';
            } else {
                severityBadge = '<span class="badge badge-cyan">LOW SEVERITY</span>';
            }

            let statusPill = '';
            let actionBtn = '';
            if (threat.status === 'ACTIVE') {
                statusPill = '<span class="badge badge-red"><span class="pulse-dot dot-red"></span> ACTIVE THREAT</span>';
                actionBtn = `
                    <button class="btn btn-purple btn-sm" onclick="ThreatsView.mitigate('${threat.id}')">
                        <i data-lucide="shield-alert" style="width: 14px; height: 14px;"></i>
                        <span>Execute Autonomous Mitigation</span>
                    </button>
                `;
            } else if (threat.status === 'INVESTIGATING') {
                statusPill = '<span class="badge badge-purple"><span class="pulse-dot dot-purple"></span> UNDER AI PROBING</span>';
                actionBtn = `
                    <button class="btn btn-purple btn-sm" onclick="ThreatsView.mitigate('${threat.id}')">
                        <i data-lucide="shield" style="width: 14px; height: 14px;"></i>
                        <span>Enforce Quarantine</span>
                    </button>
                `;
            } else {
                statusPill = '<span class="badge badge-green"><span class="pulse-dot"></span> MITIGATED</span>';
                actionBtn = `
                    <button class="btn btn-outline btn-sm" disabled style="opacity: 0.6; cursor: default;">
                        <i data-lucide="check" style="width: 14px; height: 14px; color: var(--green-bright);"></i>
                        <span>Mitigation Complete</span>
                    </button>
                `;
            }

            const scorePercent = Math.round(threat.anomalyScore * 100);
            const scoreColorClass = threat.anomalyScore > 0.85 ? 'fill-red' : (threat.anomalyScore > 0.70 ? 'fill-purple' : 'fill-cyan');

            return `
                <div class="threat-card ${cardBorderClass}">
                    <div class="threat-card-header">
                        <div class="threat-header-left">
                            <span class="threat-id" style="cursor: pointer;" onclick="ThreatsView.openThreatDetails('${threat.id}')">${threat.id}</span>
                            <span class="threat-title" style="cursor: pointer;" onclick="ThreatsView.openThreatDetails('${threat.id}')">${threat.threatType}</span>
                            ${severityBadge}
                        </div>
                        <div>
                            ${statusPill}
                        </div>
                    </div>

                    <!-- Machine Learning Vector Features -->
                    <div class="threat-details-grid">
                        <div class="detail-item">
                            <span class="detail-key">Affected Target</span>
                            <span class="detail-val" style="color: #fff; font-weight: 600;">
                                ${threat.affectedDeviceName} (${threat.affectedIp})
                            </span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-key">ML Anomaly Outlier Score</span>
                            <div style="display: flex; align-items: baseline; gap: 6px;">
                                <span class="detail-val" style="color: ${threat.anomalyScore > 0.85 ? 'var(--red-bright)' : 'var(--purple-light)'}; font-weight: 700;">
                                    ${threat.anomalyScore} / 1.00
                                </span>
                                <span style="font-size: 0.68rem; font-family: var(--font-mono); color: var(--text-dim);">(${scorePercent}%)</span>
                            </div>
                            <div class="progress-track" style="height: 5px; margin-top: 4px;">
                                <div class="progress-fill ${scoreColorClass}" style="width: ${scorePercent}%;"></div>
                            </div>
                        </div>
                        <div class="detail-item">
                            <span class="detail-key">Packet Entropy</span>
                            <span class="detail-val">${threat.mlFeatures?.packetEntropy || '6.42'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-key">Baseline Deviation</span>
                            <span class="detail-val" style="color: var(--amber);">${threat.mlFeatures?.baselineDeviation || '3.2σ'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-key">Detection Timestamp</span>
                            <span class="detail-val" style="font-size: 0.78rem;">${threat.timestamp}</span>
                        </div>
                    </div>

                    <!-- AI Explanation & Recommendation -->
                    <div class="threat-explanation-box">
                        <div style="font-weight: 600; color: var(--purple-light); font-size: 0.75rem; text-transform: uppercase; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                            <i data-lucide="bot" style="width: 14px; height: 14px;"></i>
                            <span>Isolation Forest Diagnostic Explanation:</span>
                        </div>
                        ${threat.explanation}
                    </div>

                    <div class="threat-action-row">
                        <div style="font-size: 0.8rem; color: var(--text-secondary);">
                            <strong style="color: var(--cyan);">Recommended SOC Action:</strong> ${threat.recommendedAction}
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button class="btn btn-outline btn-sm" onclick="ThreatsView.inspectVector('${threat.id}')">
                                <i data-lucide="microscope" style="width: 14px; height: 14px;"></i>
                                <span>Inspect Vectors</span>
                            </button>
                            ${actionBtn}
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        if (window.lucide) window.lucide.createIcons();
    },

    async mitigate(threatId) {
        if (window.NetGuardianApp) {
            window.NetGuardianApp.showToast(`Deploying AI mitigation rule for ${threatId}...`, 'purple');
        }
        
        await window.NetGuardianAPI.mitigateThreat(threatId);
        
        if (window.NetGuardianApp) {
            window.NetGuardianApp.showToast(`Threat ${threatId} successfully mitigated and device traffic restored.`, 'success');
        }
    },

    inspectVector(threatId) {
        this.openThreatDetails(threatId);
    },

    openThreatDetails(threatId) {
        const threat = window.NetGuardianStore.getThreats().find(t => t.id === threatId);
        if (!threat || !window.NetGuardianApp) return;

        const scorePercent = Math.round(threat.anomalyScore * 100);
        const scoreColor = threat.anomalyScore > 0.85 ? 'var(--red-bright)' : (threat.anomalyScore > 0.70 ? 'var(--purple-light)' : 'var(--cyan)');
        const scoreBarClass = threat.anomalyScore > 0.85 ? 'fill-red' : (threat.anomalyScore > 0.70 ? 'fill-purple' : 'fill-cyan');

        // Look up correlated security alerts
        const allAlerts = window.NetGuardianStore.getAlerts() || [];
        const relatedAlerts = allAlerts.filter(a => 
            a.threatType === threat.threatType || 
            a.deviceName === threat.affectedDeviceName || 
            a.ip === threat.affectedIp
        );

        const alertHistoryHtml = relatedAlerts.length > 0 
            ? relatedAlerts.map(a => `
                <div style="display: flex; justify-content: space-between; align-items: center; padding: 8px 12px; background: rgba(0,0,0,0.3); border-radius: 6px; font-size: 0.78rem;">
                    <div>
                        <span style="font-family: var(--font-mono); color: var(--cyan); font-weight: 600;">${a.id}</span>
                        <span style="color: #cbd5e1; margin-left: 8px;">${a.threatType}</span>
                        <span style="color: var(--text-dim); margin-left: 8px;">(${a.timestamp})</span>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <span class="badge ${a.severity === 'CRITICAL' ? 'badge-red' : (a.severity === 'HIGH' ? 'badge-amber' : 'badge-purple')}" style="font-size: 0.65rem;">${a.severity}</span>
                        <span class="badge ${a.status === 'RESOLVED' ? 'badge-green' : 'badge-red'}" style="font-size: 0.65rem;">${a.status}</span>
                    </div>
                </div>
            `).join('')
            : '<div style="color: var(--text-muted); font-size: 0.78rem; padding: 6px 0;">No prior security alerts logged for this entity.</div>';

        const body = `
            <div style="display: flex; flex-direction: column; gap: 14px; font-size: 0.85rem;">
                <!-- Demonstration Mode Banner -->
                <div style="background: rgba(168, 85, 247, 0.1); border: 1px solid var(--border-purple); padding: 10px 14px; border-radius: 8px;">
                    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 4px;">
                        <span style="font-weight: 700; color: #fff; font-size: 0.85rem;">
                            <i data-lucide="sparkles" style="width: 14px; height: 14px; vertical-align: middle; margin-right: 4px; color: var(--purple-light);"></i>
                            ML Isolation Forest Inference Profile
                        </span>
                        <span class="badge badge-purple" style="font-size: 0.65rem;">DEMO ENGINE // PRE-API</span>
                    </div>
                    <p style="color: var(--text-secondary); font-size: 0.78rem; margin: 0;">
                        Multidimensional anomaly isolation using binary decision trees. Ready for direct Scikit-Learn IsolationForest inference API integration.
                    </p>
                </div>

                <!-- Anomaly Score Metric -->
                <div style="background: rgba(0,0,0,0.3); padding: 12px 16px; border-radius: 8px; border: 1px solid var(--border-subtle);">
                    <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 6px;">
                        <span style="font-size: 0.75rem; text-transform: uppercase; font-family: var(--font-mono); color: var(--text-dim);">Outlier Anomaly Score</span>
                        <span style="font-size: 1.1rem; font-weight: 700; color: ${scoreColor}; font-family: var(--font-mono);">${threat.anomalyScore} / 1.00 (${scorePercent}%)</span>
                    </div>
                    <div class="progress-track" style="height: 6px;">
                        <div class="progress-fill ${scoreBarClass}" style="width: ${scorePercent}%;"></div>
                    </div>
                </div>

                <!-- Feature Vector Grid -->
                <div class="threat-details-grid">
                    <div class="detail-item"><span class="detail-key">Target Entity</span><span class="detail-val" style="color: #fff; font-weight: 600;">${threat.affectedDeviceName} (${threat.affectedIp})</span></div>
                    <div class="detail-item"><span class="detail-key">Ingress/Egress Rate</span><span class="detail-val">${threat.mlFeatures?.requestFrequency || '450 req/s'}</span></div>
                    <div class="detail-item"><span class="detail-key">Shannon Entropy</span><span class="detail-val">${threat.mlFeatures?.packetEntropy || '7.92'}</span></div>
                    <div class="detail-item"><span class="detail-key">Payload Variance</span><span class="detail-val" style="color: var(--amber);">${threat.mlFeatures?.payloadVariance || '+380%'}</span></div>
                    <div class="detail-item"><span class="detail-key">Baseline Deviation</span><span class="detail-val">${threat.mlFeatures?.baselineDeviation || '3.2σ'}</span></div>
                    <div class="detail-item"><span class="detail-key">Isolation Depth</span><span class="detail-val" style="color: var(--cyan);">3 (Avg Normal: 11)</span></div>
                </div>

                <!-- Diagnostic Explanation & Recommended Action -->
                <div style="background: rgba(0,0,0,0.25); border-left: 3px solid var(--purple-light); padding: 10px 14px; border-radius: 0 8px 8px 0; font-size: 0.8rem; color: #cbd5e1;">
                    <strong style="color: var(--purple-light);">AI Root Cause Diagnostic:</strong><br>${threat.explanation}
                </div>
                <div style="font-size: 0.8rem; color: var(--text-secondary);">
                    <strong style="color: var(--cyan);">Recommended SOC Action:</strong> ${threat.recommendedAction}
                </div>

                <!-- Correlated Alert History -->
                <div>
                    <div style="font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase; font-family: var(--font-mono); margin-bottom: 6px;">
                        Correlated Security Alert History (${relatedAlerts.length} Events):
                    </div>
                    <div style="display: flex; flex-direction: column; gap: 6px; max-height: 140px; overflow-y: auto;">
                        ${alertHistoryHtml}
                    </div>
                </div>
            </div>
        `;

        window.NetGuardianApp.openCustomModal(`AI Threat Analysis: ${threat.id} // ${threat.threatType}`, body);
    }
};

window.ThreatsView = ThreatsView;
