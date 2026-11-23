/**
 * NetGuardian AI - Security Alerts View Controller
 * Page 6 - Incident Management & Threat Resolution
 */

const AlertsView = {
    searchQuery: '',
    severityFilter: 'all',
    statusFilter: 'all',

    init() {
        this.renderAlerts();
        this.bindEvents();

        // Subscribe to store updates
        window.NetGuardianStore.subscribe((event, payload) => {
            this.renderAlerts();
        });
    },

    bindEvents() {
        const searchInput = document.getElementById('alert-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchQuery = e.target.value.toLowerCase().trim();
                this.renderAlerts();
            });
        }

        const severityPills = document.querySelectorAll('.tab-pill-group .tab-pill');
        severityPills.forEach(pill => {
            pill.addEventListener('click', () => {
                severityPills.forEach(p => p.classList.remove('active'));
                pill.classList.add('active');
                this.severityFilter = pill.getAttribute('data-severity');
                this.renderAlerts();
            });
        });

        const statusSelect = document.getElementById('alert-status-filter');
        if (statusSelect) {
            statusSelect.addEventListener('change', (e) => {
                this.statusFilter = e.target.value;
                this.renderAlerts();
            });
        }
    },

    renderAlerts() {
        const tbody = document.getElementById('alerts-table-body');
        if (!tbody) return;

        const allAlerts = window.NetGuardianStore.getAlerts();
        const filtered = allAlerts.filter(a => {
            const matchesSearch = !this.searchQuery ||
                a.id.toLowerCase().includes(this.searchQuery) ||
                a.threatType.toLowerCase().includes(this.searchQuery) ||
                a.deviceName.toLowerCase().includes(this.searchQuery) ||
                a.ip.toLowerCase().includes(this.searchQuery);

            const matchesSeverity = this.severityFilter === 'all' || a.severity === this.severityFilter;
            const matchesStatus = this.statusFilter === 'all' || a.status === this.statusFilter;

            return matchesSearch && matchesSeverity && matchesStatus;
        });

        // Update nav badge count
        const activeAlerts = allAlerts.filter(a => a.status === 'ACTIVE' || a.status === 'IN_PROGRESS');
        const navAlertsBadge = document.getElementById('nav-alerts-badge');
        if (navAlertsBadge) {
            navAlertsBadge.textContent = `${activeAlerts.length} ACTIVE`;
            if (activeAlerts.length === 0) {
                navAlertsBadge.className = 'nav-badge badge-green';
                navAlertsBadge.textContent = 'ALL RESOLVED';
            } else {
                navAlertsBadge.className = 'nav-badge badge-red';
            }
        }

        const summaryBadge = document.getElementById('alert-table-summary');
        if (summaryBadge) {
            summaryBadge.textContent = `${filtered.length} of ${allAlerts.length} Alerts Shown`;
        }

        if (filtered.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <i data-lucide="shield-check" style="width: 32px; height: 32px; margin-bottom: 8px; color: var(--green-bright);"></i>
                        <div>No alerts matching the selected filters.</div>
                    </td>
                </tr>
            `;
            if (window.lucide) window.lucide.createIcons();
            return;
        }

        tbody.innerHTML = filtered.map(a => {
            let severityBadge = '';
            if (a.severity === 'CRITICAL') severityBadge = '<span class="badge badge-red">CRITICAL</span>';
            else if (a.severity === 'HIGH') severityBadge = '<span class="badge badge-amber">HIGH</span>';
            else if (a.severity === 'MEDIUM') severityBadge = '<span class="badge badge-purple">MEDIUM</span>';
            else severityBadge = '<span class="badge badge-cyan">LOW</span>';

            let statusBadge = '';
            let actionBtn = '';
            if (a.status === 'ACTIVE') {
                statusBadge = '<span class="badge badge-red"><span class="pulse-dot dot-red"></span> ACTIVE</span>';
                actionBtn = `
                    <button class="btn btn-green btn-sm" onclick="event.stopPropagation(); AlertsView.resolve('${a.id}')">
                        <i data-lucide="check" style="width: 14px; height: 14px;"></i>
                        <span>Resolve</span>
                    </button>
                `;
            } else if (a.status === 'IN_PROGRESS') {
                statusBadge = '<span class="badge badge-amber"><span class="pulse-dot"></span> IN PROGRESS</span>';
                actionBtn = `
                    <button class="btn btn-green btn-sm" onclick="event.stopPropagation(); AlertsView.resolve('${a.id}')">
                        <i data-lucide="check" style="width: 14px; height: 14px;"></i>
                        <span>Resolve</span>
                    </button>
                `;
            } else {
                statusBadge = '<span class="badge badge-green">RESOLVED</span>';
                actionBtn = `
                    <span style="font-size: 0.75rem; color: var(--text-muted); font-family: var(--font-mono);">
                        <i data-lucide="check-check" style="width: 12px; height: 12px; color: var(--green-bright); vertical-align: middle;"></i> Closed
                    </span>
                `;
            }

            return `
                <tr onclick="AlertsView.openAlertModal('${a.id}')" style="cursor: pointer;">
                    <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyan);">${a.id}</td>
                    <td>
                        <strong style="color: #fff;">${a.threatType || a.threat_type || 'Security Threat'}</strong>
                        <div style="font-size: 0.72rem; color: var(--text-muted);">${a.summary || a.description || 'Security baseline deviation detected.'}</div>
                    </td>
                    <td>
                        <div style="font-weight: 600; color: #fff;">${a.deviceName}</div>
                        <div style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--cyan);">${a.ip}</div>
                    </td>
                    <td>${severityBadge}</td>
                    <td style="font-family: var(--font-mono); font-size: 0.75rem;">${a.timestamp}</td>
                    <td>${statusBadge}</td>
                    <td>
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); AlertsView.openAlertModal('${a.id}')">
                                <i data-lucide="info" style="width: 14px; height: 14px;"></i>
                            </button>
                            ${actionBtn}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        if (window.lucide) window.lucide.createIcons();
    },

    async resolve(alertId) {
        if (window.NetGuardianApp) {
            window.NetGuardianApp.showToast(`Resolving security incident ${alertId}...`, 'cyan');
        }

        await window.NetGuardianAPI.resolveAlert(alertId);

        if (window.NetGuardianApp) {
            window.NetGuardianApp.showToast(`Alert ${alertId} resolved and logged to SOC audit history.`, 'success');
        }
    },

    openAlertModal(alertId) {
        const alert = window.NetGuardianStore.getAlerts().find(a => a.id === alertId);
        if (!alert || !window.NetGuardianApp) return;

        window.NetGuardianApp.openAlertDetailsModal(alert);
    }
};

window.AlertsView = AlertsView;
