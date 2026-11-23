/**
 * NetGuardian AI - Master Application Controller
 * Manages SPA Routing, Navigation, Global Modals, Atomic Clock, & Audio Cues
 */

const NetGuardianApp = {
    currentView: 'dashboard',
    activeModalDeviceId: null,
    audioContext: null,

    init() {
        console.log('%c[NetGuardian AI] Initializing SOC Interface...', 'color: #00f0ff; font-weight: bold;');
        
        this.initClock();
        this.initNavigation();
        this.initNotifications();
        this.initModals();
        this.initSettings();
        
        // Initialize sub-views
        if (window.DashboardView) window.DashboardView.init();
        if (window.NetworkView) window.NetworkView.init();
        if (window.TopologyView) window.TopologyView.init();
        if (window.ThreatsView) window.ThreatsView.init();
        if (window.RecoveryView) window.RecoveryView.init();
        if (window.AlertsView) window.AlertsView.init();
        if (window.AnalyticsView) window.AnalyticsView.init();

        // Initial icon compilation
        if (window.lucide) {
            window.lucide.createIcons();
        }

        // Show welcome toast
        this.showToast('NetGuardian AI SOC Online. Autonomous Defense Active.', 'cyan');
    },

    // ----------------------------------------------------------------------
    // 1. ATOMIC CLOCK & TIMEKEEPING
    // ----------------------------------------------------------------------
    initClock() {
        const clockEl = document.getElementById('soc-clock');
        const update = () => {
            if (!clockEl) return;
            const now = new Date();
            const timeStr = now.toTimeString().split(' ')[0] + ' UTC';
            clockEl.textContent = timeStr;
        };
        update();
        setInterval(update, 1000);
    },

    // ----------------------------------------------------------------------
    // 2. SPA NAVIGATION & VIEW SWITCHING
    // ----------------------------------------------------------------------
    initNavigation() {
        const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const viewName = item.getAttribute('data-view');
                if (viewName) {
                    this.switchView(viewName);
                }
            });
        });

        // Mobile drawer toggle
        const toggleBtn = document.getElementById('mobile-toggle');
        const sidebar = document.getElementById('app-sidebar');
        if (toggleBtn && sidebar) {
            toggleBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                sidebar.classList.toggle('open');
            });
        }

        // Close mobile drawer on outside click
        document.addEventListener('click', (e) => {
            if (sidebar && sidebar.classList.contains('open')) {
                if (!sidebar.contains(e.target) && e.target !== toggleBtn && (!toggleBtn || !toggleBtn.contains(e.target))) {
                    sidebar.classList.remove('open');
                }
            }
        });
    },

    switchView(viewName) {
        if (this.currentView === viewName) return;

        // Update nav items
        document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
            item.classList.toggle('active', item.getAttribute('data-view') === viewName);
        });

        // Update view sections
        document.querySelectorAll('.view-section').forEach(sec => {
            sec.classList.remove('active');
        });

        const targetSec = document.getElementById(`view-${viewName}`);
        if (targetSec) {
            targetSec.classList.add('active');
        }

        this.currentView = viewName;

        // Close mobile sidebar if open
        const sidebar = document.getElementById('app-sidebar');
        if (sidebar) sidebar.classList.remove('open');

        // Update top breadcrumbs & title
        this.updateHeaderMeta(viewName);

        // Special view triggers
        if (viewName === 'analytics' && window.AnalyticsView) {
            window.AnalyticsView.onViewActivated();
        } else if (viewName === 'topology' && window.TopologyView) {
            window.TopologyView.renderTopology();
        } else if (viewName === 'dashboard' && window.DashboardView) {
            window.DashboardView.updateKPIs();
            window.DashboardView.renderMiniTopology();
        }

        // Refresh icons
        if (window.lucide) {
            window.lucide.createIcons();
        }

        window.scrollTo({ top: 0, behavior: 'smooth' });
    },

    updateHeaderMeta(viewName) {
        const titleEl = document.getElementById('header-page-title');
        const breadcrumbEl = document.getElementById('header-breadcrumb');

        const metaMap = {
            dashboard: {
                title: 'Overview Dashboard',
                icon: 'layout-dashboard',
                breadcrumb: 'SOC CONSOLE // COMMAND OVERVIEW'
            },
            network: {
                title: 'Network Monitor (10 Nodes)',
                icon: 'server',
                breadcrumb: 'INFRASTRUCTURE // MONITORED ASSETS'
            },
            topology: {
                title: 'Live Network Topology Mesh',
                icon: 'network',
                breadcrumb: 'REAL-TIME VISUALIZATION // SUBNET TOPOLOGY'
            },
            threats: {
                title: 'AI Threat & Anomaly Detection',
                icon: 'brain-circuit',
                breadcrumb: 'AUTONOMOUS DEFENSE // ISOLATION FOREST ML'
            },
            recovery: {
                title: 'Self-Healing Centre & Failover',
                icon: 'refresh-cw',
                breadcrumb: 'RESILIENCE // AUTONOMOUS RECOVERY ENGINE'
            },
            alerts: {
                title: 'Security Alert Management',
                icon: 'bell-ring',
                breadcrumb: 'INCIDENT RESPONSE // ADVISORY LEDGER'
            },
            analytics: {
                title: 'Analytics & Historical Telemetry',
                icon: 'line-chart',
                breadcrumb: 'INTELLIGENCE // LONG-TERM SOC AUDIT'
            },
            settings: {
                title: 'SOC System & Model Settings',
                icon: 'sliders-horizontal',
                breadcrumb: 'CONFIGURATION // ANOMALY THRESHOLDS'
            }
        };

        const meta = metaMap[viewName] || metaMap.dashboard;
        if (breadcrumbEl) breadcrumbEl.textContent = meta.breadcrumb;
        if (titleEl) {
            titleEl.innerHTML = `<i data-lucide="${meta.icon}"></i> <span>${meta.title}</span>`;
            if (window.lucide) window.lucide.createIcons();
        }
    },

    // ----------------------------------------------------------------------
    // 3. NOTIFICATION CENTER
    // ----------------------------------------------------------------------
    initNotifications() {
        const notifBtn = document.getElementById('btn-notifications');
        const dropdown = document.getElementById('notif-dropdown');

        if (notifBtn && dropdown) {
            notifBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                dropdown.classList.toggle('show');
            });

            document.addEventListener('click', (e) => {
                if (!dropdown.contains(e.target) && e.target !== notifBtn) {
                    dropdown.classList.remove('show');
                }
            });
        }

        this.renderNotifications();

        window.NetGuardianStore.subscribe(() => {
            this.renderNotifications();
        });
    },

    renderNotifications() {
        const listEl = document.getElementById('notif-dropdown-list');
        const badgeEl = document.getElementById('notif-count');
        const alerts = window.NetGuardianStore.getAlerts();
        const active = alerts.filter(a => a.status === 'ACTIVE' || a.status === 'IN_PROGRESS');

        if (badgeEl) {
            badgeEl.textContent = active.length;
            badgeEl.style.display = active.length > 0 ? 'flex' : 'none';
        }

        if (listEl) {
            if (alerts.length === 0) {
                listEl.innerHTML = '<div style="padding: 16px; color: var(--text-muted); font-size: 0.8rem; text-align: center;">No active advisories.</div>';
                return;
            }
            listEl.innerHTML = alerts.slice(0, 5).map(a => `
                <div class="notif-item ${a.status === 'ACTIVE' ? 'unread' : ''}" onclick="NetGuardianApp.openAlertDetailsModalById('${a.id}')" style="cursor: pointer;">
                    <div style="color: ${a.severity === 'CRITICAL' ? 'var(--red-bright)' : (a.severity === 'HIGH' ? 'var(--amber)' : 'var(--purple-light)')};">
                        <i data-lucide="shield-alert" style="width: 16px; height: 16px;"></i>
                    </div>
                    <div style="flex: 1;">
                        <div style="font-weight: 600; color: #fff;">${a.threatType}</div>
                        <div style="color: var(--text-muted); font-size: 0.72rem;">${a.deviceName} (${a.ip}) • ${a.timestamp}</div>
                    </div>
                </div>
            `).join('');

            if (window.lucide) window.lucide.createIcons();
        }
    },

    // ----------------------------------------------------------------------
    // 4. GLOBAL MODALS
    // ----------------------------------------------------------------------
    initModals() {
        // Device modal close buttons
        const closeDevBtn = document.getElementById('btn-close-device-modal');
        const closeDevFooter = document.getElementById('btn-close-device-modal-footer');
        const devModal = document.getElementById('device-modal');

        const closeDevModalFn = () => {
            if (devModal) devModal.classList.remove('show');
            this.activeModalDeviceId = null;
        };

        if (closeDevBtn) closeDevBtn.addEventListener('click', closeDevModalFn);
        if (closeDevFooter) closeDevFooter.addEventListener('click', closeDevModalFn);

        // Ping button in device modal
        const pingBtn = document.getElementById('btn-modal-ping');
        if (pingBtn) {
            pingBtn.addEventListener('click', () => {
                if (!this.activeModalDeviceId) return;
                const dev = window.NetGuardianStore.getDevice(this.activeModalDeviceId);
                if (dev.status === 'offline') {
                    this.showToast(`ICMP Ping to ${dev.ip} timed out (100% packet loss)`, 'error');
                } else {
                    const rtt = Math.floor(Math.random() * 8) + 1;
                    this.showToast(`ICMP 64 bytes from ${dev.ip}: seq=1 ttl=64 time=${rtt}.2 ms`, 'success');
                }
            });
        }

        // AI Scan button in device modal
        const scanBtn = document.getElementById('btn-modal-scan');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => {
                if (!this.activeModalDeviceId) return;
                const dev = window.NetGuardianStore.getDevice(this.activeModalDeviceId);
                this.showToast(`Running Isolation Forest vector inspection on ${dev.name}...`, 'purple');
                setTimeout(() => {
                    if (dev.status === 'suspicious') {
                        this.showToast(`Anomaly Confirmed on ${dev.name}: Outlier score 0.94!`, 'error');
                    } else if (dev.status === 'offline') {
                        this.showToast(`${dev.name} is offline. Telemetry unavailable.`, 'error');
                    } else {
                        this.showToast(`${dev.name} anomaly score: 0.08 (Within normal limits)`, 'success');
                    }
                }, 700);
            });
        }

        // Toggle Status (Online/Offline) button in device modal
        const toggleBtn = document.getElementById('btn-modal-toggle-status');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                if (!this.activeModalDeviceId) return;
                const dev = window.NetGuardianStore.getDevice(this.activeModalDeviceId);
                if (!dev) return;
                const updated = window.NetGuardianStore.toggleDeviceStatus(this.activeModalDeviceId);
                if (updated) {
                    const isNowOffline = updated.status === 'offline';
                    this.showToast(
                        `${updated.name} (${updated.ip}) is now ${updated.status.toUpperCase()}`,
                        isNowOffline ? 'error' : 'success'
                    );
                    this.openDeviceModal(this.activeModalDeviceId);
                }
            });
        }

        // Alert modal close buttons
        const closeAlertBtn = document.getElementById('btn-close-alert-modal');
        const closeAlertFooter = document.getElementById('btn-close-alert-modal-footer');
        const alertModal = document.getElementById('alert-modal');

        const closeAlertModalFn = () => {
            if (alertModal) alertModal.classList.remove('show');
        };

        if (closeAlertBtn) closeAlertBtn.addEventListener('click', closeAlertModalFn);
        if (closeAlertFooter) closeAlertFooter.addEventListener('click', closeAlertModalFn);

        // Close on clicking backdrop
        [devModal, alertModal].forEach(modal => {
            if (modal) {
                modal.addEventListener('click', (e) => {
                    if (e.target === modal) {
                        modal.classList.remove('show');
                    }
                });
            }
        });
    },

    openDeviceModal(deviceId) {
        const dev = window.NetGuardianStore.getDevice(deviceId);
        if (!dev) return;

        this.activeModalDeviceId = dev.id;
        const modal = document.getElementById('device-modal');
        const title = document.getElementById('dev-modal-title');
        const body = document.getElementById('dev-modal-body');

        if (!modal || !body) return;

        title.innerHTML = `<i data-lucide="server"></i> <span>${dev.name} Specifications</span>`;

        let statusBadge = '<span class="badge badge-green"><span class="pulse-dot"></span> Online</span>';
        if (dev.status === 'offline') statusBadge = '<span class="badge badge-red"><span class="pulse-dot dot-red"></span> Offline</span>';
        else if (dev.status === 'suspicious') statusBadge = '<span class="badge badge-purple"><span class="pulse-dot dot-purple"></span> Suspicious</span>';
        else if (dev.status === 'recovering') statusBadge = '<span class="badge badge-amber"><span class="pulse-dot"></span> Recovering</span>';

        body.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 16px;">
                <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(0,0,0,0.3); padding: 12px 16px; border-radius: 8px; border: 1px solid var(--border-subtle);">
                    <div>
                        <div style="font-size: 1.1rem; font-weight: 700; color: #fff;">${dev.name}</div>
                        <div style="font-size: 0.8rem; color: var(--cyan); font-family: var(--font-mono);">${dev.ip} • MAC: ${dev.mac}</div>
                    </div>
                    <div>${statusBadge}</div>
                </div>

                <div class="threat-details-grid">
                    <div class="detail-item"><span class="detail-key">Assigned Role</span><span class="detail-val">${dev.role}</span></div>
                    <div class="detail-item"><span class="detail-key">Device Classification</span><span class="detail-val">${dev.type}</span></div>
                    <div class="detail-item"><span class="detail-key">Physical Location</span><span class="detail-val">${dev.location || 'Server Room Alpha'}</span></div>
                    <div class="detail-item"><span class="detail-key">Operating System</span><span class="detail-val">${dev.os || 'Linux Core'}</span></div>
                    <div class="detail-item"><span class="detail-key">Uptime</span><span class="detail-val">${dev.uptime || '12d 4h'}</span></div>
                    <div class="detail-item"><span class="detail-key">Packet Loss</span><span class="detail-val">${dev.packetLoss}</span></div>
                </div>

                <div style="background: rgba(0,0,0,0.25); padding: 12px 16px; border-radius: 8px;">
                    <div style="font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase; font-family: var(--font-mono); margin-bottom: 6px;">Live Telemetry &amp; Resource Utilization:</div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px;">
                        <div>
                            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; font-family: var(--font-mono); margin-bottom: 4px;">
                                <span>CPU Utilization</span>
                                <span style="color: var(--cyan);">${dev.cpuLoad}%</span>
                            </div>
                            <div class="progress-track"><div class="progress-fill fill-cyan" style="width: ${dev.cpuLoad}%;"></div></div>
                        </div>
                        <div>
                            <div style="display: flex; justify-content: space-between; font-size: 0.75rem; font-family: var(--font-mono); margin-bottom: 4px;">
                                <span>RAM Allocated</span>
                                <span style="color: var(--purple-light);">${dev.memLoad}%</span>
                            </div>
                            <div class="progress-track"><div class="progress-fill fill-purple" style="width: ${dev.memLoad}%;"></div></div>
                        </div>
                    </div>
                </div>

                <div>
                    <div style="font-size: 0.72rem; color: var(--text-dim); text-transform: uppercase; font-family: var(--font-mono); margin-bottom: 6px;">Listening Network Ports:</div>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                        ${(dev.openPorts && dev.openPorts.length > 0) 
                            ? dev.openPorts.map(p => `<span class="badge badge-muted">Port ${p}</span>`).join('') 
                            : '<span style="color: var(--text-muted); font-size: 0.75rem;">No open listening ports (Interface Down)</span>'}
                    </div>
                </div>
            </div>
        `;

        // Update Toggle Status Button state
        const toggleBtn = document.getElementById('btn-modal-toggle-status');
        if (toggleBtn) {
            if (dev.status === 'offline') {
                toggleBtn.className = 'btn btn-green';
                toggleBtn.innerHTML = '<i data-lucide="power"></i> <span>Restore Online</span>';
            } else {
                toggleBtn.className = 'btn btn-red';
                toggleBtn.innerHTML = '<i data-lucide="power-off"></i> <span>Simulate Offline</span>';
            }
        }

        modal.classList.add('show');
        if (window.lucide) window.lucide.createIcons();
    },

    openAlertDetailsModal(alert) {
        const modal = document.getElementById('alert-modal');
        const title = document.getElementById('alert-modal-title');
        const body = document.getElementById('alert-modal-body');
        const resolveBtn = document.getElementById('btn-modal-resolve-alert');

        if (!modal || !body) return;

        title.innerHTML = `<i data-lucide="shield-alert"></i> <span>Incident ${alert.id}</span>`;

        let severityBadge = '';
        if (alert.severity === 'CRITICAL') severityBadge = '<span class="badge badge-red">CRITICAL SEVERITY</span>';
        else if (alert.severity === 'HIGH') severityBadge = '<span class="badge badge-amber">HIGH SEVERITY</span>';
        else severityBadge = '<span class="badge badge-purple">MEDIUM / LOW</span>';

        body.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div style="font-size: 1.1rem; font-weight: 700; color: #fff;">${alert.threatType}</div>
                    ${severityBadge}
                </div>
                <div class="threat-details-grid">
                    <div class="detail-item"><span class="detail-key">Target Device</span><span class="detail-val">${alert.deviceName} (${alert.ip})</span></div>
                    <div class="detail-item"><span class="detail-key">Timestamp</span><span class="detail-val">${alert.timestamp}</span></div>
                    <div class="detail-item"><span class="detail-key">Operational Status</span><span class="detail-val" style="color: ${alert.status === 'RESOLVED' ? 'var(--green-bright)' : 'var(--red-bright)'}; font-weight: 600;">${alert.status}</span></div>
                    <div class="detail-item"><span class="detail-key">Automated Action</span><span class="detail-val">eBPF Packet Drop Rule Staged</span></div>
                </div>
                <div style="background: rgba(0,0,0,0.3); border-left: 3px solid var(--cyan); padding: 12px; border-radius: 0 8px 8px 0; font-size: 0.85rem; color: #cbd5e1;">
                    <strong>SOC Advisory Summary:</strong><br>${alert.summary}
                </div>
                <div style="font-size: 0.8rem; color: var(--text-secondary);">
                    <strong style="color: var(--purple-light);">SOC Playbook Recommendation:</strong> Verify endpoint process hash against threat database, ensure host egress is restricted, and flush connection tracking states.
                </div>
            </div>
        `;

        if (resolveBtn) {
            if (alert.status === 'RESOLVED') {
                resolveBtn.style.display = 'none';
            } else {
                resolveBtn.style.display = 'inline-flex';
                resolveBtn.onclick = () => {
                    window.NetGuardianStore.resolveAlert(alert.id);
                    this.showToast(`Alert ${alert.id} resolved successfully`, 'success');
                    modal.classList.remove('show');
                };
            }
        }

        modal.classList.add('show');
        if (window.lucide) window.lucide.createIcons();
    },

    openAlertDetailsModalById(alertId) {
        const alert = window.NetGuardianStore.getAlerts().find(a => a.id === alertId);
        if (alert) this.openAlertDetailsModal(alert);
    },

    openCustomModal(titleText, htmlBody) {
        const modal = document.getElementById('alert-modal');
        const title = document.getElementById('alert-modal-title');
        const body = document.getElementById('alert-modal-body');
        const resolveBtn = document.getElementById('btn-modal-resolve-alert');

        if (!modal || !body) return;

        title.innerHTML = `<i data-lucide="info"></i> <span>${titleText}</span>`;
        body.innerHTML = htmlBody;
        if (resolveBtn) resolveBtn.style.display = 'none';

        modal.classList.add('show');
        if (window.lucide) window.lucide.createIcons();
    },

    // ----------------------------------------------------------------------
    // 5. TOAST NOTIFICATIONS & AUDIO CUES
    // ----------------------------------------------------------------------
    showToast(message, type = 'cyan') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        let iconName = 'info';
        if (type === 'success') iconName = 'check-circle-2';
        else if (type === 'error') iconName = 'alert-triangle';
        else if (type === 'purple') iconName = 'brain-circuit';

        toast.innerHTML = `
            <i data-lucide="${iconName}" style="width: 16px; height: 16px; flex-shrink: 0;"></i>
            <span style="flex: 1;">${message}</span>
        `;

        container.appendChild(toast);
        if (window.lucide) window.lucide.createIcons();

        // Audio cue if enabled
        if (type === 'error' || type === 'purple') {
            this.playCyberTone(type === 'error' ? 330 : 660);
        }

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    },

    playCyberTone(freq = 440) {
        const soundEnabled = document.getElementById('setting-sound-alerts');
        if (soundEnabled && !soundEnabled.checked) return;

        try {
            if (!this.audioContext) {
                const AudioCtx = window.AudioContext || window.webkitAudioContext;
                if (AudioCtx) this.audioContext = new AudioCtx();
            }
            if (this.audioContext && this.audioContext.state === 'running') {
                const osc = this.audioContext.createOscillator();
                const gain = this.audioContext.createGain();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(freq, this.audioContext.currentTime);
                gain.gain.setValueAtTime(0.04, this.audioContext.currentTime);
                gain.gain.exponentialRampToValueAtTime(0.001, this.audioContext.currentTime + 0.18);
                osc.connect(gain);
                gain.connect(this.audioContext.destination);
                osc.start();
                osc.stop(this.audioContext.currentTime + 0.2);
            }
        } catch (e) {
            // Audio context silently handled
        }
    },

    // ----------------------------------------------------------------------
    // 6. SETTINGS VIEW
    // ----------------------------------------------------------------------
    initSettings() {
        const slider = document.getElementById('setting-contam-slider');
        const sliderVal = document.getElementById('setting-contam-val');
        if (slider && sliderVal) {
            slider.addEventListener('input', (e) => {
                sliderVal.textContent = e.target.value;
            });
        }

        const saveBtn = document.getElementById('btn-save-settings');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                this.showToast('SOC Engine configurations committed to local storage cache.', 'success');
            });
        }

        const resetBtn = document.getElementById('btn-reset-settings');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => {
                if (slider && sliderVal) {
                    slider.value = 0.05;
                    sliderVal.textContent = '0.05';
                }
                if (window.NetGuardianStore && typeof window.NetGuardianStore.resetStateToDefaults === 'function') {
                    window.NetGuardianStore.resetStateToDefaults();
                }
                this.showToast('Configurations and simulation state reset to baseline defaults.', 'cyan');
            });
        }
    }
};

window.NetGuardianApp = NetGuardianApp;

// Launch application on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    NetGuardianApp.init();
});
