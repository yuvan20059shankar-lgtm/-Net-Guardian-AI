/**
 * NetGuardian AI - Self-Healing Centre View Controller
 * Page 5 - Autonomous Network Recovery Control Centre
 */

const RecoveryView = {
    isRecovering: false,

    init() {
        this.renderState();
        this.renderHistory();
        this.bindEvents();

        // Subscribe to store updates
        window.NetGuardianStore.subscribe((event, payload) => {
            this.renderState();
            this.renderHistory();
        });
    },

    bindEvents() {
        // 1. Simulate Device Failure
        const simFailBtn = document.getElementById('btn-simulate-failure');
        if (simFailBtn) {
            simFailBtn.addEventListener('click', () => {
                this.simulateFailure();
            });
        }

        // 2. Find Alternative Route
        const findRouteBtn = document.getElementById('btn-find-alt-route');
        if (findRouteBtn) {
            findRouteBtn.addEventListener('click', () => {
                this.findAlternativeRoute();
            });
        }

        // 3. Start Recovery
        const startRecBtn = document.getElementById('btn-start-recovery');
        if (startRecBtn) {
            startRecBtn.addEventListener('click', () => {
                this.startRecovery();
            });
        }

        // 4. Restore Device
        const restoreBtn = document.getElementById('btn-restore-device');
        if (restoreBtn) {
            restoreBtn.addEventListener('click', () => {
                this.restoreDevice();
            });
        }
    },

    renderState() {
        const rec = window.NetGuardianStore.getRecoveryState();
        const pipelineBadge = document.getElementById('recovery-pipeline-status');
        const backupBadge = document.getElementById('backup-server-badge');
        const altRouteBadge = document.getElementById('alt-route-active-badge');
        const planDisplay = document.getElementById('alt-route-plan-display');
        const navRecBadge = document.getElementById('nav-recovery-badge');

        // Pipeline steps visual highlighting
        for (let i = 1; i <= 4; i++) {
            const stepEl = document.getElementById(`pipe-step-${i}`);
            if (!stepEl) continue;

            stepEl.className = 'pipeline-step';
            if (rec.recoveryStep === i) {
                stepEl.classList.add('step-active');
            } else if (rec.recoveryStep > i || (!rec.isFailureSimulated && rec.recoveryStep === 4)) {
                stepEl.classList.add('step-done');
            }
        }

        if (rec.isFailureSimulated) {
            const failedDev = window.NetGuardianStore.getDevice(rec.failedDeviceId || 'dev-3');
            const devName = failedDev ? failedDev.name : 'Server 02';

            if (pipelineBadge) {
                pipelineBadge.className = 'badge badge-red';
                pipelineBadge.textContent = `ALERT // ${devName.toUpperCase()} OFFLINE`;
            }
            if (navRecBadge) {
                navRecBadge.className = 'nav-badge badge-red';
                navRecBadge.textContent = 'FAULT DETECTED';
            }
        } else {
            if (pipelineBadge) {
                pipelineBadge.className = 'badge badge-cyan';
                pipelineBadge.textContent = 'STANDBY // READY';
            }
            if (navRecBadge) {
                navRecBadge.className = 'nav-badge badge-green';
                navRecBadge.textContent = 'READY';
            }
        }

        // Backup server badge
        if (backupBadge) {
            if (rec.backupServerStatus === 'HOT_ACTIVE') {
                backupBadge.className = 'badge badge-purple';
                backupBadge.textContent = 'HOT ACTIVE (FAILOVER PROXY)';
            } else if (rec.backupServerStatus === 'STANDBY_ALERT') {
                backupBadge.className = 'badge badge-amber';
                backupBadge.textContent = 'STANDBY (STAGING MESH)';
            } else {
                backupBadge.className = 'badge badge-green';
                backupBadge.textContent = 'STANDBY READY';
            }
        }

        // Alternative Route badge & display
        if (altRouteBadge && planDisplay) {
            if (rec.alternativeRouteActive && rec.activeRoutePlan && rec.activeRoutePlan.success) {
                altRouteBadge.className = 'badge badge-green';
                altRouteBadge.textContent = 'ACTIVE REROUTE';
                const pathNodes = rec.activeRoutePlan.path || [];
                const pathHtml = pathNodes.map((node, i) => {
                    if (i === pathNodes.length - 1) return `<span style="color: var(--amber); font-weight: 600;">${node}</span>`;
                    return node;
                }).join(' ➔ ');

                planDisplay.innerHTML = `
                    <div style="background: rgba(0, 240, 255, 0.05); border: 1px solid var(--border-cyan); border-radius: 6px; padding: 10px;">
                        <strong style="color: var(--cyan); display: block; margin-bottom: 4px;">Dynamic Mesh Bypass Engaged:</strong>
                        <div style="font-family: var(--font-mono); font-size: 0.75rem; color: #fff;">
                            ${pathHtml}
                        </div>
                        <div style="font-size: 0.72rem; color: var(--green-bright); margin-top: 6px;">
                            Zero packet drops. Ingress latency: ${rec.activeRoutePlan.latency || '1.2ms'} via ${rec.activeRoutePlan.protocol || 'BGP Dynamic Failover Mesh'}.
                        </div>
                    </div>
                `;
            } else if (rec.activeRoutePlan && !rec.activeRoutePlan.success) {
                altRouteBadge.className = 'badge badge-red';
                altRouteBadge.textContent = 'NO ROUTE AVAILABLE';
                planDisplay.innerHTML = `
                    <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid var(--border-red); border-radius: 6px; padding: 10px; color: #fca5a5; font-size: 0.8rem;">
                        <strong style="color: var(--red-bright);">Dynamic Failover Failed:</strong> ${rec.activeRoutePlan.error}<br>
                        <span style="font-size: 0.72rem; color: var(--text-muted); margin-top: 4px; display: block;">No redundant secondary route exists in the simulated star topology. Manual hardware servicing required.</span>
                    </div>
                `;
            } else {
                altRouteBadge.className = 'badge badge-amber';
                altRouteBadge.textContent = 'INACTIVE';
                planDisplay.innerHTML = `No active reroute engaged. Primary network routes operating at nominal capacity. Click <strong>"Find Alternative Route"</strong> to calculate failover path.`;
            }
        }
    },

    renderHistory() {
        const tbody = document.getElementById('recovery-history-tbody');
        const badge = document.getElementById('recovery-history-count');
        if (!tbody) return;

        const rec = window.NetGuardianStore.getRecoveryState();
        if (badge) badge.textContent = `${rec.history.length} Recoveries Recorded`;

        tbody.innerHTML = rec.history.map(item => `
            <tr>
                <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyan);">${item.id}</td>
                <td style="font-family: var(--font-mono); font-size: 0.75rem;">${item.timestamp}</td>
                <td style="font-weight: 600; color: #fff;">${item.targetDevice}</td>
                <td><span class="badge badge-muted">${item.faultType}</span></td>
                <td style="font-size: 0.78rem; color: var(--text-secondary); max-width: 320px;">${item.actionTaken}</td>
                <td style="font-family: var(--font-mono); color: var(--purple-light);">${item.duration}</td>
                <td><span class="badge badge-green"><span class="pulse-dot"></span> ${item.status}</span></td>
            </tr>
        `).join('');

        if (window.lucide) window.lucide.createIcons();
    },

    logTerminal(prefix, message) {
        const terminal = document.getElementById('healing-terminal-output');
        if (!terminal) return;

        const now = new Date().toTimeString().split(' ')[0];
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = `<span class="terminal-time">[${now} ${prefix}]</span> <span>${message}</span>`;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    },

    getSelectedTargetId() {
        const select = document.getElementById('recovery-target-select');
        return select ? select.value : (window.NetGuardianStore.getRecoveryState().failedDeviceId || 'dev-4');
    },

    async simulateFailure() {
        const targetDevId = this.getSelectedTargetId();
        const targetDev = window.NetGuardianStore.getDevice(targetDevId);
        const name = targetDev ? targetDev.name : 'Target Node';
        const ip = targetDev ? targetDev.ip : '192.168.1.x';

        this.logTerminal('FAULT_INJECT', `Simulating hardware fault & network partition on ${name} (${ip})...`);
        
        const device = await window.NetGuardianAPI.simulateFailure(targetDevId);
        
        this.logTerminal('ALERT', `Heartbeat ping timeout on interface eth0 (${device.ip}). Node marked FAILED.`);
        
        if (window.NetGuardianApp) {
            window.NetGuardianApp.showToast(`Simulated failure triggered on ${device.name}. Outage detected!`, 'error');
        }
    },

    async findAlternativeRoute() {
        const targetDevId = window.NetGuardianStore.getRecoveryState().failedDeviceId || this.getSelectedTargetId();
        const targetDev = window.NetGuardianStore.getDevice(targetDevId);
        const name = targetDev ? targetDev.name : 'Failed Node';

        this.logTerminal('ROUTING_ENGINE', `Analyzing BGP mesh topology for zero-loss failover route bypassing ${name}...`);
        
        const plan = await window.NetGuardianAPI.findAlternativeRoute(targetDevId);
        
        if (plan.success) {
            this.logTerminal('REROUTE_SUCCESS', `Bypass path calculated: ${plan.path.join(' ➔ ')}. Dynamic mesh active.`);
            if (window.NetGuardianApp) {
                window.NetGuardianApp.showToast(`Alternative route established: ${plan.path[plan.path.length - 1]}!`, 'cyan');
            }
        } else {
            this.logTerminal('REROUTE_FAIL', `CRITICAL: ${plan.error}`);
            if (window.NetGuardianApp) {
                window.NetGuardianApp.showToast(`Reroute failed: ${plan.error}`, 'error');
            }
        }
    },

    async startRecovery() {
        if (this.isRecovering) return;
        this.isRecovering = true;

        const targetDevId = window.NetGuardianStore.getRecoveryState().failedDeviceId || this.getSelectedTargetId();
        const targetDev = window.NetGuardianStore.getDevice(targetDevId);
        const name = targetDev ? targetDev.name : 'Target Node';

        const startBtn = document.getElementById('btn-start-recovery');
        if (startBtn) {
            startBtn.disabled = true;
            startBtn.innerHTML = `<i data-lucide="loader" class="spin" style="width: 14px; height: 14px;"></i> <span>Recovering...</span>`;
            if (window.lucide) window.lucide.createIcons();
        }

        this.logTerminal('HEAL_EXEC', `Starting automated self-healing pipeline for ${name}...`);
        if (window.NetGuardianApp) {
            window.NetGuardianApp.showToast(`Initiating autonomous recovery sequence for ${name}...`, 'purple');
        }

        try {
            await window.NetGuardianAPI.startRecovery(targetDevId, (progress) => {
                this.logTerminal(`PHASE_${progress.step}`, progress.text);
            });

            this.logTerminal('RESTORE_VERIFIED', `All microservice health probes for ${name} returned HTTP 200 OK. Zero latency jitter.`);
            if (window.NetGuardianApp) {
                window.NetGuardianApp.showToast(`${name} fully recovered and returned to active rotation!`, 'success');
            }
        } catch (err) {
            this.logTerminal('ERROR', `Recovery encountered an exception: ${err.message}`);
        } finally {
            this.isRecovering = false;
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.innerHTML = `<i data-lucide="play"></i> <span>Start Recovery</span>`;
                if (window.lucide) window.lucide.createIcons();
            }
        }
    },

    async restoreDevice() {
        const targetDevId = window.NetGuardianStore.getRecoveryState().failedDeviceId || this.getSelectedTargetId();
        const targetDev = window.NetGuardianStore.getDevice(targetDevId);
        const name = targetDev ? targetDev.name : 'Target Node';

        this.logTerminal('MANUAL_OVERRIDE', `Restoring ${name} nominal baseline parameters...`);
        const dev = await window.NetGuardianAPI.restoreDevice(targetDevId);
        this.logTerminal('RESTORE_OK', `${dev.name} operational state confirmed healthy.`);

        if (window.NetGuardianApp) {
            window.NetGuardianApp.showToast(`${dev.name} restored to healthy online status!`, 'success');
        }
    }
};

window.RecoveryView = RecoveryView;
