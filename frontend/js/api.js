/**
 * NetGuardian AI - API Communication Layer & Backend Integration
 * Tagline: Detect. Defend. Recover. Automatically.
 * 
 * Provides robust communication between the Frontend SOC and the Python Flask Backend:
 * - Active Live Backend: http://127.0.0.1:5000/api
 * - Automatic Fallback to Local Store on Connection Failures
 * - Full Bidirectional Synchronization with SQLite Database
 * - Payload Normalization for Device, Alert, and Threat Schemas
 */

const NetGuardianAPI = {
    // Set to true to communicate with the live Python Flask backend
    USE_LIVE_BACKEND: true,
    API_BASE_URL: 'http://127.0.0.1:5000/api',

    /**
     * Helper for simulated latency fallback
     */
    _simulateLatency(ms = 80) {
        return new Promise(resolve => setTimeout(resolve, ms));
    },

    /**
     * Normalizes backend device record into frontend-compatible schema
     */
    normalizeDevice(d) {
        if (!d) return null;
        const numId = typeof d.id === 'number' ? d.id : parseInt(String(d.id).replace('dev-', ''), 10) || 1;
        return {
            id: `dev-${numId}`,
            numericId: numId,
            name: d.device_name || d.name || `Device ${numId}`,
            ip: d.ip_address || d.ip || `192.168.1.${numId}`,
            mac: d.mac || `00:1A:2B:3C:4D:${String(numId).padStart(2, '0')}`,
            type: d.device_type || d.type || 'Server',
            role: d.role || '',
            status: d.status || 'online',
            trafficIn: d.traffic_in || d.trafficIn || '0.0 Mbps',
            trafficOut: d.traffic_out || d.trafficOut || '0.0 Mbps',
            cpuLoad: d.cpu_usage !== undefined ? d.cpu_usage : (d.cpuLoad || 0),
            memLoad: d.memory_usage !== undefined ? d.memory_usage : (d.memLoad || 0),
            packetLoss: d.packet_loss || d.packetLoss || '0.00%',
            lastActive: d.last_active || d.lastActive || 'Just now',
            uptime: d.uptime || '14d 08h',
            openPorts: d.openPorts || [22, 80],
            location: d.location || 'Rack Alpha'
        };
    },

    /**
     * Normalizes security alert record
     */
    normalizeAlert(a) {
        if (!a) return null;
        const desc = a.description || a.summary || a.explanation || 'Security anomaly detected by automated rule.';
        return {
            id: a.alert_code || a.id || `ALT-${a.id}`,
            alertCode: a.alert_code || a.id,
            deviceId: a.device_id ? `dev-${a.device_id}` : (a.deviceId || 'dev-1'),
            deviceName: a.device_name || a.deviceName || 'Network Device',
            ip: a.ip_address || a.ip || '192.168.1.1',
            threatType: a.threat_type || a.threatType || a.threat_classification || 'Security Incident',
            severity: a.severity || 'MEDIUM',
            status: a.status || 'ACTIVE',
            description: desc,
            summary: desc,
            explanation: desc,
            detectionSource: a.detection_source || a.detectionSource || 'AI Detection Engine',
            recommendedAction: a.recommended_action || a.recommendedAction || 'Review security event',
            anomalyScore: a.anomaly_score !== undefined ? a.anomaly_score : 0.82,
            timestamp: a.created_at || a.timestamp || 'Just now'
        };
    },

    /**
     * Normalizes threat intelligence record
     */
    normalizeThreat(t) {
        if (!t) return null;
        return {
            id: t.id || t.threat_id || t.alert_code || 'THR-1001',
            threatType: t.threatType || t.threat_type || 'Potential Security Threat',
            affectedDeviceId: t.affectedDeviceId || (t.device_id ? `dev-${t.device_id}` : 'dev-1'),
            affectedDeviceName: t.affectedDeviceName || t.device_name || 'Network Host',
            affectedIp: t.affectedIp || t.ip_address || '192.168.1.1',
            severity: t.severity || 'MEDIUM',
            status: t.status || 'ACTIVE',
            anomalyScore: t.anomalyScore !== undefined ? t.anomalyScore : (t.anomaly_score || 0.82),
            explanation: t.explanation || t.description || 'Behavioral traffic anomaly detected.',
            recommendedAction: t.recommendedAction || t.recommended_action || 'Inspect network logs',
            mlFeatures: t.mlFeatures || { packetEntropy: 6.5, baselineDeviation: '3.4σ' },
            timestamp: t.timestamp || t.created_at || 'Just now',
            detectionSource: t.detectionSource || 'Isolation Forest Model'
        };
    },

    /**
     * Bidirectional Store Sync: Pulls live SQLite state into NetGuardianStore
     */
    async syncStoreWithBackend() {
        if (!this.USE_LIVE_BACKEND || !window.NetGuardianStore) return;
        try {
            const [devRes, alertRes, threatRes, metricsRes] = await Promise.all([
                fetch(`${this.API_BASE_URL}/devices`).then(r => r.ok ? r.json() : null).catch(() => null),
                fetch(`${this.API_BASE_URL}/alerts`).then(r => r.ok ? r.json() : null).catch(() => null),
                fetch(`${this.API_BASE_URL}/threats`).then(r => r.ok ? r.json() : null).catch(() => null),
                fetch(`${this.API_BASE_URL}/dashboard`).then(r => r.ok ? r.json() : null).catch(() => null)
            ]);

            if (devRes && (devRes.data || devRes.devices)) {
                const rawDevices = devRes.data || devRes.devices;
                window.NetGuardianStore.state.devices = rawDevices.map(d => this.normalizeDevice(d));
            }

            if (alertRes && (alertRes.data || alertRes.alerts)) {
                const rawAlerts = alertRes.data || alertRes.alerts;
                window.NetGuardianStore.state.alerts = rawAlerts.map(a => this.normalizeAlert(a));
            }

            if (threatRes && (threatRes.data || threatRes.threats)) {
                const rawThreats = threatRes.data || threatRes.threats;
                window.NetGuardianStore.state.threats = rawThreats.map(t => this.normalizeThreat(t));
            }

            if (metricsRes && (metricsRes.data || metricsRes.metrics)) {
                const m = metricsRes.data || metricsRes.metrics;
                window.NetGuardianStore.state.metrics = {
                    ...window.NetGuardianStore.state.metrics,
                    ...m
                };
                const succRec = m.successfulRecoveries !== undefined ? m.successfulRecoveries : m.successful_recoveries;
                if (succRec !== undefined) {
                    window.NetGuardianStore.simulatedRecoveriesCount = succRec;
                }
            }

            window.NetGuardianStore.notify('STORE_SYNCED', { source: 'LIVE_BACKEND' });
            console.log('[NetGuardian AI] Synchronized frontend store with live Flask backend.');
        } catch (err) {
            console.warn('[NetGuardian AI] Store sync with backend bypassed:', err);
        }
    },

    // =========================================================================
    // 1. SYSTEM HEALTH & DASHBOARD ENDPOINTS
    // =========================================================================

    async getHealth() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/health`);
                if (res.ok) return await res.json();
            } catch (e) {
                console.warn('Backend /health error, using fallback:', e);
            }
        }
        await this._simulateLatency(40);
        return window.NetGuardianStore.getHealth();
    },

    async getDashboard() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/dashboard`);
                if (res.ok) {
                    const data = await res.json();
                    return data.data || data;
                }
            } catch (e) {
                console.warn('Backend /dashboard error, using fallback:', e);
            }
        }
        await this._simulateLatency(60);
        return window.NetGuardianStore.getDashboard();
    },

    async getDashboardStatistics() {
        return this.getMetrics();
    },

    async getMetrics() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/dashboard`);
                if (res.ok) {
                    const data = await res.json();
                    return data.data || data.metrics || data;
                }
            } catch (e) {
                console.warn('Backend /dashboard metrics error:', e);
            }
        }
        return window.NetGuardianStore.getMetrics();
    },

    // =========================================================================
    // 2. DEVICE & INVENTORY ENDPOINTS
    // =========================================================================

    async getDevices() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/devices`);
                if (res.ok) {
                    const data = await res.json();
                    const rawList = data.data || data.devices || [];
                    return rawList.map(d => this.normalizeDevice(d));
                }
            } catch (e) {
                console.warn('Backend /devices error, using fallback:', e);
            }
        }
        await this._simulateLatency(50);
        return window.NetGuardianStore.getDevices();
    },

    async getDeviceById(id) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const numId = typeof id === 'number' ? id : parseInt(String(id).replace('dev-', ''), 10) || id;
                const res = await fetch(`${this.API_BASE_URL}/devices/${numId}`);
                if (res.ok) {
                    const data = await res.json();
                    return this.normalizeDevice(data.data || data.device || data);
                }
            } catch (e) {
                console.warn(`Backend /devices/${id} error, using fallback:`, e);
            }
        }
        await this._simulateLatency(30);
        return window.NetGuardianStore.getDevice(id);
    },

    async setDeviceStatus(id, status) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const numId = typeof id === 'number' ? id : parseInt(String(id).replace('dev-', ''), 10) || id;
                const res = await fetch(`${this.API_BASE_URL}/devices/${numId}/status`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status })
                });
                if (res.ok) {
                    await this.syncStoreWithBackend();
                    return await res.json();
                }
            } catch (e) {
                console.warn(`Backend PATCH /devices/${id}/status error:`, e);
            }
        }
        await this._simulateLatency(80);
        return window.NetGuardianStore.setDeviceStatus(id, status);
    },

    async toggleDeviceStatus(id) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const numId = typeof id === 'number' ? id : parseInt(String(id).replace('dev-', ''), 10) || id;
                const res = await fetch(`${this.API_BASE_URL}/devices/${numId}/toggle`, { method: 'POST' });
                if (res.ok) {
                    await this.syncStoreWithBackend();
                    return await res.json();
                }
            } catch (e) {
                console.warn(`Backend POST /devices/${id}/toggle error:`, e);
            }
        }
        await this._simulateLatency(80);
        return window.NetGuardianStore.toggleDeviceStatus(id);
    },

    // =========================================================================
    // 3. NETWORK TRAFFIC & TOPOLOGY ENDPOINTS
    // =========================================================================

    async getTraffic() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/traffic`);
                if (res.ok) return await res.json();
            } catch (e) {
                console.warn('Backend /traffic error, using fallback:', e);
            }
        }
        await this._simulateLatency(40);
        return {
            rx: 482,
            tx: 410,
            unit: 'Mbps',
            trend: 'stable',
            packetLoss: '0.01%',
            bandwidthUtilization: '64.8%'
        };
    },

    async getTopology() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/topology`);
                if (res.ok) return await res.json();
            } catch (e) {
                console.warn('Backend /topology error, using fallback:', e);
            }
        }
        await this._simulateLatency(50);
        return window.NetGuardianStore.getTopology();
    },

    // =========================================================================
    // 4. SECURITY ALERTS & THREATS ENDPOINTS
    // =========================================================================

    async getAlerts() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/alerts`);
                if (res.ok) {
                    const data = await res.json();
                    const raw = data.data || data.alerts || [];
                    return raw.map(a => this.normalizeAlert(a));
                }
            } catch (e) {
                console.warn('Backend /alerts error, using fallback:', e);
            }
        }
        await this._simulateLatency(60);
        return window.NetGuardianStore.getAlerts();
    },

    async resolveAlert(alertId) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/alerts/${alertId}/resolve`, {
                    method: 'POST'
                });
                if (res.ok) {
                    await this.syncStoreWithBackend();
                    return await res.json();
                }
            } catch (e) {
                console.warn(`Backend /alerts/${alertId}/resolve error:`, e);
            }
        }
        await this._simulateLatency(80);
        return window.NetGuardianStore.resolveAlert(alertId);
    },

    async getThreats() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/threats`);
                if (res.ok) {
                    const data = await res.json();
                    const raw = data.data || data.threats || [];
                    return raw.map(t => this.normalizeThreat(t));
                }
            } catch (e) {
                console.warn('Backend /threats error, using fallback:', e);
            }
        }
        await this._simulateLatency(80);
        return window.NetGuardianStore.getThreats();
    },

    async mitigateThreat(threatId) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/threats/${threatId}/mitigate`, {
                    method: 'POST'
                });
                if (res.ok) {
                    await this.syncStoreWithBackend();
                    return await res.json();
                }
            } catch (e) {
                console.warn(`Backend /threats/${threatId}/mitigate error:`, e);
            }
        }
        await this._simulateLatency(120);
        return window.NetGuardianStore.mitigateThreat(threatId);
    },

    // =========================================================================
    // 5. HISTORICAL TELEMETRY & AUDIT ENDPOINTS
    // =========================================================================

    async getHistory() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/history`);
                if (res.ok) {
                    const data = await res.json();
                    return data.data || data.history || data;
                }
            } catch (e) {
                console.warn('Backend /history error, using fallback:', e);
            }
        }
        await this._simulateLatency(60);
        return window.NetGuardianStore.getHistory();
    },

    async getAnalytics(range = '24h') {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/analytics?range=${encodeURIComponent(range)}`);
                if (res.ok) {
                    const data = await res.json();
                    return data.data || data;
                }
            } catch (e) {
                console.warn('Backend /analytics error, using fallback:', e);
            }
        }
        await this._simulateLatency(80);
        return window.NetGuardianStore.getAnalytics(range);
    },

    // =========================================================================
    // 6. SELF-HEALING & SIMULATION CONTROLS
    // =========================================================================

    async getHealingSummary() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/healing/summary`);
                if (res.ok) return await res.json();
            } catch (e) {
                console.warn('Backend /healing/summary error:', e);
            }
        }
        await this._simulateLatency(40);
        return {
            success: true,
            data: {
                total_failures_detected: 1,
                active_failures: 1,
                devices_isolated: 0,
                successful_recoveries: 5,
                failed_recoveries: 2,
                recovery_success_rate: 71.4,
                average_recovery_duration_seconds: 1.85
            }
        };
    },

    async detectFailures(deviceId = null) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/healing/detect`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(deviceId ? { deviceId } : {})
                });
                if (res.ok) {
                    await this.syncStoreWithBackend();
                    return await res.json();
                }
            } catch (e) {
                console.warn('Backend /healing/detect error:', e);
            }
        }
        await this._simulateLatency(80);
        return {
            success: true,
            failures: [
                { failure_id: 'FLR-1001', device_id: 9, failure_type: 'Device Offline', severity: 'MEDIUM' }
            ]
        };
    },

    async simulateFailure(deviceId = 'dev-4') {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/simulate/failure`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ deviceId })
                });
                if (res.ok) {
                    const data = await res.json();
                    await this.syncStoreWithBackend();
                    return data;
                }
            } catch (e) {
                console.warn('Backend /simulate/failure error:', e);
            }
        }
        await this._simulateLatency(120);
        return window.NetGuardianStore.simulateDeviceFailure(deviceId);
    },

    async simulateThreat(threatData = {}) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/simulate/threat`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(threatData)
                });
                if (res.ok) {
                    const data = await res.json();
                    await this.syncStoreWithBackend();
                    return data;
                }
            } catch (e) {
                console.warn('Backend /simulate/threat error:', e);
            }
        }
        await this._simulateLatency(120);
        return window.NetGuardianStore.simulateThreat(threatData);
    },

    async findAlternativeRoute(deviceId = null) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/recovery/find-route`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ deviceId })
                });
                if (res.ok) return await res.json();
            } catch (e) {
                console.warn('Backend /recovery/find-route error:', e);
            }
        }
        await this._simulateLatency(120);
        return window.NetGuardianStore.findAlternativeRoute(deviceId);
    },

    async recover(deviceId = null, onProgress = null) {
        if (this.USE_LIVE_BACKEND) {
            try {
                if (onProgress) {
                    onProgress({ step: 1, text: 'Executing backend autonomous recovery workflow...' });
                }
                const res = await fetch(`${this.API_BASE_URL}/recover`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ deviceId })
                });
                if (res.ok) {
                    const data = await res.json();
                    if (onProgress && data.progress_steps) {
                        data.progress_steps.forEach((s, idx) => {
                            onProgress({ step: idx + 1, text: `[${s.step}] ${s.status}: ${s.details}` });
                        });
                    }
                    await this.syncStoreWithBackend();
                    return data;
                }
            } catch (e) {
                console.warn('Backend /recover error:', e);
            }
        }
        return window.NetGuardianStore.startRecovery(deviceId, onProgress);
    },

    async startRecovery(deviceId = null, onProgress = null) {
        return this.recover(deviceId, onProgress);
    },

    async isolate(deviceId) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/isolate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ deviceId })
                });
                if (res.ok) {
                    const data = await res.json();
                    await this.syncStoreWithBackend();
                    return data;
                }
            } catch (e) {
                console.warn('Backend /isolate error:', e);
            }
        }
        await this._simulateLatency(100);
        return window.NetGuardianStore.isolateDevice(deviceId);
    },

    async restore(deviceId = null) {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/restore`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ deviceId })
                });
                if (res.ok) {
                    const data = await res.json();
                    await this.syncStoreWithBackend();
                    return data;
                }
            } catch (e) {
                console.warn('Backend /restore error:', e);
            }
        }
        await this._simulateLatency(100);
        return window.NetGuardianStore.restoreDevice(deviceId);
    },

    async restoreDevice(deviceId = null) {
        return this.restore(deviceId);
    },

    async getRecoveryState() {
        if (this.USE_LIVE_BACKEND) {
            try {
                const res = await fetch(`${this.API_BASE_URL}/recovery/status`);
                if (res.ok) return await res.json();
            } catch (e) {
                console.warn('Backend /recovery/status error:', e);
            }
        }
        await this._simulateLatency(40);
        return window.NetGuardianStore.getRecoveryState();
    },

    async resetToDefaults() {
        return window.NetGuardianStore.resetStateToDefaults();
    }
};

window.NetGuardianAPI = NetGuardianAPI;
