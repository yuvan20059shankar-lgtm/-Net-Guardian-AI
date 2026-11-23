/**
 * NetGuardian AI - Interactive Network Topology Visualization
 * Page 3 - Full SVG Topology Engine with Animated Packet Flow
 */

const TopologyView = {
    svg: null,
    zoomLevel: 1,
    selectedNodeId: null,
    highlightThreatOnly: false,

    init() {
        this.svg = document.getElementById('topology-svg');
        if (!this.svg) return;

        this.renderTopology();
        this.bindEvents();

        // Subscribe to store updates
        window.NetGuardianStore.subscribe((event, payload) => {
            this.renderTopology();
            if (this.selectedNodeId) {
                this.updateInspector(this.selectedNodeId);
            }
        });
    },

    bindEvents() {
        // Zoom controls
        const zoomInBtn = document.getElementById('btn-topo-zoom-in');
        if (zoomInBtn) {
            zoomInBtn.addEventListener('click', () => this.zoom(0.15));
        }

        const zoomOutBtn = document.getElementById('btn-topo-zoom-out');
        if (zoomOutBtn) {
            zoomOutBtn.addEventListener('click', () => this.zoom(-0.15));
        }

        const resetBtn = document.getElementById('btn-topo-reset');
        if (resetBtn) {
            resetBtn.addEventListener('click', () => this.resetZoom());
        }

        const threatFocusBtn = document.getElementById('btn-topo-highlight-threat');
        if (threatFocusBtn) {
            threatFocusBtn.addEventListener('click', () => {
                this.highlightThreatOnly = !this.highlightThreatOnly;
                threatFocusBtn.classList.toggle('active', this.highlightThreatOnly);
                this.renderTopology();
                if (window.NetGuardianApp) {
                    window.NetGuardianApp.showToast(
                        this.highlightThreatOnly ? 'Focusing suspicious & failover vectors' : 'Restored standard network mesh view',
                        'purple'
                    );
                }
            });
        }

        // Close Inspector flyout
        const closeInspectorBtn = document.getElementById('btn-close-topo-inspector');
        if (closeInspectorBtn) {
            closeInspectorBtn.addEventListener('click', () => {
                const panel = document.getElementById('topo-inspector');
                if (panel) panel.classList.remove('show');
                this.selectedNodeId = null;
            });
        }

        // Inspector Action: Full modal
        const inspectFullBtn = document.getElementById('btn-inspect-full');
        if (inspectFullBtn) {
            inspectFullBtn.addEventListener('click', () => {
                if (this.selectedNodeId && window.NetGuardianApp) {
                    window.NetGuardianApp.openDeviceModal(this.selectedNodeId);
                }
            });
        }

        // Inspector Action: Toggle fail/heal node
        const toggleFailBtn = document.getElementById('btn-inspect-toggle-fail');
        if (toggleFailBtn) {
            toggleFailBtn.addEventListener('click', () => {
                if (!this.selectedNodeId) return;
                const dev = window.NetGuardianStore.getDevice(this.selectedNodeId);
                if (!dev) return;

                if (dev.status === 'offline') {
                    window.NetGuardianStore.restoreDevice(dev.id);
                    if (window.NetGuardianApp) window.NetGuardianApp.showToast(`${dev.name} restored to nominal state`, 'success');
                } else {
                    window.NetGuardianStore.simulateDeviceFailure(dev.id);
                    if (window.NetGuardianApp) window.NetGuardianApp.showToast(`${dev.name} forced to failed state`, 'error');
                }
            });
        }
    },

    zoom(delta) {
        this.zoomLevel = Math.max(0.6, Math.min(1.8, this.zoomLevel + delta));
        this.applyTransform();
    },

    resetZoom() {
        this.zoomLevel = 1;
        this.highlightThreatOnly = false;
        this.selectedNodeId = null;
        const panel = document.getElementById('topo-inspector');
        if (panel) panel.classList.remove('show');
        const btn = document.getElementById('btn-topo-highlight-threat');
        if (btn) btn.classList.remove('active');
        this.applyTransform();
        this.renderTopology();
    },

    applyTransform() {
        const layers = ['topology-grid-layer', 'topology-links-layer', 'topology-particles-layer', 'topology-nodes-layer'];
        const cx = 500;
        const cy = 275;
        const transformStr = `translate(${cx}, ${cy}) scale(${this.zoomLevel}) translate(-${cx}, -${cy})`;

        layers.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.setAttribute('transform', transformStr);
        });
    },

    renderTopology() {
        if (!this.svg) return;

        const { nodes, links } = window.NetGuardianStore.getTopology();
        const devices = window.NetGuardianStore.getDevices();

        const devStatusMap = {};
        devices.forEach(d => devStatusMap[d.id] = d);

        // Find connected neighbors and links if a node is selected
        const activeNodeId = this.selectedNodeId;
        const neighborNodeIds = new Set();
        if (activeNodeId) {
            links.forEach(l => {
                if (l.from === activeNodeId) neighborNodeIds.add(l.to);
                if (l.to === activeNodeId) neighborNodeIds.add(l.from);
            });
        }

        // 1. Grid Background
        const gridLayer = document.getElementById('topology-grid-layer');
        if (gridLayer) {
            let gridHtml = '';
            for (let x = 40; x < 1000; x += 60) {
                gridHtml += `<line x1="${x}" y1="0" x2="${x}" y2="550" stroke="rgba(255,255,255,0.02)" stroke-width="1" />`;
            }
            for (let y = 30; y < 550; y += 60) {
                gridHtml += `<line x1="0" y1="${y}" x2="1000" y2="${y}" stroke="rgba(255,255,255,0.02)" stroke-width="1" />`;
            }
            // Perimeter Security Boundary visual ring
            gridHtml += `
                <circle cx="130" cy="220" r="75" fill="none" stroke="rgba(0, 240, 255, 0.12)" stroke-dasharray="4, 4" />
                <text x="130" y="130" fill="rgba(0, 240, 255, 0.4)" font-family="JetBrains Mono" font-size="10" text-anchor="middle">PERIMETER DMZ</text>
            `;
            // Servers Enclave Zone
            gridHtml += `
                <rect x="580" y="50" width="360" height="250" rx="12" fill="rgba(168, 85, 247, 0.02)" stroke="rgba(168, 85, 247, 0.15)" stroke-dasharray="6, 6" />
                <text x="600" y="75" fill="rgba(168, 85, 247, 0.5)" font-family="JetBrains Mono" font-size="10">CORE SERVICES & CLOUD ENCLAVE</text>
            `;
            // Internal Subnet Zone
            gridHtml += `
                <rect x="220" y="340" width="720" height="150" rx="12" fill="rgba(0, 119, 254, 0.02)" stroke="rgba(0, 119, 254, 0.15)" stroke-dasharray="6, 6" />
                <text x="240" y="365" fill="rgba(0, 119, 254, 0.5)" font-family="JetBrains Mono" font-size="10">SUBNET 192.168.1.0/24 (WORKSTATION FLEET)</text>
            `;
            gridLayer.innerHTML = gridHtml;
        }

        // 2. Links Layer
        const linksLayer = document.getElementById('topology-links-layer');
        const particlesLayer = document.getElementById('topology-particles-layer');
        let linksHtml = '';
        let particlesHtml = '';

        links.forEach((l, idx) => {
            const source = nodes.find(n => n.id === l.from);
            const target = nodes.find(n => n.id === l.to);
            if (!source || !target) return;

            const isDirectlyConnected = activeNodeId && (l.from === activeNodeId || l.to === activeNodeId);
            const isDimmed = (this.highlightThreatOnly && l.status !== 'suspicious' && l.status !== 'rerouted-active' && l.status !== 'inactive') ||
                             (activeNodeId && !isDirectlyConnected);

            let linkClass = 'topo-link link-active';
            if (l.status === 'inactive') linkClass = 'topo-link link-failed';
            else if (l.status === 'suspicious') linkClass = 'topo-link link-threat';
            else if (l.status === 'rerouted-active') linkClass = 'topo-link link-rerouted';
            else if (l.status === 'standby') linkClass = 'topo-link link-redundant';

            if (isDirectlyConnected) {
                linkClass += ' link-highlighted';
            }

            const opacityVal = isDimmed ? '0.12' : '1.0';
            const strokeWidthStyle = isDirectlyConnected ? 'stroke-width: 3.5px;' : '';

            // Curved links for organic cyber layout
            const dx = target.x - source.x;
            const dy = target.y - source.y;
            const cx1 = source.x + dx * 0.5;
            const cy1 = source.y;
            const cx2 = source.x + dx * 0.5;
            const cy2 = target.y;

            const pathD = `M ${source.x} ${source.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${target.x} ${target.y}`;

            linksHtml += `<path id="topo-path-${idx}" d="${pathD}" class="${linkClass}" style="opacity: ${opacityVal}; ${strokeWidthStyle}" />`;

            // Animated Moving Data Packet Particle on active links
            if (l.status === 'active' || l.status === 'rerouted-active' || l.status === 'suspicious') {
                const particleColor = l.status === 'suspicious' ? '#c084fc' : (l.status === 'rerouted-active' ? '#f59e0b' : '#00f0ff');
                const duration = l.status === 'suspicious' ? '2.5s' : '3.5s';
                
                particlesHtml += `
                    <circle r="${isDirectlyConnected ? '4.5' : '3.5'}" fill="${particleColor}" filter="url(#glow-cyan)" style="opacity: ${opacityVal};">
                        <animateMotion dur="${duration}" repeatCount="indefinite" path="${pathD}" />
                    </circle>
                `;
            }
        });

        if (linksLayer) linksLayer.innerHTML = linksHtml;
        if (particlesLayer) particlesLayer.innerHTML = particlesHtml;

        // 3. Nodes Layer
        const nodesLayer = document.getElementById('topology-nodes-layer');
        if (nodesLayer) {
            let nodesHtml = '';
            nodes.forEach(n => {
                const dev = devStatusMap[n.id] || { status: 'online', ip: n.ip, name: n.name };
                const isSelected = activeNodeId === n.id;
                const isNeighbor = neighborNodeIds.has(n.id);
                const isDimmed = (this.highlightThreatOnly && dev.status !== 'suspicious' && dev.status !== 'offline') ||
                                 (activeNodeId && !isSelected && !isNeighbor);

                let statusClass = 'node-healthy';
                let iconChar = '💻';
                if (n.type === 'router') iconChar = '🌐';
                else if (n.type === 'server') iconChar = '🗄️';
                else if (n.type === 'firewall') iconChar = '🛡️';

                if (dev.status === 'offline') statusClass = 'node-failed';
                else if (dev.status === 'suspicious') statusClass = 'node-suspicious';
                else if (dev.status === 'recovering') statusClass = 'node-suspicious';

                const opacityVal = isDimmed ? '0.28' : '1.0';
                
                let highlightAura = '';
                if (isSelected) {
                    highlightAura = `<circle r="36" fill="none" stroke="var(--cyan)" stroke-width="2.5" stroke-dasharray="4, 4" filter="url(#glow-cyan)" />`;
                } else if (isNeighbor) {
                    highlightAura = `<circle r="32" fill="none" stroke="rgba(0, 240, 255, 0.5)" stroke-width="1.5" stroke-dasharray="2, 2" />`;
                }

                nodesHtml += `
                    <g class="topo-node ${statusClass}" transform="translate(${n.x}, ${n.y})" style="opacity: ${opacityVal};" onclick="TopologyView.onNodeClick('${n.id}')">
                        ${highlightAura}
                        <circle class="node-pulse" r="28" fill="none" stroke-width="1.8" />
                        <circle class="node-core" r="23" />
                        <text y="5" text-anchor="middle" font-size="13">${iconChar}</text>
                        <text class="node-text-title" y="38">${n.name}</text>
                        <text class="node-text-ip" y="52">${n.ip}</text>
                    </g>
                `;
            });
            nodesLayer.innerHTML = nodesHtml;
        }

        this.applyTransform();
    },

    onNodeClick(nodeId) {
        this.selectedNodeId = nodeId;
        this.renderTopology();
        this.updateInspector(nodeId);
    },

    updateInspector(nodeId) {
        const panel = document.getElementById('topo-inspector');
        const title = document.getElementById('topo-inspect-title');
        const content = document.getElementById('topo-inspect-content');
        const toggleBtn = document.getElementById('btn-inspect-toggle-fail');
        if (!panel || !content) return;

        const dev = window.NetGuardianStore.getDevice(nodeId);
        if (!dev) return;

        title.innerHTML = `<i data-lucide="info"></i> ${dev.name} Details`;

        let statusBadge = '<span class="badge badge-green"><span class="pulse-dot"></span> Healthy Online</span>';
        if (dev.status === 'offline') statusBadge = '<span class="badge badge-red"><span class="pulse-dot dot-red"></span> Offline / Outage</span>';
        else if (dev.status === 'suspicious') statusBadge = '<span class="badge badge-purple"><span class="pulse-dot dot-purple"></span> AI Flagged Suspicious</span>';
        else if (dev.status === 'recovering') statusBadge = '<span class="badge badge-amber"><span class="pulse-dot"></span> Self-Healing</span>';

        // Get Connected Devices list
        const connectedDevices = window.NetGuardianStore.getConnectedDevices(nodeId);
        const connectedHtml = connectedDevices.length > 0
            ? connectedDevices.map(c => `
                <div style="display: flex; align-items: center; justify-content: space-between; padding: 4px 0; border-bottom: 1px dotted rgba(255,255,255,0.08); font-size: 0.72rem;">
                    <div>
                        <span style="color: #fff; font-weight: 600;">${c.name}</span>
                        <span style="color: var(--text-dim); font-family: var(--font-mono);">(${c.ip})</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="color: var(--cyan); font-family: var(--font-mono);">${c.speed}</span>
                        <span class="badge ${c.status === 'offline' ? 'badge-red' : (c.status === 'suspicious' ? 'badge-purple' : 'badge-green')}" style="padding: 1px 4px; font-size: 0.65rem;">
                            ${c.status.toUpperCase()}
                        </span>
                    </div>
                </div>
            `).join('')
            : '<div style="color: var(--text-muted); font-size: 0.72rem;">No direct topology links.</div>';

        content.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 10px;">
                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-subtle); padding-bottom: 6px;">
                    <span style="color: var(--text-dim);">Device Name:</span>
                    <strong style="color: #fff;">${dev.name}</strong>
                </div>
                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-subtle); padding-bottom: 6px;">
                    <span style="color: var(--text-dim);">IP Address:</span>
                    <strong style="color: var(--cyan); font-family: var(--font-mono);">${dev.ip}</strong>
                </div>
                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-subtle); padding-bottom: 6px;">
                    <span style="color: var(--text-dim);">Device Type:</span>
                    <span style="color: var(--text-secondary);">${dev.type} (${dev.role})</span>
                </div>
                <div style="display: flex; justify-content: space-between; border-bottom: 1px solid var(--border-subtle); padding-bottom: 6px;">
                    <span style="color: var(--text-dim);">Current Status:</span>
                    ${statusBadge}
                </div>

                <!-- Traffic Information -->
                <div style="background: rgba(0,0,0,0.3); padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border-subtle);">
                    <div style="font-size: 0.68rem; color: var(--cyan); text-transform: uppercase; font-family: var(--font-mono); margin-bottom: 4px;">Traffic Information:</div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.75rem; font-family: var(--font-mono); margin-bottom: 2px;">
                        <span style="color: var(--text-secondary);">Inbound Rx:</span>
                        <span style="color: var(--cyan); font-weight: 600;">${dev.trafficIn}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.75rem; font-family: var(--font-mono); margin-bottom: 2px;">
                        <span style="color: var(--text-secondary);">Outbound Tx:</span>
                        <span style="color: var(--purple-light); font-weight: 600;">${dev.trafficOut}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between; font-size: 0.75rem; font-family: var(--font-mono);">
                        <span style="color: var(--text-secondary);">Packet Loss:</span>
                        <span style="color: ${dev.packetLoss === '0.00%' ? 'var(--green-bright)' : 'var(--red-bright)'}; font-weight: 600;">${dev.packetLoss}</span>
                    </div>
                </div>

                <!-- Connected Devices -->
                <div style="background: rgba(0,0,0,0.2); padding: 8px 10px; border-radius: 6px; border: 1px solid var(--border-subtle); max-height: 120px; overflow-y: auto;">
                    <div style="font-size: 0.68rem; color: var(--purple-light); text-transform: uppercase; font-family: var(--font-mono); margin-bottom: 4px;">
                        Connected Topology Nodes (${connectedDevices.length}):
                    </div>
                    ${connectedHtml}
                </div>
            </div>
        `;

        if (toggleBtn) {
            if (dev.status === 'offline') {
                toggleBtn.textContent = 'Restore Node';
                toggleBtn.className = 'btn btn-green btn-sm';
            } else {
                toggleBtn.textContent = 'Fail Node';
                toggleBtn.className = 'btn btn-red btn-sm';
            }
        }

        panel.classList.add('show');
        if (window.lucide) window.lucide.createIcons();
    }
};

window.TopologyView = TopologyView;
