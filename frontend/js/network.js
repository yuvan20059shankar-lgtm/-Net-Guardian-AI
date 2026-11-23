/**
 * NetGuardian AI - Network Monitor View Controller
 * Page 2 - Full Monitored Inventory (10 Devices)
 */

const NetworkView = {
    searchQuery: '',
    statusFilter: 'all',
    typeFilter: 'all',

    init() {
        this.renderDevices();
        this.bindEvents();

        // Subscribe to store updates
        window.NetGuardianStore.subscribe((event, payload) => {
            this.renderDevices();
        });
    },

    bindEvents() {
        const searchInput = document.getElementById('device-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.searchQuery = e.target.value.toLowerCase().trim();
                this.renderDevices();
            });
        }

        const statusSelect = document.getElementById('device-status-filter');
        if (statusSelect) {
            statusSelect.addEventListener('change', (e) => {
                this.statusFilter = e.target.value;
                this.renderDevices();
            });
        }

        const typeSelect = document.getElementById('device-type-filter');
        if (typeSelect) {
            typeSelect.addEventListener('change', (e) => {
                this.typeFilter = e.target.value;
                this.renderDevices();
            });
        }

        const refreshBtn = document.getElementById('btn-refresh-devices');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => {
                this.scanSubnet();
            });
        }
    },

    scanSubnet() {
        if (window.NetGuardianApp) {
            window.NetGuardianApp.showToast('Initiating ARP sweep on subnet 192.168.1.0/24...', 'cyan');
        }
        const btn = document.getElementById('btn-refresh-devices');
        if (btn) {
            btn.innerHTML = `<i data-lucide="loader" class="spin" style="width: 14px; height: 14px;"></i> <span>Scanning...</span>`;
            if (window.lucide) window.lucide.createIcons();
            setTimeout(() => {
                btn.innerHTML = `<i data-lucide="rotate-cw" style="width: 14px; height: 14px;"></i> <span>Scan Subnet</span>`;
                if (window.lucide) window.lucide.createIcons();
                this.renderDevices();
                if (window.NetGuardianApp) {
                    window.NetGuardianApp.showToast('Subnet scan complete. 10 hosts verified.', 'success');
                }
            }, 800);
        }
    },

    renderDevices() {
        const tbody = document.getElementById('devices-table-body');
        if (!tbody) return;

        const allDevices = window.NetGuardianStore.getDevices();
        const filtered = allDevices.filter(dev => {
            // Search query match
            const matchesSearch = !this.searchQuery || 
                dev.name.toLowerCase().includes(this.searchQuery) ||
                dev.ip.toLowerCase().includes(this.searchQuery) ||
                dev.role.toLowerCase().includes(this.searchQuery) ||
                dev.mac.toLowerCase().includes(this.searchQuery);

            // Status filter
            const matchesStatus = this.statusFilter === 'all' || dev.status === this.statusFilter;

            // Type filter
            const matchesType = this.typeFilter === 'all' || dev.type === this.typeFilter;

            return matchesSearch && matchesStatus && matchesType;
        });

        const summaryBadge = document.getElementById('device-table-summary');
        if (summaryBadge) {
            summaryBadge.textContent = `${filtered.length} of ${allDevices.length} Hosts Active`;
        }

        if (filtered.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="9" style="text-align: center; padding: 40px; color: var(--text-muted);">
                        <i data-lucide="search-x" style="width: 32px; height: 32px; margin-bottom: 8px; opacity: 0.5;"></i>
                        <div>No network devices match the active search and filter criteria.</div>
                    </td>
                </tr>
            `;
            if (window.lucide) window.lucide.createIcons();
            return;
        }

        tbody.innerHTML = filtered.map(dev => {
            // Status styling
            let statusBadge = '<span class="badge badge-green"><span class="pulse-dot"></span> Online</span>';
            if (dev.status === 'offline') {
                statusBadge = '<span class="badge badge-red"><span class="pulse-dot dot-red"></span> Offline</span>';
            } else if (dev.status === 'suspicious') {
                statusBadge = '<span class="badge badge-purple"><span class="pulse-dot dot-purple"></span> Suspicious</span>';
            } else if (dev.status === 'recovering') {
                statusBadge = '<span class="badge badge-amber"><span class="pulse-dot"></span> Recovering</span>';
            }

            // Device icon
            let iconName = 'monitor';
            if (dev.type === 'Router') iconName = 'router';
            else if (dev.type === 'Server') iconName = 'server';
            else if (dev.type === 'Firewall') iconName = 'shield-check';

            return `
                <tr onclick="NetworkView.openDeviceDetails('${dev.id}')" title="Click to view detailed specifications">
                    <td>
                        <div class="device-name-cell">
                            <div class="device-icon-box">
                                <i data-lucide="${iconName}"></i>
                            </div>
                            <div>
                                <div class="device-title-text">${dev.name}</div>
                                <div class="device-role-text">${dev.role}</div>
                            </div>
                        </div>
                    </td>
                    <td style="font-family: var(--font-mono); font-weight: 600; color: #fff;">${dev.ip}</td>
                    <td><span class="badge badge-muted">${dev.type}</span></td>
                    <td>${statusBadge}</td>
                    <td>
                        <div style="font-family: var(--font-mono); font-size: 0.78rem;">
                            <span style="color: var(--cyan);">↓ ${dev.trafficIn}</span><br>
                            <span style="color: var(--purple-light);">↑ ${dev.trafficOut}</span>
                        </div>
                    </td>
                    <td>
                        <div style="width: 100px;">
                            <div style="display: flex; justify-content: space-between; font-size: 0.68rem; font-family: var(--font-mono);">
                                <span>CPU ${dev.cpuLoad}%</span>
                                <span>RAM ${dev.memLoad}%</span>
                            </div>
                            <div class="progress-track" style="height: 5px; margin-top: 3px;">
                                <div class="progress-fill fill-cyan" style="width: ${dev.cpuLoad}%;"></div>
                            </div>
                        </div>
                    </td>
                    <td style="font-family: var(--font-mono); font-size: 0.8rem; color: ${dev.packetLoss === '0.00%' || dev.packetLoss === '0.01%' ? 'var(--green-bright)' : 'var(--red-bright)'};">
                        ${dev.packetLoss}
                    </td>
                    <td style="font-size: 0.78rem; color: var(--text-muted);">${dev.lastActive}</td>
                    <td>
                        <button class="btn btn-outline btn-sm" onclick="event.stopPropagation(); NetworkView.openDeviceDetails('${dev.id}')">
                            <i data-lucide="eye" style="width: 14px; height: 14px;"></i>
                            <span>Inspect</span>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');

        if (window.lucide) window.lucide.createIcons();
    },

    openDeviceDetails(deviceId) {
        if (window.NetGuardianApp) {
            window.NetGuardianApp.openDeviceModal(deviceId);
        }
    }
};

window.NetworkView = NetworkView;
