/**
 * NetGuardian AI - Mock Data & State Management Store
 * Holds simulation datasets and reactive state for the SOC frontend.
 * Prepared for future Flask / Scikit-Learn API integration.
 */

const NetGuardianMock = {
    // Initial 10 Network Devices
    devices: [
        {
            id: 'dev-1',
            name: 'Router 01',
            ip: '192.168.1.1',
            mac: '00:1A:2B:3C:4D:01',
            type: 'Router',
            role: 'Core Gateway & Subnet Switch',
            status: 'online', // 'online' | 'offline' | 'suspicious' | 'recovering'
            trafficIn: '428.5 Mbps',
            trafficOut: '382.1 Mbps',
            cpuLoad: 38,
            memLoad: 45,
            packetLoss: '0.01%',
            lastActive: 'Just now',
            uptime: '42d 18h 12m',
            os: 'GuardianOS Router v4.2',
            openPorts: [22, 53, 80, 443, 161],
            location: 'Rack Alpha - Unit 01'
        },
        {
            id: 'dev-2',
            name: 'Server 01',
            ip: '192.168.1.10',
            mac: '00:1A:2B:3C:4D:10',
            type: 'Server',
            role: 'Primary PostgreSQL Database Cluster',
            status: 'online',
            trafficIn: '184.2 Mbps',
            trafficOut: '215.8 Mbps',
            cpuLoad: 64,
            memLoad: 72,
            packetLoss: '0.00%',
            lastActive: 'Just now',
            uptime: '18d 04h 32m',
            os: 'Ubuntu 24.04 LTS (Kernel 6.8)',
            openPorts: [22, 5432, 9100],
            location: 'Server Room 2 - Rack B3'
        },
        {
            id: 'dev-3',
            name: 'Server 02',
            ip: '192.168.1.11',
            mac: '00:1A:2B:3C:4D:11',
            type: 'Server',
            role: 'Application API & Microservices Host',
            status: 'online', // can be toggled in self-healing simulation
            trafficIn: '312.4 Mbps',
            trafficOut: '289.0 Mbps',
            cpuLoad: 52,
            memLoad: 61,
            packetLoss: '0.02%',
            lastActive: 'Just now',
            uptime: '12d 11h 05m',
            os: 'Debian 12 Bookworm',
            openPorts: [22, 80, 443, 8080, 8443],
            location: 'Server Room 2 - Rack B4'
        },
        {
            id: 'dev-4',
            name: 'Server 03',
            ip: '192.168.1.12',
            mac: '00:1A:2B:3C:4D:12',
            type: 'Server',
            role: 'Backup Storage & Standby Failover',
            status: 'online',
            trafficIn: '45.1 Mbps',
            trafficOut: '12.8 Mbps',
            cpuLoad: 18,
            memLoad: 34,
            packetLoss: '0.00%',
            lastActive: '1m ago',
            uptime: '65d 20h 40m',
            os: 'TrueNAS Enterprise v13.0',
            openPorts: [22, 445, 2049, 9000],
            location: 'Disaster Recovery Vault C'
        },
        {
            id: 'dev-5',
            name: 'PC 01',
            ip: '192.168.1.20',
            mac: '00:1A:2B:3C:4D:20',
            type: 'Computer',
            role: 'Finance Dept Workstation',
            status: 'online',
            trafficIn: '8.4 Mbps',
            trafficOut: '3.2 Mbps',
            cpuLoad: 24,
            memLoad: 42,
            packetLoss: '0.00%',
            lastActive: 'Just now',
            uptime: '6h 15m',
            os: 'Windows 11 Pro Enterprise',
            openPorts: [135, 445, 3389],
            location: 'Floor 3 - Finance Office 302'
        },
        {
            id: 'dev-6',
            name: 'PC 02',
            ip: '192.168.1.21',
            mac: '00:1A:2B:3C:4D:21',
            type: 'Computer',
            role: 'Dev Station Alpha (Lead Engineer)',
            status: 'online',
            trafficIn: '34.8 Mbps',
            trafficOut: '19.4 Mbps',
            cpuLoad: 41,
            memLoad: 68,
            packetLoss: '0.01%',
            lastActive: 'Just now',
            uptime: '9h 42m',
            os: 'Fedora Workstation 40',
            openPorts: [22, 3000, 8000],
            location: 'Floor 2 - Engineering Lab'
        },
        {
            id: 'dev-7',
            name: 'PC 03',
            ip: '192.168.1.22',
            mac: '00:1A:2B:3C:4D:22',
            type: 'Computer',
            role: 'HR Terminal & Employee Records',
            status: 'suspicious', // Flagged by AI Anomaly detection
            trafficIn: '142.6 Mbps',
            trafficOut: '298.4 Mbps', // Abnormal outbound data surge!
            cpuLoad: 89,
            memLoad: 91,
            packetLoss: '1.45%',
            lastActive: 'Just now',
            uptime: '3d 02h 10m',
            os: 'Windows 10 Enterprise',
            openPorts: [135, 445, 4444],
            location: 'Floor 1 - HR Wing'
        },
        {
            id: 'dev-8',
            name: 'PC 04',
            ip: '192.168.1.23',
            mac: '00:1A:2B:3C:4D:23',
            type: 'Computer',
            role: 'Engineering CAD Workstation',
            status: 'online',
            trafficIn: '12.1 Mbps',
            trafficOut: '6.5 Mbps',
            cpuLoad: 31,
            memLoad: 54,
            packetLoss: '0.00%',
            lastActive: '4m ago',
            uptime: '5h 50m',
            os: 'Windows 11 Pro Enterprise',
            openPorts: [135, 445],
            location: 'Floor 2 - Design Studio'
        },
        {
            id: 'dev-9',
            name: 'PC 05',
            ip: '192.168.1.24',
            mac: '00:1A:2B:3C:4D:24',
            type: 'Computer',
            role: 'Admin Ops Terminal',
            status: 'offline', // Currently in maintenance / offline
            trafficIn: '0.0 Mbps',
            trafficOut: '0.0 Mbps',
            cpuLoad: 0,
            memLoad: 0,
            packetLoss: '100%',
            lastActive: '1h 22m ago',
            uptime: '0m',
            os: 'Ubuntu 24.04 LTS',
            openPorts: [],
            location: 'Floor 4 - IT Operations Center'
        },
        {
            id: 'dev-10',
            name: 'Firewall 01',
            ip: '192.168.1.254',
            mac: '00:1A:2B:3C:4D:FE',
            type: 'Firewall',
            role: 'Edge Perimeter & Deep Packet Inspection (DPI)',
            status: 'online',
            trafficIn: '612.9 Mbps',
            trafficOut: '584.3 Mbps',
            cpuLoad: 46,
            memLoad: 58,
            packetLoss: '0.00%',
            lastActive: 'Just now',
            uptime: '92d 14h 22m',
            os: 'NetGuardian FortifyOS v5.1',
            openPorts: [22, 443, 8443],
            location: 'Perimeter Gateway Facility A'
        }
    ],

    // Topology Nodes coordinates & topology hierarchy (optimized for clean non-overlapping rendering)
    topologyNodes: [
        { id: 'dev-10', name: 'Firewall 01', ip: '192.168.1.254', type: 'firewall', x: 130, y: 220, label: 'Edge Firewall' },
        { id: 'dev-1', name: 'Router 01', ip: '192.168.1.1', type: 'router', x: 380, y: 220, label: 'Core Gateway' },
        
        // Servers (Upper cluster)
        { id: 'dev-2', name: 'Server 01', ip: '192.168.1.10', type: 'server', x: 620, y: 100, label: 'PostgreSQL DB' },
        { id: 'dev-3', name: 'Server 02', ip: '192.168.1.11', type: 'server', x: 780, y: 150, label: 'API Services' },
        { id: 'dev-4', name: 'Server 03', ip: '192.168.1.12', type: 'server', x: 680, y: 260, label: 'Backup Standby' },

        // Workstations (Lower cluster)
        { id: 'dev-5', name: 'PC 01', ip: '192.168.1.20', type: 'computer', x: 260, y: 400, label: 'Finance' },
        { id: 'dev-6', name: 'PC 02', ip: '192.168.1.21', type: 'computer', x: 400, y: 410, label: 'Dev Alpha' },
        { id: 'dev-7', name: 'PC 03', ip: '192.168.1.22', type: 'computer', x: 540, y: 410, label: 'HR Terminal' },
        { id: 'dev-8', name: 'PC 04', ip: '192.168.1.23', type: 'computer', x: 680, y: 410, label: 'CAD Studio' },
        { id: 'dev-9', name: 'PC 05', ip: '192.168.1.24', type: 'computer', x: 820, y: 390, label: 'IT Ops' }
    ],

    // Topology Links
    topologyLinks: [
        // Perimeter to Core
        { from: 'dev-10', to: 'dev-1', status: 'active', speed: '10 Gbps', type: 'backbone' },
        
        // Core to Servers
        { from: 'dev-1', to: 'dev-2', status: 'active', speed: '1 Gbps', type: 'server-link' },
        { from: 'dev-1', to: 'dev-3', status: 'active', speed: '1 Gbps', type: 'server-link' },
        { from: 'dev-1', to: 'dev-4', status: 'standby', speed: '1 Gbps', type: 'redundant-link' },
        
        // Inter-server cluster links
        { from: 'dev-2', to: 'dev-3', status: 'active', speed: '10 Gbps', type: 'cluster' },
        { from: 'dev-2', to: 'dev-4', status: 'active', speed: '10 Gbps', type: 'sync' },
        { from: 'dev-3', to: 'dev-4', status: 'standby', speed: '10 Gbps', type: 'failover-link' },

        // Core to Workstations Subnet
        { from: 'dev-1', to: 'dev-5', status: 'active', speed: '1 Gbps', type: 'client-link' },
        { from: 'dev-1', to: 'dev-6', status: 'active', speed: '1 Gbps', type: 'client-link' },
        { from: 'dev-1', to: 'dev-7', status: 'suspicious', speed: '1 Gbps', type: 'threat-flow' },
        { from: 'dev-1', to: 'dev-8', status: 'active', speed: '1 Gbps', type: 'client-link' },
        { from: 'dev-1', to: 'dev-9', status: 'inactive', speed: '0 Gbps', type: 'client-link' }
    ],

    // AI Threat Detection Records (Demo Mode for Isolation Forest)
    threats: [
        {
            id: 'ATD-9042',
            threatType: 'Data Exfiltration via DNS Tunneling',
            affectedDeviceId: 'dev-7',
            affectedDeviceName: 'PC 03',
            affectedIp: '192.168.1.22',
            anomalyScore: 0.94,
            severity: 'CRITICAL',
            timestamp: '2026-11-18 09:41:15',
            status: 'ACTIVE',
            explanation: 'Isolation Forest flagged a 940% surge in outbound base64-encoded UDP queries directed to unauthorized external nameserver (185.220.101.5). Exfiltration pattern matches APT-29 signature.',
            recommendedAction: 'Quarantine PC 03 port, blacklist destination IP on Firewall 01, and flush DNS cache.',
            mlFeatures: {
                packetEntropy: 7.92,
                requestFrequency: '480 req/sec',
                payloadVariance: '+412%',
                baselineDeviation: '4.8σ'
            }
        },
        {
            id: 'ATD-8821',
            threatType: 'SYN Flood / Distributed Denial-of-Service',
            affectedDeviceId: 'dev-10',
            affectedDeviceName: 'Firewall 01',
            affectedIp: '192.168.1.254',
            anomalyScore: 0.88,
            severity: 'HIGH',
            timestamp: '2026-11-18 09:35:40',
            status: 'MITIGATED',
            explanation: 'Abnormal influx of half-open TCP SYN packets from spoofed external /24 CIDR blocks targeting WAN ingress port 443.',
            recommendedAction: 'Deploy SYN cookies on Firewall 01 and activate rate-limiting rate bucket.',
            mlFeatures: {
                packetEntropy: 3.14,
                requestFrequency: '2,400 syn/sec',
                payloadVariance: '-85%',
                baselineDeviation: '3.6σ'
            }
        },
        {
            id: 'ATD-8740',
            threatType: 'Lateral Port Sweep (Reconnaissance)',
            affectedDeviceId: 'dev-5',
            affectedDeviceName: 'PC 01',
            affectedIp: '192.168.1.20',
            anomalyScore: 0.72,
            severity: 'MEDIUM',
            timestamp: '2026-11-18 09:12:08',
            status: 'INVESTIGATING',
            explanation: 'Sequential scanning of TCP ports 445, 135, and 3389 across subnet 192.168.1.0/24 initiated from Finance terminal.',
            recommendedAction: 'Restrict SMB egress on subnet switch and inspect running processes on PC 01.',
            mlFeatures: {
                packetEntropy: 5.61,
                requestFrequency: '85 probes/sec',
                payloadVariance: '+15%',
                baselineDeviation: '2.1σ'
            }
        },
        {
            id: 'ATD-8519',
            threatType: 'Abnormal SSH Brute Force Ingress',
            affectedDeviceId: 'dev-2',
            affectedDeviceName: 'Server 01',
            affectedIp: '192.168.1.10',
            anomalyScore: 0.65,
            severity: 'LOW',
            timestamp: '2026-11-18 08:44:30',
            status: 'RESOLVED',
            explanation: '18 failed authentication attempts over SSH within 60 seconds from external gateway probe.',
            recommendedAction: 'IP automatically banned via fail2ban rule for 24 hours.',
            mlFeatures: {
                packetEntropy: 4.88,
                requestFrequency: '18 attempts/min',
                payloadVariance: 'Normal',
                baselineDeviation: '1.4σ'
            }
        }
    ],

    // Security Alerts (Comprehensive Management List)
    alerts: [
        {
            id: 'ALT-1001',
            threatType: 'Data Exfiltration Surge',
            deviceId: 'dev-7',
            deviceName: 'PC 03',
            ip: '192.168.1.22',
            severity: 'CRITICAL',
            timestamp: '2026-11-18 09:41:15',
            status: 'ACTIVE',
            summary: 'Outbound anomaly on port 53. Exceeds baseline threshold by 940%.'
        },
        {
            id: 'ALT-1002',
            threatType: 'SYN Flood Ingress',
            deviceId: 'dev-10',
            deviceName: 'Firewall 01',
            ip: '192.168.1.254',
            severity: 'HIGH',
            timestamp: '2026-11-18 09:35:40',
            status: 'RESOLVED',
            summary: 'Rate limiter activated. Scrubbed 142k malicious packets.'
        },
        {
            id: 'ALT-1003',
            threatType: 'Internal SMB Sweep',
            deviceId: 'dev-5',
            deviceName: 'PC 01',
            ip: '192.168.1.20',
            severity: 'MEDIUM',
            timestamp: '2026-11-18 09:12:08',
            status: 'IN_PROGRESS',
            summary: 'Host initiated scans toward 192.168.1.10 and 192.168.1.11.'
        },
        {
            id: 'ALT-1004',
            threatType: 'Repeated Auth Failures',
            deviceId: 'dev-2',
            deviceName: 'Server 01',
            ip: '192.168.1.10',
            severity: 'LOW',
            timestamp: '2026-11-18 08:44:30',
            status: 'RESOLVED',
            summary: 'Source IP 198.51.100.41 blocked at perimeter.'
        },
        {
            id: 'ALT-1005',
            threatType: 'Host Unreachable (Keepalive Loss)',
            deviceId: 'dev-9',
            deviceName: 'PC 05',
            ip: '192.168.1.24',
            severity: 'MEDIUM',
            timestamp: '2026-11-18 08:24:00',
            status: 'ACTIVE',
            summary: 'Device timed out on ICMP polling. Scheduled IT maintenance.'
        },
        {
            id: 'ALT-1006',
            threatType: 'TLS Certificate Expiry Notice',
            deviceId: 'dev-3',
            deviceName: 'Server 02',
            ip: '192.168.1.11',
            severity: 'LOW',
            timestamp: '2026-11-18 07:15:22',
            status: 'RESOLVED',
            summary: 'Wildcard cert renewed automatically via ACME challenge.'
        }
    ],

    // Self-Healing Status & Recovery History
    recoveryState: {
        isFailureSimulated: false,
        failedDeviceId: null,
        alternativeRouteActive: false,
        recoveryInProgress: false,
        recoveryStep: 0, // 0: Idle, 1: Isolate, 2: Reroute, 3: Restart/Restore, 4: Verified
        backupServerStatus: 'STANDBY_READY', // 'STANDBY_READY' | 'HOT_ACTIVE' | 'SYNCING'
        activeOperations: [],
        history: [
            {
                id: 'REC-501',
                timestamp: '2026-11-18 06:14:22',
                targetDevice: 'Server 02 (192.168.1.11)',
                faultType: 'Kernel Panic / Memory Leak',
                actionTaken: 'Auto-rerouted traffic via Server 03 standby cluster; soft-restarted Docker containers.',
                duration: '4.8 seconds',
                status: 'SUCCESS'
            },
            {
                id: 'REC-500',
                timestamp: '2026-11-17 21:40:11',
                targetDevice: 'Router 01 (192.168.1.1)',
                faultType: 'Routing Table Loop Detected',
                actionTaken: 'OSPF route flush & convergence optimization applied.',
                duration: '2.1 seconds',
                status: 'SUCCESS'
            },
            {
                id: 'REC-499',
                timestamp: '2026-11-17 14:02:50',
                targetDevice: 'Firewall 01 (192.168.1.254)',
                faultType: 'DDoS Buffer Exhaustion',
                actionTaken: 'Dynamic syn-proxy filter injected into eBPF XDP layer.',
                duration: '1.2 seconds',
                status: 'SUCCESS'
            }
        ]
    },

    // User Activity Monitoring
    userActivity: [
        { user: 'admin_sysops', role: 'Security Admin', ip: '192.168.1.1', action: 'Policy Rule Update', status: 'Authorized', time: '2m ago' },
        { user: 'service_ai', role: 'Autonomous Agent', ip: '127.0.0.1', action: 'Isolation Forest Scan Run', status: 'Completed', time: '5m ago' },
        { user: 'dev_lead', role: 'Dev Alpha', ip: '192.168.1.21', action: 'Git Push to Repo Alpha', status: 'Authorized', time: '14m ago' },
        { user: 'guest_wifi', role: 'External Guest', ip: '192.168.10.45', action: 'Attempted Subnet Probe', status: 'Blocked', time: '22m ago' },
        { user: 'hr_manager', role: 'HR Terminal', ip: '192.168.1.22', action: 'Unusual Outbound Socket', status: 'Flagged', time: '28m ago' }
    ],

    // Critical Incidents for Overview Dashboard
    criticalIncidents: [
        { id: 'INC-991', title: 'Data Exfiltration via DNS', target: 'PC 03 (HR)', severity: 'CRITICAL', status: 'Auto-Mitigating', time: '4m ago' },
        { id: 'INC-990', title: 'Perimeter SYN Flood Spike', target: 'Firewall 01', severity: 'HIGH', status: 'Blocked', time: '11m ago' },
        { id: 'INC-989', title: 'Internal Port Sweep Detected', target: 'PC 01 (Finance)', severity: 'MEDIUM', status: 'Investigating', time: '34m ago' }
    ],

    // Recent Network Events Live Stream
    recentEvents: [
        { type: 'SEC_WARN', msg: 'Anomaly score 0.94 triggered on 192.168.1.22', time: '09:41:15' },
        { type: 'AI_AGENT', msg: 'Isolation Forest auto-recalibrated baseline threshold', time: '09:40:00' },
        { type: 'NET_OK', msg: 'Server 01 database replication lag: 0.12ms', time: '09:38:12' },
        { type: 'DEFENSE', msg: 'SYN flood blocked on Firewall 01 edge filter', time: '09:35:40' },
        { type: 'NET_WARN', msg: 'PC 05 heartbeat timeout registered', time: '09:24:00' },
        { type: 'RECOVER', msg: 'Self-healing diagnostic check passed on all core nodes', time: '09:15:30' }
    ],

    // Analytics Time-Series Datasets for 24h, 7d, and 30d
    analyticsData: {
        '24h': {
            trafficHistory: {
                labels: ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00', '16:00', '18:00', '20:00', '22:00'],
                inbound: [120, 140, 110, 160, 480, 620, 590, 680, 510, 430, 310, 220],
                outbound: [90, 105, 85, 120, 390, 510, 490, 550, 410, 340, 260, 180],
                maliciousScrubbed: [4, 6, 2, 8, 45, 112, 68, 140, 38, 22, 12, 8]
            },
            deviceAvailability: {
                devices: ['Router 01', 'Firewall 01', 'Server 01', 'Server 02', 'Server 03', 'PC 01', 'PC 02', 'PC 03', 'PC 04', 'PC 05'],
                uptimePercentages: [99.99, 100.0, 99.98, 98.45, 99.95, 99.80, 99.90, 96.20, 99.75, 91.10]
            },
            threatHistory: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                critical: [1, 0, 1, 2, 0, 1],
                high: [2, 1, 3, 4, 2, 1],
                medium: [5, 4, 8, 9, 6, 4],
                low: [12, 8, 15, 18, 14, 10]
            },
            recoveryOperations: {
                labels: ['02:00', '06:00', '10:00', '14:00', '18:00', '22:00'],
                autoHealed: [3, 2, 5, 4, 2, 1],
                avgTimeSeconds: [2.8, 3.1, 2.4, 2.9, 3.4, 2.2]
            }
        },
        '7d': {
            trafficHistory: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                inbound: [420, 510, 480, 620, 710, 380, 340],
                outbound: [360, 430, 410, 540, 620, 310, 290],
                maliciousScrubbed: [24, 38, 42, 65, 88, 18, 12]
            },
            deviceAvailability: {
                devices: ['Router 01', 'Firewall 01', 'Server 01', 'Server 02', 'Server 03', 'PC 01', 'PC 02', 'PC 03', 'PC 04', 'PC 05'],
                uptimePercentages: [99.98, 100.0, 99.95, 98.10, 99.92, 99.70, 99.85, 95.80, 99.60, 90.50]
            },
            threatHistory: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                critical: [1, 0, 2, 1, 3, 0, 1],
                high: [4, 3, 5, 2, 6, 1, 2],
                medium: [12, 9, 14, 11, 15, 6, 7],
                low: [28, 24, 31, 22, 35, 18, 16]
            },
            recoveryOperations: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                autoHealed: [4, 2, 5, 3, 6, 1, 2],
                avgTimeSeconds: [3.4, 2.8, 3.1, 2.6, 2.2, 3.5, 2.9]
            }
        },
        '30d': {
            trafficHistory: {
                labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                inbound: [3200, 3600, 4100, 3900],
                outbound: [2700, 3100, 3500, 3300],
                maliciousScrubbed: [180, 240, 310, 290]
            },
            deviceAvailability: {
                devices: ['Router 01', 'Firewall 01', 'Server 01', 'Server 02', 'Server 03', 'PC 01', 'PC 02', 'PC 03', 'PC 04', 'PC 05'],
                uptimePercentages: [99.95, 99.99, 99.90, 97.80, 99.88, 99.60, 99.75, 94.90, 99.50, 89.80]
            },
            threatHistory: {
                labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                critical: [4, 6, 3, 5],
                high: [18, 22, 14, 19],
                medium: [52, 61, 48, 56],
                low: [120, 142, 115, 134]
            },
            recoveryOperations: {
                labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                autoHealed: [14, 19, 16, 22],
                avgTimeSeconds: [3.4, 2.8, 3.1, 2.2]
            }
        }
    }
};

/**
 * NetGuardian State Manager with reactive pub/sub event system and LocalStorage persistence
 */
class StateManager {
    constructor() {
        this.STORAGE_KEY = 'netguardian_soc_state_v2';
        this.listeners = [];
        this.simulatedRecoveriesCount = 17; // initial count from requirements
        this.state = this.loadState();
    }

    // Safely load state from LocalStorage or fall back to default mock data
    loadState() {
        if (typeof window !== 'undefined' && window.localStorage) {
            try {
                const saved = window.localStorage.getItem(this.STORAGE_KEY);
                if (saved) {
                    const parsed = JSON.parse(saved);
                    if (parsed && parsed.devices && parsed.devices.length === 10) {
                        if (parsed.simulatedRecoveriesCount !== undefined) {
                            this.simulatedRecoveriesCount = parsed.simulatedRecoveriesCount;
                        }
                        return parsed;
                    }
                }
            } catch (err) {
                console.warn('Could not restore state from localStorage, using defaults:', err);
            }
        }
        return JSON.parse(JSON.stringify(NetGuardianMock));
    }

    // Persist current simulated state to LocalStorage
    saveState() {
        if (typeof window !== 'undefined' && window.localStorage) {
            try {
                this.state.simulatedRecoveriesCount = this.simulatedRecoveriesCount;
                window.localStorage.setItem(this.STORAGE_KEY, JSON.stringify(this.state));
            } catch (err) {
                console.warn('Could not save state to localStorage:', err);
            }
        }
    }

    // Reset state back to initial baseline defaults
    resetStateToDefaults() {
        if (typeof window !== 'undefined' && window.localStorage) {
            try {
                window.localStorage.removeItem(this.STORAGE_KEY);
            } catch (e) {}
        }
        this.simulatedRecoveriesCount = 17;
        this.state = JSON.parse(JSON.stringify(NetGuardianMock));
        this.saveState();
        this.notify('STATE_RESET', {});
        return this.state;
    }

    // Subscribe to state change notifications
    subscribe(listener) {
        this.listeners.push(listener);
        return () => {
            this.listeners = this.listeners.filter(l => l !== listener);
        };
    }

    notify(eventType, payload) {
        this.listeners.forEach(fn => {
            try {
                fn(eventType, payload, this.state);
            } catch (err) {
                console.error('Listener callback error:', err);
            }
        });
    }

    // --- Accessors ---
    getDevices() {
        return this.state.devices;
    }

    getDevice(id) {
        return this.state.devices.find(d => d.id === id || d.name.toLowerCase() === id.toLowerCase());
    }

    // Get directly connected devices for a given device ID
    getConnectedDevices(deviceId) {
        const connected = [];
        this.state.topologyLinks.forEach(link => {
            if (link.from === deviceId || link.to === deviceId) {
                const neighborId = link.from === deviceId ? link.to : link.from;
                const neighbor = this.getDevice(neighborId);
                if (neighbor) {
                    connected.push({
                        id: neighbor.id,
                        name: neighbor.name,
                        ip: neighbor.ip,
                        type: neighbor.type,
                        status: neighbor.status,
                        speed: link.speed,
                        linkType: link.type,
                        linkStatus: link.status
                    });
                }
            }
        });
        return connected;
    }

    getTopology() {
        return {
            nodes: this.state.topologyNodes,
            links: this.state.topologyLinks
        };
    }

    getThreats() {
        return this.state.threats;
    }

    getAlerts() {
        return this.state.alerts;
    }

    getRecoveryState() {
        return this.state.recoveryState;
    }

    getMetrics() {
        const total = this.state.devices.length;
        const online = this.state.devices.filter(d => d.status === 'online').length;
        const offline = this.state.devices.filter(d => d.status === 'offline').length;
        const suspicious = this.state.devices.filter(d => d.status === 'suspicious').length;
        const recovering = this.state.devices.filter(d => d.status === 'recovering').length;
        const activeThreats = this.state.threats.filter(t => t.status === 'ACTIVE' || t.status === 'INVESTIGATING').length;
        
        // Calculate dynamic health percentage
        // Each online device contributes 10 pts, suspicious 4 pts, recovering 6 pts, offline 0 pts
        const earned = (online * 10) + (suspicious * 4) + (recovering * 6);
        const max = total * 10;
        const healthPercent = Math.min(100, Math.max(0, Math.round((earned / max) * 1000) / 10));

        return {
            totalDevices: total,
            onlineDevices: online,
            offlineDevices: offline,
            suspiciousDevices: suspicious,
            recoveringDevices: recovering,
            activeThreats: activeThreats,
            networkHealth: healthPercent,
            successfulRecoveries: this.simulatedRecoveriesCount
        };
    }

    // --- State Mutations (Simulations) ---
    
    // Simulate Failure on a device (defaults to Server 02 or passed deviceId)
    simulateDeviceFailure(deviceId = 'dev-3') {
        const target = this.state.devices.find(d => d.id === deviceId);
        if (!target) return null;

        target.status = 'offline';
        target.packetLoss = '100%';
        target.trafficIn = '0.0 Mbps';
        target.trafficOut = '0.0 Mbps';
        target.lastActive = 'Failure triggered';

        // Update topology links
        this.state.topologyLinks.forEach(link => {
            if (link.from === deviceId || link.to === deviceId) {
                link.status = 'inactive';
            }
        });

        // Update Recovery state
        this.state.recoveryState.isFailureSimulated = true;
        this.state.recoveryState.failedDeviceId = deviceId;
        this.state.recoveryState.alternativeRouteActive = false;
        this.state.recoveryState.recoveryStep = 1;
        this.state.recoveryState.backupServerStatus = 'STANDBY_ALERT';

        // Add event
        this.state.recentEvents.unshift({
            type: 'FAILURE_ALERT',
            msg: `SIMULATED FAILURE: ${target.name} (${target.ip}) dropped offline. Heartbeat lost.`,
            time: new Date().toTimeString().split(' ')[0]
        });

        // Add to critical incidents
        this.state.criticalIncidents.unshift({
            id: `INC-${Math.floor(1000 + Math.random() * 9000)}`,
            title: `Service Outage: ${target.name}`,
            target: `${target.name} (${target.ip})`,
            severity: 'CRITICAL',
            status: 'Offline',
            time: 'Just now'
        });

        // Add alert
        this.state.alerts.unshift({
            id: `ALT-${Math.floor(2000 + Math.random() * 8000)}`,
            threatType: 'Node Outage / Heartbeat Loss',
            deviceId: target.id,
            deviceName: target.name,
            ip: target.ip,
            severity: 'CRITICAL',
            timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
            status: 'ACTIVE',
            summary: `Automated health check failed. Zero telemetry received from ${target.name}.`
        });

        this.saveState();
        this.notify('DEVICE_FAILED', { device: target });
        return target;
    }

    // Find Alternative Route for failed traffic
    findAlternativeRoute(deviceId = null) {
        const targetId = deviceId || this.state.recoveryState.failedDeviceId || 'dev-4';
        const target = this.getDevice(targetId) || this.getDevice('dev-4');

        let routePlan;
        if (target.id === 'dev-4') {
            // Server 03 failed -> Reroute via Server 02 (Application Cluster) & Server 01
            this.state.recoveryState.alternativeRouteActive = true;
            this.state.recoveryState.recoveryStep = 2;
            this.state.recoveryState.backupServerStatus = 'STANDBY_ALERT';
            this.state.topologyLinks.forEach(link => {
                if ((link.to === 'dev-2' || link.from === 'dev-2') && (link.to === 'dev-1' || link.from === 'dev-1')) {
                    link.status = 'rerouted-active';
                }
            });
            routePlan = {
                success: true,
                targetId: target.id,
                targetName: target.name,
                path: ['Firewall 01 (192.168.1.254)', 'Router 01 (192.168.1.1)', 'Server 02 [Dynamic Failover Bridge] (192.168.1.11)'],
                latency: '1.2ms',
                capacity: '10 Gbps',
                protocol: 'BGP Anycast / Dynamic Failover Mesh'
            };
        } else if (target.id === 'dev-3') {
            // Server 02 failed -> Reroute via Server 03 standby failover
            this.state.recoveryState.alternativeRouteActive = true;
            this.state.recoveryState.recoveryStep = 2;
            this.state.recoveryState.backupServerStatus = 'HOT_ACTIVE';
            this.state.topologyLinks.forEach(link => {
                if (link.to === 'dev-4' || link.from === 'dev-4') {
                    link.status = 'rerouted-active';
                }
            });
            routePlan = {
                success: true,
                targetId: target.id,
                targetName: target.name,
                path: ['Firewall 01 (192.168.1.254)', 'Router 01 (192.168.1.1)', 'Server 03 [Failover Proxy] (192.168.1.12)'],
                latency: '1.4ms',
                capacity: '10 Gbps',
                protocol: 'BGP Anycast / Dynamic Failover Mesh'
            };
        } else if (target.id === 'dev-2') {
            // Server 01 failed -> Reroute via Server 02 replica
            this.state.recoveryState.alternativeRouteActive = true;
            this.state.recoveryState.recoveryStep = 2;
            this.state.recoveryState.backupServerStatus = 'HOT_ACTIVE';
            this.state.topologyLinks.forEach(link => {
                if (link.to === 'dev-3' || link.from === 'dev-3') {
                    link.status = 'rerouted-active';
                }
            });
            routePlan = {
                success: true,
                targetId: target.id,
                targetName: target.name,
                path: ['Firewall 01 (192.168.1.254)', 'Router 01 (192.168.1.1)', 'Server 02 [Database Standby Replica] (192.168.1.11)'],
                latency: '1.1ms',
                capacity: '10 Gbps',
                protocol: 'BGP Anycast / Dynamic Failover Mesh'
            };
        } else {
            // Device without redundant secondary route in star subnet
            this.state.recoveryState.alternativeRouteActive = false;
            routePlan = {
                success: false,
                targetId: target.id,
                targetName: target.name,
                path: [],
                error: `No valid redundant alternative route exists for ${target.name} in the topology mesh.`
            };
        }

        this.state.recoveryState.activeRoutePlan = routePlan;

        if (routePlan.success) {
            this.state.recentEvents.unshift({
                type: 'REROUTE',
                msg: `DYNAMIC REROUTE: Traffic bypassed around ${target.name} via ${routePlan.path[routePlan.path.length - 1]}.`,
                time: new Date().toTimeString().split(' ')[0]
            });
        } else {
            this.state.recentEvents.unshift({
                type: 'REROUTE_FAIL',
                msg: `REROUTE FAILED: ${routePlan.error}`,
                time: new Date().toTimeString().split(' ')[0]
            });
        }

        this.saveState();
        this.notify('ROUTE_REROUTED', { routePlan, target });
        return routePlan;
    }

    // Start Recovery Workflow
    startRecovery(deviceId = null, onStepProgress = null) {
        const targetId = deviceId || this.state.recoveryState.failedDeviceId || 'dev-4';
        const target = this.getDevice(targetId);
        if (!target) return Promise.reject(new Error('Target device not found'));

        // Check if an alternative route exists or can be established
        const routePlan = this.findAlternativeRoute(target.id);
        if (!routePlan.success) {
            return Promise.reject(new Error(`Recovery could not be completed: ${routePlan.error}`));
        }

        target.status = 'recovering';
        this.state.recoveryState.recoveryInProgress = true;
        this.state.recoveryState.recoveryStep = 3;
        this.saveState();
        this.notify('RECOVERY_STARTED', { device: target });

        const steps = [
            { step: 1, text: `Quarantining damaged memory segments on ${target.name} & clearing I/O locks...` },
            { step: 2, text: `Mounting pristine snapshot replica from standby cluster for ${target.name}...` },
            { step: 3, text: `Restarting core service daemon on ${target.ip} & running parity test...` },
            { step: 4, text: `Re-verifying network interface bonding & firewall rules for ${target.name}...` }
        ];

        return new Promise((resolve) => {
            let index = 0;
            const interval = setInterval(() => {
                if (index < steps.length) {
                    if (onStepProgress) onStepProgress(steps[index]);
                    index++;
                } else {
                    clearInterval(interval);
                    this.restoreDevice(target.id);
                    resolve(target);
                }
            }, 750);
        });
    }

    // Restore Device completely to Healthy state
    restoreDevice(deviceId = null) {
        const targetId = deviceId || this.state.recoveryState.failedDeviceId || 'dev-3';
        const target = this.getDevice(targetId);
        if (!target) return null;

        target.status = 'online';
        target.packetLoss = '0.01%';
        target.trafficIn = '284.4 Mbps';
        target.trafficOut = '262.1 Mbps';
        target.cpuLoad = 44;
        target.memLoad = 52;
        target.lastActive = 'Just now';

        // Restore links
        this.state.topologyLinks.forEach(link => {
            if (link.from === target.id || link.to === target.id) {
                link.status = 'active';
            }
            if (link.type === 'failover-link' || link.type === 'redundant-link') {
                link.status = 'standby';
            }
        });

        // Update Recovery state
        this.state.recoveryState.isFailureSimulated = false;
        this.state.recoveryState.failedDeviceId = null;
        this.state.recoveryState.alternativeRouteActive = false;
        this.state.recoveryState.recoveryInProgress = false;
        this.state.recoveryState.recoveryStep = 4;
        this.state.recoveryState.backupServerStatus = 'STANDBY_READY';

        this.simulatedRecoveriesCount++;

        // Add to history ONLY AFTER simulation completes
        this.state.recoveryState.history.unshift({
            id: `REC-${Math.floor(510 + Math.random() * 490)}`,
            timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
            targetDevice: `${target.name} (${target.ip})`,
            faultType: 'Hardware Fault & Telemetry Outage',
            actionTaken: `Autonomous failover convergence completed. ${target.name} verified and restored.`,
            duration: '3.1 seconds',
            status: 'SUCCESS'
        });

        this.state.recentEvents.unshift({
            type: 'RECOVER_SUCCESS',
            msg: `RESTORATION COMPLETE: ${target.name} is fully healthy and verified.`,
            time: new Date().toTimeString().split(' ')[0]
        });

        this.saveState();
        this.notify('DEVICE_RESTORED', { device: target });
        return target;
    }

    // Resolve an alert
    resolveAlert(alertId) {
        const alert = this.state.alerts.find(a => a.id === alertId);
        if (!alert) return null;

        alert.status = 'RESOLVED';
        this.state.recentEvents.unshift({
            type: 'ALERT_RESOLVED',
            msg: `Alert ${alertId} resolved by SOC Operator.`,
            time: new Date().toTimeString().split(' ')[0]
        });

        this.saveState();
        this.notify('ALERT_RESOLVED', { alert });
        return alert;
    }

    // Mitigate Threat
    mitigateThreat(threatId) {
        const threat = this.state.threats.find(t => t.id === threatId);
        if (!threat) return null;

        threat.status = 'MITIGATED';
        
        // If it was PC 03 (suspicious), return it to online or quarantined
        if (threat.affectedDeviceId === 'dev-7') {
            const dev = this.state.devices.find(d => d.id === 'dev-7');
            if (dev) {
                dev.status = 'online';
                dev.trafficOut = '24.2 Mbps';
                dev.cpuLoad = 32;
                dev.memLoad = 48;
            }
            this.state.topologyLinks.forEach(link => {
                if (link.to === 'dev-7' || link.from === 'dev-7') {
                    link.status = 'active';
                }
            });
        }

        this.state.recentEvents.unshift({
            type: 'THREAT_MITIGATED',
            msg: `AI Mitigation applied to threat ${threatId} (${threat.threatType}).`,
            time: new Date().toTimeString().split(' ')[0]
        });

        this.saveState();
        this.notify('THREAT_MITIGATED', { threat });
        return threat;
    }

    // Toggle device status directly (e.g. from topology inspector or network monitor)
    setDeviceStatus(deviceId, newStatus) {
        const target = this.state.devices.find(d => d.id === deviceId);
        if (!target) return null;

        target.status = newStatus;
        this.state.topologyLinks.forEach(link => {
            if (link.from === deviceId || link.to === deviceId) {
                if (newStatus === 'offline') link.status = 'inactive';
                else if (newStatus === 'suspicious') link.status = 'suspicious';
                else link.status = 'active';
            }
        });

        this.saveState();
        this.notify('DEVICE_STATUS_CHANGED', { device: target, newStatus });
        return target;
    }

    // Toggle device status (online <-> offline) from monitor or topology
    toggleDeviceStatus(deviceId) {
        const target = this.getDevice(deviceId);
        if (!target) return null;

        if (target.status === 'offline') {
            return this.restoreDevice(target.id);
        } else {
            return this.simulateDeviceFailure(target.id);
        }
    }

    // Dynamic analytics getter that synchronizes device availability with current live device state
    getAnalytics(range = '24h') {
        const raw = this.state.analyticsData[range] || this.state.analyticsData['24h'];
        const computed = JSON.parse(JSON.stringify(raw));
        
        // Dynamically reflect current device status in availability SLA percentages
        const deviceNames = this.state.devices.map(d => d.name);
        const uptimes = this.state.devices.map(d => {
            if (d.status === 'offline') return 88.40;
            if (d.status === 'suspicious') return 94.60;
            if (d.status === 'recovering') return 96.80;
            return 99.98;
        });
        computed.deviceAvailability = {
            devices: deviceNames,
            uptimePercentages: uptimes
        };
        return computed;
    }

    // Isolate a device from the network (quarantine)
    isolateDevice(deviceId) {
        const target = this.getDevice(deviceId);
        if (!target) return null;

        target.status = 'offline';
        target.packetLoss = '100%';
        target.trafficIn = '0.0 Mbps';
        target.trafficOut = '0.0 Mbps';
        
        // Sever all links connected to device
        this.state.topologyLinks.forEach(link => {
            if (link.from === deviceId || link.to === deviceId) {
                link.status = 'inactive';
            }
        });

        this.state.recentEvents.unshift({
            type: 'DEFENSE',
            msg: `DEVICE ISOLATED: ${target.name} (${target.ip}) quarantined via eBPF host filter.`,
            time: new Date().toTimeString().split(' ')[0]
        });

        this.saveState();
        this.notify('DEVICE_ISOLATED', { device: target });
        return target;
    }

    // Simulate injecting a threat on a target device
    simulateThreat(threatData = {}) {
        const targetId = threatData.deviceId || 'dev-7';
        const target = this.getDevice(targetId) || this.getDevice('dev-7');
        
        target.status = 'suspicious';
        const newThreat = {
            id: `ATD-${Math.floor(9100 + Math.random() * 800)}`,
            threatType: threatData.threatType || 'Zero-Day Polymorphic C2 Beaconing',
            affectedDeviceId: target.id,
            affectedDeviceName: target.name,
            affectedIp: target.ip,
            severity: threatData.severity || 'CRITICAL',
            status: 'ACTIVE',
            timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
            anomalyScore: threatData.anomalyScore || 0.96,
            explanation: `Isolation forest multidimensional split depth 2 detected high entropy bursts on ${target.ip}.`,
            recommendedAction: `Apply micro-segmentation quarantine rule to isolate ${target.name}.`,
            mlFeatures: {
                packetEntropy: 7.94,
                payloadVariance: '+412%',
                baselineDeviation: '4.1σ',
                requestFrequency: '540 req/s'
            }
        };

        this.state.threats.unshift(newThreat);

        this.state.alerts.unshift({
            id: `ALT-${Math.floor(2000 + Math.random() * 8000)}`,
            threatType: newThreat.threatType,
            deviceId: target.id,
            deviceName: target.name,
            ip: target.ip,
            severity: newThreat.severity,
            timestamp: newThreat.timestamp,
            status: 'ACTIVE',
            summary: `Automated ML anomaly detection flagged suspicious vector on ${target.name}.`
        });

        this.saveState();
        this.notify('THREAT_SIMULATED', { threat: newThreat, device: target });
        return newThreat;
    }

    // System Health Status (GET /api/health)
    getHealth() {
        return {
            status: 'UP',
            socOnline: true,
            version: 'v2.4 LTS',
            timestamp: new Date().toISOString(),
            latencyMs: 14,
            engine: 'Autonomous SOC Orchestrator'
        };
    }

    // Comprehensive SOC History (GET /api/history)
    getHistory() {
        return {
            recoveryHistory: this.state.recoveryState.history,
            recentEvents: this.state.recentEvents,
            criticalIncidents: this.state.criticalIncidents
        };
    }

    // Comprehensive Dashboard Payload (GET /api/dashboard)
    getDashboard() {
        return {
            metrics: this.getMetrics(),
            criticalIncidents: this.state.criticalIncidents,
            recentEvents: this.state.recentEvents,
            userActivity: this.state.userActivity,
            recoveryState: this.state.recoveryState
        };
    }
}

// Global Singleton Instance
window.NetGuardianStore = new StateManager();
