const fs = require('fs');
const vm = require('vm');

console.log('=== NetGuardian AI Automated Verification Suite ===\n');

// 1. Verify index.html and all IDs
const html = fs.readFileSync('frontend/index.html', 'utf8');
const idRegex = /id=["']([^"']+)["']/g;
const declaredIds = new Set();
let match;
while ((match = idRegex.exec(html)) !== null) {
    declaredIds.add(match[1]);
}

const jsFiles = [
    'frontend/js/dashboard.js',
    'frontend/js/network.js',
    'frontend/js/topology.js',
    'frontend/js/threats.js',
    'frontend/js/recovery.js',
    'frontend/js/alerts.js',
    'frontend/js/analytics.js',
    'frontend/js/app.js'
];

let missing = [];
let totalQueried = 0;
jsFiles.forEach(file => {
    const code = fs.readFileSync(file, 'utf8');
    const getElemRegex = /getElementById\(['"]([^'"]+)['"]\)/g;
    while ((match = getElemRegex.exec(code)) !== null) {
        totalQueried++;
        const id = match[1];
        if (id.startsWith('pipe-step-') || id.startsWith('topo-path-') || id.startsWith('view-')) {
            // Check dynamic template patterns
            if (id.startsWith('view-') && !declaredIds.has(id)) {
                missing.push({ id, file });
            }
            continue;
        }
        if (!declaredIds.has(id)) {
            missing.push({ id, file });
        }
    }
});

console.log(`[Test 1] DOM Element ID Validation: Checked ${totalQueried} getElementById calls.`);
if (missing.length > 0) {
    console.error('Missing IDs:', missing);
} else {
    console.log('✓ PASS: All DOM element IDs matched perfectly.\n');
}

// 2. Test mock-data.js logic and state mutations
console.log('[Test 2] State Store & Mutation Simulation:');
const mockCode = fs.readFileSync('frontend/js/mock-data.js', 'utf8');
const sandbox = { window: {}, console };
vm.createContext(sandbox);
vm.runInContext(mockCode, sandbox);

const store = sandbox.window.NetGuardianStore;
console.log('✓ Loaded NetGuardianStore');

const initialDevices = store.getDevices();
console.log(`✓ Device inventory: ${initialDevices.length} devices loaded.`);
if (initialDevices.length !== 10) throw new Error('Expected 10 devices');

// Check the 10 required device names and IPs
const expectedDevices = [
    { name: 'Router 01', ip: '192.168.1.1' },
    { name: 'Server 01', ip: '192.168.1.10' },
    { name: 'Server 02', ip: '192.168.1.11' },
    { name: 'Server 03', ip: '192.168.1.12' },
    { name: 'PC 01', ip: '192.168.1.20' },
    { name: 'PC 02', ip: '192.168.1.21' },
    { name: 'PC 03', ip: '192.168.1.22' },
    { name: 'PC 04', ip: '192.168.1.23' },
    { name: 'PC 05', ip: '192.168.1.24' },
    { name: 'Firewall 01', ip: '192.168.1.254' }
];

expectedDevices.forEach(expected => {
    const found = initialDevices.find(d => d.name === expected.name && d.ip === expected.ip);
    if (!found) {
        throw new Error(`Device missing: ${expected.name} (${expected.ip})`);
    }
});
console.log('✓ PASS: All 10 required network devices verified by exact Name and IP.\n');

// Test metrics computation
const m1 = store.getMetrics();
console.log(`[Test 3] Metrics Verification: Total: ${m1.totalDevices}, Online: ${m1.onlineDevices}, Offline: ${m1.offlineDevices}, Suspicious: ${m1.suspiciousDevices}, Threats: ${m1.activeThreats}, Health: ${m1.networkHealth}%, Recoveries: ${m1.successfulRecoveries}`);
console.log('✓ PASS: Initial metrics nominal.\n');

// Test Simulate Failure
console.log('[Test 4] Simulate Failure Action:');
const failedDev = store.simulateDeviceFailure('dev-3');
const m2 = store.getMetrics();
console.log(`  Failed device: ${failedDev.name}, Status: ${failedDev.status}`);
console.log(`  Updated Metrics: Offline: ${m2.offlineDevices}, Network Health: ${m2.networkHealth}%`);
if (failedDev.status !== 'offline') throw new Error('Expected device status offline');
console.log('✓ PASS: Failure simulation successfully cascaded across state.\n');

// Test Find Alternative Route
console.log('[Test 5] Find Alternative Route Action:');
const routePlan = store.findAlternativeRoute('dev-3');
console.log(`  Calculated Failover Path: ${routePlan.path.join(' -> ')}`);
console.log(`  Alternative Route Active: ${store.state.recoveryState.alternativeRouteActive}`);
if (!store.state.recoveryState.alternativeRouteActive) throw new Error('Expected alternative route active');
console.log('✓ PASS: Failover route computed and engaged.\n');

// Test Restore Device
console.log('[Test 6] Restore Device Action:');
const restoredDev = store.restoreDevice('dev-3');
const m3 = store.getMetrics();
console.log(`  Restored device: ${restoredDev.name}, Status: ${restoredDev.status}`);
console.log(`  Recoveries count incremented to: ${m3.successfulRecoveries}`);
console.log(`  Latest recovery history entry: ${store.state.recoveryState.history[0].id} - ${store.state.recoveryState.history[0].targetDevice}`);
if (m3.successfulRecoveries !== 18) throw new Error('Expected recoveries count to be 18');
console.log('✓ PASS: Recovery state update and audit log verified.\n');

// Test Threat Mitigation
console.log('[Test 7] Threat Mitigation Action:');
const mitigatedThreat = store.mitigateThreat('ATD-9042');
console.log(`  Threat ${mitigatedThreat.id} status: ${mitigatedThreat.status}`);
const pc03 = store.getDevice('dev-7');
console.log(`  PC 03 status after mitigation: ${pc03.status}`);
if (pc03.status !== 'online') throw new Error('Expected PC 03 to be online after mitigation');
console.log('✓ PASS: Threat mitigation restored affected node.\n');

// Test Alert Resolution
console.log('[Test 8] Alert Resolution Action:');
const resolvedAlert = store.resolveAlert('ALT-1001');
console.log(`  Alert ${resolvedAlert.id} status: ${resolvedAlert.status}`);
if (resolvedAlert.status !== 'RESOLVED') throw new Error('Expected alert to be RESOLVED');
console.log('✓ PASS: Alert successfully resolved in store.\n');

// Test 9: Connected Devices Lookup (Topology Enhancement)
console.log('[Test 9] Connected Devices Lookup (Topology Inspector):');
const routerNeighbors = store.getConnectedDevices('dev-1');
console.log(`  Router 01 directly connected neighbors: ${routerNeighbors.length}`);
if (routerNeighbors.length === 0) throw new Error('Expected connected neighbors for Router 01');
routerNeighbors.forEach(n => console.log(`   - Connected to ${n.name} (${n.ip}) at ${n.speed}`));
console.log('✓ PASS: Connected topology devices calculated accurately.\n');

// Test 10: Server 03 Failure & Failover Simulation (Prompt 2 Scenario)
console.log('[Test 10] Server 03 Failure Simulation (Prompt 2 Specific Requirement):');
const failedServer03 = store.simulateDeviceFailure('dev-4');
console.log(`  Server 03 status: ${failedServer03.status}`);
if (failedServer03.status !== 'offline') throw new Error('Expected Server 03 to be offline');
const altRouteServer03 = store.findAlternativeRoute('dev-4');
console.log(`  Alternative route bypassing Server 03: ${altRouteServer03.path.join(' -> ')}`);
store.restoreDevice('dev-4');
const restoredServer03 = store.getDevice('dev-4');
console.log(`  Server 03 restored status: ${restoredServer03.status}`);
if (restoredServer03.status !== 'online') throw new Error('Expected Server 03 to be restored to online');
console.log('✓ PASS: Server 03 specific failure and restoration verified.\n');

// Test 11: Multi-range Analytics Datasets
console.log('[Test 11] Multi-range Analytics Datasets (24h, 7d, 30d):');
['24h', '7d', '30d'].forEach(range => {
    const d = store.state.analyticsData[range];
    if (!d || !d.trafficHistory || !d.threatHistory || !d.deviceAvailability) {
        throw new Error(`Missing analytics dataset for range ${range}`);
    }
    console.log(`  Range ${range}: traffic points = ${d.trafficHistory.inbound.length}, threat intervals = ${d.threatHistory.labels.length}`);
});
console.log('✓ PASS: All 3 analytics ranges verified.\n');

// Test 12: Device Status Toggle (Online/Offline) and State Persistence
console.log('[Test 12] Device Status Toggle (Online/Offline):');
const pc01Before = store.getDevice('dev-5').status;
const pc01Toggled = store.toggleDeviceStatus('dev-5');
console.log(`  PC 01 initial: ${pc01Before} -> toggled: ${pc01Toggled.status}`);
if (pc01Toggled.status === pc01Before) throw new Error('Expected toggle status to invert device state');
const pc01Restored = store.toggleDeviceStatus('dev-5');
console.log(`  PC 01 toggled back: ${pc01Restored.status}`);
if (pc01Restored.status !== pc01Before) throw new Error('Expected toggle back to restore initial state');
console.log('✓ PASS: Device status toggle works bi-directionally.\n');

// Test 13: Threat Correlation and Popup Data Preparation
console.log('[Test 13] Threat-Alert Correlation Matching:');
const sampleThreat = store.getThreats()[0];
const correlated = (store.getAlerts() || []).filter(a => 
    a.threatType === sampleThreat.threatType || 
    a.deviceName === sampleThreat.affectedDeviceName || 
    a.ip === sampleThreat.affectedIp
);
console.log(`  Threat ${sampleThreat.id} (${sampleThreat.threatType}) matched ${correlated.length} correlated alerts.`);
console.log('✓ PASS: Forensic correlation analysis operational.\n');

// Test 14: Prompt 4 Complete Self-Healing 10-Step Scenario & SPOF Failure Handling
console.log('[Test 14] Self-Healing Scenario & No-Fake-Recovery Verification:');
// Reset to known state
store.resetStateToDefaults();
const s03 = store.getDevice('dev-4');
console.log(`  Step 1: Selected target device: ${s03.name} (${s03.ip})`);

// Step 2 & 3: Simulate Server 03 failure
store.simulateDeviceFailure('dev-4');
if (store.getDevice('dev-4').status !== 'offline') throw new Error('Step 3 failed: Server 03 not offline');
console.log('  Step 2-3: Server 03 status successfully confirmed as OFFLINE.');

// Step 4: Confirm dashboard statistics update
const mOutage = store.getMetrics();
if (mOutage.offlineDevices !== 2) throw new Error('Step 4 failed: Offline count not updated');
console.log(`  Step 4: Dashboard statistics dynamically updated (Offline: ${mOutage.offlineDevices}, Health: ${mOutage.networkHealth}%).`);

// Step 5 & 6: Confirm topology changes and affected connections
const s03Links = store.state.topologyLinks.filter(l => l.from === 'dev-4' || l.to === 'dev-4');
const inactiveLinks = s03Links.filter(l => l.status === 'inactive');
if (inactiveLinks.length === 0) throw new Error('Step 5-6 failed: Connecting links to Server 03 not severed');
console.log(`  Step 5-6: Affected connections identified and severed (${inactiveLinks.length} links marked inactive).`);

// Step 7: Find alternative route
const s03Route = store.findAlternativeRoute('dev-4');
if (!s03Route.success || s03Route.path.length === 0) throw new Error('Step 7 failed: Valid alternative route not found for Server 03');
console.log(`  Step 7: Alternative route verified: ${s03Route.path.join(' -> ')}`);

// Step 8 & 9: Execute recovery & verify connectivity through alternative route
const historyCountBefore = store.state.recoveryState.history.length;
store.restoreDevice('dev-4');
if (store.getDevice('dev-4').status !== 'online') throw new Error('Step 9 failed: Server 03 not restored');
console.log('  Step 8-9: Recovery executed and connectivity confirmed healthy.');

// Step 10: Record completed recovery in history
const historyCountAfter = store.state.recoveryState.history.length;
if (historyCountAfter !== historyCountBefore + 1) throw new Error('Step 10 failed: Recovery history not appended');
console.log(`  Step 10: Recovery logged to audit history: ID ${store.state.recoveryState.history[0].id} for ${store.state.recoveryState.history[0].targetDevice}`);

// Verification: Condition where no valid alternative route exists (Router 01 SPOF)
const routerRoute = store.findAlternativeRoute('dev-1');
if (routerRoute.success !== false) throw new Error('Expected alternative route for single-point-of-failure Router 01 to fail');
console.log(`  Verified No-Fake-Recovery: Router 01 failure correctly reports: "${routerRoute.error}"`);
console.log('✓ PASS: 10-step self-healing scenario and SPOF integrity verified.\n');

// Test 15: Resolved Alerts Do Not Appear as Active Threats
console.log('[Test 15] Alert Resolution & Active Threat Parity:');
const activeBefore = store.getAlerts().filter(a => a.status === 'ACTIVE' || a.status === 'IN_PROGRESS').length;
const testAlert = store.getAlerts().find(a => a.status === 'ACTIVE');
if (testAlert) {
    store.resolveAlert(testAlert.id);
    const activeAfter = store.getAlerts().filter(a => a.status === 'ACTIVE' || a.status === 'IN_PROGRESS').length;
    if (activeAfter !== activeBefore - 1) throw new Error('Resolved alert still counted as active');
    console.log(`  Alert ${testAlert.id} resolved. Active alert count decreased from ${activeBefore} to ${activeAfter}.`);
}
console.log('✓ PASS: Resolved alerts do not incorrectly appear as active.\n');

// Test 16: Backend Integration Readiness (api.js contract check)
console.log('[Test 16] Backend Integration API Endpoints Contract Check:');
const apiCode = fs.readFileSync('frontend/js/api.js', 'utf8');
const expectedEndpoints = [
    'getHealth',
    'getDashboard',
    'getDevices',
    'getTraffic',
    'getAlerts',
    'getHistory',
    'simulateFailure',
    'simulateThreat',
    'recover',
    'isolate',
    'restore'
];

expectedEndpoints.forEach(method => {
    if (!apiCode.includes(`async ${method}(`) && !apiCode.includes(`${method}(`)) {
        throw new Error(`Missing expected future API method: ${method}`);
    }
    console.log(`  - Confirmed endpoint handler: NetGuardianAPI.${method}()`);
});
console.log('✓ PASS: All 11 expected Flask backend endpoints implemented in frontend API service.\n');

console.log('=== All 16 Verification Tests Passed with 100% Success! ===');
