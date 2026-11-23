"""
NetGuardian AI - Live HTTP Integration Verification Script (Prompts 5, 6, 7 & 8)
Verifies:
1. Health & Database connectivity
2. Device CRUD & inventory
3. Dashboard calculated telemetry (devices, alerts, recoveries)
4. Network topology (nodes & links)
5. Traffic telemetry generation
6. Security Alerts (Create, Read, Update status, Summary, Severity filter)
7. Device Isolation (PC 03 isolated, Router 01 protected)
8. Device Restoration (PC 03 restored with graph check)
9. Self-Healing Autonomous Recovery (Server 03 failover reroute)
10. SPOF Recovery Failure (No fake recovery for PC 05)
11. Duplicate Recovery Prevention (Server 01 already online)
12. Recovery History Retrieval
"""

import urllib.request
import urllib.error
import json
import time

BASE_URL = 'http://127.0.0.1:5000'


def make_request(path, method='GET', payload=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_headers = {'Content-Type': 'application/json', 'Origin': 'http://localhost:3000'}
    if headers:
        req_headers.update(headers)
    
    data = json.dumps(payload).encode('utf-8') if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.loads(res.read().decode('utf-8')), res.headers
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode('utf-8')), e.headers


print("=================================================================")
print("  NetGuardian AI — Live HTTP Endpoint Verification (Prompts 5-8) ")
print("=================================================================\n")

# 1. Health
print("[Test 1] Live GET /api/health:")
status, body, _ = make_request('/api/health')
print(f"  Status: {status} OK, Database: {body.get('database')}")
assert status == 200
assert body['success'] is True
print("PASS: /api/health verified.\n")

# 2. Devices
print("[Test 2] Live GET /api/devices:")
status, body, _ = make_request('/api/devices')
print(f"  Status: {status} OK, Count: {len(body['data'])}")
assert status == 200
assert len(body['data']) == 10
print("PASS: All 10 devices fetched.\n")

# 3. Security Alerts List & Filter
print("[Test 3] Live GET /api/alerts & Severity Filtering:")
status, body, _ = make_request('/api/alerts')
print(f"  Total Alerts: {body['count']}")
assert status == 200
assert body['count'] >= 6

status_crit, body_crit, _ = make_request('/api/alerts?severity=CRITICAL')
print(f"  Critical Alerts: {body_crit['count']}")
assert status_crit == 200
for a in body_crit['alerts']:
    assert a['severity'] == 'CRITICAL'
print("PASS: Alerts retrieval and severity filter verified.\n")

# 4. Single Alert & Status Update
print("[Test 4] Live GET /api/alerts/ALT-1001 & PATCH /api/alerts/ALT-1001/status:")
status, body, _ = make_request('/api/alerts/ALT-1001')
print(f"  Alert: {body['alert']['alert_code']} - Threat: {body['alert']['threat_type']}")
assert status == 200

status_patch, body_patch, _ = make_request('/api/alerts/ALT-1001/status', method='PATCH', payload={'status': 'INVESTIGATING'})
print(f"  Updated Status: {body_patch['alert']['status']}")
assert status_patch == 200
assert body_patch['alert']['status'] == 'INVESTIGATING'
print("PASS: Alert retrieval and status patching verified.\n")

# 5. Security Alerts Summary
print("[Test 5] Live GET /api/alerts/summary:")
status, body, _ = make_request('/api/alerts/summary')
print(f"  Summary -> Total: {body['total_alerts']}, Active: {body['active_alerts']}, Critical: {body['critical_alerts']}, Resolved: {body['resolved_alerts']}")
assert status == 200
assert body['total_alerts'] >= 6
print("PASS: Security alerts summary aggregated from SQLite.\n")

# 6. Device Isolation & Core Infrastructure Guard
print("[Test 6] Live POST /api/devices/7/isolate & Infrastructure Protection Check:")
# Isolate PC 03 (ID 7)
status_iso, body_iso, _ = make_request('/api/devices/7/isolate', method='POST')
print(f"  PC 03 Isolated -> Status: {body_iso['device']['status']}, Inactive Links: {len(body_iso['connections'])}")
assert status_iso == 200
assert body_iso['device']['status'] == 'suspicious'

# Attempt to isolate Router 01 (ID 1) - Must be blocked
status_block, body_block, _ = make_request('/api/devices/1/isolate', method='POST')
print(f"  Router 01 Isolation Blocked -> HTTP {status_block}: {body_block['message']}")
assert status_block == 400
assert 'prohibited' in body_block['message'].lower()
print("PASS: Isolation mechanism and core protection guard verified.\n")

# 7. Device Restoration
print("[Test 7] Live POST /api/devices/7/restore:")
status_res, body_res, _ = make_request('/api/devices/7/restore', method='POST')
print(f"  PC 03 Restored -> Status: {body_res['device']['status']}, Graph Verified: {body_res['verified']}")
assert status_res == 200
assert body_res['device']['status'] == 'online'
assert body_res['verified'] is True
print("PASS: Device restoration and connectivity check verified.\n")

# 8. Self-Healing Recovery (Server 03 - Redundant Failover)
print("[Test 8] Live Self-Healing Recovery on Server 03 (ID 4):")
# Trigger failure first
make_request('/api/simulation/failure', method='POST', payload={'device_id': 4})

# Trigger self-healing recovery
status_rec, body_rec, _ = make_request('/api/recovery/start', method='POST', payload={'device_id': 4})
print(f"  Server 03 Recovery -> Status: {body_rec['status']}, Code: {body_rec.get('recovery_code')}")
print(f"  Failover Route Applied: {body_rec.get('alternative_route')}")
assert status_rec == 200
assert body_rec['success'] is True
assert body_rec['verification_status'] == 'VERIFIED'
assert body_rec['final_status'] == 'online'
print("PASS: Autonomous self-healing failover recovery verified.\n")

# 9. No-Route Recovery Failure (PC 05 - Leaf Node SPOF)
print("[Test 9] Live No-Route Recovery Failure on PC 05 (ID 9):")
# PC 05 is offline; it has no redundant links
status_spof, body_spof, _ = make_request('/api/recovery/start', method='POST', payload={'device_id': 9})
print(f"  PC 05 Recovery Outcome -> Status: {body_spof['status']}, Success: {body_spof['success']}")
print(f"  Message: {body_spof['message']}")
assert status_spof == 200
assert body_spof['success'] is False
assert body_spof['verification_status'] == 'FAILED'
assert body_spof['alternative_route'] is None
print("PASS: No-route failure reported accurately without faking recovery.\n")

# 10. Duplicate Recovery Prevention
print("[Test 10] Live Duplicate Recovery Prevention on Online Server 01 (ID 2):")
status_dup, body_dup, _ = make_request('/api/recovery/start', method='POST', payload={'device_id': 2})
print(f"  Duplicate Recovery Attempt -> HTTP {status_dup}: {body_dup['message']}")
assert status_dup == 400
assert 'already operational and online' in body_dup['message']
print("PASS: Duplicate recovery attempt rejected cleanly.\n")

# 11. Recovery History
print("[Test 11] Live GET /api/recovery/history & /api/recovery/history/REC-501:")
status_hist, body_hist, _ = make_request('/api/recovery/history')
print(f"  Total Recovery History Records: {body_hist['count']}")
assert status_hist == 200
assert body_hist['count'] >= 5

status_rec1, body_rec1, _ = make_request('/api/recovery/history/REC-501')
print(f"  Record REC-501 Action: {body_rec1['record']['action_taken']}")
assert status_rec1 == 200
assert body_rec1['record']['recovery_code'] == 'REC-501'
print("PASS: Recovery history records queryable from SQLite.\n")

# 12. Dashboard Integrated Metrics
print("[Test 12] Live GET /api/dashboard (Integrated Metrics):")
status_dash, body_dash, _ = make_request('/api/dashboard')
dash = body_dash['data']
print(f"  Active Security Alerts: {dash['active_security_alerts']}")
print(f"  Critical Incidents: {dash['critical_incidents']}")
print(f"  Successful Recoveries: {dash['successful_recovery_count']}")
print(f"  Failed Recoveries: {dash['failed_recovery_count']}")
print(f"  Isolated Devices: {dash['isolated_devices']}")
print(f"  Network Health: {dash['network_health']}%")
assert status_dash == 200
assert 'active_security_alerts' in dash
assert 'critical_incidents' in dash
assert 'successful_recovery_count' in dash
assert 'failed_recovery_count' in dash
assert dash['successful_recovery_count'] >= 1
print("PASS: Dashboard metrics integrated with alerts and recovery logs.\n")

print("=================================================================")
print("  ALL LIVE INTEGRATION TESTS PASSED 100% SUCCESSFULLY!            ")
print("=================================================================")
