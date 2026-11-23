# NetGuardian AI – Complete Self-Healing Network Engine
## Master Implementation & Verification Report

> **Tagline:** *Detect. Defend. Recover. Automatically.*  
> **System Architecture:** Autonomous Cyber Defense & Self-Healing Network Engine  
> **Simulation Notice:** Software-only local prototype. All network nodes, links, telemetry, and cyber incidents are modeled in SQLite and NetworkX. No physical hardware is controlled.

---

## 1. Executive Summary

The **NetGuardian AI Self-Healing Network Engine** is a closed-loop autonomous system designed to eliminate network downtime and mitigate cybersecurity threats across smart grid and enterprise network topologies. Building directly upon the BESCOM Smart Meter Communication Network architecture and the unified 6-stage AI/ML detection pipeline, the engine autonomously detects failures, assesses service impact, safely quarantines malicious or compromised endpoints, computes dynamic failover bypass routes using graph theory, verifies post-recovery operational state, and maintains complete forensic audit trails.

### Key Milestones Achieved:
- **Five Integrated Self-Healing Modules:** Deployed across dedicated service layers in `backend/services/` and exposed via REST APIs in `backend/routes/healing_routes.py`.
- **Honest Resilience Evaluation:** Star-topology leaf nodes (e.g., smart meters with a single uplink to the gateway) are honestly diagnosed as Single-Points-of-Failure (SPOF) when an uplink fails, while redundant server meshes dynamically engage standby failovers.
- **Safety Policy Enforcement:** Core infrastructure (Router 01 / Smart Meter Gateway, Firewall 01) is strictly protected from automated isolation to prevent catastrophic network blackouts.
- **20/20 Dedicated Self-Healing Tests Passing:** Automated test suite `backend/tests/test_self_healing.py` covers all 20 required verification conditions.
- **179/179 Total System Tests Passing:** Full regression validation confirmed across all 12 test suites with 0 failures and 0 errors.

---

## 2. Architecture & Autonomous Workflow

The self-healing lifecycle follows a closed-loop 9-step state machine:

```
[ Step 1: Detect Failure ] ────> [ Step 2: Identify Affected Topology ]
           │                                      │
           ▼                                      ▼
[ Step 4: AI & Policy Gate ] <──── [ Step 3: Assess Failure Severity ]
           │
           ├──> (Critical Threat / High Severity) ──> [ Quarantined Isolation ]
           │
           ▼
[ Step 5: Compute Alternative Path (NetworkX Dijkstra) ]
           │
           ├──> (Viable Path Found) ──> [ Engage Dynamic Standby Route ]
           │
           └──> (No Viable Path)   ──> [ Honest SPOF Failure Report ]
           │
           ▼
[ Step 6: Post-Recovery Connectivity Verification ]
           │
           ├──> (Verified Online & Routable) ──> Status: RECOVERED
           │
           └──> (Verification Failed / Unreachable) ──> Status: FAILED
           │
           ▼
[ Step 7: Update SQLite Inventory & NetworkX Graph ]
           │
           ▼
[ Step 8: Persist Audit Record to recovery_logs ]
           │
           ▼
[ Step 9: Stream Live Telemetry & KPIs to SOC Dashboard ]
```

---

## 3. Implemented Modules Breakdown

### Module 1: Failure Detection Engine (`backend/services/failure_detection.py`)
Continuously sweeps device metrics and topological links against 8 distinct failure conditions:
1. **Device Offline:** Device status in inventory is `offline`. Severity: `HIGH` (or `CRITICAL` for core infrastructure).
2. **Device Unreachable:** Packet loss $\ge 95\%$ or complete link starvation while marked online.
3. **Connection Failure:** Severed interface or link status marked `inactive` in `network_connections`.
4. **High Simulated Latency:** Response delay $> 50.0\text{ ms}$ (threshold configured via `THRESHOLD_LATENCY_MS`).
5. **High Packet Loss:** Measured packet loss between $15.0\%$ and $95.0\%$.
6. **Abnormal Traffic Interruption:** Zero throughput ($0.0\text{ Mbps}$) on active core infrastructure nodes.
7. **Repeated Device Failure:** Recurring failure events ($\ge 2$ historical incidents in `recovery_logs`).
8. **Critical Network Path Failure:** Any communication degradation on primary Gateway, Firewall, or Core HES/MDMS servers.

*Deduplication & Storage:* Features active failure deduplication to prevent incident log flooding (`find_active_failure`) and persists records directly to the `network_failures` table.

---

### Module 2: Intelligent Device Isolation & Restoration (`backend/services/device_isolation.py`)
Provides safe, auditable quarantine and restoration workflows:
- **Core Infrastructure Protection:** Prohibits automated isolation of Router 01 (ID 1) and Firewall 01 (ID 10) to avoid network-wide blackouts. Attempts raise `ValidationError` unless explicitly overridden.
- **Critical Service Impact Analysis (`check_critical_service_impact`):** Uses NetworkX bridge analysis and articulation point calculations to verify whether disconnecting a node causes graph partitioning for other active nodes.
- **Edge Severance & Synchronization:** Disables all connected links in `network_connections` (`status = 'inactive'`) and synchronizes the live NetworkX topology graph.
- **Restoration Protocol (`restore_device`):** Re-enables links (`status = 'active'`, standby links to `standby`), sets device status to `online`, resets loss and latency to baseline, and performs a post-restoration graph connectivity check.
- **Forensic Audit Logging:** Logs every quarantine and restoration action into `device_isolation_logs`.

---

### Module 3: Graph-Based Path Recovery (`backend/services/path_recovery.py`)
Computes dynamic network reroutes using NetworkX graph algorithms:
- **Routable Subgraph Extraction (`get_routable_subgraph`):** Builds a live NetworkX subgraph excluding severed links (`status = 'inactive'`), offline nodes, and quarantined devices (`status = 'suspicious'`). Active links are assigned weight 1.0; standby failover links are assigned weight 1.5.
- **Dijkstra Shortest-Path Computation:** Computes shortest viable path using `nx.shortest_path(subgraph, source, target, weight='weight')`.
- **Honest Single-Point-of-Failure Reporting:** Recognizes star topology leaves (Smart Meters 01–05, IDs 5–9). If the single uplink to Gateway (ID 1) is down, the engine returns `viable: False, is_single_point_of_failure: True, error: "No alternative route exists..."`. It never fabricates non-existent bypass routes.
- **Standby Server Failover:** Server 01 (HES) and Server 02 (MDMS) automatically reroute through Server 03 (Backup HES/MDMS Server, ID 4) upon degradation.
- **Dynamic Link Engagement (`apply_route_recovery`):** Engages standby links in `network_connections`, logs the transition to `network_route_changes`, and synchronizes the active topology graph.

---

### Module 4: Automatic Recovery & Connectivity Verification (`backend/services/auto_recovery.py`)
Coordinates end-to-end remediation:
- **9-Step Workflow Execution:** Executes detection, identification, severity analysis, isolation policy check, alternative routing, post-recovery probe, database sync, audit logging, and SOC notification.
- **Managed Lifecycle Statuses:** Tracks operations across 8 explicit states: `DETECTED`, `ANALYZING`, `ISOLATING`, `RECOVERING`, `VERIFYING`, `RECOVERED`, `FAILED`, and `MANUAL_INTERVENTION_REQUIRED`.
- **Strict Connectivity Verification (`verify_connectivity`):** Confirms device status is `online`, node exists in NetworkX, device has $\ge 1$ active edge, and device can route packets to the Core Gateway (or partner cluster).
- **Anti-Loop Safety Limits:** Enforces `MAX_RECOVERY_RETRIES = 3`. If a device fails repeatedly within 1 hour, status transitions to `MANUAL_INTERVENTION_REQUIRED` to prevent infinite oscillation loops.
- **Concurrency Collision Lock:** Maintains thread-safe in-memory tracking `_active_recovery_jobs` to reject duplicate recovery jobs on the same device.

---

### Module 5: Recovery History, Dashboard & API Integration
Exposes 12 REST endpoints under the `/api/healing/*` prefix with legacy aliases under `/api/recovery/*`:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/healing/status` | GET | Engine health, standby cluster readiness, active counts |
| `/api/healing/summary` | GET | Comprehensive KPIs (success rate, avg duration, recent history) |
| `/api/healing/detect` | POST | Triggers live failure detection sweep across all or specific nodes |
| `/api/healing/failures` | GET | Lists active or all simulated failure records |
| `/api/healing/failures/<id>` | GET | Retrieves failure details by failure ID |
| `/api/healing/simulate-failure` | POST | Injects simulated failure on a device |
| `/api/healing/isolate/<device_id>` | POST | Quarantines device with safety policy check |
| `/api/healing/restore/<device_id>` | POST | Restores device to operational baseline |
| `/api/healing/recover/<target_id>` | POST | Executes autonomous 9-step recovery workflow |
| `/api/healing/history` | GET | Retrieves paginated recovery operation history |
| `/api/healing/history/<id>` | GET | Retrieves specific recovery operation record |
| `/api/healing/topology` | GET | Live NetworkX topology nodes, links, and route changes |

**Frontend Integration (`frontend/index.html`, `frontend/js/recovery.js`, `frontend/js/api.js`):**
- **7 KPI Cards:** Total Failures Detected, Active Failures, Isolated Devices, Successful Recoveries, Failed Recoveries, Success Rate (%), Average Duration (s).
- **6 Active Control Buttons:** Simulate Network Failure, Trigger Failure Detection, Isolate Device, Find Alternative Route, Execute Autonomous Recovery, Restore Device.
- **BESCOM Inventory Integration:** Node selector populated with 10 BESCOM network entities (Gateway, Firewall, HES, MDMS, Backup Server, Smart Meters 01–05).

---

## 4. AI/ML Pipeline Integration

The Self-Healing Engine connects directly with the 6-stage AI/ML pipeline via `AutoRecoveryService.evaluate_healing_advisory()`:
- **Decision Matrix:** An anomaly alone never triggers automated quarantine. Automated isolation and rerouting requires `severity == 'CRITICAL'`, `confidence == 'HIGH'`, and a confirmed attack signature (e.g., `Potential Data Exfiltration` or `Denial of Service (DoS) - like traffic spikes`).
- **Safety Policy Gate:** Even when AI criteria are met, the advisory queries `DeviceIsolationService.check_critical_service_impact` first. If quarantine would isolate dependent network segments, the action falls back to `ENGAGE_PERIMETER_DEFENSE`.
- **Pipeline Output:** The unified pipeline output includes `self_healing_advisory` containing `recommended_healing_action`, `isolate_recommended`, `justification`, and `can_safely_isolate`.

---

## 5. Database Schema Extensions

Four persistent SQLite tables underpin the Self-Healing Engine:

1. **`network_failures`:**
   - Columns: `id`, `failure_id` (e.g. `FLR-1001`), `device_id`, `device_ip`, `failure_type`, `severity`, `status`, `description`, `recommended_action`, `affected_connections_json`, `created_at`, `resolved_at`.
2. **`device_isolation_logs`:**
   - Columns: `id`, `isolation_id` (e.g. `ISO-1001`), `device_id`, `device_name`, `device_ip`, `isolation_reason`, `isolation_trigger`, `status`, `affected_connections_count`, `critical_service_check_passed`, `isolated_at`, `restored_at`.
3. **`network_route_changes`:**
   - Columns: `id`, `change_id` (e.g. `RTE-1001`), `device_id`, `recovery_code`, `source_device_id`, `target_device_id`, `original_path`, `alternative_path`, `path_hops`, `status`, `created_at`.
4. **`recovery_logs` (extended with backward-compatible migrations):**
   - Added columns: `failure_id`, `isolation_id`, `error_description`, `retry_count`.

---

## 6. Automated Verification Results

### Dedicated Test Suite: `backend/tests/test_self_healing.py`
All 20 required verification scenarios executed successfully against an isolated temporary test database (`netguardian_test.db`):

| # | Test Scenario | Verified Behavior | Status |
|---|---|---|:---:|
| 1 | Normal Device Monitoring | Healthy device 6 triggers 0 failure alerts | **PASS** |
| 2 | Offline Device Detection | Device 5 offline flags `Device Offline` with HIGH/CRITICAL severity | **PASS** |
| 3 | Connection Failure Detection | Severed link flags `Connection Failure` on affected device | **PASS** |
| 4 | High Latency Detection | Latency $88.5\text{ ms} > 50\text{ ms}$ triggers `High Simulated Latency` | **PASS** |
| 5 | Packet Loss Detection | Packet loss $42.0\%$ triggers `High Packet Loss` | **PASS** |
| 6 | Device Isolation | Device quarantined: status `suspicious`, links severed, audit log created | **PASS** |
| 7 | Device Restoration | Device restored: status `online`, links re-engaged, log status `RESTORED` | **PASS** |
| 8 | Critical Infrastructure Protection | Attempts to isolate Router 01 or Firewall 01 raise `ValidationError` | **PASS** |
| 9 | Alternative Route Calculation | Server 03 computes viable bypass via Server 01/02 using Dijkstra | **PASS** |
| 10 | Failed Route Handling | Smart Meter 03 honestly returns `viable: False` & `is_single_point_of_failure` | **PASS** |
| 11 | Autonomous 9-Step Recovery | Complete workflow runs through all steps to `RECOVERED` status | **PASS** |
| 12 | Connectivity Verification | Verifies online status, active graph edges, and backbone reachability | **PASS** |
| 13 | Failed Recovery Handling | Node with all links down honestly reports `FAILED` with failure details | **PASS** |
| 14 | Recovery Retry Limits | 3 failed attempts triggers `MANUAL_INTERVENTION_REQUIRED` | **PASS** |
| 15 | Duplicate Recovery Prevention | Concurrent recovery job on same device raises duplicate error | **PASS** |
| 16 | Database Persistence | Records persist across failures, isolations, route changes, recovery logs | **PASS** |
| 17 | Recovery History APIs | `GET /api/healing/history` and `/history/<id>` return expected payloads | **PASS** |
| 18 | Dashboard API Integration | `GET /api/healing/summary`, `/status`, and `/topology` return 200 OK | **PASS** |
| 19 | AI/ML Pipeline Integration | Critical threat triggers `ISOLATE_AND_REROUTE`; advisory attached to pipeline | **PASS** |
| 20 | Invalid Input Handling | Invalid IDs, formats, and empty payloads return proper 400/404 errors | **PASS** |

### Complete Backend Regression Run:
```
Ran 179 tests in 21.938s

OK
```
- Total test files: 12 modules
- Total tests executed: 179
- Total passed: 179 (100%)
- Failures: 0
- Errors: 0

---

## 7. Demonstration Scenarios

### Scenario A: Server 03 Standby Failover (Successful Autonomous Recovery)
1. **Initial State:** Primary direct link between Gateway Router (ID 1) and Server 03 (Backup HES/MDMS Server, ID 4) is severed.
2. **Detection:** Failure Detection Engine flags `Connection Failure`.
3. **Execution:** Autonomous Recovery Service executes:
   - Evaluates impact: Server 03 is a core cluster node.
   - Computes alternative path via NetworkX Dijkstra: `Router 01 -> Server 01 -> Server 03`.
   - Engages standby link between Server 01 and Server 03 (`status = 'active'`).
   - Logs change `RTE-1001` in `network_route_changes`.
4. **Verification:** Connectivity probe verifies 2 active edges and reachability to Gateway Router.
5. **Outcome:** Status declared `RECOVERED`. Recovery log `REC-6` saved with duration $1.21\text{ s}$.

### Scenario B: Smart Meter 03 Link Severance (Honest Single-Point-of-Failure Report)
1. **Initial State:** Smart Meter 03 (BES-SM-003, ID 7) star uplink to Gateway Router (ID 1) is severed.
2. **Detection:** Failure Detection Engine flags `Device Offline` and `Device Unreachable`.
3. **Execution:** Autonomous Recovery Service inspects topology graph:
   - Node is identified as a star leaf endpoint.
   - NetworkX confirms no alternate physical redundant path exists.
4. **Honest Diagnosis:** Rerouting returns `viable: False, is_single_point_of_failure: True`.
5. **Outcome:** Status declared `FAILED`. Log record created honestly stating: *"No alternative route exists for Smart Meter 03. Single uplink to Gateway. Manual link servicing required."* No false recovery is declared.

---

## 8. Limitations & Simulation Scope

- **Prototype Scope:** NetGuardian AI is a local software-only research and demonstration prototype. All devices, routing tables, and failure events are simulated in SQLite and NetworkX.
- **No Physical Hardware:** The software does not control physical routers, switches, smart meters, or real electric power grid infrastructure.
- **Simulation Fidelity:** Network latency and packet loss are modeled mathematically. Rerouting modifies simulated graph weights and database connection records.
