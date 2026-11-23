# NetGuardian AI – Demonstration & Verification Guide

> **Tagline:** *Detect. Defend. Recover. Automatically.*  
> **Target Audience:** Evaluators, SOC Analysts, AI/ML Engineers, and Demonstrators.  
> **Scope:** Step-by-step instructions to demonstrate all core capabilities of NetGuardian AI.

---

## 1. System Launch

1. **Launch Both Services:**
   - On Windows: Run `start.bat` from the project root.
   - On Linux/macOS: Run `./start.sh` from the project root.
2. **Access the Application:**
   - Open your web browser and navigate to: **[http://localhost:3000](http://localhost:3000)**.
   - Verify the top navigation bar shows:
     - SOC Atomic Clock (UTC)
     - Core Network Health ($90.0\% - 100\%$)
     - Defcon Status (Defcon 5: Normal Readiness)
     - Mode Badge: `LIVE BACKEND ONLINE`

---

## 2. DEMO 1 – Normal Network Monitoring

**Objective:** Demonstrate baseline monitoring and verify that healthy network traffic does not generate false alarms.

1. **Navigate to "Network Monitor" (View 2):**
   - Click **Network Monitor** in the left sidebar.
   - Observe the 10 monitored BESCOM nodes:
     - Smart Meter Gateway (Router 01)
     - Security Firewall (Firewall 01)
     - Head-End System (Server 01)
     - Meter Data Management System (Server 02)
     - Backup Server (Server 03)
     - Smart Meters 01 through 05 (Yelahanka, Vijayanagar, Rajajinagar, Hebbal, Jayanagar).
   - Verify all healthy nodes display **Online** green status badges and baseline packet loss ($0.00\%$).
2. **Navigate to "Network Topology" (View 3):**
   - Observe the interactive SVG topology mesh.
   - Note the perimeter DMZ boundary, active mesh links, and animated packet flow lines.
3. **Verify AI Baseline via "Overview Dashboard" (View 1):**
   - Note the **Network Health** gauge displaying optimal percentage.
   - Active Threats count shows `0 ACTIVE` (or historical demonstration baseline).

---

## 3. DEMO 2 – AI Threat Detection & Alert Generation

**Objective:** Demonstrate the complete AI/ML pipeline converting anomalous traffic telemetry into classified threats, evidence-based explanations, and persistent security alerts.

1. **Navigate to "AI Threat Detection" (View 4):**
   - Click **AI Threat Detection** in the left sidebar.
   - Observe the cards displaying active/historical AI threat analyses.
2. **Inspect an Active Threat Vector:**
   - Locate an active critical threat (e.g. `Data Exfiltration via DNS`).
   - Notice:
     - **Anomaly Score:** e.g., `0.88` (Exceeds Isolation Forest threshold of $0.65$).
     - **Mathematical Baseline Deviation:** e.g., `4.8σ Outbound Spike`.
     - **Dynamic Explanation:** Plain-text description mathematically grounded in actual telemetry metrics.
     - **Recommended Action:** Non-destructive mitigation advisory.
3. **Trigger Threat Mitigation:**
   - Click the purple **Deploy AI Rule** (or **Mitigate Threat**) button on the threat card.
   - Watch the toast notification confirm: *"Deploying AI mitigation rule..."* followed by *"Threat successfully mitigated"*.
4. **Verify in "Security Alerts" (View 6):**
   - Click **Security Alerts** in the left sidebar.
   - Filter by status `RESOLVED` to confirm the incident was updated directly in SQLite.

---

## 4. DEMO 3 – Autonomous Self-Healing Recovery

**Objective:** Demonstrate automatic failure detection, alternative bypass calculation using NetworkX Dijkstra, and verified recovery on a redundant server node.

1. **Navigate to "Self-Healing Centre" (View 5):**
   - Click **Self-Healing Centre** in the left sidebar.
   - Observe the 7 KPI metric cards at the top:
     - Total Failures Detected
     - Active Failures
     - Isolated Devices
     - Recoveries Successful
     - Recoveries Failed
     - Recovery Success Rate (%)
     - Average Recovery Duration (s)
2. **Select Target Device:**
   - In the **Select Simulated Device** dropdown, choose:
     `Server 03 – Backup HES/MDMS Server (192.168.1.12)`
3. **Inject Simulated Fault:**
   - Click the red **Simulate Network Failure** button.
   - The diagnostic terminal immediately logs link severance and updates status.
4. **Trigger Live Failure Sweep:**
   - Click **Trigger Failure Detection**.
   - Terminal logs: `[ALERT] Active failures detected... Connection Failure on Device 4`.
5. **Calculate Redundant Bypass Path:**
   - Click **Find Alternative Route**.
   - Terminal logs: `[REROUTE_FOUND] Viable bypass path identified: Router 01 -> Server 01 -> Server 03`.
6. **Execute Autonomous Recovery:**
   - Click the green **Start Recovery** button.
   - Watch the terminal stream through all 9 autonomous steps:
     - `STEP 1: DETECTED`
     - `STEP 2: IDENTIFY CONNECTIONS`
     - `STEP 3: ASSESS SEVERITY`
     - `STEP 5: APPLY DYNAMIC REROUTE (Engaging standby link)`
     - `STEP 6: VERIFY CONNECTIVITY PROBE (Active edges & gateway reachability)`
     - `STEP 7-8: STATUS RECOVERED (Logged to recovery_logs)`
7. **Verify Post-Recovery State:**
   - Terminal displays: `Recovery successful: Target restored and connectivity verified.`
   - KPI metrics increment `Recoveries Successful` and recalculate success rate.

---

## 5. DEMO 4 – Recovery Failure on Single-Point-of-Failure (SPOF)

**Objective:** Demonstrate honest failure reporting when an endpoint loses its only physical uplink, ensuring the system never fabricates non-existent recovery.

1. **Stay in "Self-Healing Centre" (View 5):**
2. **Select Star Leaf Endpoint:**
   - In the device dropdown, select a smart meter with a single star uplink:
     `Smart Meter 03 – BES-SM-003 – Rajajinagar (192.168.1.22)`
3. **Inject Failure:**
   - Click **Simulate Network Failure**.
4. **Attempt Alternative Route Discovery:**
   - Click **Find Alternative Route**.
   - Notice the terminal output:
     `[NO_ALT_PATH] No alternative route exists in current topology mesh... Device is a single point of failure (SPOF) star leaf node.`
5. **Attempt Recovery:**
   - Click **Start Recovery**.
   - Watch the autonomous pipeline evaluate the topology:
     - Detects that Smart Meter 03 connects exclusively to the Gateway Router.
     - With the link severed, no bypass route exists.
     - Performs connectivity probe $\rightarrow$ Fails.
   - Terminal displays:
     `[FAILED] Autonomous recovery failed: No alternative route exists for Smart Meter 03. Single uplink to Gateway. Manual link servicing required.`
   - Toast notification appears: *"Recovery failed: Single point of failure. Manual intervention required."*
   - Audit record is saved in SQLite `recovery_logs` with `verification_status: 'FAILED'`.
   - The system **honestly reports failure** rather than declaring fake success!

---

## 6. Summary of Key Demonstration Commands

| Action | Control / Endpoint | Expected Output |
|---|---|---|
| Health Probe | `GET /api/health` | `HTTP 200 OK` (Flask operational, SQLite connected) |
| Live Dashboard | `GET /api/dashboard` | Computed KPIs from SQLite `devices` & `security_alerts` |
| Failure Detection | `POST /api/healing/detect` | Identified active incidents with severity & recommended actions |
| Dijkstra Reroute | `POST /api/recovery/find-route` | Shortest redundant path for core servers, honest SPOF for leaf meters |
| Autonomous Heal | `POST /api/recover` | 9-step recovery sequence with real connectivity verification probe |
| Device Quarantine | `POST /api/isolate` | Quarantines node with Critical Infrastructure Protection guard |
| Device Restore | `POST /api/restore` | Restores node to nominal baseline and reenables links |

---

> **Demonstration Tip:** Keep `http://localhost:3000` open in your main browser window. You can watch the Network Monitor, Topology Mesh, and Self-Healing Centre update in real-time as background actions are performed!
