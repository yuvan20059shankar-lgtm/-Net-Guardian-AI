# NetGuardian AI
### Tagline: Detect. Defend. Recover. Automatically.

Next-Generation Autonomous Cybersecurity Operations Centre (SOC) Dashboard & Incident Response Engine.

---

## 1. Project Architecture

```
NetGuardian-AI-ML/
│
├── frontend/
│   ├── index.html              # Main single-page SOC console application
│   ├── css/
│   │   └── style.css           # Master cyberpunk SOC dark stylesheet
│   ├── js/
│   │   ├── mock-data.js        # Centralized NetGuardianStore & localStorage state
│   │   ├── api.js              # Decoupled backend REST API integration client
│   │   ├── dashboard.js        # Overview Dashboard telemetry & KPI controller
│   │   ├── network.js          # 10-node monitored inventory controller
│   │   ├── topology.js         # Interactive SVG network mesh & particle engine
│   │   ├── threats.js          # AI Isolation Forest anomaly detection view
│   │   ├── recovery.js         # Self-Healing Centre & BGP failover simulator
│   │   ├── alerts.js           # Security advisory ledger & incident response
│   │   ├── analytics.js        # Historical Chart.js multi-range charts
│   │   └── app.js              # Application core, notifications, audio & routing
│   └── assets/                 # Graphics, icons and static assets
│
├── backend/
│   ├── app.py                  # Flask WSGI application factory & entrypoint
│   ├── config.py               # Environment & development configuration
│   ├── database.py             # SQLite connection management, schemas & initial seeders
│   ├── requirements.txt        # Python dependencies (Flask, Flask-CORS, python-dotenv, networkx)
│   ├── .env.example            # Environment variable template
│   ├── .env                    # Local development environment configuration
│   ├── verify_live.py          # Live HTTP integration test suite across all endpoints
│   │
│   ├── routes/
│   │   ├── __init__.py         # Blueprint exports
│   │   ├── health_routes.py    # Health check & SQLite diagnostic API (/api/health)
│   │   ├── device_routes.py    # Device management CRUD endpoints (/api/devices)
│   │   ├── dashboard_routes.py # Calculated dashboard metrics API (/api/dashboard)
│   │   ├── traffic_routes.py   # Traffic telemetry, topology & simulation control APIs
│   │   ├── alert_routes.py     # Security alerts CRUD, status lifecycle & summary APIs
│   │   └── recovery_routes.py  # Device isolation, restoration, and self-healing recovery APIs
│   │
│   ├── services/
│   │   ├── __init__.py
│   │   ├── device_service.py   # Business logic for device inventory operations
│   │   ├── network_simulator.py# NetworkX graph model, telemetry generator & pathfinding
│   │   ├── alert_service.py    # Security alert management, validation & KPI aggregation
│   │   ├── recovery_service.py # Quarantine isolation, restoration & 10-step self-healing
│   │   └── response_service.py # Standardized JSON envelope response formatting
│   │
│   ├── models/
│   │   └── __init__.py         # Data models and entity schemas
│   │
│   ├── data/
│   │   └── netguardian.db      # SQLite production & development database file
│   │
│   └── tests/
│       ├── __init__.py
│       ├── test_health.py      # Automated Flask client & SQLite health test suite (7 tests)
│       ├── test_devices.py     # Automated device CRUD & dashboard calculation test suite (12 tests)
│       ├── test_simulation.py  # NetworkX graph, simulation & traffic APIs test suite (16 tests)
│       └── test_recovery.py    # Security alerts, isolation & self-healing test suite (17 tests)
│
├── serve.js                    # Local Node.js static frontend web server
├── test_runner.js              # Automated frontend verification test runner
├── verify_all.js               # Comprehensive 12-item quality assurance audit
└── README.md                   # System documentation and execution guidelines
```

---

## 2. Technology Stack

- **Frontend:** HTML5, CSS3, Vanilla ES6 JavaScript, Chart.js, Lucide Icons.
- **Backend:** Python 3.11+, Flask 3.0.3, Flask-CORS 4.0.1, python-dotenv 1.0.1.
- **Networking & Graph Simulation:** NetworkX 3.3 (Graph theory, topology representation, Dijkstra shortest-path alternative routing).
- **Database:** SQLite 3 with WAL mode, parameterized queries, relational constraints, foreign keys, and indexes.

---

## 3. Computer Networking, Security & Resilience Concepts

NetGuardian AI simulates realistic enterprise network security and self-healing resilience:

### Security Incident Lifecycle
- **Severities:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- **Status Progression:** `ACTIVE` $\rightarrow$ `INVESTIGATING` $\rightarrow$ `MITIGATED` $\rightarrow$ `RESOLVED`.
- When an alert is resolved, `resolved_at` is timestamped automatically.

### Device Quarantine & Isolation Guard
- **Simulated Quarantine:** When a device exhibits hostile or abnormal activity, `POST /api/devices/<id>/isolate` marks its operational state as `suspicious` and severs all connected links (`status = 'inactive'`) in the SQLite database and NetworkX graph.
- **Infrastructure Protection Rule:** Core infrastructure (`Router 01` / `Firewall 01`) cannot be isolated through the general API to prevent complete network blackout.

### Autonomous Self-Healing Recovery (10-Step Pipeline)
When a network node suffers hardware failure or link severance:
1. **Target Verification:** Verifies the target device exists.
2. **Failure Confirmation:** Confirms device is offline (prevents duplicate recovery if already online).
3. **Link Identification:** Maps all affected inbound and outbound connections.
4. **NetworkX Pathfinding:** Prunes severed nodes/edges and searches for viable alternative routes via Dijkstra’s algorithm.
5. **Route Usability Check:** Validates that every intermediate node and connection in the candidate path is healthy.
6. **Simulated Reroute:** Activates failover standby links and dynamic bridges.
7. **Post-Reroute Graph Verification:** Verifies full connectivity in the NetworkX graph.
8. **State Transition:** Restores the device to `online` status and zeroes packet loss.
9. **Permanent Audit Logging:** Persists operation outcome (`VERIFIED`, `FAILED`) in `recovery_logs`.
10. **Result Dispatch:** Returns complete path and hop statistics.

> [!IMPORTANT]
> **No-Fake-Recovery Guarantee:** For single-point-of-failure (SPOF) endpoints such as leaf workstations or core routers where no redundant link exists, the self-healing engine transparently reports recovery failure (`verification_status: "FAILED"`). The system never fabricates an impossible route.

> [!NOTE]
> **Simulation Boundary:** All security alerts, network events, and recovery operations operate within a simulated local network environment. The system does not alter physical host network interfaces or claim real packet capture.

---

## 4. API Endpoints Reference

All endpoints return standardized JSON envelopes:

### System & Dashboard Endpoints
- `GET /api/health` — Backend system status, timestamp, and SQLite database connectivity diagnostic.
- `GET /api/dashboard` — Dynamically computed SOC metrics:
  - `total_devices`, `online_devices`, `offline_devices`, `suspicious_devices`, `network_health`
  - `active_security_alerts`, `critical_incidents`, `successful_recovery_count`, `failed_recovery_count`, `isolated_devices`

### Device Management Endpoints
- `GET /api/devices` — Fetch all 10 monitored network devices from SQLite.
- `GET /api/devices/<id>` — Retrieve detailed metadata for a single device asset.
- `POST /api/devices` — Register a new network asset (validates name, type, role, status, unique IP).
- `PUT /api/devices/<id>` — Full update of an existing device's metadata.
- `PATCH /api/devices/<id>/status` — Update device operational state (`online`, `offline`, `suspicious`).
- `DELETE /api/devices/<id>` — Remove a device from the database.

### Traffic Monitoring & Simulation Endpoints
- `GET /api/topology` — Return nodes and links from SQLite and NetworkX graph.
- `GET /api/network/summary` — Aggregate network totals (active/failed devices, links, bandwidth).
- `GET /api/network/connected/<device_id>` — Return neighbor devices directly linked to the node ID.
- `GET /api/traffic?limit=50` — Retrieve recent traffic telemetry log records.
- `GET /api/traffic/<device_id>?limit=30` — Retrieve historical traffic telemetry for a single device.
- `POST /api/simulation/start` — Start background telemetry generation loop (interval: 2.5s).
- `POST /api/simulation/stop` — Pause background telemetry generation loop.
- `GET /api/simulation/status` — Query whether the simulation engine is actively running.
- `POST /api/simulation/failure` — Inject device failure (`{"device_id": 4}`), sever links, and compute failover.
- `POST /api/simulation/restore` — Restore a device to operational online status.

### Security Alert Endpoints
- `GET /api/alerts` — Fetch all security alerts (supports `?severity=CRITICAL`, `?status=ACTIVE`, `limit`, `offset`).
- `GET /api/alerts/<alert_id>` — Retrieve single alert by numeric ID or code (e.g. `ALT-1001`).
- `POST /api/alerts` — Create security incident alert (validates device_id, severity, threat_type, description).
- `PATCH /api/alerts/<alert_id>/status` — Update alert lifecycle status (`ACTIVE`, `INVESTIGATING`, `MITIGATED`, `RESOLVED`).
- `GET /api/alerts/summary` — Summary of alert totals grouped by severity and status.

### Device Isolation & Self-Healing Recovery Endpoints
- `POST /api/devices/<device_id>/isolate` — Quarantine device, disable its connections (Router/Firewall protected).
- `POST /api/devices/<device_id>/restore` — Restore device, re-enable links, verify NetworkX graph.
- `POST /api/recovery/start` — Trigger 10-step self-healing recovery pipeline (`{"device_id": 4}`).
- `GET /api/recovery/history` — Retrieve recovery audit logs from SQLite.
- `GET /api/recovery/history/<recovery_id>` — Retrieve specific recovery record by ID or code (e.g. `REC-501`).

---

## 5. Running the Application

### A. Frontend (Port 3000)
Run the local HTTP server:
```bash
node serve.js
```
Access the dashboard at: **http://localhost:3000**

### B. Backend (Port 5000)
1. Open PowerShell and navigate to `backend/`:
   ```powershell
   cd backend
   ```
2. Activate Python virtual environment:
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```
3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
4. Start the Flask application:
   ```powershell
   python app.py
   ```

---

## 6. Running Automated Tests

### Backend Unit & Integration Tests (52 Tests Passing)
Execute all test suites covering health, device CRUD, NetworkX topology, pathfinding, simulation, security alerts, device isolation, and self-healing:
```powershell
cd backend
.\venv\Scripts\python.exe -m unittest discover tests -v
```

### Live HTTP Verification (12 Scenarios)
Verify all endpoints live against running Flask server:
```powershell
cd backend
.\venv\Scripts\python.exe verify_live.py
```

### Frontend Quality Assurance (12 Verification Categories)
Audit all frontend pages, router, reactive state, topology render, and incident resolution:
```bash
node verify_all.js
```
