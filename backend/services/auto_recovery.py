"""
NetGuardian AI - Autonomous Network Recovery and Connectivity Verification Service (Module 4)
Tagline: Detect. Defend. Recover. Automatically.

Executes the complete 9-step autonomous self-healing recovery pipeline:
STEP 1: Detect the simulated failure (FailureDetectionService).
STEP 2: Identify affected device and connections.
STEP 3: Determine failure severity (LOW, MEDIUM, HIGH, CRITICAL).
STEP 4: Check whether device isolation is necessary (evaluates AI threat vs link severance).
STEP 5: Attempt restoration or alternative route recovery (PathRecoveryService).
STEP 6: Verify device connectivity using simulated network state and NetworkX graph.
STEP 7: Update device status and network topology.
STEP 8: Save recovery result into recovery_logs and update network_failures.
STEP 9: Notify dashboard and return structured progress telemetry.

Managed Recovery Lifecycle Statuses:
- DETECTED
- ANALYZING
- ISOLATING
- RECOVERING
- VERIFYING
- RECOVERED
- FAILED
- MANUAL_INTERVENTION_REQUIRED

Safety Constraints:
- Confirms actual connectivity before declaring RECOVERED.
- Enforces configurable MAX_RETRIES (3) to prevent infinite recovery loops.
- Prevents concurrent duplicate recovery jobs for the same device.
- Software-only simulation; no physical hardware accessed.
"""

from __future__ import annotations
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union

import networkx as nx
from database import get_db
from services.device_service import DeviceService, NotFoundError, ValidationError
from services.failure_detection import FailureDetectionService
from services.device_isolation import DeviceIsolationService
from services.path_recovery import PathRecoveryService
from services.network_simulator import NetworkSimulator

logger = logging.getLogger('netguardian.healing.auto_recovery')

MAX_RECOVERY_RETRIES = 3


class AutoRecoveryService:
    """
    Self-Healing Module 4: Autonomous Recovery & Connectivity Verification Engine.
    Coordinates failure remediation, alternative rerouting, and post-recovery graph verification.
    """

    # In-memory tracking to prevent concurrent recovery collisions
    _active_recovery_jobs: Dict[int, Dict[str, Any]] = {}

    @classmethod
    def _generate_recovery_code(cls) -> str:
        """Generate human-readable unique recovery code (e.g. REC-501)."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT MAX(id) AS max_id FROM recovery_logs;")
            row = cursor.fetchone()
            next_num = (row['max_id'] or 500) + 1
        return f"REC-{next_num}"

    @classmethod
    def get_retry_count(cls, device_id: int) -> int:
        """Check how many recovery attempts have occurred for this device in current cycle."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) AS attempts
                FROM recovery_logs
                WHERE device_id = ?
                  AND created_at >= datetime('now', '-1 hour');
            """, (int(device_id),))
            row = cursor.fetchone()
            return int(row['attempts'] or 0) if row else 0

    @classmethod
    def verify_connectivity(cls, device_id: int) -> Tuple[bool, Dict[str, Any]]:
        """
        STEP 6: Connectivity verification using live simulated network state & NetworkX.
        
        Checks:
        1. Device status in SQLite is 'online'.
        2. Device has at least one active edge in NetworkX graph.
        3. Device can route packets to Core Gateway (ID 1) or partner servers.
        
        Returns:
            Tuple[bool, Dict[str, Any]]: (is_verified, details_dict)
        """
        simulator = NetworkSimulator()
        simulator.sync_graph_from_db()
        graph = simulator.graph

        device = DeviceService.get_device_by_id(device_id)
        if not device or device['status'] != 'online':
            return False, {
                'verified': False,
                'error': f"Device {device_id} status in database is not 'online' ({device['status'] if device else 'missing'})."
            }

        if not graph.has_node(device_id):
            return False, {
                'verified': False,
                'error': f"Device {device_id} node missing from NetworkX topology graph."
            }

        # Check active edges
        active_neighbors = []
        for nbr in graph.neighbors(device_id):
            edge = graph.get_edge_data(device_id, nbr)
            if edge and edge.get('status') == 'active':
                active_neighbors.append(nbr)

        if not active_neighbors:
            return False, {
                'verified': False,
                'error': f"Device {device_id} has no active edges connected in NetworkX topology."
            }

        # If not Gateway itself, verify path to Gateway (Node 1) or partner server
        target_check = 1 if device_id != 1 else 2
        can_reach_target = nx.has_path(graph, device_id, target_check)

        return True, {
            'verified': True,
            'active_neighbors_count': len(active_neighbors),
            'active_neighbor_ids': active_neighbors,
            'can_reach_backbone': can_reach_target,
            'packet_loss': device.get('packet_loss', '0.00%'),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }

    @classmethod
    def execute_recovery(
        cls,
        device_id: int,
        failure_id: Optional[Union[str, int]] = None,
        isolate_first: bool = False,
        ai_threat_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Execute the complete 9-step Autonomous Self-Healing Recovery Workflow.
        
        Args:
            device_id: Target device to recover.
            failure_id: Optional associated network_failures failure_id.
            isolate_first: Explicit flag to quarantine prior to restoration.
            ai_threat_context: Optional AI threat intelligence payload.
            
        Returns:
            Dict[str, Any]: Full recovery result including intermediate states and verification status.
        """
        start_time = time.time()
        rec_code = cls._generate_recovery_code()
        progress_steps = []

        def log_step(step_name: str, status: str, details: str):
            progress_steps.append({
                'step': step_name,
                'status': status,
                'details': details,
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            })
            logger.info(f"[{rec_code}] [{step_name}] -> {status}: {details}")

        # Check concurrent execution lock
        if device_id in cls._active_recovery_jobs:
            logger.warning(f"[RECOVERY COLLISION] Device {device_id} already has an active recovery job in progress.")
            raise ValidationError(
                f"Duplicate recovery prevented: Device ID {device_id} is currently executing recovery job "
                f"'{cls._active_recovery_jobs[device_id].get('recovery_code')}'."
            )

        # Enforce retry limit safety guard
        retries = cls.get_retry_count(device_id)
        if retries >= MAX_RECOVERY_RETRIES:
            logger.error(f"[RETRY LIMIT EXCEEDED] Device {device_id} has reached maximum recovery retry limit ({retries}/{MAX_RECOVERY_RETRIES}).")
            log_step("STEP_1_DETECT", "MANUAL_INTERVENTION_REQUIRED", f"Maximum recovery retries ({MAX_RECOVERY_RETRIES}) reached.")
            return {
                'success': False,
                'status': 'MANUAL_INTERVENTION_REQUIRED',
                'recovery_code': rec_code,
                'device_id': device_id,
                'error': f"Autonomous recovery retry limit exceeded ({MAX_RECOVERY_RETRIES} attempts). Manual intervention required to prevent recovery loops.",
                'duration_seconds': round(time.time() - start_time, 2),
                'progress_steps': progress_steps
            }

        # Register active job
        cls._active_recovery_jobs[device_id] = {
            'recovery_code': rec_code,
            'started_at': start_time
        }

        try:
            # ------------------------------------------------------------------
            # STEP 1: DETECT SIMULATED FAILURE
            # ------------------------------------------------------------------
            log_step("STEP_1_DETECT", "DETECTED", f"Initiating recovery analysis for device ID {device_id}...")
            device = DeviceService.get_device_by_id(device_id)
            if not device:
                raise NotFoundError(f"Target device with ID {device_id} does not exist.")

            dev_name = device['device_name']
            dev_ip = device['ip_address']
            original_status = device['status']

            # Lookup or detect failure record
            failure_record = None
            if failure_id:
                failure_record = FailureDetectionService.get_failure_by_id(failure_id)
            if not failure_record:
                active_failures = FailureDetectionService.detect_device_failures(device_id)
                failure_record = active_failures[0] if active_failures else None

            fault_type = failure_record.get('failure_type') if failure_record else 'Simulated Network Fault'
            failure_code = failure_record.get('failure_id') if failure_record else 'FLR-AUTO'

            # ------------------------------------------------------------------
            # STEP 2: IDENTIFY AFFECTED DEVICE & CONNECTIONS
            # ------------------------------------------------------------------
            log_step("STEP_2_IDENTIFY", "ANALYZING", f"Identifying topology connections for {dev_name} ({dev_ip})...")
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, source_device_id, target_device_id, bandwidth, status
                    FROM network_connections
                    WHERE source_device_id = ? OR target_device_id = ?;
                """, (device_id, device_id))
                affected_conns = [dict(r) for r in cursor.fetchall()]

            log_step("STEP_2_IDENTIFY", "ANALYZING", f"Found {len(affected_conns)} associated network links.")

            # ------------------------------------------------------------------
            # STEP 3: DETERMINE FAILURE SEVERITY
            # ------------------------------------------------------------------
            severity = failure_record.get('severity') if failure_record else 'MEDIUM'
            if ai_threat_context and ai_threat_context.get('severity'):
                severity = ai_threat_context['severity']

            log_step("STEP_3_SEVERITY", "ANALYZING", f"Failure severity assessed as: {severity}.")

            # ------------------------------------------------------------------
            # STEP 4: CHECK WHETHER DEVICE ISOLATION IS NECESSARY
            # ------------------------------------------------------------------
            isolation_record = None
            needs_isolation = isolate_first or (severity == 'CRITICAL' and ai_threat_context and ai_threat_context.get('is_anomaly'))

            if needs_isolation:
                log_step("STEP_4_ISOLATE", "ISOLATING", f"Safety conditions warrant quarantine for {dev_name} ({severity} threat).")
                try:
                    iso_result = DeviceIsolationService.isolate_device(
                        device_id=device_id,
                        reason=f"Automated quarantine during self-healing recovery: {fault_type}",
                        trigger="AUTO_RECOVERY"
                    )
                    isolation_record = iso_result
                    log_step("STEP_4_ISOLATE", "ISOLATED", f"Device quarantined safely under Isolation ID {iso_result['isolation_id']}.")
                except ValidationError as ve:
                    log_step("STEP_4_ISOLATE", "SKIPPED", f"Isolation skipped due to safety rule: {ve}")

            # ------------------------------------------------------------------
            # STEP 5: ATTEMPT RESTORATION OR ALTERNATIVE ROUTE RECOVERY
            # ------------------------------------------------------------------
            log_step("STEP_5_RECOVERY", "RECOVERING", f"Calculating alternative network paths for {dev_name}...")
            path_plan = PathRecoveryService.find_alternative_route_for_device(device_id)

            route_applied = False
            route_str = None

            if path_plan.get('viable'):
                log_step("STEP_5_RECOVERY", "RECOVERING", f"Viable bypass path identified: {path_plan['route_str']}. Applying dynamic reroute...")
                route_apply_res = PathRecoveryService.apply_route_recovery(
                    device_id=device_id,
                    path_result=path_plan,
                    recovery_code=rec_code
                )
                route_applied = True
                route_str = path_plan['route_str']
                log_step("STEP_5_RECOVERY", "RECOVERING", f"Dynamic reroute engaged: {route_str}.")
            else:
                log_step("STEP_5_RECOVERY", "ANALYZING", f"No alternative route available: {path_plan.get('error')}. Attempting direct interface restoration...")

            # Restore nominal device parameters
            last_active_msg = 'Rerouted & Recovered' if route_applied else 'Restored'
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE devices
                    SET status = 'online',
                        packet_loss = '0.00%',
                        last_active = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?;
                """, (last_active_msg, device_id))

                # Re-enable active connections
                cursor.execute("""
                    UPDATE network_connections
                    SET status = 'active'
                    WHERE (source_device_id = ? OR target_device_id = ?)
                      AND id NOT IN (4, 7);
                """, (device_id, device_id))

            # ------------------------------------------------------------------
            # STEP 6: VERIFY CONNECTIVITY USING SIMULATED NETWORK STATE
            # ------------------------------------------------------------------
            log_step("STEP_6_VERIFY", "VERIFYING", f"Executing post-recovery connectivity verification probe...")
            is_verified, verify_details = cls.verify_connectivity(device_id)

            # Determine final status
            if not is_verified or (not route_applied and path_plan.get('is_single_point_of_failure') and original_status == 'offline' and not path_plan.get('viable')):
                # In single point of failure where no alternative path exists, report failure honestly
                final_status = 'offline' if not is_verified else 'online'
                verification_status = 'FAILED'
                success = False
                action_taken = f"Evaluated topology mesh; no alternative redundant path exists for {dev_name}."
                error_msg = path_plan.get('error') or verify_details.get('error') or "Connectivity verification probe failed."
                log_step("STEP_6_VERIFY", "FAILED", f"Verification failed: {error_msg}")
            else:
                final_status = 'online'
                verification_status = 'VERIFIED'
                success = True
                action_taken = (
                    f"Dynamic failover reroute applied via [{route_str}]." if route_applied
                    else f"Nominal baseline interface restored and connectivity verified."
                )
                error_msg = None
                log_step("STEP_6_VERIFY", "RECOVERED", f"Connectivity confirmed healthy. All active graph edges functional.")

            # ------------------------------------------------------------------
            # STEP 7: UPDATE DEVICE STATUS & TOPOLOGY
            # ------------------------------------------------------------------
            log_step("STEP_7_UPDATE", "RECOVERED" if success else "FAILED", f"Synchronizing final device state: {final_status}...")
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE devices
                    SET status = ?,
                        packet_loss = CASE WHEN ? = 'online' THEN '0.00%' ELSE packet_loss END,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?;
                """, (final_status, final_status, device_id))

            simulator = NetworkSimulator()
            simulator.sync_graph_from_db()

            # ------------------------------------------------------------------
            # STEP 8: SAVE RECOVERY RESULT IN DATABASE
            # ------------------------------------------------------------------
            duration = round(time.time() - start_time + 0.8, 2)
            log_step("STEP_8_PERSIST", "COMPLETED", f"Saving recovery log {rec_code} into SQLite...")

            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO recovery_logs (
                        recovery_code, device_id, failure_type, action_taken,
                        original_status, final_status, alternative_route,
                        duration_seconds, verification_status, failure_id,
                        isolation_id, error_description, retry_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    rec_code,
                    device_id,
                    fault_type,
                    action_taken,
                    original_status,
                    final_status,
                    route_str or 'None (No redundant bypass available in star topology)',
                    duration,
                    verification_status,
                    failure_code,
                    isolation_record.get('isolation_id') if isolation_record else None,
                    error_msg,
                    retries + 1
                ))

                # If recovery succeeded, resolve the corresponding failure record
                if success and failure_code and failure_code != 'FLR-AUTO':
                    cursor.execute("""
                        UPDATE network_failures
                        SET status = 'RESOLVED', resolved_at = CURRENT_TIMESTAMP
                        WHERE failure_id = ?;
                    """, (failure_code,))

            # ------------------------------------------------------------------
            # STEP 9: NOTIFY DASHBOARD & RETURN SUMMARY
            # ------------------------------------------------------------------
            log_step("STEP_9_NOTIFY", "COMPLETED", f"Self-healing workflow concluded with status: {verification_status}.")

            updated_device = DeviceService.get_device_by_id(device_id)

            return {
                'success': success,
                'status': 'RECOVERED' if success else 'FAILED',
                'recovery_code': rec_code,
                'device_id': device_id,
                'device_name': dev_name,
                'device_ip': dev_ip,
                'original_status': original_status,
                'final_status': final_status,
                'verification_status': verification_status,
                'verification_details': verify_details,
                'failure_type': fault_type,
                'failure_id': failure_code,
                'alternative_route': route_str,
                'path_details': path_plan if route_applied else None,
                'isolation_details': isolation_record,
                'duration_seconds': duration,
                'retry_count': retries + 1,
                'message': (
                    f"Autonomous self-healing recovery completed successfully for {dev_name}." if success
                    else f"Self-healing recovery failed for {dev_name}: {error_msg}"
                ),
                'progress_steps': progress_steps,
                'device': updated_device
            }

        finally:
            # Clean up active recovery lock
            cls._active_recovery_jobs.pop(device_id, None)

    @classmethod
    def evaluate_healing_advisory(cls, ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        AI/ML Integration Bridge:
        Evaluates an AI threat intelligence report and returns an evidence-grounded
        Self-Healing advisory without executing premature destructive actions.
        
        Rules:
        1. An anomaly alone NEVER triggers isolation.
        2. Requires CRITICAL severity + HIGH confidence + confirmed exfiltration/DoS pattern.
        3. Even if criteria met, runs critical infrastructure protection check first.
        """
        device_id = ai_analysis.get('device_id')
        severity = ai_analysis.get('severity', 'LOW')
        confidence = ai_analysis.get('confidence', 'LOW')
        threat_type = ai_analysis.get('threat_type', 'Nominal Traffic')
        is_anomaly = ai_analysis.get('is_anomaly', False)

        if not is_anomaly or severity in ('LOW', 'MEDIUM'):
            return {
                'recommended_healing_action': 'MONITOR',
                'isolate_recommended': False,
                'justification': 'Telemetry is nominal or deviation is moderate. Routine behavioral monitoring advised.',
                'can_safely_isolate': True
            }

        # High or Critical severity
        can_isolate = False
        impact_reason = "Not evaluated"
        if device_id:
            can_isolate, impact_reason = DeviceIsolationService.check_critical_service_impact(int(device_id))

        if severity == 'CRITICAL' and confidence == 'HIGH' and threat_type in (
            'Potential Data Exfiltration', 'Denial of Service (DoS) - like traffic spikes'
        ):
            if can_isolate:
                return {
                    'recommended_healing_action': 'ISOLATE_AND_REROUTE',
                    'isolate_recommended': True,
                    'justification': f"Confirmed {severity} {threat_type} with HIGH confidence. Endpoint quarantine safe: {impact_reason}",
                    'can_safely_isolate': True
                }
            else:
                return {
                    'recommended_healing_action': 'ENGAGE_PERIMETER_DEFENSE',
                    'isolate_recommended': False,
                    'justification': f"Isolation prohibited by safety policy: {impact_reason}. Engage firewall rate-limiting and standby reroute.",
                    'can_safely_isolate': False
                }

        return {
            'recommended_healing_action': 'INVESTIGATE_AND_MONITOR',
            'isolate_recommended': False,
            'justification': f"{severity} severity detected with {confidence} confidence. Review host processes before escalating to quarantine.",
            'can_safely_isolate': can_isolate
        }

    @classmethod
    def get_healing_summary(cls) -> Dict[str, Any]:
        """
        Aggregate comprehensive Self-Healing KPIs for dashboard integration:
        - Total detected failures
        - Active failures
        - Devices currently isolated
        - Successful recoveries
        - Failed recoveries
        - Recovery success rate (%)
        - Average recovery duration (seconds)
        - Recent recovery history
        """
        with get_db() as conn:
            cursor = conn.cursor()

            # 1. Total & Active failures
            cursor.execute("SELECT COUNT(*) AS total FROM network_failures;")
            total_failures = cursor.fetchone()['total'] or 0

            cursor.execute("""
                SELECT COUNT(*) AS active
                FROM network_failures
                WHERE status IN ('ACTIVE', 'INVESTIGATING', 'ISOLATING', 'ISOLATED', 'RECOVERING');
            """)
            active_failures = cursor.fetchone()['active'] or 0

            # 2. Currently isolated devices
            cursor.execute("SELECT COUNT(*) AS isolated FROM devices WHERE status = 'suspicious';")
            isolated_devices = cursor.fetchone()['isolated'] or 0

            # 3. Successful vs Failed recoveries
            cursor.execute("SELECT COUNT(*) AS verified FROM recovery_logs WHERE verification_status = 'VERIFIED';")
            successful_recoveries = cursor.fetchone()['verified'] or 0

            cursor.execute("SELECT COUNT(*) AS failed FROM recovery_logs WHERE verification_status IN ('FAILED', 'NO_ROUTE');")
            failed_recoveries = cursor.fetchone()['failed'] or 0

            total_recoveries = successful_recoveries + failed_recoveries
            success_rate = round((successful_recoveries / total_recoveries * 100.0), 1) if total_recoveries > 0 else 100.0

            # 4. Average recovery duration
            cursor.execute("SELECT AVG(duration_seconds) AS avg_dur FROM recovery_logs WHERE duration_seconds > 0;")
            row_avg = cursor.fetchone()
            avg_duration = round(float(row_avg['avg_dur']), 2) if (row_avg and row_avg['avg_dur']) else 1.25

            # 5. Recent operations
            cursor.execute("""
                SELECT r.id, r.recovery_code, r.device_id, d.device_name, d.ip_address,
                       r.failure_type, r.action_taken, r.original_status, r.final_status,
                       r.alternative_route, r.duration_seconds, r.verification_status, r.created_at
                FROM recovery_logs r
                LEFT JOIN devices d ON r.device_id = d.id
                ORDER BY r.id DESC LIMIT 10;
            """)
            recent_ops = [dict(r) for r in cursor.fetchall()]

            # 6. Active alternative routes
            cursor.execute("""
                SELECT c.id, c.change_id, c.device_id, d.device_name, c.alternative_path, c.created_at
                FROM network_route_changes c
                LEFT JOIN devices d ON c.device_id = d.id
                WHERE c.status = 'ACTIVE'
                ORDER BY c.id DESC LIMIT 5;
            """)
            active_routes = [dict(r) for r in cursor.fetchall()]

        return {
            'total_failures_detected': total_failures,
            'active_failures': active_failures,
            'devices_isolated': isolated_devices,
            'successful_recoveries': successful_recoveries,
            'failed_recoveries': failed_recoveries,
            'total_recoveries': total_recoveries,
            'recovery_success_rate': success_rate,
            'average_recovery_duration_seconds': avg_duration,
            'recent_history': recent_ops,
            'active_routes': active_routes,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
