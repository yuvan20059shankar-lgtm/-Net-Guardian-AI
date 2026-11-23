"""
NetGuardian AI - Self-Healing Network REST API Blueprint (Module 5)
Tagline: Detect. Defend. Recover. Automatically.

Provides RESTful endpoints for the Self-Healing Centre:
- GET  /api/healing/status
- GET  /api/healing/failures
- GET  /api/healing/failures/<failure_id>
- POST /api/healing/detect
- POST /api/healing/simulate-failure
- POST /api/healing/isolate/<device_id>
- POST /api/healing/restore/<device_id>
- POST /api/healing/recover/<failure_id>
- GET  /api/healing/history
- GET  /api/healing/history/<recovery_id>
- GET  /api/healing/topology
- GET  /api/healing/summary
"""

import logging
from flask import Blueprint, request, jsonify

from services.failure_detection import FailureDetectionService
from services.device_isolation import DeviceIsolationService
from services.path_recovery import PathRecoveryService
from services.auto_recovery import AutoRecoveryService
from services.device_service import DeviceService, NotFoundError, ValidationError
from services.network_simulator import NetworkSimulator
from services.response_service import success_response, error_response

logger = logging.getLogger('netguardian.healing.routes')

healing_bp = Blueprint('healing', __name__, url_prefix='/api/healing')


# ------------------------------------------------------------------------------
# 1. STATUS & KPI SUMMARY
# ------------------------------------------------------------------------------

@healing_bp.route('/status', methods=['GET'])
def get_healing_status():
    """
    GET /api/healing/status
    High-level operational health of the Self-Healing Engine.
    """
    try:
        summary = AutoRecoveryService.get_healing_summary()
        return success_response(
            data={
                'engine_status': 'OPERATIONAL',
                'backup_cluster_status': 'STANDBY_READY',
                'active_failures_count': summary['active_failures'],
                'isolated_devices_count': summary['devices_isolated'],
                'recovery_success_rate': summary['recovery_success_rate'],
                'timestamp': summary['timestamp']
            },
            message="Self-Healing engine status retrieved successfully",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error fetching healing status: {e}", exc_info=True)
        return error_response(message="Failed to retrieve self-healing status.", status_code=500)


@healing_bp.route('/summary', methods=['GET'])
def get_healing_summary():
    """
    GET /api/healing/summary
    Comprehensive KPIs, statistics, and recent recovery operations for the dashboard.
    """
    try:
        summary = AutoRecoveryService.get_healing_summary()
        return success_response(
            data=summary,
            message="Self-healing dashboard summary retrieved successfully",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error fetching healing summary: {e}", exc_info=True)
        return error_response(message="Failed to retrieve self-healing summary.", status_code=500)


# ------------------------------------------------------------------------------
# 2. FAILURE DETECTION & MANAGEMENT
# ------------------------------------------------------------------------------

@healing_bp.route('/detect', methods=['POST'])
def trigger_failure_detection():
    """
    POST /api/healing/detect
    Triggers a live sweep across the simulated network to identify active failures.
    Optional payload: {"device_id": 4} to inspect a specific node.
    """
    try:
        payload = request.get_json(silent=True) or {}
        raw_dev_id = payload.get('device_id') or payload.get('deviceId')

        if raw_dev_id is not None:
            parsed_id = DeviceService.parse_device_id(raw_dev_id)
            if parsed_id is None:
                return error_response(message=f"Invalid device ID: '{raw_dev_id}'", status_code=400)
            failures = FailureDetectionService.detect_device_failures(parsed_id)
        else:
            failures = FailureDetectionService.detect_all_failures()

        return success_response(
            data={
                'detected_failures_count': len(failures),
                'failures': failures
            },
            message=f"Failure detection sweep complete. Found {len(failures)} active incident(s).",
            status_code=200
        )
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error executing failure detection: {e}", exc_info=True)
        return error_response(message="Failure detection sweep failed.", status_code=500)


@healing_bp.route('/failures', methods=['GET'])
def get_failures():
    """
    GET /api/healing/failures
    Lists simulated failures. Query param ?active_only=true (default: true).
    """
    try:
        active_only = request.args.get('active_only', 'true').lower() == 'true'
        if active_only:
            failures = FailureDetectionService.get_active_failures()
        else:
            failures = FailureDetectionService.get_all_failures()

        return success_response(
            data={
                'count': len(failures),
                'failures': failures
            },
            message="Failures retrieved successfully",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error retrieving failures: {e}", exc_info=True)
        return error_response(message="Failed to retrieve failure records.", status_code=500)


@healing_bp.route('/failures/<failure_id>', methods=['GET'])
def get_failure_by_id(failure_id):
    """
    GET /api/healing/failures/<failure_id>
    Lookup a specific failure record by numeric ID or code (e.g. 'FLR-1001').
    """
    try:
        failure = FailureDetectionService.get_failure_by_id(failure_id)
        if not failure:
            return error_response(message=f"Failure record '{failure_id}' not found.", status_code=404)

        return success_response(
            data=failure,
            message="Failure record retrieved successfully",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error fetching failure {failure_id}: {e}", exc_info=True)
        return error_response(message="Failed to fetch failure details.", status_code=500)


@healing_bp.route('/simulate-failure', methods=['POST'])
def simulate_failure():
    """
    POST /api/healing/simulate-failure
    Simulates sudden fault or link severance on a device:
    Payload: {"device_id": 4} or {"deviceId": "dev-4"}
    """
    try:
        payload = request.get_json(silent=True) or {}
        raw_id = payload.get('device_id') or payload.get('deviceId')
        if raw_id is None:
            return error_response(message="Missing required field 'device_id'.", status_code=400)

        device_id = DeviceService.parse_device_id(raw_id)
        if device_id is None:
            return error_response(message=f"Invalid device ID format: '{raw_id}'", status_code=400)

        simulator = NetworkSimulator()
        sim_res = simulator.simulate_device_failure(device_id)

        # Trigger failure detection immediately so incident is registered
        detected = FailureDetectionService.detect_device_failures(device_id)

        return success_response(
            data={
                'simulation': sim_res,
                'detected_failures': detected
            },
            message=f"Simulated failure successfully injected on device {device_id}.",
            status_code=200
        )
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error injecting failure: {e}", exc_info=True)
        return error_response(message="Failed to inject simulated failure.", status_code=500)


# ------------------------------------------------------------------------------
# 3. DEVICE ISOLATION & RESTORATION
# ------------------------------------------------------------------------------

@healing_bp.route('/isolate/<device_id>', methods=['POST'])
def isolate_device(device_id):
    """
    POST /api/healing/isolate/<device_id>
    Quarantines a simulated device with critical service impact verification.
    """
    try:
        parsed_id = DeviceService.parse_device_id(device_id)
        if parsed_id is None:
            return error_response(message=f"Invalid device ID format: '{device_id}'", status_code=400)

        payload = request.get_json(silent=True) or {}
        reason = payload.get('reason', 'Security threat quarantine')
        force = payload.get('force', False)

        result = DeviceIsolationService.isolate_device(
            device_id=parsed_id,
            reason=reason,
            trigger="API_MANUAL",
            force=force
        )

        return success_response(
            data=result,
            message=f"Device {device_id} successfully isolated from simulated network.",
            status_code=200
        )
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error isolating device {device_id}: {e}", exc_info=True)
        return error_response(message=f"Failed to isolate device {device_id}.", status_code=500)


@healing_bp.route('/restore/<device_id>', methods=['POST'])
def restore_device(device_id):
    """
    POST /api/healing/restore/<device_id>
    Restores an isolated or offline simulated device back to operational online state.
    """
    try:
        parsed_id = DeviceService.parse_device_id(device_id)
        if parsed_id is None:
            return error_response(message=f"Invalid device ID format: '{device_id}'", status_code=400)

        payload = request.get_json(silent=True) or {}
        reason = payload.get('reason', 'Authorized manual restoration')

        result = DeviceIsolationService.restore_device(device_id=parsed_id, reason=reason)

        return success_response(
            data=result,
            message=f"Device {device_id} restored to operational state and verified.",
            status_code=200
        )
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error restoring device {device_id}: {e}", exc_info=True)
        return error_response(message=f"Failed to restore device {device_id}.", status_code=500)


# ------------------------------------------------------------------------------
# 4. AUTONOMOUS RECOVERY
# ------------------------------------------------------------------------------

@healing_bp.route('/recover/<target_id>', methods=['POST'])
def recover_failure_or_device(target_id):
    """
    POST /api/healing/recover/<target_id>
    Executes the 9-step autonomous self-healing recovery workflow.
    <target_id> can be a failure_id ('FLR-1001') or device_id (4 or 'dev-4').
    """
    try:
        # Determine whether target_id is a failure_id or device_id
        dev_id = None
        f_id = None

        if str(target_id).upper().startswith('FLR-'):
            f_id = str(target_id).upper()
            f_record = FailureDetectionService.get_failure_by_id(f_id)
            if not f_record:
                return error_response(message=f"Failure record '{f_id}' not found.", status_code=404)
            dev_id = f_record['device_id']
        else:
            dev_id = DeviceService.parse_device_id(target_id)
            if dev_id is None:
                return error_response(message=f"Invalid failure or device ID: '{target_id}'", status_code=400)

        payload = request.get_json(silent=True) or {}
        isolate_first = payload.get('isolate_first', False)
        ai_context = payload.get('ai_context')

        result = AutoRecoveryService.execute_recovery(
            device_id=dev_id,
            failure_id=f_id,
            isolate_first=isolate_first,
            ai_threat_context=ai_context
        )

        status_code = 200
        return success_response(
            data=result,
            message=result.get('message', 'Self-healing recovery sequence completed.'),
            status_code=status_code
        )
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error executing recovery on {target_id}: {e}", exc_info=True)
        return error_response(message="Autonomous recovery execution failed.", status_code=500)


# ------------------------------------------------------------------------------
# 5. RECOVERY HISTORY & TOPOLOGY
# ------------------------------------------------------------------------------

@healing_bp.route('/history', methods=['GET'])
def get_recovery_history():
    """
    GET /api/healing/history
    Retrieve log records of autonomous self-healing recovery operations.
    """
    try:
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)

        from services.recovery_service import RecoveryService
        history = RecoveryService.get_recovery_history(limit=limit, offset=offset)

        return success_response(
            data={
                'count': len(history),
                'history': history
            },
            message=f"Retrieved {len(history)} recovery operation records.",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error retrieving recovery history: {e}", exc_info=True)
        return error_response(message="Failed to retrieve recovery history.", status_code=500)


@healing_bp.route('/history/<recovery_id>', methods=['GET'])
def get_recovery_by_id(recovery_id):
    """
    GET /api/healing/history/<recovery_id>
    Retrieve a specific recovery record by numeric ID or code (e.g. REC-501).
    """
    try:
        from services.recovery_service import RecoveryService
        record = RecoveryService.get_recovery_by_id(recovery_id)
        if not record:
            return error_response(message=f"Recovery record '{recovery_id}' not found.", status_code=404)

        return success_response(
            data=record,
            message=f"Retrieved recovery record '{recovery_id}'.",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error fetching recovery {recovery_id}: {e}", exc_info=True)
        return error_response(message="Failed to retrieve recovery details.", status_code=500)


@healing_bp.route('/topology', methods=['GET'])
def get_healing_topology():
    """
    GET /api/healing/topology
    Retrieve simulated NetworkX topology with live link states and active failover routes.
    """
    try:
        simulator = NetworkSimulator()
        topology = simulator.get_topology()
        active_routes = PathRecoveryService.get_route_changes_history(limit=5)

        return success_response(
            data={
                'nodes': topology['nodes'],
                'connections': topology['connections'],
                'active_route_changes': active_routes
            },
            message="Self-healing network topology retrieved successfully",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error fetching healing topology: {e}", exc_info=True)
        return error_response(message="Failed to retrieve healing topology.", status_code=500)
