"""
NetGuardian AI - Device Isolation & Self-Healing Recovery Blueprint Routes
Provides endpoints for quarantining suspicious devices, restoring connectivity,
executing automated self-healing failover recovery, and querying recovery history.
"""

import logging
from flask import Blueprint, request, jsonify
from services.recovery_service import RecoveryService
from services.device_service import DeviceService, ValidationError, NotFoundError
from services.response_service import error_response

logger = logging.getLogger('netguardian.recovery_routes')

recovery_bp = Blueprint('recovery', __name__, url_prefix='/api')


@recovery_bp.route('/devices/<int:device_id>/isolate', methods=['POST'])
@recovery_bp.route('/devices/<device_id>/isolate', methods=['POST'])
def isolate_device(device_id):
    """
    POST /api/devices/<device_id>/isolate
    Isolates a simulated device from the network:
    - Sets device status = 'suspicious'
    - Disables all active network connections
    - Enforces safety guard on core infrastructure (Router 01 / Firewall 01)
    """
    try:
        parsed_id = DeviceService.parse_device_id(device_id)
        if parsed_id is None:
            return error_response(message=f"Invalid device ID format: '{device_id}'", status_code=400)

        result = RecoveryService.isolate_device(parsed_id)
        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Device {device_id} successfully quarantined and isolated.",
            "device": result['device'],
            "connections": result['connections'],
            "data": result
        }), 200
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error isolating device {device_id}: {e}", exc_info=True)
        return error_response(message=f"Failed to isolate device {device_id}.", status_code=500)


@recovery_bp.route('/isolate', methods=['POST'])
def isolate_device_body():
    """
    POST /api/isolate
    Alias endpoint for frontend compatibility (reads deviceId / device_id from body).
    """
    payload = request.get_json(silent=True) or {}
    raw_id = payload.get('deviceId') or payload.get('device_id')
    if not raw_id:
        return error_response(message="Missing required field 'deviceId' in JSON body.", status_code=400)
    return isolate_device(raw_id)


@recovery_bp.route('/devices/<int:device_id>/restore', methods=['POST'])
@recovery_bp.route('/devices/<device_id>/restore', methods=['POST'])
def restore_device(device_id):
    """
    POST /api/devices/<device_id>/restore
    Restores an isolated or offline device back to operational online state:
    - Re-enables eligible connection links
    - Verifies connectivity in NetworkX graph
    - Does not report success if restoration fails
    """
    try:
        parsed_id = DeviceService.parse_device_id(device_id)
        if parsed_id is None:
            return error_response(message=f"Invalid device ID format: '{device_id}'", status_code=400)

        result = RecoveryService.restore_device(parsed_id)
        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Device {device_id} restored to operational state and connectivity verified.",
            "device": result['device'],
            "verified": result['verified'],
            "connections": result['connections'],
            "data": result
        }), 200
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error restoring device {device_id}: {e}", exc_info=True)
        return error_response(message=f"Failed to restore device {device_id}.", status_code=500)


@recovery_bp.route('/restore', methods=['POST'])
def restore_device_body():
    """
    POST /api/restore
    Alias endpoint for frontend compatibility (reads deviceId / device_id from body).
    """
    payload = request.get_json(silent=True) or {}
    raw_id = payload.get('deviceId') or payload.get('device_id')
    if not raw_id:
        return error_response(message="Missing required field 'deviceId' in JSON body.", status_code=400)
    return restore_device(raw_id)


@recovery_bp.route('/recovery/start', methods=['POST'])
@recovery_bp.route('/recover', methods=['POST'])
def start_self_healing_recovery():
    """
    POST /api/recovery/start (or POST /api/recover)
    Initiates 10-step autonomous self-healing recovery pipeline.
    Payload:
    {
        "device_id": 4
    }
    """
    try:
        payload = request.get_json(silent=True) or {}
        raw_id = payload.get('device_id') or payload.get('deviceId')
        if raw_id is None:
            return error_response(message="Missing required field: 'device_id'", status_code=400)

        device_id = DeviceService.parse_device_id(raw_id)
        if device_id is None:
            return error_response(message="Field 'device_id' must be a valid integer or 'dev-X' format.", status_code=400)

        result = RecoveryService.execute_self_healing_recovery(device_id)

        # If recovery failed because no alternative route exists
        if not result.get('success', False):
            return jsonify({
                "status": "failed",
                "success": False,
                "message": result.get('message', 'Recovery failed: No alternative route exists.'),
                **result,
                "data": result
            }), 200

        return jsonify({
            "status": "success",
            "success": True,
            "message": result.get('message', 'Self-healing recovery completed successfully.'),
            **result,
            "data": result
        }), 200
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error executing self-healing recovery: {e}", exc_info=True)
        return error_response(message="Self-healing recovery execution failed.", status_code=500)


@recovery_bp.route('/recovery/history', methods=['GET'])
@recovery_bp.route('/history', methods=['GET'])
def get_recovery_history():
    """
    GET /api/recovery/history (or GET /api/history)
    Retrieve log records of autonomous self-healing and rerouting operations.
    """
    try:
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)

        history = RecoveryService.get_recovery_history(limit=limit, offset=offset)
        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Successfully retrieved {len(history)} recovery operation records.",
            "count": len(history),
            "history": history,
            "data": history
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving recovery history: {e}", exc_info=True)
        return error_response(message="Failed to retrieve recovery history.", status_code=500)


@recovery_bp.route('/recovery/status', methods=['GET'])
def get_recovery_status():
    """
    GET /api/recovery/status
    Query high-level self-healing status for frontend store synchronization.
    """
    try:
        history = RecoveryService.get_recovery_history(limit=5)
        return jsonify({
            "status": "success",
            "success": True,
            "backup_server_status": "STANDBY_READY",
            "recent_operations": history
        }), 200
    except Exception as e:
        logger.error(f"Error getting recovery status: {e}", exc_info=True)
        return error_response(message="Failed to retrieve recovery status.", status_code=500)


@recovery_bp.route('/recovery/history/<recovery_id>', methods=['GET'])
def get_recovery_by_id(recovery_id):
    """
    GET /api/recovery/history/<recovery_id>
    Retrieve a specific recovery record by numeric ID or alphanumeric code (e.g. REC-501).
    """
    try:
        record = RecoveryService.get_recovery_by_id(recovery_id)
        if not record:
            return error_response(message=f"Recovery record '{recovery_id}' not found.", status_code=404)

        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Retrieved recovery record '{recovery_id}'.",
            "record": record,
            "data": record
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving recovery record {recovery_id}: {e}", exc_info=True)
        return error_response(message=f"Failed to retrieve recovery record '{recovery_id}'.", status_code=500)


@recovery_bp.route('/recovery/find-route', methods=['POST'])
def find_alternative_route():
    """
    POST /api/recovery/find-route
    Calculates alternative failover route bypassing failed node.
    Payload: {"deviceId": "dev-4"} or {"device_id": 4}
    """
    try:
        from services.path_recovery import PathRecoveryService
        payload = request.get_json(silent=True) or {}
        raw_id = payload.get('deviceId') or payload.get('device_id')
        if raw_id is None:
            return error_response(message="Missing required field 'deviceId'.", status_code=400)

        device_id = DeviceService.parse_device_id(raw_id)
        if device_id is None:
            return error_response(message=f"Invalid device ID format: '{raw_id}'", status_code=400)

        plan = PathRecoveryService.find_alternative_route_for_device(device_id)
        return jsonify(plan), 200
    except Exception as e:
        logger.error(f"Error finding alternative route: {e}", exc_info=True)
        return error_response(message="Failed to compute alternative route.", status_code=500)


@recovery_bp.route('/simulate/failure', methods=['POST'])
def simulate_failure_legacy():
    """
    POST /api/simulate/failure
    Simulate device failure (legacy endpoint compatibility).
    """
    try:
        from services.network_simulator import NetworkSimulator
        from services.failure_detection import FailureDetectionService
        payload = request.get_json(silent=True) or {}
        raw_id = payload.get('deviceId') or payload.get('device_id')
        if raw_id is None:
            return error_response(message="Missing required field 'deviceId'.", status_code=400)

        device_id = DeviceService.parse_device_id(raw_id)
        if device_id is None:
            return error_response(message=f"Invalid device ID format: '{raw_id}'", status_code=400)

        simulator = NetworkSimulator()
        sim_res = simulator.simulate_device_failure(device_id)
        FailureDetectionService.detect_device_failures(device_id)

        device = DeviceService.get_device_by_id(device_id)
        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Simulated failure successfully injected on {device['device_name']}.",
            "device": device,
            "simulation": sim_res
        }), 200
    except Exception as e:
        logger.error(f"Error simulating failure: {e}", exc_info=True)
        return error_response(message="Failed to simulate failure.", status_code=500)
