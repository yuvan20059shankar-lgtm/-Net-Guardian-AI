"""
NetGuardian AI - Traffic Monitoring & Network Simulation Blueprint Routes
Handles network topology, real-time traffic telemetry, and simulation control.
"""

import logging
from flask import Blueprint, request, jsonify
from services.network_simulator import NetworkSimulator
from services.device_service import DeviceService
from services.response_service import error_response

logger = logging.getLogger('netguardian.traffic_routes')

traffic_bp = Blueprint('traffic', __name__, url_prefix='/api')
simulator = NetworkSimulator()


@traffic_bp.route('/traffic', methods=['GET'])
def get_recent_traffic():
    """
    GET /api/traffic
    Retrieve the most recent traffic telemetry logs across all monitored devices.
    Optional query parameter:
    - limit: int (default 50, max 200)
    """
    try:
        limit = request.args.get('limit', 50, type=int)
        limit = max(1, min(limit, 200))
        
        logs = simulator.get_recent_traffic(limit=limit)
        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Retrieved {len(logs)} recent traffic telemetry records.",
            "count": len(logs),
            "traffic": logs,
            "data": logs
        }), 200
    except Exception as e:
        logger.error(f"Error fetching recent traffic: {e}", exc_info=True)
        return error_response(message="Failed to retrieve traffic telemetry logs.", status_code=500)


@traffic_bp.route('/traffic/<int:device_id>', methods=['GET'])
def get_device_traffic(device_id):
    """
    GET /api/traffic/<device_id>
    Retrieve recent traffic telemetry history for a specific device.
    Optional query parameter:
    - limit: int (default 30, max 100)
    """
    try:
        # Validate device existence
        device = DeviceService.get_device_by_id(device_id)
        if not device:
            return error_response(message=f"Device with ID {device_id} not found.", status_code=404)

        limit = request.args.get('limit', 30, type=int)
        limit = max(1, min(limit, 100))

        logs = simulator.get_device_traffic_history(device_id=device_id, limit=limit)
        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Retrieved {len(logs)} traffic records for device {device_id}.",
            "device_id": device_id,
            "device_name": device['device_name'],
            "count": len(logs),
            "traffic": logs,
            "data": logs
        }), 200
    except Exception as e:
        logger.error(f"Error fetching device traffic for {device_id}: {e}", exc_info=True)
        return error_response(message=f"Failed to retrieve traffic for device {device_id}.", status_code=500)


@traffic_bp.route('/topology', methods=['GET'])
def get_network_topology():
    """
    GET /api/topology
    Retrieve full network topology graph including device nodes and physical/logical links.
    """
    try:
        topo = simulator.get_topology()
        return jsonify({
            "status": "success",
            "success": True,
            "message": "Topology data retrieved successfully.",
            "nodes": topo['nodes'],
            "links": topo['connections'],
            "connections": topo['connections'],
            "data": topo
        }), 200
    except Exception as e:
        logger.error(f"Error fetching network topology: {e}", exc_info=True)
        return error_response(message="Failed to retrieve network topology graph.", status_code=500)


@traffic_bp.route('/network/summary', methods=['GET'])
def get_network_summary():
    """
    GET /api/network/summary
    Aggregate network metrics including device counts, link statuses, and total bandwidth.
    """
    try:
        summary = simulator.get_network_summary()
        return jsonify({
            "status": "success",
            "success": True,
            "message": "Network summary aggregated successfully.",
            **summary,
            "data": summary
        }), 200
    except Exception as e:
        logger.error(f"Error aggregating network summary: {e}", exc_info=True)
        return error_response(message="Failed to aggregate network summary.", status_code=500)


@traffic_bp.route('/network/connected/<int:device_id>', methods=['GET'])
def get_connected_devices(device_id):
    """
    GET /api/network/connected/<device_id>
    Retrieve all devices directly connected to a specific device node.
    """
    try:
        device = DeviceService.get_device_by_id(device_id)
        if not device:
            return error_response(message=f"Device with ID {device_id} not found.", status_code=404)

        neighbors = simulator.get_connected_devices(device_id=device_id)
        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Retrieved {len(neighbors)} connected devices for node {device_id}.",
            "device_id": device_id,
            "device_name": device['device_name'],
            "connected_devices": neighbors,
            "count": len(neighbors),
            "data": neighbors
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving connected devices for {device_id}: {e}", exc_info=True)
        return error_response(message=f"Failed to get connected devices for ID {device_id}.", status_code=500)


@traffic_bp.route('/simulation/start', methods=['POST'])
def start_simulation():
    """
    POST /api/simulation/start
    Start the background telemetry generation thread.
    """
    try:
        started, msg = simulator.start_simulation()
        return jsonify({
            "status": "success",
            "success": True,
            "message": "Network simulation started",
            "detail": msg,
            "interval_seconds": 2.5,
            "is_running": simulator.is_running
        }), 200
    except Exception as e:
        logger.error(f"Error starting simulation: {e}", exc_info=True)
        return error_response(message="Failed to start network simulation.", status_code=500)


@traffic_bp.route('/simulation/stop', methods=['POST'])
def stop_simulation():
    """
    POST /api/simulation/stop
    Pause/stop the background telemetry generation thread.
    """
    try:
        stopped, msg = simulator.stop_simulation()
        return jsonify({
            "status": "success",
            "success": True,
            "message": "Network simulation stopped",
            "detail": msg,
            "is_running": simulator.is_running
        }), 200
    except Exception as e:
        logger.error(f"Error stopping simulation: {e}", exc_info=True)
        return error_response(message="Failed to stop network simulation.", status_code=500)


@traffic_bp.route('/simulation/status', methods=['GET'])
def get_simulation_status():
    """
    GET /api/simulation/status
    Check if the background telemetry generator is actively running.
    """
    return jsonify({
        "status": "success",
        "success": True,
        "is_running": simulator.is_running
    }), 200


@traffic_bp.route('/simulation/failure', methods=['POST'])
@traffic_bp.route('/simulate/failure', methods=['POST'])
def simulate_failure():
    """
    POST /api/simulation/failure (or POST /api/simulate/failure)
    Simulate a hardware failure or severed link on a given device ID.
    Payload:
    {
        "device_id": 4
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_id = data.get('device_id') or data.get('deviceId')
        if raw_id is None:
            return error_response(message="Missing required field: 'device_id'", status_code=400)

        device_id = DeviceService.parse_device_id(raw_id)
        if device_id is None:
            return error_response(message="'device_id' must be a valid integer or 'dev-X' format", status_code=400)

        device = DeviceService.get_device_by_id(device_id)
        if not device:
            return error_response(message=f"Device with ID {device_id} not found.", status_code=404)

        result = simulator.simulate_device_failure(device_id)

        # Attempt to calculate an alternative failover path if applicable
        # E.g. Can Router (ID 1) reach Server 01 (ID 2) or Server 02 (ID 3) bypassing failed node?
        alternate_path = None
        if device_id in (2, 3, 4):  # Core servers with redundancy
            # Determine target server that is not the failed one
            target_id = 2 if device_id != 2 else 3
            alternate_path = simulator.calculate_path(1, target_id, avoid_node_id=device_id)

        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Device {device_id} failure simulated successfully",
            "device_id": device_id,
            "device_name": result['device_name'],
            "device_status": "offline",
            "affected_connections": result['affected_connections'],
            "reroute_path": alternate_path
        }), 200
    except Exception as e:
        logger.error(f"Error simulating device failure: {e}", exc_info=True)
        return error_response(message="Failed to simulate device failure.", status_code=500)


@traffic_bp.route('/simulation/restore', methods=['POST'])
@traffic_bp.route('/simulate/restore', methods=['POST'])
def restore_device():
    """
    POST /api/simulation/restore (or POST /api/simulate/restore)
    Restore a failed device back to online operational status and reconnect graph edges.
    Payload:
    {
        "device_id": 4
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_id = data.get('device_id') or data.get('deviceId')
        if raw_id is None:
            return error_response(message="Missing required field: 'device_id'", status_code=400)

        device_id = DeviceService.parse_device_id(raw_id)
        if device_id is None:
            return error_response(message="'device_id' must be a valid integer or 'dev-X' format", status_code=400)

        device = DeviceService.get_device_by_id(device_id)
        if not device:
            return error_response(message=f"Device with ID {device_id} not found.", status_code=404)

        result = simulator.restore_device(device_id)

        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Device {device_id} restored successfully",
            "device_id": device_id,
            "device_name": result['device_name'],
            "device_status": "online"
        }), 200
    except Exception as e:
        logger.error(f"Error restoring device: {e}", exc_info=True)
        return error_response(message="Failed to restore device.", status_code=500)


@traffic_bp.route('/simulation/threat', methods=['POST'])
@traffic_bp.route('/simulate/threat', methods=['POST'])
def simulate_threat():
    """
    POST /api/simulation/threat (or POST /api/simulate/threat)
    Inject simulated anomalous network traffic for a device through the unified AI/ML pipeline.
    Payload:
    {
        "deviceId": "dev-3",
        "threatType": "DoS"
    }
    """
    try:
        data = request.get_json(silent=True) or {}
        raw_id = data.get('deviceId') or data.get('device_id') or 3
        device_id = DeviceService.parse_device_id(raw_id) or 3
        threat_type = data.get('threatType') or data.get('threat_type') or 'DoS'

        telemetry = simulator.generate_simulated_telemetry_for_ai(device_id, threat_type=threat_type)
        from services.ai_pipeline import AIPipelineService
        pipeline = AIPipelineService()
        result = pipeline.run_pipeline(telemetry, persist_results=True)

        return jsonify({
            "status": "success",
            "success": True,
            "message": f"Simulated threat ({threat_type}) evaluated through AI pipeline",
            "data": result,
            "device_id": result['device_id'],
            "device_status": result['device_status'],
            "analysis": result['analysis'],
            "evidence": result['evidence'],
            "recommended_actions": result['recommended_actions'],
            "alert_created": result['alert_created'],
            "timestamp": result['timestamp']
        }), 200
    except Exception as e:
        logger.error(f"Error simulating threat injection: {e}", exc_info=True)
        return error_response(message="Failed to simulate threat.", status_code=500)
