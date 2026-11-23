"""
NetGuardian AI - Device Management Blueprint Routes
Provides RESTful endpoints for querying, creating, updating, and deleting network devices.
"""

import logging
from flask import Blueprint, request
from services.device_service import (
    DeviceService,
    ValidationError,
    DuplicateError,
    NotFoundError
)
from services.response_service import success_response, error_response

logger = logging.getLogger('netguardian.device_routes')

device_bp = Blueprint('devices', __name__, url_prefix='/api')


@device_bp.route('/devices', methods=['GET'])
def get_all_devices():
    """
    GET /api/devices
    Fetch all monitored network devices from SQLite.
    """
    try:
        devices = DeviceService.get_all_devices()
        return success_response(
            data=devices,
            message=f"Successfully retrieved {len(devices)} network devices.",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error fetching devices: {e}", exc_info=True)
        return error_response(message="Failed to retrieve devices from database.", status_code=500)


@device_bp.route('/devices/<int:device_id>', methods=['GET'])
def get_device_by_id(device_id):
    """
    GET /api/devices/<device_id>
    Retrieve full details for a single network asset by ID.
    """
    try:
        device = DeviceService.get_device_by_id(device_id)
        if not device:
            return error_response(
                message=f"Device with ID {device_id} was not found.",
                status_code=404
            )
        return success_response(
            data=device,
            message="Device details retrieved successfully.",
            status_code=200
        )
    except Exception as e:
        logger.error(f"Error fetching device {device_id}: {e}", exc_info=True)
        return error_response(message="Failed to retrieve device details.", status_code=500)


@device_bp.route('/devices', methods=['POST'])
def create_device():
    """
    POST /api/devices
    Register a new network device with payload and IPv4 validation.
    """
    try:
        payload = request.get_json(silent=True)
        if payload is None:
            return error_response(
                message="Invalid or missing JSON payload in request body.",
                status_code=400
            )

        new_device = DeviceService.create_device(payload)
        return success_response(
            data=new_device,
            message="Network device registered successfully.",
            status_code=201
        )
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except DuplicateError as e:
        return error_response(message=str(e), status_code=409)
    except Exception as e:
        logger.error(f"Error creating device: {e}", exc_info=True)
        return error_response(message="Internal server error registering device.", status_code=500)


@device_bp.route('/devices/<int:device_id>', methods=['PUT'])
def update_device(device_id):
    """
    PUT /api/devices/<device_id>
    Update specifications and metadata for a specific device.
    """
    try:
        payload = request.get_json(silent=True)
        if payload is None:
            return error_response(
                message="Invalid or missing JSON payload in request body.",
                status_code=400
            )

        updated_device = DeviceService.update_device(device_id, payload)
        return success_response(
            data=updated_device,
            message=f"Device ID {device_id} updated successfully.",
            status_code=200
        )
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except DuplicateError as e:
        return error_response(message=str(e), status_code=409)
    except Exception as e:
        logger.error(f"Error updating device {device_id}: {e}", exc_info=True)
        return error_response(message="Internal server error updating device.", status_code=500)


@device_bp.route('/devices/<int:device_id>', methods=['DELETE'])
def delete_device(device_id):
    """
    DELETE /api/devices/<device_id>
    Remove a device safely from the SQLite database.
    """
    try:
        DeviceService.delete_device(device_id)
        return success_response(
            data={'deleted_id': device_id},
            message=f"Device ID {device_id} deleted successfully.",
            status_code=200
        )
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except Exception as e:
        logger.error(f"Error deleting device {device_id}: {e}", exc_info=True)
        return error_response(message="Internal server error deleting device.", status_code=500)


@device_bp.route('/devices/<int:device_id>/status', methods=['PATCH'])
@device_bp.route('/devices/<device_id>/status', methods=['PATCH'])
def update_device_status(device_id):
    """
    PATCH /api/devices/<device_id>/status
    Modify the operational status of a device between ('online', 'offline', 'suspicious').
    """
    try:
        payload = request.get_json(silent=True)
        if not payload or 'status' not in payload:
            return error_response(
                message="Missing required field 'status' in JSON request body.",
                status_code=400
            )

        status_value = payload['status']
        updated_device = DeviceService.update_device_status(device_id, status_value)
        return success_response(
            data=updated_device,
            message=f"Device ID {device_id} status changed to '{updated_device['status']}'.",
            status_code=200
        )
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except Exception as e:
        logger.error(f"Error updating status for device {device_id}: {e}", exc_info=True)
        return error_response(message="Internal server error updating device status.", status_code=500)


@device_bp.route('/devices/<device_id>/toggle', methods=['POST'])
def toggle_device_status(device_id):
    """
    POST /api/devices/<device_id>/toggle
    Toggles device operational status between 'online' and 'offline'.
    Provides direct compatibility with frontend NetGuardianAPI.toggleDeviceStatus(id).
    """
    try:
        updated = DeviceService.toggle_device_status(device_id)
        return success_response(
            data=updated,
            message=f"Device {device_id} toggled to '{updated['status']}'.",
            status_code=200
        )
    except NotFoundError as e:
        return error_response(message=str(e), status_code=404)
    except ValidationError as e:
        return error_response(message=str(e), status_code=400)
    except Exception as e:
        logger.error(f"Error toggling device {device_id}: {e}", exc_info=True)
        return error_response(message="Internal server error toggling device status.", status_code=500)
