"""
NetGuardian AI - Standardized API Response Service
Enforces consistent JSON envelope formatting across all API routes.
"""

from flask import jsonify


def success_response(data=None, message="Operation completed successfully", status_code=200):
    """
    Generate a standardized successful JSON response envelope.
    
    Format:
    {
        "success": true,
        "message": "...",
        "data": { ... }
    }
    """
    payload = {
        "success": True,
        "message": message,
        "data": data if data is not None else {}
    }
    return jsonify(payload), status_code


def error_response(message="An error occurred", status_code=400, data=None):
    """
    Generate a standardized error JSON response envelope.
    
    Format:
    {
        "success": false,
        "message": "...",
        "data": null
    }
    """
    payload = {
        "success": False,
        "message": message,
        "data": data
    }
    return jsonify(payload), status_code
