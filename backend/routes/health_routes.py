"""
NetGuardian AI - Health Check Routes
Exposes system diagnostic endpoints to verify backend and database operational readiness.
"""

import logging
from flask import Blueprint, jsonify
from database import check_db_connection

logger = logging.getLogger('netguardian.health')

health_bp = Blueprint('health', __name__, url_prefix='/api')


@health_bp.route('/health', methods=['GET'])
def health_check():
    """
    GET /api/health
    
    Verifies that the Flask application and SQLite database are fully operational.
    
    Expected Success (HTTP 200):
    {
      "success": true,
      "application": "NetGuardian AI",
      "backend": "online",
      "database": "connected",
      "version": "1.0.0"
    }
    
    Expected Failure (HTTP 503):
    {
      "success": false,
      "application": "NetGuardian AI",
      "backend": "online",
      "database": "disconnected",
      "version": "1.0.0",
      "error": "..."
    }
    """
    db_ok, db_status = check_db_connection()
    
    if db_ok:
        response_payload = {
            "success": True,
            "application": "NetGuardian AI",
            "backend": "online",
            "database": "connected",
            "version": "1.0.0"
        }
        return jsonify(response_payload), 200
    else:
        logger.error(f"Health check failed database verification: {db_status}")
        response_payload = {
            "success": False,
            "application": "NetGuardian AI",
            "backend": "online",
            "database": "disconnected",
            "version": "1.0.0",
            "error": f"Database unavailable: {db_status}"
        }
        return jsonify(response_payload), 503
