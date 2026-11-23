"""
NetGuardian AI - Flask Application Entry Point
Detect. Defend. Recover. Automatically.

Backend Foundation Architecture:
- Flask application factory pattern
- Secure CORS configuration for frontend origin (http://localhost:3000)
- Modular blueprint registration
- Centralized JSON error handling
- SQLite foundation verification
- Structured operational logging
"""

import os
import sys
import time
import logging
from flask import Flask, request, jsonify
from flask_cors import CORS

from config import get_config
from database import init_database
from routes import health_bp, device_bp, dashboard_bp, traffic_bp, alert_bp, recovery_bp, healing_bp, ai_bp, intelligence_bp
from services.response_service import error_response


def configure_logging(app, config):
    """Set up structured application logging."""
    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)
    
    # Configure root logger format if not already configured
    logging.basicConfig(
        level=log_level,
        format=config.LOG_FORMAT,
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    app.logger.setLevel(log_level)
    app.logger.info("Structured logging initialized for NetGuardian AI.")


def register_error_handlers(app):
    """Enforce standardized JSON error response envelopes across the entire API."""

    @app.errorhandler(400)
    def bad_request(error):
        return error_response(
            message=getattr(error, 'description', 'Bad request syntax or parameter'),
            status_code=400
        )

    @app.errorhandler(404)
    def not_found(error):
        return error_response(
            message=f"Endpoint not found: {request.path}",
            status_code=404
        )

    @app.errorhandler(405)
    def method_not_allowed(error):
        return error_response(
            message=f"Method {request.method} is not allowed for {request.path}",
            status_code=405
        )

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {error}", exc_info=True)
        return error_response(
            message="Internal server error occurred in NetGuardian AI backend",
            status_code=500
        )


def register_request_logging(app):
    """Audit incoming requests and execution duration without logging sensitive payloads."""

    @app.before_request
    def record_start_time():
        request.start_time = time.time()

    @app.after_request
    def log_request_outcome(response):
        duration_ms = 0.0
        if hasattr(request, 'start_time'):
            duration_ms = round((time.time() - request.start_time) * 1000, 2)
            
        # Exclude static/health noise from high-verbosity logs if desired
        app.logger.info(
            f"HTTP {request.method} {request.path} -> {response.status_code} ({duration_ms}ms) "
            f"[Client: {request.remote_addr}]"
        )
        return response


def create_app(config_class=None):
    """
    Application Factory for NetGuardian AI Flask Backend.
    
    Args:
        config_class: Configuration class override (e.g. TestingConfig).
        
    Returns:
        Flask: Fully configured Flask WSGI application.
    """
    app = Flask(__name__)
    
    # 1. Load Configuration
    config = config_class() if config_class else get_config()
    app.config.from_object(config)
    
    # 2. Setup Logging
    configure_logging(app, config)
    
    # 3. Configure CORS
    allowed_origins = config.CORS_ALLOWED_ORIGINS
    CORS(
        app,
        resources={r"/api/*": {"origins": allowed_origins}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    app.logger.info(f"CORS initialized. Allowed origins: {allowed_origins}")
    
    # 4. Initialize Database Foundation
    with app.app_context():
        init_database()
        
    # 5. Register Blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(device_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(recovery_bp)
    app.register_blueprint(healing_bp)
    app.register_blueprint(ai_bp)
    app.register_blueprint(intelligence_bp)
    app.logger.info("Registered blueprints: health_bp, device_bp, dashboard_bp, traffic_bp, alert_bp, recovery_bp, healing_bp, ai_bp, intelligence_bp")
    
    # 6. Register Global JSON Error Handlers & Request Auditing
    register_error_handlers(app)
    register_request_logging(app)
    
    return app


# Application instance for WSGI runners
app = create_app()


if __name__ == '__main__':
    config = get_config()
    app.logger.info(f"Starting NetGuardian AI Backend on http://{config.HOST}:{config.PORT}")
    app.logger.info(f"Environment: {getattr(config, 'ENV', 'development')}, Debug: {config.DEBUG}")
    
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG
    )
