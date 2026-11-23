"""
NetGuardian AI - Routes Package
Registers and exports all blueprint route handlers.
"""

from .health_routes import health_bp
from .device_routes import device_bp
from .dashboard_routes import dashboard_bp
from .traffic_routes import traffic_bp
from .alert_routes import alert_bp
from .recovery_routes import recovery_bp
from .healing_routes import healing_bp
from .ai_routes import ai_bp
from .intelligence_routes import intelligence_bp

__all__ = [
    'health_bp',
    'device_bp',
    'dashboard_bp',
    'traffic_bp',
    'alert_bp',
    'recovery_bp',
    'healing_bp',
    'ai_bp',
    'intelligence_bp'
]
