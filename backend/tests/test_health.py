"""
NetGuardian AI - Health API & Backend Foundation Test Suite
Verifies:
1. Flask application initializes cleanly
2. Health endpoint responds (GET /api/health)
3. JSON response structure matches required schema
4. SQLite database connection establishes safely
5. Database status correctly reported as "connected"
6. CORS configuration allows frontend origin (http://localhost:3000)
7. Invalid routes return standardized JSON 404 responses
"""

import sys
import unittest
import json
from pathlib import Path

# Add backend directory to sys.path so modules resolve correctly
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from config import TestingConfig
from database import check_db_connection, get_db


class HealthAndFoundationTestCase(unittest.TestCase):
    """Test suite for backend foundation, database checks, and CORS headers."""

    def setUp(self):
        """Configure test application and client."""
        self.app = create_app(TestingConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        """Clean up application context."""
        self.app_context.pop()

    def test_1_app_initialization(self):
        """Test 1: Flask application starts cleanly with valid testing configuration."""
        self.assertIsNotNone(self.app)
        self.assertTrue(self.app.config['TESTING'])
        self.assertTrue(self.app.config['DEBUG'])

    def test_2_health_endpoint_response(self):
        """Test 2: Health endpoint responds with HTTP 200 OK."""
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'application/json')

    def test_3_health_json_schema(self):
        """Test 3: JSON response contains all required fields and valid types."""
        response = self.client.get('/api/health')
        data = json.loads(response.data.decode('utf-8'))
        
        # Verify required keys
        expected_keys = ['success', 'application', 'backend', 'database', 'version']
        for key in expected_keys:
            self.assertIn(key, data, f"Key '{key}' missing from /api/health response")
            
        self.assertTrue(data['success'])
        self.assertEqual(data['application'], 'NetGuardian AI')
        self.assertEqual(data['backend'], 'online')
        self.assertEqual(data['version'], '1.0.0')

    def test_4_sqlite_connection_works(self):
        """Test 4: SQLite connection can execute parameterized queries."""
        is_connected, msg = check_db_connection()
        self.assertTrue(is_connected, f"Database connection failed: {msg}")
        self.assertEqual(msg, "connected")

        # Verify executing query inside context manager
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM _system_metadata WHERE key = ?;", ('version',))
            row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row['value'], '1.0.0')

    def test_5_database_status_reported_correctly(self):
        """Test 5: Database status in health response accurately reflects 'connected'."""
        response = self.client.get('/api/health')
        data = json.loads(response.data.decode('utf-8'))
        self.assertEqual(data['database'], 'connected')

    def test_6_cors_allows_frontend_origin(self):
        """Test 6: CORS headers permit requests from http://localhost:3000."""
        # Simple GET request with Origin header
        response = self.client.get(
            '/api/health',
            headers={'Origin': 'http://localhost:3000'}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get('Access-Control-Allow-Origin'),
            'http://localhost:3000'
        )

        # Preflight OPTIONS request
        options_response = self.client.options(
            '/api/health',
            headers={
                'Origin': 'http://localhost:3000',
                'Access-Control-Request-Method': 'GET',
                'Access-Control-Request-Headers': 'Content-Type'
            }
        )
        self.assertEqual(options_response.status_code, 200)
        self.assertEqual(
            options_response.headers.get('Access-Control-Allow-Origin'),
            'http://localhost:3000'
        )

    def test_7_invalid_route_returns_json_404(self):
        """Test 7: Unregistered routes return a structured JSON 404 response."""
        response = self.client.get('/api/non-existent-route')
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.content_type, 'application/json')
        
        data = json.loads(response.data.decode('utf-8'))
        self.assertFalse(data['success'])
        self.assertIn("Endpoint not found", data['message'])
        self.assertIsNone(data['data'])


if __name__ == '__main__':
    unittest.main()
