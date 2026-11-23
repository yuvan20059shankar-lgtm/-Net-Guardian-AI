"""
NetGuardian AI - Device Management & Dashboard Test Suite (Prompt 6)
Covers all 12 required test scenarios:
1. Database initialization
2. Inserting 10 initial devices
3. GET all devices (GET /api/devices)
4. GET a device by ID (GET /api/devices/<id>)
5. Adding a new device (POST /api/devices)
6. Updating a device (PUT /api/devices/<id>)
7. Deleting a device (DELETE /api/devices/<id>)
8. Changing device status (PATCH /api/devices/<id>/status)
9. Duplicate IP rejection
10. Invalid status rejection
11. Dashboard statistics calculation (GET /api/dashboard)
12. Database persistence after application restart
"""

import os
import sys
import json
import unittest
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app import create_app
from config import TestingConfig
from database import get_db, init_database


class DeviceManagementTestCase(unittest.TestCase):
    """Integration test suite for device management CRUD and dashboard metrics."""

    @classmethod
    def setUpClass(cls):
        """Set up test environment and remove any existing test database."""
        cls.test_db_path = TestingConfig.DATABASE_PATH
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except OSError:
                pass

    @classmethod
    def tearDownClass(cls):
        """Clean up test database file."""
        if os.path.exists(cls.test_db_path):
            try:
                os.remove(cls.test_db_path)
            except OSError:
                pass

    def setUp(self):
        """Initialize test client using isolated test database."""
        self.app = create_app(TestingConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Reset devices table in test database to pristine 10 initial devices
        with get_db() as conn:
            conn.execute("DELETE FROM devices WHERE id > 10;")
            conn.execute("UPDATE devices SET status = 'online' WHERE id IN (1, 2, 3, 4, 5, 6, 8, 10);")
            conn.execute("UPDATE devices SET status = 'suspicious' WHERE id = 7;")
            conn.execute("UPDATE devices SET status = 'offline' WHERE id = 9;")
            conn.execute("UPDATE devices SET device_name = 'Server 01', role = 'PostgreSQL Database', cpu_usage = 52.0 WHERE id = 2;")

    def tearDown(self):
        """Tear down test context."""
        self.app_context.pop()

    def test_01_database_initialization(self):
        """Test 1: Verify database initialization creates tables."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='devices';")
            table = cursor.fetchone()
            self.assertIsNotNone(table, "Table 'devices' was not created during init.")

    def test_02_inserting_10_initial_devices(self):
        """Test 2: Verify all 10 initial devices exist in SQLite."""
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS total FROM devices;")
            count = cursor.fetchone()['total']
            self.assertEqual(count, 10, f"Expected 10 initial devices, found {count}")

        # Check key device names and IPs
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT device_name, ip_address, device_type FROM devices ORDER BY id ASC;")
            devices = cursor.fetchall()
            names = [d['device_name'] for d in devices]
            self.assertIn("Router 01", names)
            self.assertIn("Server 01", names)
            self.assertIn("Server 02", names)
            self.assertIn("Server 03", names)
            self.assertIn("PC 01", names)
            self.assertIn("PC 05", names)
            self.assertIn("Firewall 01", names)

    def test_03_get_all_devices(self):
        """Test 3: GET /api/devices returns all 10 devices in standardized envelope."""
        response = self.client.get('/api/devices')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        
        self.assertTrue(data['success'])
        self.assertIsInstance(data['data'], list)
        self.assertEqual(len(data['data']), 10)
        
        # Verify device properties on first device
        first = data['data'][0]
        self.assertEqual(first['device_name'], 'Router 01')
        self.assertEqual(first['ip_address'], '192.168.1.1')
        self.assertEqual(first['status'], 'online')
        # Check camelCase compatibility aliases
        self.assertEqual(first['name'], 'Router 01')
        self.assertEqual(first['ip'], '192.168.1.1')

    def test_04_get_device_by_id(self):
        """Test 4: GET /api/devices/<id> returns specific device details."""
        response = self.client.get('/api/devices/1')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['id'], 1)
        self.assertEqual(data['data']['device_name'], 'Router 01')
        self.assertEqual(data['data']['ip_address'], '192.168.1.1')

        # Test non-existent device returns 404
        res_404 = self.client.get('/api/devices/9999')
        self.assertEqual(res_404.status_code, 404)
        data_404 = json.loads(res_404.data.decode('utf-8'))
        self.assertFalse(data_404['success'])

    def test_05_add_new_device(self):
        """Test 5: POST /api/devices adds a new device with input validation."""
        new_payload = {
            "device_name": "IoT Sensor 01",
            "ip_address": "192.168.1.50",
            "device_type": "IoT",
            "role": "Environmental Sensor",
            "status": "online"
        }
        response = self.client.post(
            '/api/devices',
            data=json.dumps(new_payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data.decode('utf-8'))
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['device_name'], "IoT Sensor 01")
        self.assertEqual(data['data']['ip_address'], "192.168.1.50")
        self.assertEqual(data['data']['status'], "online")

        # Verify invalid IP format returns 400
        invalid_ip_payload = {
            "device_name": "Bad IP Device",
            "ip_address": "999.999.999.999",
            "device_type": "Computer"
        }
        res_bad = self.client.post(
            '/api/devices',
            data=json.dumps(invalid_ip_payload),
            content_type='application/json'
        )
        self.assertEqual(res_bad.status_code, 400)

    def test_06_update_device(self):
        """Test 6: PUT /api/devices/<id> updates device attributes."""
        update_payload = {
            "device_name": "Server 01 [Primary Master]",
            "role": "Core Enterprise PostgreSQL Cluster",
            "cpu_usage": 65.5
        }
        response = self.client.put(
            '/api/devices/2',
            data=json.dumps(update_payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertTrue(data['success'])
        self.assertEqual(data['data']['device_name'], "Server 01 [Primary Master]")
        self.assertEqual(data['data']['role'], "Core Enterprise PostgreSQL Cluster")
        self.assertEqual(data['data']['cpu_usage'], 65.5)

    def test_07_delete_device(self):
        """Test 7: DELETE /api/devices/<id> safely removes a device."""
        # Create a temporary device to delete
        temp_payload = {
            "device_name": "Temporary Test Node",
            "ip_address": "192.168.1.99",
            "device_type": "TestNode"
        }
        create_res = self.client.post(
            '/api/devices',
            data=json.dumps(temp_payload),
            content_type='application/json'
        )
        temp_id = json.loads(create_res.data.decode('utf-8'))['data']['id']

        # Delete it
        del_res = self.client.delete(f'/api/devices/{temp_id}')
        self.assertEqual(del_res.status_code, 200)
        del_data = json.loads(del_res.data.decode('utf-8'))
        self.assertTrue(del_data['success'])

        # Verify it no longer exists (404)
        get_res = self.client.get(f'/api/devices/{temp_id}')
        self.assertEqual(get_res.status_code, 404)

    def test_08_change_device_status(self):
        """Test 8: PATCH /api/devices/<id>/status updates status between online/offline/suspicious."""
        # Change to offline
        res_offline = self.client.patch(
            '/api/devices/3/status',
            data=json.dumps({"status": "offline"}),
            content_type='application/json'
        )
        self.assertEqual(res_offline.status_code, 200)
        data = json.loads(res_offline.data.decode('utf-8'))
        self.assertEqual(data['data']['status'], "offline")

        # Change to suspicious
        res_susp = self.client.patch(
            '/api/devices/3/status',
            data=json.dumps({"status": "suspicious"}),
            content_type='application/json'
        )
        self.assertEqual(res_susp.status_code, 200)
        self.assertEqual(json.loads(res_susp.data.decode('utf-8'))['data']['status'], "suspicious")

        # Change back to online
        res_online = self.client.patch(
            '/api/devices/3/status',
            data=json.dumps({"status": "online"}),
            content_type='application/json'
        )
        self.assertEqual(res_online.status_code, 200)
        self.assertEqual(json.loads(res_online.data.decode('utf-8'))['data']['status'], "online")

    def test_09_duplicate_ip_rejection(self):
        """Test 9: Duplicate IP addresses are rejected with HTTP 409 Conflict."""
        # Try to register a new device using Router 01's IP (192.168.1.1)
        duplicate_payload = {
            "device_name": "Rogue Device",
            "ip_address": "192.168.1.1",
            "device_type": "Rogue"
        }
        response = self.client.post(
            '/api/devices',
            data=json.dumps(duplicate_payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 409)
        data = json.loads(response.data.decode('utf-8'))
        self.assertFalse(data['success'])
        self.assertIn("already exists", data['message'])

    def test_10_invalid_status_rejection(self):
        """Test 10: Invalid status values return HTTP 400 Bad Request."""
        bad_status_payload = {"status": "DESTROYED_OR_UNKNOWN"}
        response = self.client.patch(
            '/api/devices/1/status',
            data=json.dumps(bad_status_payload),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        data = json.loads(response.data.decode('utf-8'))
        self.assertFalse(data['success'])
        self.assertIn("Invalid status", data['message'])

    def test_11_dashboard_statistics_calculation(self):
        """
        Test 11: GET /api/dashboard calculates metrics directly from database.
        Formula: (online_devices / total_devices) * 100
        """
        response = self.client.get('/api/dashboard')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data.decode('utf-8'))
        self.assertTrue(data['success'])
        
        metrics = data['data']
        self.assertIn('total_devices', metrics)
        self.assertIn('online_devices', metrics)
        self.assertIn('offline_devices', metrics)
        self.assertIn('suspicious_devices', metrics)
        self.assertIn('network_health', metrics)

        # Verify mathematical formula
        total = metrics['total_devices']
        online = metrics['online_devices']
        expected_health = round((online / total) * 100, 1) if total > 0 else 0.0
        self.assertEqual(metrics['network_health'], expected_health)

    def test_12_database_persistence_after_application_restart(self):
        """Test 12: Verify database records persist across new app/connection instances."""
        # Modify a device attribute in current instance
        self.client.patch(
            '/api/devices/4/status',
            data=json.dumps({"status": "suspicious"}),
            content_type='application/json'
        )

        # Simulate full server restart by creating a brand new app context
        new_app = create_app(TestingConfig)
        new_client = new_app.test_client()

        # Query the device in the new app instance
        res = new_client.get('/api/devices/4')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data.decode('utf-8'))
        
        # Verify persistence
        self.assertEqual(data['data']['status'], "suspicious")


if __name__ == '__main__':
    unittest.main()
