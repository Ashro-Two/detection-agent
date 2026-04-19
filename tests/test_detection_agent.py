import unittest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alert_analyzer import DetectionAgent

class TestDetectionAgent(unittest.TestCase):
    def setUp(self):
        config = {
            'risk_weights': {
                'attack_success': 40,
                'asset_criticality': {'critical': 40, 'important': 20, 'normal': 10, 'edge': 5},
                'attack_type': {'command_execution': 30, 'sql_injection': 25, 'scan': 5}
            }
        }
        
        whitelist = {
            'ip_whitelist': [],
            'url_whitelist': [],
            'suppression_rules': []
        }
        
        asset_mapping = {}
        
        self.agent = DetectionAgent(config, whitelist, asset_mapping)
    
    def test_sql_injection_success_critical(self):
        alert = {
            'alert_id': 'TEST-001',
            'attack_type': 'SQL Injection',
            'status': 'success',
            'count': 10,
            'src_ip': '25.216.42.6',
            'dest_ip': '10.0.0.1',
            'asset_type': 'critical'
        }
        
        result = self.agent.analyze_alert(alert)
        
        self.assertEqual(result['risk_level'], 'L1_CRITICAL')
        self.assertTrue(result['risk_score'] >= 90)
        self.assertTrue(result['attack_success'])
    
    def test_rce_success_critical(self):
        alert = {
            'alert_id': 'TEST-002',
            'attack_type': 'Remote Command Execution',
            'status': 'success',
            'count': 5,
            'src_ip': '45.33.32.156',
            'dest_ip': '10.0.0.1',
            'asset_type': 'critical'
        }
        
        result = self.agent.analyze_alert(alert)
        
        self.assertEqual(result['risk_level'], 'L1_CRITICAL')
        self.assertTrue(result['risk_score'] >= 90)
    
    def test_failed_attack(self):
        alert = {
            'alert_id': 'TEST-003',
            'attack_type': 'SQL Injection',
            'status': 'failed',
            'count': 5,
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'asset_type': 'critical'
        }
        
        result = self.agent.analyze_alert(alert)
        
        self.assertFalse(result['attack_success'])
        self.assertNotEqual(result['risk_level'], 'L1_CRITICAL')
    
    def test_scan_edge_asset(self):
        alert = {
            'alert_id': 'TEST-004',
            'attack_type': 'Port Scan',
            'status': 'failed',
            'count': 10,
            'src_ip': '141.101.104.11',
            'dest_ip': '10.0.2.1',
            'asset_type': 'edge'
        }
        
        result = self.agent.analyze_alert(alert)
        
        self.assertEqual(result['risk_level'], 'L4_LOW')
    
    def test_false_positive(self):
        alert = {
            'alert_id': 'TEST-005',
            'attack_type': 'SQL Injection',
            'status': 'success',
            'count': 1,
            'src_ip': '10.0.0.50',
            'dest_ip': '10.0.0.1',
            'asset_type': 'critical',
            'is_false_positive': True,
            'reason': 'Normal search'
        }
        
        result = self.agent.analyze_alert(alert)
        
        self.assertEqual(result['risk_level'], 'L4_LOW')
        self.assertTrue(result['is_false_positive'])

if __name__ == '__main__':
    unittest.main()
