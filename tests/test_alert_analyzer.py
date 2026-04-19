import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from alert_analyzer import (
    AttackSuccessDetector,
    AssetManager,
    SuppressionEngine,
    RiskScorer,
    LLMIntegrator,
    DetectionAgent
)

class TestAttackSuccessDetector(unittest.TestCase):
    """测试攻击成功判定插件"""
    
    def setUp(self):
        self.detector = AttackSuccessDetector()
    
    def test_sql_injection_detection(self):
        """测试SQL注入检测"""
        payload = "GET /api?id=1' UNION SELECT username,password FROM users--"
        success, reason = self.detector.detect_sql_injection(payload, 200)
        self.assertTrue(success)
        self.assertIn("UNION SELECT", reason)
    
    def test_sql_injection_failed(self):
        """测试SQL注入未成功"""
        payload = "GET /api?id=1"
        success, reason = self.detector.detect_sql_injection(payload, 404)
        self.assertFalse(success)
    
    def test_command_execution_detection(self):
        """测试命令执行检测"""
        payload = "uid=0(root) gid=0(root)"
        success, reason = self.detector.detect_command_execution(payload, 100)
        self.assertTrue(success)
        self.assertIn("命令执行回显", reason)
    
    def test_file_upload_detection(self):
        """测试文件上传检测"""
        payload = "Content-Disposition: form-data; filename=\"shell.php\""
        success, reason = self.detector.detect_file_upload(payload, 200)
        self.assertTrue(success)
    
    def test_xss_detection(self):
        """测试XSS检测"""
        payload = "<script>alert('XSS')</script>"
        success, reason = self.detector.analyze("XSS", payload)
        self.assertTrue(success)
    
    def test_login_brute_detection(self):
        """测试登录爆破检测"""
        success, reason = self.detector.detect_login_brute(25, 0)
        self.assertTrue(success)
        self.assertIn("失败次数超过阈值", reason)

class TestAssetManager(unittest.TestCase):
    """测试资产管理器"""
    
    def setUp(self):
        self.manager = AssetManager()
    
    def test_get_asset_info(self):
        """测试获取资产信息"""
        info = self.manager.get_asset_info("10.0.0.1")
        self.assertEqual(info['criticality'], 'critical')
        self.assertEqual(info['environment'], 'prod')
    
    def test_get_asset_info_network(self):
        """测试通过IP段获取资产信息"""
        info = self.manager.get_asset_info("10.10.0.5")
        self.assertEqual(info['hostname'], 'intranet-servers')
    
    def test_get_unknown_asset(self):
        """测试获取未知资产"""
        info = self.manager.get_asset_info("1.1.1.1")
        self.assertEqual(info['criticality'], 'normal')

class TestSuppressionEngine(unittest.TestCase):
    """测试动态抑制规则引擎"""
    
    def setUp(self):
        self.engine = SuppressionEngine()
    
    def test_match_scan_rule(self):
        """测试匹配扫描规则"""
        alert = {
            'event_type': '端口扫描-Nmap',
            'asset_criticality': 'normal',
            'alert_count': 5
        }
        rule = self.engine.match_rule(alert)
        self.assertIsNotNone(rule)
    
    def test_critical_asset_scan(self):
        """测试核心资产扫描规则"""
        alert = {
            'event_type': '端口扫描-Nmap',
            'asset_criticality': 'critical',
            'alert_count': 1
        }
        rule = self.engine.match_rule(alert)
        self.assertIsNotNone(rule)
        self.assertEqual(rule['name'], 'critical_asset_scan')

class TestRiskScorer(unittest.TestCase):
    """测试风险评分器"""
    
    def setUp(self):
        self.scorer = RiskScorer()
    
    def test_calculate_score(self):
        """测试风险评分计算"""
        alert = {
            'attack_success': True,
            'asset_criticality': 'critical',
            'event_type': 'SQL注入'
        }
        score, breakdown = self.scorer.calculate_score(alert)
        self.assertEqual(score, 100)
        self.assertEqual(breakdown['attack_success'], 40)
        self.assertEqual(breakdown['asset_criticality'], 40)
        self.assertEqual(breakdown['attack_type'], 25)
    
    def test_get_risk_level(self):
        """测试风险等级获取"""
        level, actions = self.scorer.get_risk_level(85)
        self.assertEqual(level, 'L2_HIGH')
        self.assertIn('钉钉', actions)
        
        level, actions = self.scorer.get_risk_level(95)
        self.assertEqual(level, 'L1_CRITICAL')
        self.assertIn('电话', actions)

class TestDetectionAgent(unittest.TestCase):
    """测试检测智能体主类"""
    
    def setUp(self):
        self.agent = DetectionAgent()
    
    def test_process_alert(self):
        """测试处理单个告警"""
        alert = {
            'alert_id': 'TEST-001',
            'event_type': 'SQL注入',
            'source_ip': '192.168.1.1',
            'dest_ip': '10.0.0.1',
            'alert_status': '成功',
            'alert_count': 10,
            'raw_payload': "GET /api?id=1' UNION SELECT",
            'return_code': 200,
            'response_length': 1024
        }
        result = self.agent._process_alert(alert)
        self.assertEqual(result['alert_id'], 'TEST-001')
        self.assertIn('risk_level', result)
        self.assertIn('risk_score', result)
    
    def test_check_login_escalation(self):
        """测试登录失败升级检测"""
        alert = {
            'event_type': '密码猜解',
            'alert_count': 25,
            'asset_criticality': 'critical'
        }
        escalated, reason = self.agent._check_login_escalation(alert)
        self.assertTrue(escalated)

if __name__ == '__main__':
    unittest.main(verbosity=2)
