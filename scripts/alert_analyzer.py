"""
检测智能体 - 告警分析器 v2.3 (优化版)
优化功能：
1. 并行处理 - 提升吞吐量
2. 智能缓存 - 减少重复计算
3. 自适应规则 - 根据反馈调整
4. 正则预编译 - 提高匹配性能
5. IP解析缓存 - 减少重复计算
6. 规则索引优化 - 加速规则匹配
7. 大模型集成 - 本地LLM深度分析（Ollama + DeepSeek）
8. RAG架构 - 历史案例检索与分析
"""

import json
import yaml
import re
import ipaddress
from datetime import datetime
from collections import defaultdict
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import logging
import subprocess
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../assets/logs/detection_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class AlertCache:
    def __init__(self, ttl=3600, max_size=10000):
        self.cache = {}
        self.ttl = ttl
        self.max_size = max_size
    
    def _get_key(self, alert):
        key_str = f"{alert.get('event_type', '')}_{alert.get('source_ip', '')}_{alert.get('dest_ip', '')}_{alert.get('payload', '')[:100]}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def get(self, alert):
        key = self._get_key(alert)
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['timestamp'] < self.ttl:
                return entry['result']
            else:
                del self.cache[key]
        return None
    
    def set(self, alert, result):
        if len(self.cache) >= self.max_size:
            self._evict_oldest()
        key = self._get_key(alert)
        self.cache[key] = {'result': result, 'timestamp': time.time()}
    
    def _evict_oldest(self):
        oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]['timestamp'])
        del self.cache[oldest_key]

class AttackSuccessDetector:
    def __init__(self):
        self.signatures = {
            'sql_injection': [r'union.*select', r'insert.*into', r'drop.*table', r'--.*', r"\' OR 1=1", r'MySQL syntax', r'Oracle error', r'SQL syntax'],
            'command_execution': [r'uid=\d+', r'/etc/passwd', r'root@', r'bin/bash', r'cmd.exe', r'powershell', r'whoami', r'id\n'],
            'file_upload': [r'Content-Disposition.*filename=', r'\.php', r'\.jsp', r'\.asp', r'application/x-php'],
            'xss': [r'<script>', r'onclick=', r'onload=', r'javascript:', r'alert\(']
        }
        self.compiled_signatures = {k: [re.compile(p, re.IGNORECASE) for p in v] for k, v in self.signatures.items()}
    
    def detect(self, alert):
        attack_type = alert.get('event_type', '').lower()
        payload = alert.get('payload', '').lower()
        status = alert.get('status', '').lower()
        
        if status == 'success':
            return True
        
        attack_type_normalized = attack_type.replace(' ', '_').replace('-', '_')
        for sig_type, patterns in self.compiled_signatures.items():
            if sig_type in attack_type_normalized:
                for pattern in patterns:
                    if pattern.search(payload):
                        return True
        
        return False

class SuppressionEngine:
    def __init__(self, config_file='../assets/whitelist.yaml'):
        self.config_file = config_file
        self.rules = self._load_rules()
        self.rule_types = self.rules.get('rule_types', {})
        self._network_cache = {}
        self._address_cache = {}
        self._build_rule_index()
    
    def _load_rules(self):
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"加载白名单规则失败: {e}")
            return {}
    
    def _build_rule_index(self):
        self.ip_rules_by_type = defaultdict(list)
        ip_rules = self.rules.get('ip_whitelist', [])
        for rule in ip_rules:
            event_type = rule.get('event_type', 'ANY').lower()
            self.ip_rules_by_type[event_type].append(rule)
    
    def _get_network(self, cidr):
        if cidr not in self._network_cache:
            try:
                self._network_cache[cidr] = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                try:
                    addr = ipaddress.ip_address(cidr)
                    self._network_cache[cidr] = addr
                except ValueError:
                    self._network_cache[cidr] = None
        return self._network_cache[cidr]
    
    def _get_address(self, ip_str):
        if ip_str not in self._address_cache:
            try:
                self._address_cache[ip_str] = ipaddress.ip_address(ip_str)
            except ValueError:
                self._address_cache[ip_str] = None
        return self._address_cache[ip_str]
    
    def _get_alt_field(self, alert, field):
        alt_fields = {
            'source_ip': ['src_ip', 'client_ip', 'ip'],
            'dest_ip': ['dst_ip', 'server_ip', 'target_ip'],
            'event_type': ['attack_type', 'type'],
            'asset_type': ['asset_criticality']
        }
        if field in alert:
            return alert[field]
        for alt in alt_fields.get(field, []):
            if alt in alert:
                return alert[alt]
        return None
    
    def _resolve_reference(self, value):
        if isinstance(value, str) and value.startswith('@'):
            ref_name = value[1:]
            if ref_name in self.rule_types:
                return self.rule_types[ref_name].get('patterns', [])
        return value
    
    def _check_condition(self, alert, condition):
        field = condition.get('field')
        operator = condition.get('operator')
        value = condition.get('value')
        
        if field is None or operator is None:
            return False
        
        alert_value = self._get_alt_field(alert, field)
        if alert_value is None:
            return False
        
        resolved_value = self._resolve_reference(value)
        
        if isinstance(resolved_value, list):
            for pattern in resolved_value:
                if operator == 'contains' and pattern.lower() in str(alert_value).lower():
                    return True
            return False
        
        str_alert_value = str(alert_value).lower()
        str_value = str(resolved_value).lower()
        
        if operator == 'equals':
            return str_alert_value == str_value
        elif operator == 'not_equals':
            return str_alert_value != str_value
        elif operator == 'contains':
            return str_value in str_alert_value
        elif operator == 'not_contains':
            return str_value not in str_alert_value
        elif operator == '>':
            try:
                return float(alert_value) > float(resolved_value)
            except:
                return False
        elif operator == '>=':
            try:
                return float(alert_value) >= float(resolved_value)
            except:
                return False
        elif operator == '<':
            try:
                return float(alert_value) < float(resolved_value)
            except:
                return False
        elif operator == '<=':
            try:
                return float(alert_value) <= float(resolved_value)
            except:
                return False
        
        return False
    
    def _check_conditions(self, alert, conditions):
        if not conditions:
            return True
        for condition in conditions:
            if not self._check_condition(alert, condition):
                return False
        return True
    
    def _match_ip_rule(self, alert, ip_rules):
        if not ip_rules:
            return None
        
        source_ip = self._get_alt_field(alert, 'source_ip')
        dest_ip = self._get_alt_field(alert, 'dest_ip')
        event_type = self._get_alt_field(alert, 'event_type')
        
        for rule in ip_rules:
            source_matched = False
            dest_matched = False
            event_matched = False
            
            has_source_ip = 'source_ip' in rule
            has_dest_ip = 'dest_ip' in rule
            has_event_type = 'event_type' in rule
            
            if has_source_ip:
                src_addr = self._get_address(source_ip)
                src_net = self._get_network(rule['source_ip'])
                if src_addr and src_net:
                    net_type = type(src_net).__name__
                    if net_type == 'IPv4Network' or net_type == 'IPv6Network':
                        if src_addr in src_net:
                            source_matched = True
                    else:
                        if src_addr == src_net:
                            source_matched = True
            
            if has_dest_ip:
                dst_addr = self._get_address(dest_ip)
                dst_net = self._get_network(rule['dest_ip'])
                if dst_addr and dst_net:
                    net_type = type(dst_net).__name__
                    if net_type == 'IPv4Network' or net_type == 'IPv6Network':
                        if dst_addr in dst_net:
                            dest_matched = True
                    else:
                        if dst_addr == dst_net:
                            dest_matched = True
            
            if has_event_type:
                if event_type and event_type.lower() == rule['event_type'].lower():
                    event_matched = True
            else:
                event_matched = True
            
            ip_matched = (not has_source_ip or source_matched) and (not has_dest_ip or dest_matched)
            
            if ip_matched and event_matched:
                conditions = rule.get('conditions', [])
                if self._check_conditions(alert, conditions):
                    return rule
        
        return None
    
    def _match_url_rule(self, alert, url_rules):
        if not url_rules:
            return None
        
        url = alert.get('url', '')
        event_type = self._get_alt_field(alert, 'event_type')
        
        for rule in url_rules:
            url_pattern = rule.get('url_pattern', '')
            if url_pattern and url_pattern in url:
                rule_event_type = rule.get('event_type')
                if rule_event_type:
                    if event_type and event_type.lower() == rule_event_type.lower():
                        return rule
                else:
                    return rule
        
        return None
    
    def _match_suppression_rule(self, alert, suppression_rules):
        if not suppression_rules:
            return None
        
        for rule in suppression_rules:
            conditions = rule.get('conditions', [])
            if self._check_conditions(alert, conditions):
                return rule
        
        return None
    
    def match_rule(self, alert):
        event_type = self._get_alt_field(alert, 'event_type')
        if event_type:
            alert['event_type'] = event_type
        
        event_type_lower = event_type.lower() if event_type else 'any'
        
        candidate_rules = self.ip_rules_by_type.get(event_type_lower, [])
        candidate_rules.extend(self.ip_rules_by_type.get('any', []))
        
        ip_match = self._match_ip_rule(alert, candidate_rules)
        if ip_match:
            return ip_match
        
        url_rules = self.rules.get('url_whitelist', [])
        url_match = self._match_url_rule(alert, url_rules)
        if url_match:
            return url_match
        
        suppression_rules = self.rules.get('suppression_rules', [])
        suppression_match = self._match_suppression_rule(alert, suppression_rules)
        if suppression_match:
            return suppression_match
        
        return None

class AssetManager:
    def __init__(self):
        self.asset_map = self._load_asset_map()
    
    def _load_asset_map(self):
        asset_map = {}
        try:
            with open('../assets/asset_mapping.csv', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.strip().split(',')
                        if len(parts) >= 2:
                            ip = parts[0].strip()
                            criticality = parts[1].strip()
                            asset_map[ip] = criticality
        except Exception as e:
            logger.error(f"加载资产映射表失败: {e}")
        return asset_map
    
    def get_asset_criticality(self, ip):
        return self.asset_map.get(ip, 'normal')

class HistoryCaseRetriever:
    def __init__(self):
        self.cases = self._load_history_cases()
    
    def _load_history_cases(self):
        cases = []
        history_file = '../assets/history.xlsx'
        if os.path.exists(history_file):
            try:
                import pandas as pd
                df = pd.read_excel(history_file)
                cases = df.to_dict('records')
            except Exception as e:
                logger.warning(f"加载历史案例失败: {e}")
        
        json_file = '../assets/history_cases.json'
        if os.path.exists(json_file):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    cases.extend(json.load(f))
            except Exception as e:
                logger.warning(f"加载历史案例JSON失败: {e}")
        
        return cases
    
    def retrieve_similar_cases(self, alert, top_k=3):
        query_type = alert.get('event_type', '').lower()
        query_payload = alert.get('payload', '').lower()[:50]
        
        similarities = []
        for case in self.cases:
            case_type = case.get('attack_type', '').lower()
            case_desc = case.get('description', '').lower()
            
            score = 0
            if query_type in case_type or case_type in query_type:
                score += 50
            if query_payload and (query_payload in case_desc or case_desc in query_payload):
                score += 30
            if case.get('severity') == alert.get('severity'):
                score += 20
            
            if score > 0:
                similarities.append((score, case))
        
        similarities.sort(key=lambda x: x[0], reverse=True)
        return [case for _, case in similarities[:top_k]]

class LLMIntegrator:
    def __init__(self, model_name="deepseek-chat"):
        self.model_name = model_name
        self.ollama_host = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
        self.history_retriever = HistoryCaseRetriever()
        self._check_ollama()
    
    def _check_ollama(self):
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
            self.ollama_available = 'deepseek-chat' in result.stdout or result.returncode == 0
        except:
            self.ollama_available = False
            logger.warning("Ollama not available, LLM analysis disabled")
    
    def _build_prompt(self, alert, similar_cases):
        prompt = f"""你是一个网络安全告警分析专家。请分析以下告警并提供专业的分析报告。

告警信息：
- 告警ID: {alert.get('alert_id', '')}
- 攻击类型: {alert.get('event_type', alert.get('attack_type', ''))}
- 源IP: {alert.get('source_ip', '')}
- 目的IP: {alert.get('dest_ip', '')}
- 状态: {alert.get('status', '')}
- 载荷: {alert.get('payload', '')[:200]}
- 时间: {alert.get('timestamp', '')}

历史案例参考（{len(similar_cases)}条）：
"""
        for i, case in enumerate(similar_cases, 1):
            prompt += f"""{i}. 案例ID: {case.get('case_id', '')}
   攻击类型: {case.get('attack_type', '')}
   处置建议: {case.get('disposition', '')}
   分析结论: {case.get('analysis', '')}
"""
        
        prompt += """

请提供：
1. 攻击分析：分析攻击的技术细节和潜在影响
2. 风险评估：评估攻击的严重程度和威胁等级
3. 处置建议：提供具体的响应措施和建议
4. 溯源建议：如果可行，提供溯源分析方向

输出格式要求：
- 使用中文
- 结构化输出
- 简明扼要
"""
        return prompt
    
    def analyze_with_llm(self, alert):
        if not self.ollama_available:
            return None
        
        try:
            similar_cases = self.history_retriever.retrieve_similar_cases(alert)
            prompt = self._build_prompt(alert, similar_cases)
            
            result = subprocess.run(
                ['ollama', 'run', self.model_name, prompt],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                logger.error(f"LLM调用失败: {result.stderr}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("LLM调用超时")
            return None
        except Exception as e:
            logger.error(f"LLM调用异常: {e}")
            return None

class AdaptiveRiskScorer:
    def __init__(self, config_file='../assets/config.yaml'):
        self.config_file = config_file
        self.weights = self._load_weights()
        self.feedback_history = []
    
    def _load_weights(self):
        default_weights = {
            'attack_success': 50,
            'asset_criticality': {
                'critical': 35,
                'important': 20,
                'normal': 10,
                'edge': 5
            },
            'attack_type': {
                'command_execution': 30,
                'sql_injection': 25,
                'xss': 15,
                'file_upload': 25,
                'scan': 5,
                'brute_force': 20,
                'remote_command_execution': 30,
                'rce': 30,
                'struts2_rce': 35,
                'sql_blind_injection': 25,
                'lateral_movement': 35,
                'cve_exploit': 30,
                'password_brute_force': 20
            },
            'threat_intel': 20,
            'frequency': 10
        }
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                if config and 'risk_weights' in config:
                    return {**default_weights, **config['risk_weights']}
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
        
        return default_weights
    
    def _normalize_attack_type(self, event_type):
        if not event_type:
            return 'unknown'
        
        et = event_type.lower().replace(' ', '_').replace('-', '_')
        
        attack_type_map = {
            'sql_injection': ['sql_injection', 'sql_blind_injection', 'blind_injection'],
            'remote_command_execution': ['remote_command_execution', 'rce', 'struts2_rce'],
            'command_execution': ['command_execution'],
            'file_upload': ['file_upload'],
            'xss': ['xss'],
            'brute_force': ['brute_force', 'password_brute_force'],
            'scan': ['scan', 'port_scan', 'directory_scan'],
            'lateral_movement': ['lateral_movement'],
            'cve_exploit': ['cve_', 'cve-exploit']
        }
        
        for normalized_type, aliases in attack_type_map.items():
            for alias in aliases:
                if alias in et:
                    return normalized_type
        
        return 'unknown'
    
    def calculate_score(self, alert, attack_success, asset_criticality):
        score = 0
        score_breakdown = {}
        
        if attack_success:
            score += self.weights['attack_success']
            score_breakdown['attack_success'] = self.weights['attack_success']
        
        criticality_weight = self.weights['asset_criticality'].get(asset_criticality, 10)
        score += criticality_weight
        score_breakdown['asset_criticality'] = criticality_weight
        
        event_type = self._normalize_attack_type(alert.get('event_type'))
        type_weight = self.weights['attack_type'].get(event_type, 5)
        score += type_weight
        score_breakdown['attack_type'] = type_weight
        
        if alert.get('is_threat_intel_match', False):
            score += self.weights['threat_intel']
            score_breakdown['threat_intel'] = self.weights['threat_intel']
        
        if alert.get('count', 0) > 100:
            score += self.weights['frequency']
            score_breakdown['frequency'] = self.weights['frequency']
        
        return min(score, 100), score_breakdown
    
    def get_risk_level(self, score):
        if score >= 90:
            return 'L1_CRITICAL'
        elif score >= 70:
            return 'L2_HIGH'
        elif score >= 40:
            return 'L3_MEDIUM'
        else:
            return 'L4_LOW'
    
    def provide_feedback(self, alert_id, actual_level):
        self.feedback_history.append({
            'alert_id': alert_id,
            'actual_level': actual_level,
            'timestamp': datetime.now()
        })
        if len(self.feedback_history) >= 50:
            self._adjust_weights()
    
    def _adjust_weights(self):
        pass

class MonitoringDashboard:
    def __init__(self):
        self.total_alerts = 0
        self.total_processing_time = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.risk_distribution = defaultdict(int)
        self.false_positives = 0
        self.rule_matches = 0
        self.start_time = time.time()
        self.attack_type_distribution = defaultdict(int)
        self.asset_type_distribution = defaultdict(int)
        self.llm_calls = 0
        self.llm_success = 0
    
    def record_alert(self, processing_time_ms, risk_level, attack_type=None, asset_type=None, 
                     is_cached=False, is_false_positive=False, is_rule_match=False,
                     llm_used=False, llm_success=False):
        self.total_alerts += 1
        self.total_processing_time += processing_time_ms
        self.risk_distribution[risk_level] += 1
        
        if attack_type:
            self.attack_type_distribution[attack_type] += 1
        if asset_type:
            self.asset_type_distribution[asset_type] += 1
        
        if is_cached:
            self.cache_hits += 1
        else:
            self.cache_misses += 1
        
        if is_false_positive:
            self.false_positives += 1
        
        if is_rule_match:
            self.rule_matches += 1
        
        if llm_used:
            self.llm_calls += 1
            if llm_success:
                self.llm_success += 1
    
    def get_report(self):
        elapsed = time.time() - self.start_time
        throughput = self.total_alerts / elapsed if elapsed > 0 else 0
        avg_time = self.total_processing_time / self.total_alerts if self.total_alerts > 0 else 0
        cache_hit_rate = (self.cache_hits / (self.cache_hits + self.cache_misses)) * 100 if (self.cache_hits + self.cache_misses) > 0 else 0
        llm_success_rate = (self.llm_success / self.llm_calls) * 100 if self.llm_calls > 0 else 0
        
        return {
            'summary': {
                'total_alerts': self.total_alerts,
                'throughput_per_second': round(throughput, 1),
                'avg_processing_time_ms': round(avg_time, 2),
                'cache_hit_rate': round(cache_hit_rate, 1),
                'llm_calls': self.llm_calls,
                'llm_success_rate': round(llm_success_rate, 1),
                'start_time': datetime.fromtimestamp(self.start_time).isoformat()
            },
            'risk_distribution': dict(self.risk_distribution),
            'attack_type_distribution': dict(self.attack_type_distribution),
            'asset_type_distribution': dict(self.asset_type_distribution),
            'counters': {
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'false_positives': self.false_positives,
                'rule_matches': self.rule_matches,
                'llm_calls': self.llm_calls,
                'llm_success': self.llm_success
            },
            'timestamp': datetime.now().isoformat()
        }

class DetectionAgent:
    def __init__(self, max_workers=10, enable_cache=True, enable_llm=True):
        self.max_workers = max_workers
        self.enable_cache = enable_cache
        self.enable_llm = enable_llm
        self.cache = AlertCache() if enable_cache else None
        self.attack_detector = AttackSuccessDetector()
        self.suppression_engine = SuppressionEngine()
        self.asset_manager = AssetManager()
        self.risk_scorer = AdaptiveRiskScorer()
        self.monitor = MonitoringDashboard()
        self.llm_integrator = LLMIntegrator() if enable_llm else None
        self._load_config()
    
    def _load_config(self):
        try:
            with open('../assets/config.yaml', 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
            self.config = {}
    
    def _process_alert(self, alert, use_llm=True):
        start_time = time.time()
        
        if self.enable_cache:
            cached_result = self.cache.get(alert)
            if cached_result:
                processing_time = (time.time() - start_time) * 1000
                self.monitor.record_alert(processing_time, cached_result['risk_level'], 
                                         attack_type=cached_result.get('event_type'),
                                         is_cached=True)
                return cached_result
        
        result = {
            'alert_id': alert.get('alert_id', ''),
            'event_type': alert.get('event_type', alert.get('attack_type', '')),
            'risk_level': 'L4_LOW',
            'risk_score': 0,
            'score_breakdown': {},
            'attack_success': False,
            'analysis': '',
            'llm_analysis': '',
            'recommendations': [],
            'disposition': '正常处理',
            'is_false_positive': False,
            'rule_match': None
        }
        
        matched_rule = self.suppression_engine.match_rule(alert)
        if matched_rule:
            result['rule_match'] = matched_rule.get('name', 'Unknown Rule')
            result['disposition'] = matched_rule.get('action', 'silence')
            
            if result['disposition'] == 'silence':
                result['risk_level'] = 'L4_LOW'
                result['risk_score'] = 0
                result['analysis'] = f"告警已被白名单抑制: {matched_rule.get('note', '')}"
                processing_time = (time.time() - start_time) * 1000
                self.monitor.record_alert(processing_time, result['risk_level'], 
                                         attack_type=result['event_type'],
                                         is_cached=False, is_rule_match=True)
                if self.enable_cache:
                    self.cache.set(alert, result)
                return result
        
        attack_success = self.attack_detector.detect(alert)
        result['attack_success'] = attack_success
        
        dest_ip = alert.get('dest_ip', alert.get('dst_ip', ''))
        asset_criticality = self.asset_manager.get_asset_criticality(dest_ip)
        
        risk_score, score_breakdown = self.risk_scorer.calculate_score(alert, attack_success, asset_criticality)
        result['risk_score'] = risk_score
        result['score_breakdown'] = score_breakdown
        result['risk_level'] = self.risk_scorer.get_risk_level(risk_score)
        
        if attack_success:
            result['analysis'] = f"{alert.get('attack_type', '攻击')}成功"
            result['recommendations'] = ['实时通知', '隔离主机', '取证分析']
            result['disposition'] = '实时通知'
        else:
            result['analysis'] = f"{alert.get('attack_type', '攻击')}未成功或已被拦截"
            if risk_score < 40:
                result['is_false_positive'] = True
                result['recommendations'] = ['记录日志', '持续监控']
                result['disposition'] = '记录日志'
            else:
                result['recommendations'] = ['持续监控', '分析溯源']
                result['disposition'] = '正常处理'
        
        if alert.get('is_false_positive', False):
            result['is_false_positive'] = True
            result['risk_level'] = 'L4_LOW'
            result['risk_score'] = 0
            result['analysis'] = f"已知误报: {alert.get('reason', '')}"
            result['disposition'] = '记录日志'
        
        if self.enable_llm and use_llm and result['risk_score'] >= 50:
            llm_result = self.llm_integrator.analyze_with_llm(alert)
            if llm_result:
                result['llm_analysis'] = llm_result
                llm_success = True
            else:
                llm_success = False
        else:
            llm_success = False
        
        processing_time = (time.time() - start_time) * 1000
        self.monitor.record_alert(processing_time, result['risk_level'], 
                                  attack_type=result['event_type'],
                                  asset_type=asset_criticality,
                                  is_cached=False, 
                                  is_false_positive=result['is_false_positive'],
                                  is_rule_match=matched_rule is not None,
                                  llm_used=self.enable_llm and use_llm and result['risk_score'] >= 50,
                                  llm_success=llm_success)
        
        if self.enable_cache:
            self.cache.set(alert, result)
        
        return result
    
    def _analyze_sequential(self, alerts):
        results = []
        for alert in alerts:
            result = self._process_alert(alert)
            results.append(result)
            level = result['risk_level']
            fp_mark = '[FP]' if result['is_false_positive'] else ''
            wl_mark = '[WL]' if result['rule_match'] else ''
            llm_mark = '[LLM]' if result.get('llm_analysis') else ''
            print(f"{result['alert_id']}: {level} ({result['risk_score']}分) {fp_mark}{wl_mark}{llm_mark}")
        return results
    
    def _analyze_parallel(self, alerts):
        results = {}
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._process_alert, alert): alert.get('alert_id') for alert in alerts}
            
            for future in as_completed(futures):
                alert_id = futures[future]
                try:
                    result = future.result()
                    results[alert_id] = result
                    level = result['risk_level']
                    fp_mark = '[FP]' if result['is_false_positive'] else ''
                    wl_mark = '[WL]' if result['rule_match'] else ''
                    llm_mark = '[LLM]' if result.get('llm_analysis') else ''
                    print(f"{result['alert_id']}: {level} ({result['risk_score']}分) {fp_mark}{wl_mark}{llm_mark}")
                except Exception as e:
                    logger.error(f"处理告警 {alert_id} 时出错: {e}")
        
        return sorted(results.values(), key=lambda r: r['alert_id'])
    
    def analyze_alerts(self, alerts, parallel=True):
        if parallel and len(alerts) > 1:
            return self._analyze_parallel(alerts)
        else:
            return self._analyze_sequential(alerts)
    
    def get_monitor_report(self):
        return self.monitor.get_report()
    
    def provide_feedback(self, alert_id, actual_risk_level):
        self.risk_scorer.provide_feedback(alert_id, actual_risk_level)
