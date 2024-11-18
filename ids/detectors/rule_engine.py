import yaml
import logging
from pathlib import Path
from threading import Lock
from typing import List, Dict, Any

from ids.models.packet_features import PacketFeatures

class Rule:
    def __init__(self, name: str, conditions: List, severity: str = 'medium', enabled: bool = True):
        self.name = name
        self.conditions = conditions
        self.severity = severity
        self.enabled = enabled

class RuleEngine:
    def __init__(self, rules_dir: str = 'rules'):
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, Rule] = {}
        self.rules_lock = Lock()
        self.logger = logging.getLogger(__name__)
        
    def add_rule(self, rule):
        self.rules.append(rule)
        
    def check_packet(self, packet, features):
        """检查数据包是否触发规则"""
        alerts = []
        for rule in self.rules:
            if all(self._check_condition(features, cond) for cond in rule.conditions):
                alerts.append({
                    'rule_name': rule.name,
                    'severity': rule.severity,
                    'timestamp': time.time()
                })
        return alerts
    
    def _check_condition(self, features, condition):
        """检查单个条件"""
        feature, operator, value = condition
        
        if feature not in features:
            return False
            
        if operator == '==':
            return features[feature] == value
        elif operator == '>':
            return features[feature] > value
        elif operator == '<':
            return features[feature] < value
        elif operator == 'in':
            return features[feature] in value
        
        return False 