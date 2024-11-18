import yaml
import json
import logging
from pathlib import Path
from threading import Lock
from typing import List, Dict, Any

class Rule:
    def __init__(self, name: str, conditions: List, severity: str = 'medium', enabled: bool = True):
        self.name = name
        self.conditions = conditions
        self.severity = severity
        self.enabled = enabled
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Rule':
        return cls(
            name=data['name'],
            conditions=data['conditions'],
            severity=data.get('severity', 'medium'),
            enabled=data.get('enabled', True)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'conditions': self.conditions,
            'severity': self.severity,
            'enabled': self.enabled
        }

class RuleEngine:
    def __init__(self, rules_dir: str = 'rules'):
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, Rule] = {}
        self.rules_lock = Lock()
        self.logger = logging.getLogger(__name__)
        
        # 创建规则目录（如果不存在）
        self.rules_dir.mkdir(exist_ok=True)
        
        # 加载默认规则
        self.load_rules()
        
    def load_rules(self) -> None:
        """从规则目录加载所有规则文件"""
        with self.rules_lock:
            self.rules.clear()
            for rule_file in self.rules_dir.glob('*.yaml'):
                try:
                    with open(rule_file, 'r', encoding='utf-8') as f:
                        rules_data = yaml.safe_load(f)
                        for rule_data in rules_data.get('rules', []):
                            rule = Rule.from_dict(rule_data)
                            self.rules[rule.name] = rule
                            self.logger.info(f"已加载规则: {rule.name}")
                except Exception as e:
                    self.logger.error(f"加载规则文件 {rule_file} 失败: {str(e)}")
    
    def reload_rules(self) -> None:
        """重新加载所有规则"""
        self.load_rules()
        self.logger.info("规则重新加载完成")
    
    def add_rule(self, rule: Rule) -> None:
        """动态添加新规则"""
        with self.rules_lock:
            self.rules[rule.name] = rule
            # 保存到文件
            self._save_rule(rule)
        self.logger.info(f"已添加新规则: {rule.name}")
    
    def remove_rule(self, rule_name: str) -> None:
        """删除规则"""
        with self.rules_lock:
            if rule_name in self.rules:
                del self.rules[rule_name]
                self.logger.info(f"已删除规则: {rule_name}")
    
    def enable_rule(self, rule_name: str) -> None:
        """启用规则"""
        with self.rules_lock:
            if rule_name in self.rules:
                self.rules[rule_name].enabled = True
                self._save_rule(self.rules[rule_name])
                self.logger.info(f"已启用规则: {rule_name}")
    
    def disable_rule(self, rule_name: str) -> None:
        """禁用规则"""
        with self.rules_lock:
            if rule_name in self.rules:
                self.rules[rule_name].enabled = False
                self._save_rule(self.rules[rule_name])
                self.logger.info(f"已禁用规则: {rule_name}")
    
    def _save_rule(self, rule: Rule) -> None:
        """保存规则到文件"""
        custom_rules_file = self.rules_dir / 'custom_rules.yaml'
        try:
            # 读取现有规则
            if custom_rules_file.exists():
                with open(custom_rules_file, 'r', encoding='utf-8') as f:
                    rules_data = yaml.safe_load(f) or {'rules': []}
            else:
                rules_data = {'rules': []}
            
            # 更新或添加规则
            rule_dict = rule.to_dict()
            found = False
            for i, existing_rule in enumerate(rules_data['rules']):
                if existing_rule['name'] == rule.name:
                    rules_data['rules'][i] = rule_dict
                    found = True
                    break
            
            if not found:
                rules_data['rules'].append(rule_dict)
            
            # 保存回文件
            with open(custom_rules_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump(rules_data, f, allow_unicode=True)
                
        except Exception as e:
            self.logger.error(f"保存规则失败: {str(e)}")
    
    def check_packet(self, packet, features: Dict) -> List[Dict]:
        """检查数据包是否触发规则"""
        alerts = []
        with self.rules_lock:
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                    
                if self._check_conditions(rule.conditions, features):
                    alerts.append({
                        'rule_name': rule.name,
                        'severity': rule.severity,
                        'timestamp': features.get('timestamp')
                    })
        return alerts
    
    def _check_conditions(self, conditions: List, features: Dict) -> bool:
        """检查是否满足规则条件"""
        for feature, operator, value in conditions:
            if feature not in features:
                return False
                
            feature_value = features[feature]
            
            if operator == "in":
                if isinstance(value, str) and '-' in value:
                    # 处理范围值，如 "1-1024"
                    start, end = map(int, value.split('-'))
                    if not (start <= feature_value <= end):
                        return False
                elif feature_value not in value:
                    return False
            elif operator == "==":
                if isinstance(value, str) and value.startswith("0x"):
                    # 处理十六进制值
                    if feature_value != int(value, 16):
                        return False
                elif feature_value != value:
                    return False
            elif operator == ">":
                if not (feature_value > value):
                    return False
            elif operator == "<":
                if not (feature_value < value):
                    return False
            elif operator == ">=":
                if not (feature_value >= value):
                    return False
            elif operator == "<=":
                if not (feature_value <= value):
                    return False
                    
        return True 