from collections import defaultdict
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
import threading
import time

class CorrelationRule:
    def __init__(self, name: str, conditions: Dict[str, Any], time_window: int, threshold: int, severity: str):
        """
        初始化关联规则
        Args:
            name: 规则名称
            conditions: 匹配条件
            time_window: 时间窗口（秒）
            threshold: 触发阈值
            severity: 严重程度
        """
        self.name = name
        self.conditions = conditions
        self.time_window = time_window
        self.threshold = threshold
        self.severity = severity

class EventCorrelator:
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.logger = logging.getLogger('EventCorrelator')
        self.event_buffer = defaultdict(list)  # 事件缓冲区
        self.correlation_rules = []  # 关联规则列表
        self.lock = threading.Lock()
        
        # 启动清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        # 初始化默认规则
        self._setup_default_rules()
        
    def _setup_default_rules(self):
        """设置默认关联规则"""
        # 端口扫描关联规则
        port_scan_rule = CorrelationRule(
            name="Distributed Port Scan",
            conditions={
                'alert_type': 'rule',
                'rule_name': 'Port Scan Detection',
                'group_by': ['src_ip']
            },
            time_window=300,  # 5分钟
            threshold=3,      # 3次及以上
            severity='high'
        )
        
        # 暴力破解关联规则
        brute_force_rule = CorrelationRule(
            name="Brute Force Attack",
            conditions={
                'dst_port': [22, 23, 3389],  # SSH, Telnet, RDP
                'group_by': ['src_ip', 'dst_ip']
            },
            time_window=600,  # 10分钟
            threshold=100,    # 100次及以上
            severity='high'
        )
        
        # DDoS攻击关联规则
        ddos_rule = CorrelationRule(
            name="DDoS Attack",
            conditions={
                'alert_type': ['rule', 'ml'],
                'severity': 'high',
                'group_by': ['dst_ip']
            },
            time_window=60,   # 1分钟
            threshold=1000,   # 1000个数据包
            severity='critical'
        )
        
        self.add_rule(port_scan_rule)
        self.add_rule(brute_force_rule)
        self.add_rule(ddos_rule)
        
    def add_rule(self, rule: CorrelationRule):
        """添加关联规则"""
        self.correlation_rules.append(rule)
        
    def process_event(self, event: Dict):
        """处理新事件"""
        with self.lock:
            current_time = datetime.utcnow()
            
            # 将事件添加到缓冲区
            for rule in self.correlation_rules:
                if self._event_matches_conditions(event, rule.conditions):
                    key = self._generate_group_key(event, rule.conditions['group_by'])
                    self.event_buffer[key].append({
                        'timestamp': current_time,
                        'event': event
                    })
                    
                    # 检查是否触发规则
                    if self._check_rule_trigger(key, rule):
                        self._generate_correlation_alert(key, rule)
                        
    def _event_matches_conditions(self, event: Dict, conditions: Dict) -> bool:
        """检查事件是否匹配条件"""
        for key, value in conditions.items():
            if key == 'group_by':
                continue
                
            if key not in event:
                return False
                
            if isinstance(value, list):
                if event[key] not in value:
                    return False
            elif event[key] != value:
                return False
                
        return True
        
    def _generate_group_key(self, event: Dict, group_by: List[str]) -> str:
        """生成分组键值"""
        return "|".join(str(event.get(field, '')) for field in group_by)
        
    def _check_rule_trigger(self, key: str, rule: CorrelationRule) -> bool:
        """检查是否触发规则"""
        current_time = datetime.utcnow()
        window_start = current_time - timedelta(seconds=rule.time_window)
        
        # 统计时间窗口内的事件数
        events_in_window = [
            e for e in self.event_buffer[key]
            if e['timestamp'] >= window_start
        ]
        
        return len(events_in_window) >= rule.threshold
        
    def _generate_correlation_alert(self, key: str, rule: CorrelationRule):
        """生成关联告警"""
        events = self.event_buffer[key]
        
        correlation_alert = {
            'timestamp': datetime.utcnow(),
            'alert_type': 'correlation',
            'rule_name': rule.name,
            'severity': rule.severity,
            'description': f"检测到关联事件: {rule.name}",
            'events_count': len(events),
            'related_events': [e['event'] for e in events[-10:]],  # 最近10个相关事件
            'first_event_time': events[0]['timestamp'],
            'last_event_time': events[-1]['timestamp']
        }
        
        # 保存到数据库
        self.db_manager.save_correlation_alert(correlation_alert)
        self.logger.warning(
            f"关联告警: {rule.name}, 严重程度: {rule.severity}, "
            f"相关事件数: {len(events)}"
        )
        
    def _cleanup_loop(self):
        """清理过期事件"""
        while True:
            with self.lock:
                current_time = datetime.utcnow()
                # 找出最长的时间窗口
                max_window = max(
                    (rule.time_window for rule in self.correlation_rules),
                    default=3600
                )
                cutoff_time = current_time - timedelta(seconds=max_window)
                
                # 清理过期事件
                for key in list(self.event_buffer.keys()):
                    self.event_buffer[key] = [
                        e for e in self.event_buffer[key]
                        if e['timestamp'] >= cutoff_time
                    ]
                    
                    # 如果没有事件了，删除这个key
                    if not self.event_buffer[key]:
                        del self.event_buffer[key]
                        
            time.sleep(60)  # 每分钟清理一次 