from scapy.layers.inet import IP, TCP, UDP
import logging
from datetime import datetime

class AlertHandler:
    def __init__(self, firewall_handler=None):
        self.logger = logging.getLogger('AlertHandler')
        self.firewall_handler = firewall_handler
        
    def handle_alert(self, packet, rule_alerts, ml_result):
        """处理告警"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = packet[IP].src
        
        # 处理规则引擎告警
        for alert in rule_alerts:
            alert_msg = (
                f"[{timestamp}] 规则告警: {alert['rule_name']}\n"
                f"源IP: {src_ip}, 严重程度: {alert['severity']}"
            )
            self.logger.warning(alert_msg)
            
            # 对高危告警进行自动封禁
            if alert['severity'] == 'high' and self.firewall_handler:
                self.firewall_handler.ban_ip(
                    src_ip,
                    f"触发高危规则: {alert['rule_name']}"
                )
                
        # 处理机器学习告警
        if ml_result and ml_result['is_attack']:
            alert_msg = (
                f"[{timestamp}] ML检测告警\n"
                f"源IP: {src_ip}, 置信度: {ml_result['confidence']:.2f}"
            )
            self.logger.warning(alert_msg)
            
            # 对高置信度的攻击进行自动封禁
            if ml_result['confidence'] > 0.9 and self.firewall_handler:
                self.firewall_handler.ban_ip(
                    src_ip,
                    f"ML检测高置信度攻击 (置信度: {ml_result['confidence']:.2f})"
                ) 