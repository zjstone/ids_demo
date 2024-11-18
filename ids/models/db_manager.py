from scapy.layers.inet import IP, TCP, UDP
from .database import init_db, Packet, Alert, Rule, Config, CorrelationAlert
from datetime import datetime
import json

class DatabaseManager:
    def __init__(self, db_url):
        self.session = init_db(db_url)
        
    def save_packet(self, packet, features):
        """保存数据包信息"""
        packet_data = {
            'timestamp': datetime.utcnow(),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'OTHER',
            'length': len(packet),
            'raw_data': self._packet_to_dict(packet),
            'features': features
        }
        
        if TCP in packet:
            packet_data.update({
                'src_port': packet[TCP].sport,
                'dst_port': packet[TCP].dport
            })
        elif UDP in packet:
            packet_data.update({
                'src_port': packet[UDP].sport,
                'dst_port': packet[UDP].dport
            })
            
        db_packet = Packet(**packet_data)
        self.session.add(db_packet)
        self.session.commit()
        return db_packet
        
    def save_alert(self, packet_db, rule_alerts, ml_result):
        """保存告警信息"""
        # 保存规则告警
        for alert in rule_alerts:
            alert_data = {
                'packet_id': packet_db.id,
                'alert_type': 'rule',
                'rule_name': alert['rule_name'],
                'severity': alert['severity'],
                'description': f"触发规则: {alert['rule_name']}"
            }
            db_alert = Alert(**alert_data)
            self.session.add(db_alert)
            
        # 保存ML告警
        if ml_result and ml_result['is_attack']:
            alert_data = {
                'packet_id': packet_db.id,
                'alert_type': 'ml',
                'severity': 'high' if ml_result['confidence'] > 0.9 else 'medium',
                'confidence': ml_result['confidence'],
                'description': f"ML检测到攻击 (置信度: {ml_result['confidence']:.2f})"
            }
            db_alert = Alert(**alert_data)
            self.session.add(db_alert)
            
        self.session.commit()
        
    def save_correlation_alert(self, alert_data):
        """保存关联告警"""
        correlation_alert = CorrelationAlert(**alert_data)
        self.session.add(correlation_alert)
        self.session.commit()
        return correlation_alert
        
    def _packet_to_dict(self, packet):
        """将数据包转换为可JSON序列化的字典"""
        return json.loads(packet.show(dump=True)) 