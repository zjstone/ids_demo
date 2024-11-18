from scapy.layers.inet import IP, TCP, UDP
import numpy as np
from collections import Counter

class SessionFeatureExtractor:
    def extract_features(self, session):
        """提取会话特征"""
        packets = [p['packet'] for p in session]
        
        features = {
            'duration': session[-1]['timestamp'] - session[0]['timestamp'],
            'packet_count': len(packets),
            'bytes_total': sum(p[IP].len for p in packets if IP in p),
            'bytes_per_second': 0,  # 将在下面计算
            'packet_size_mean': np.mean([p[IP].len for p in packets if IP in p]),
            'packet_size_std': np.std([p[IP].len for p in packets if IP in p]),
        }
        
        # 计算每秒字节数
        duration = features['duration']
        if duration > 0:
            features['bytes_per_second'] = features['bytes_total'] / duration
            
        return features 