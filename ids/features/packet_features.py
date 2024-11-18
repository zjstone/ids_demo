from scapy.layers.inet import IP, TCP, UDP
import numpy as np

class PacketFeatureExtractor:
    def extract_features(self, packet):
        """提取数据包特征"""
        features = {}
        
        if IP in packet:
            features.update({
                'ip_len': packet[IP].len,
                'ip_ttl': packet[IP].ttl,
                'ip_proto': packet[IP].proto,
            })
            
        if TCP in packet:
            features.update({
                'tcp_sport': packet[TCP].sport,
                'tcp_dport': packet[TCP].dport,
                'tcp_flags': packet[TCP].flags,
                'tcp_window': packet[TCP].window,
            })
            
        if UDP in packet:
            features.update({
                'udp_sport': packet[UDP].sport,
                'udp_dport': packet[UDP].dport,
                'udp_len': packet[UDP].len,
            })
            
        return features 