from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class PacketFeatures:
    """数据包特征类"""
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int
    dst_port: int
    packet_size: int
    tcp_flags: int = None
    udp_length: int = None
    
    @classmethod
    def from_packet(cls, packet) -> 'PacketFeatures':
        """从数据包提取特征"""
        # 实现特征提取逻辑
        pass
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'timestamp': self.timestamp,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'packet_size': self.packet_size,
            'tcp_flags': self.tcp_flags,
            'udp_length': self.udp_length
        } 