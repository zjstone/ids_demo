from collections import defaultdict
import time

class SessionHandler:
    def __init__(self, timeout=60):
        self.sessions = defaultdict(list)
        self.timeout = timeout
        
    def get_session_key(self, packet):
        """生成会话键值"""
        ip = packet.getlayer('IP')
        if TCP in packet:
            return (
                f"{ip.src}:{packet[TCP].sport}",
                f"{ip.dst}:{packet[TCP].dport}",
                'TCP'
            )
        elif UDP in packet:
            return (
                f"{ip.src}:{packet[UDP].sport}",
                f"{ip.dst}:{packet[UDP].dport}",
                'UDP'
            )
        return None
        
    def add_packet(self, packet):
        """将数据包添加到对应的会话中"""
        session_key = self.get_session_key(packet)
        if session_key:
            self.sessions[session_key].append({
                'packet': packet,
                'timestamp': time.time()
            })
            self._cleanup_old_sessions()
            
    def _cleanup_old_sessions(self):
        """清理超时的会话"""
        current_time = time.time()
        expired_sessions = []
        
        for key, session in self.sessions.items():
            if current_time - session[-1]['timestamp'] > self.timeout:
                expired_sessions.append(key)
                
        for key in expired_sessions:
            del self.sessions[key] 