import logging
from queue import Queue, Empty, Full
import threading
from scapy.all import sniff
from typing import Callable

from ids.models.packet_features import PacketFeatures

class PacketCapture:
    def __init__(self, interface=None, queue_size=1000):
        self.interface = interface
        self.is_running = False
        self.packet_queue = Queue(maxsize=queue_size)
        self.logger = logging.getLogger(__name__)
        
    def start_capture(self, packet_callback):
        """开始捕获数据包"""
        self.packet_callback = packet_callback
        self.capture_thread = threading.Thread(target=self._capture)
        self.capture_thread.start()
        
    def _capture(self):
        """实际的数据包捕获函数"""
        sniff(
            iface=self.interface,
            prn=self._packet_handler,
            stop_filter=lambda _: self.stop_capture.is_set()
        )
        
    def _packet_handler(self, packet):
        """处理捕获的数据包"""
        if IP in packet:
            if self.packet_callback:
                self.packet_callback(packet)
                
    def stop(self):
        """停止捕获"""
        self.stop_capture.set() 