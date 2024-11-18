import pytest
from scapy.all import IP, TCP
from queue import Queue

from ids.capture.packet_capture import PacketCapture
from ids.models.packet_features import PacketFeatures

def test_packet_capture_init():
    capture = PacketCapture(interface='lo')
    assert capture.interface == 'lo'
    assert not capture.is_running

def test_packet_processing():
    capture = PacketCapture(interface='lo')
    
    # 创建测试数据包
    test_packet = IP(src='127.0.0.1', dst='127.0.0.1')/TCP(sport=12345, dport=80)
    
    # 测试数据包处理
    processed = False
    def callback(packet):
        nonlocal processed
        processed = True
    
    capture.packet_queue.put(test_packet)
    capture._process_queue(callback)
    
    assert processed 