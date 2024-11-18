from queue import Queue, Empty, Full
import threading
from scapy.all import sniff
import logging

class PacketCapture:
    def __init__(self, interface=None, queue_size=1000):
        self.interface = interface
        self.is_running = False
        self.packet_queue = Queue(maxsize=queue_size)
        self.logger = logging.getLogger(__name__)
        
    def start_capture(self, callback):
        """启动数据包捕获
        
        Args:
            callback: IDS中的packet_handler回调函数
        """
        self.is_running = True
        
        # 1. 消费者线程：处理数据包
        process_thread = threading.Thread(
            target=self._process_queue,
            args=(callback,),
            name="PacketProcessor"
        )
        process_thread.start()
        
        # 2. 生产者：捕获数据包
        def packet_callback(packet):
            """数据包捕获回调"""
            try:
                # 将数据包放入队列（非阻塞）
                self.packet_queue.put(packet, block=False)
            except Full:
                self.logger.warning("数据包队列已满，丢弃数据包")
                
        # 3. 启动数据包捕获
        sniff(
            iface=self.interface,
            prn=packet_callback,    # 捕获回调
            store=0,               # 不存储数据包
            stop_filter=lambda x: not self.is_running
        )
        
        # 4. 等待处理线程结束
        process_thread.join()
        
    def _process_queue(self, callback):
        """处理队列中的数据包（消费者）"""
        while self.is_running:
            try:
                # 从队列中获取数据包（1秒超时）
                packet = self.packet_queue.get(timeout=1)
                # 调用IDS的packet_handler处理数据包
                callback(packet)
                # 标记任务完成
                self.packet_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"处理数据包时出错: {str(e)}")
                
    def stop(self):
        """停止捕获"""
        self.is_running = False