from capture.packet_capture import PacketCapture
from capture.session_handler import SessionHandler
from features.packet_features import PacketFeatureExtractor
from features.session_features import SessionFeatureExtractor
from detectors.rule_engine import RuleEngine, Rule
from detectors.ml_engine import MLEngine
from utils.alert import AlertHandler
from utils.firewall import IPTablesHandler
from models.db_manager import DatabaseManager
from web.api import IDSAPI
from correlation.event_correlator import EventCorrelator
import logging
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import yaml

class IDS:
    def __init__(self, interface=None, firewall_config=None, db_url=None, rules_dir='rules'):
        # 设置日志
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # 初始化防火墙处理器
        self.firewall_handler = IPTablesHandler(
            ban_time=300,  # 5分钟封禁
            remote_config=firewall_config
        )
        
        self.packet_capture = PacketCapture(interface)
        self.session_handler = SessionHandler()
        self.packet_feature_extractor = PacketFeatureExtractor()
        self.session_feature_extractor = SessionFeatureExtractor()
        self.rule_engine = RuleEngine(rules_dir)
        self.ml_engine = MLEngine()
        self.alert_handler = AlertHandler(firewall_handler=self.firewall_handler)
        
        # 添加防火墙清理线程
        self.firewall_cleanup_thread = threading.Thread(
            target=self._firewall_cleanup_loop,
            daemon=True
        )
        
        # 初始化数据库
        self.db_manager = DatabaseManager(db_url or 'sqlite:///ids.db')
        
        # 初始化Web API
        self.api = IDSAPI(self.db_manager, self)
        self.api_thread = threading.Thread(target=self.api.run)
        
        # 初始化事件关联器
        self.event_correlator = EventCorrelator(self.db_manager)
        
        # 添加线程池
        self.detection_executor = ThreadPoolExecutor(max_workers=2)
        
        # 添加一些基本规则
        self._setup_rules()
        
    def _firewall_cleanup_loop(self):
        """定期检查并解封超时的IP"""
        while True:
            self.firewall_handler.check_and_unban()
            time.sleep(60)  # 每分钟检查一次
            
    def _setup_rules(self):
        """设置基本检测规则"""
        # 端口扫描检测
        port_scan_rule = Rule(
            name="Port Scan Detection",
            conditions=[
                ('tcp_dport', 'in', range(1, 1024)),
                ('packet_count', '>', 100),
                ('duration', '<', 10)
            ],
            severity='high'
        )
        
        # SYN泛洪攻击检测
        syn_flood_rule = Rule(
            name="SYN Flood Detection",
            conditions=[
                ('tcp_flags', '==', 0x02),  # SYN标志
                ('packet_count', '>', 200),
                ('duration', '<', 5)
            ],
            severity='high'
        )
        
        # 大流���UDP攻击检测
        udp_flood_rule = Rule(
            name="UDP Flood Detection",
            conditions=[
                ('bytes_per_second', '>', 1000000),  # 1MB/s
                ('packet_count', '>', 1000)
            ],
            severity='high'
        )
        
        # 异常数据包大小检测
        large_packet_rule = Rule(
            name="Large Packet Detection",
            conditions=[
                ('ip_len', '>', 1500)  # 超过典型MTU
            ],
            severity='medium'
        )
        
        # 添加所有规则
        for rule in [port_scan_rule, syn_flood_rule, udp_flood_rule, large_packet_rule]:
            self.rule_engine.add_rule(rule)
        
    def packet_handler(self, packet):
        """处理捕获的数据包"""
        # 提取数据包特征
        packet_features = self.packet_feature_extractor.extract_features(packet)
        
        # 保存数据包
        packet_db = self.db_manager.save_packet(packet, packet_features)
        
        # 并行执行规则检测和机器学习检测
        rule_future = self.detection_executor.submit(
            self.rule_engine.check_packet, packet, packet_features
        )
        ml_future = self.detection_executor.submit(
            self.ml_engine.predict, packet_features
        )
        
        # 获取检测结果
        rule_alerts = rule_future.result()
        ml_result = ml_future.result()
        
        # 处理会话
        self.session_handler.add_packet(packet)
        session_key = self.session_handler.get_session_key(packet)
        if session_key:
            session = self.session_handler.sessions[session_key]
            session_features = self.session_feature_extractor.extract_features(session)
            
            # 基于会话的检测
            session_rule_alerts = self.rule_engine.check_packet(packet, session_features)
            rule_alerts.extend(session_rule_alerts)
        
        # 保存告警
        if rule_alerts or (ml_result and ml_result['is_attack']):
            self.db_manager.save_alert(packet_db, rule_alerts, ml_result)
            self.alert_handler.handle_alert(packet, rule_alerts, ml_result)
            
            # 如果产生告警，发送到事件关联器
            event_data = {
                'timestamp': datetime.utcnow(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'OTHER',
                'alert_type': 'rule' if rule_alerts else 'ml',
                'severity': rule_alerts[0]['severity'] if rule_alerts else 'high',
                'rule_name': rule_alerts[0]['rule_name'] if rule_alerts else None,
                'ml_confidence': ml_result['confidence'] if ml_result else None
            }
            self.event_correlator.process_event(event_data)
        
    def start(self):
        """启动IDS"""
        print("启动入侵检测系统...")
        # 启动Web API
        self.api_thread.start()
        # 启动其他组件
        self.firewall_cleanup_thread.start()
        self.packet_capture.start_capture(self.packet_handler)
        
    def stop(self):
        """停止IDS"""
        print("停止入侵检测系统...")
        self.detection_executor.shutdown()  # 关闭线程池
        self.packet_capture.stop() 
        
    def reload_rules(self):
        """重新加载规则"""
        self.rule_engine.reload_rules()
    
    def add_rule(self, rule_data: dict):
        """动态添加规则"""
        rule = Rule.from_dict(rule_data)
        self.rule_engine.add_rule(rule)
    
    def remove_rule(self, rule_name: str):
        """删除规则"""
        self.rule_engine.remove_rule(rule_name)
    
    def enable_rule(self, rule_name: str):
        """启用规则"""
        self.rule_engine.enable_rule(rule_name)
    
    def disable_rule(self, rule_name: str):
        """禁用规则"""
        self.rule_engine.disable_rule(rule_name)

def parse_args():
    """解析命令行参数"""
    import argparse
    parser = argparse.ArgumentParser(description='入侵检测系统')
    parser.add_argument('-i', '--interface', 
                      help='要监听的网络接口名称（例如：eth0）',
                      default=None)
    parser.add_argument('-r', '--rules-dir', 
                      help='规则文件目录路径',
                      default='rules')
    parser.add_argument('-d', '--db-url', 
                      help='数据库URL（例如：sqlite:///ids.db）',
                      default='sqlite:///ids.db')
    parser.add_argument('-f', '--firewall-config',
                      help='防火墙配置文件路径',
                      default=None)
    return parser.parse_args()

def load_config(config_file='config/ids_config.yaml'):
    """加载配置文件"""
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.warning(f"无法加载配置文件: {str(e)}")
        return {}

def main():
    """主函数"""
    # 加载配置文件
    config = load_config()
    
    # 解析命令行参数
    args = parse_args()
    
    # 合并配置（命令行参数优先）
    final_config = {
        'interface': args.interface or config.get('interface'),
        'rules_dir': args.rules_dir or config.get('rules_dir', 'rules'),
        'db_url': args.db_url or config.get('db_url', 'sqlite:///ids.db'),
        'firewall_config': args.firewall_config or config.get('firewall_config')
    }
    
    try:
        # 创建IDS实例
        ids = IDS(**final_config)
        
        # 注册信号处理
        import signal
        def signal_handler(signum, frame):
            print("\n正在关闭IDS...")
            ids.stop()
            exit(0)
            
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # 启动IDS
        print(f"""
入侵检测系统启动参数：
- 网络接口: {final_config['interface'] or '默认接口'}
- 规则目录: {final_config['rules_dir']}
- 数据库URL: {final_config['db_url']}
- 防火墙配置: {final_config['firewall_config'] or '默认配置'}
        """)
        
        ids.start()
        
        # 保持主线程运行
        while True:
            import time
            time.sleep(1)
            
    except Exception as e:
        logging.error(f"IDS启动失败: {str(e)}")
        raise

if __name__ == "__main__":
    main()