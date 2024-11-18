import subprocess
import logging
from threading import Lock
import time
import paramiko
from typing import Optional, Dict, List

class FirewallHandler:
    """防火墙处理基类"""
    def ban_ip(self, ip_address: str, reason: str) -> bool:
        raise NotImplementedError
        
    def unban_ip(self, ip_address: str) -> bool:
        raise NotImplementedError
        
    def is_banned(self, ip_address: str) -> bool:
        raise NotImplementedError
        
    def check_and_unban(self):
        raise NotImplementedError

class IPTablesHandler(FirewallHandler):
    def __init__(self, ban_time=300, remote_config: Optional[Dict] = None):
        """
        初始化IPTables处理器
        Args:
            ban_time: 封禁时长（秒）
            remote_config: 远程服务器配置，格式：
                {
                    'host': 'hostname',
                    'port': 22,
                    'username': 'user',
                    'password': 'pass'  # 或 'key_filename': '/path/to/key'
                }
        """
        self.ban_time = ban_time
        self.banned_ips = {}
        self.lock = Lock()
        self.logger = logging.getLogger('IPTablesHandler')
        self.remote_config = remote_config
        self.ssh_client = None
        
        if remote_config:
            self._setup_ssh_connection()
            
    def _setup_ssh_connection(self):
        """建立SSH连接"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.remote_config['host'],
                'port': self.remote_config.get('port', 22),
                'username': self.remote_config['username'],
            }
            
            if 'password' in self.remote_config:
                connect_kwargs['password'] = self.remote_config['password']
            elif 'key_filename' in self.remote_config:
                connect_kwargs['key_filename'] = self.remote_config['key_filename']
                
            self.ssh_client.connect(**connect_kwargs)
            self.logger.info(f"已成功连接到防火墙服务器 {self.remote_config['host']}")
            
        except Exception as e:
            self.logger.error(f"连接防火墙服务器失败: {str(e)}")
            self.ssh_client = None
            
    def _execute_command(self, command: str) -> tuple:
        """执行命令（本地或远程）"""
        if self.remote_config and self.ssh_client:
            try:
                stdin, stdout, stderr = self.ssh_client.exec_command(command)
                return stdout.read().decode(), stderr.read().decode(), stdout.channel.recv_exit_status()
            except Exception as e:
                self.logger.error(f"远程执行命令失败: {str(e)}")
                # 尝试重新连接
                self._setup_ssh_connection()
                return "", str(e), 1
        else:
            try:
                result = subprocess.run(
                    command.split(),
                    capture_output=True,
                    text=True,
                    check=False
                )
                return result.stdout, result.stderr, result.returncode
            except Exception as e:
                return "", str(e), 1
                
    def ban_ip(self, ip_address: str, reason: str) -> bool:
        """封禁指定IP"""
        with self.lock:
            if ip_address in self.banned_ips:
                return False
                
            cmd = f"iptables -A INPUT -s {ip_address} -j DROP"
            stdout, stderr, exit_code = self._execute_command(cmd)
            
            if exit_code == 0:
                self.banned_ips[ip_address] = {
                    'timestamp': time.time(),
                    'reason': reason
                }
                self.logger.info(f"已封禁IP {ip_address}, 原因: {reason}")
                return True
            else:
                self.logger.error(f"封禁IP {ip_address} 失败: {stderr}")
                return False
                
    def unban_ip(self, ip_address: str) -> bool:
        """解封指定IP"""
        with self.lock:
            if ip_address not in self.banned_ips:
                return False
                
            cmd = f"iptables -D INPUT -s {ip_address} -j DROP"
            stdout, stderr, exit_code = self._execute_command(cmd)
            
            if exit_code == 0:
                del self.banned_ips[ip_address]
                self.logger.info(f"已解封IP {ip_address}")
                return True
            else:
                self.logger.error(f"解封IP {ip_address} 失败: {stderr}")
                return False
                
    def check_and_unban(self):
        """检查并解封超时的IP"""
        current_time = time.time()
        with self.lock:
            expired_ips = [
                ip for ip, info in self.banned_ips.items()
                if current_time - info['timestamp'] > self.ban_time
            ]
            
            for ip in expired_ips:
                self.unban_ip(ip)
                
    def is_banned(self, ip_address: str) -> bool:
        """检查IP是否被封禁"""
        return ip_address in self.banned_ips
        
    def __del__(self):
        """清理SSH连接"""
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except:
                pass