#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单板连接工具 - 支持网口/Telnet/串口连接
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import threading
import queue
import socket
import telnetlib
from datetime import datetime
import sys
import os
from pathlib import Path
import re
import time
import subprocess
import ftplib

# 条件导入 serial 和 paramiko（在测试模式下使用模拟模块）
if '--test' in sys.argv:
    # 测试模式：创建模拟模块
    import types
    mock_serial = types.ModuleType('serial')
    mock_serial.Serial = type('Serial', (), {
        '__init__': lambda self, *args, **kwargs: None,
        'write': lambda self, data: None,
        'read': lambda self, size=1: b'',
        'close': lambda self: None,
        'is_open': True,
        'EIGHTBITS': 8,
        'PARITY_NONE': 'N',
        'STOPBITS_ONE': 1,
    })
    mock_serial.SerialTimeoutException = Exception
    mock_serial.SerialException = Exception
    
    mock_serial_tools = types.ModuleType('serial.tools')
    mock_list_ports = types.ModuleType('serial.tools.list_ports')
    mock_list_ports.comports = lambda: []
    mock_serial_tools.list_ports = mock_list_ports
    
    # 将 tools 添加到 serial 模块
    mock_serial.tools = mock_serial_tools
    
    sys.modules['serial'] = mock_serial
    sys.modules['serial.tools'] = mock_serial_tools
    sys.modules['serial.tools.list_ports'] = mock_list_ports
    
    mock_paramiko = types.ModuleType('paramiko')
    mock_paramiko.SSHClient = type('SSHClient', (), {
        '__init__': lambda self: None,
        'set_missing_host_key_policy': lambda self, policy: None,
        'connect': lambda self, *args, **kwargs: None,
        'open_sftp': lambda self: None,
        'close': lambda self: None,
    })
    mock_paramiko.AutoAddPolicy = type('AutoAddPolicy', (), {})
    sys.modules['paramiko'] = mock_paramiko

import serial
import serial.tools.list_ports
import paramiko
_current_send_handler = None
_current_send_raw_handler = None
_current_tab = None


def register_send_handler(handler):
    """注册全局发送函数的处理器"""
    global _current_send_handler
    _current_send_handler = handler


def register_send_raw_handler(handler):
    """注册全局原样发送函数的处理器（不自动追加行尾）"""
    global _current_send_raw_handler
    _current_send_raw_handler = handler


def register_active_tab(tab_page):
    """记录当前活动的标签页"""
    global _current_tab
    _current_tab = tab_page


def _require_active_tab():
    if not _current_tab:
        raise RuntimeError("当前没有激活的标签页，请先选择一个连接。")
    return _current_tab


def _run_on_ui_thread(tab, func):
    """确保在UI线程执行操作"""
    if threading.current_thread() == threading.main_thread():
        return func()
    
    result = {}
    event = threading.Event()
    
    def wrapper():
        try:
            result['value'] = func()
        finally:
            event.set()
    
    tab.root.after(0, wrapper)
    event.wait()
    return result.get('value')


def send(command):
    """全局发送函数：send("ls")"""
    if not isinstance(command, str):
        raise TypeError("send() 只接受字符串参数")
    if not _current_send_handler:
        raise RuntimeError("当前没有可用的连接，请先选择一个已连接的标签页。")
    return _current_send_handler(command)


def send_raw(command):
    """全局原样发送函数：send_raw("abc")（不自动追加行尾）"""
    if not isinstance(command, str):
        raise TypeError("send_raw() 只接受字符串参数")
    if not _current_send_raw_handler:
        raise RuntimeError("当前没有可用的连接，请先选择一个已连接的标签页。")
    return _current_send_raw_handler(command)


def start_receive():
    """开始捕获单板回显"""
    tab = _require_active_tab()
    tab.start_capture()


def get_receive():
    """获取当前捕获内容，不结束捕获"""
    tab = _require_active_tab()
    return tab.get_capture()


def end_receive():
    """结束捕获单板回显并返回内容"""
    tab = _require_active_tab()
    return tab.end_capture()


def send_file(source_path, dest_path):
    """
    传输文件：支持本地到远程或远程到本地
    参数:
        source_path: 源文件路径（本地或远程）
        dest_path: 目标文件路径（本地或远程）
    返回:
        bool: 成功返回True，失败返回False
    """
    tab = _require_active_tab()
    
    if not tab.file_connector or not tab.file_connector.connected:
        return False
    
    # 判断路径类型：如果源路径存在且是本地文件，则为本地->远程
    # 否则如果目标路径存在且是本地文件，则为远程->本地
    source_is_local = os.path.exists(source_path)
    dest_is_local = os.path.exists(dest_path)
    
    if source_is_local and not dest_is_local:
        # 本地 -> 远程
        success, msg = tab.file_connector.upload_file(source_path, dest_path)
        return success
    elif not source_is_local and dest_is_local:
        # 远程 -> 本地
        success, msg = tab.file_connector.download_file(source_path, dest_path)
        return success
    elif source_is_local and dest_is_local:
        # 两个都是本地路径，使用本地文件复制
        try:
            import shutil
            shutil.copy2(source_path, dest_path)
            return True
        except Exception as e:
            return False
    else:
        # 两个都是远程路径，不支持远程到远程的直接传输
        return False


def sftp_connect(host, port, username, password):
    """在智能脚本中建立SFTP连接"""
    tab = _require_active_tab()
    host = str(host).strip()
    port = str(port).strip()
    username = str(username).strip()
    password = str(password)
    
    def action():
        tab.file_protocol.set("SFTP")
        tab.file_protocol_combo.set("SFTP")
        tab.on_file_protocol_change()
        tab.sftp_host_entry.delete(0, tk.END)
        tab.sftp_host_entry.insert(0, host)
        tab.sftp_port_entry.delete(0, tk.END)
        tab.sftp_port_entry.insert(0, port or "22")
        tab.sftp_user_entry.delete(0, tk.END)
        tab.sftp_user_entry.insert(0, username)
        tab.sftp_pass_entry.delete(0, tk.END)
        tab.sftp_pass_entry.insert(0, password)
        tab.connect_file_transfer()
        return bool(tab.file_connector and tab.file_connector.connected)
    
    return _run_on_ui_thread(tab, action)


def ftp_connect(host, port, username, password):
    """在智能脚本中建立FTP连接"""
    tab = _require_active_tab()
    host = str(host).strip()
    port = str(port).strip()
    username = str(username).strip()
    password = str(password)
    
    def action():
        tab.file_protocol.set("FTP")
        tab.file_protocol_combo.set("FTP")
        tab.on_file_protocol_change()
        tab.sftp_host_entry.delete(0, tk.END)
        tab.sftp_host_entry.insert(0, host)
        tab.sftp_port_entry.delete(0, tk.END)
        tab.sftp_port_entry.insert(0, port or "21")
        tab.sftp_user_entry.delete(0, tk.END)
        tab.sftp_user_entry.insert(0, username)
        tab.sftp_pass_entry.delete(0, tk.END)
        tab.sftp_pass_entry.insert(0, password)
        tab.connect_file_transfer()
        return bool(tab.file_connector and tab.file_connector.connected)
    
    return _run_on_ui_thread(tab, action)


def sftp_disconnect():
    """断开当前文件传输连接"""
    tab = _require_active_tab()
    
    def action():
        tab.disconnect_file_transfer()
        return True
    
    return _run_on_ui_thread(tab, action)


def ftp_disconnect():
    """断开当前文件传输连接（FTP）"""
    return sftp_disconnect()


def list_remote_files(remote_path=None):
    """
    获取远程目录的文件列表（支持SFTP和FTP）
    参数:
        remote_path: 远程目录路径，如果为None则使用当前目录
    返回:
        list: 文件列表，每个元素为字典，包含 'name', 'size', 'is_dir' 等字段
              如果未连接或出错，返回空列表
    """
    tab = _require_active_tab()
    
    if not tab.file_connector or not tab.file_connector.connected:
        return []
    
    try:
        if remote_path is None:
            # 使用当前远程路径
            remote_path = tab.remote_path if hasattr(tab, 'remote_path') else "."
        
        files = tab.file_connector.list_files(str(remote_path))
        return files if files else []
    except Exception as e:
        return []


def tcp(host, port):
    """通过TCP网口连接单板"""
    tab = _require_active_tab()
    host = str(host).strip()
    port = str(port).strip()
    
    def action():
        tab.conn_type.set("TCP网口")
        tab.on_conn_type_changed()
        tab.host_entry.delete(0, tk.END)
        tab.host_entry.insert(0, host)
        tab.port_entry.delete(0, tk.END)
        tab.port_entry.insert(0, port)
        tab.connect()
        return bool(tab.connector and tab.connector.connected)
    
    return _run_on_ui_thread(tab, action)


def telnet(host, port):
    """通过Telnet连接单板"""
    tab = _require_active_tab()
    host = str(host).strip()
    port = str(port).strip()
    
    def action():
        tab.conn_type.set("Telnet")
        tab.on_conn_type_changed()
        tab.host_entry.delete(0, tk.END)
        tab.host_entry.insert(0, host)
        tab.port_entry.delete(0, tk.END)
        tab.port_entry.insert(0, port)
        tab.connect()
        return bool(tab.connector and tab.connector.connected)
    
    return _run_on_ui_thread(tab, action)


def com(port, baudrate="115200"):
    """通过串口连接单板"""
    tab = _require_active_tab()
    port = str(port).strip()
    baudrate = str(baudrate).strip()
    
    def action():
        tab.conn_type.set("串口")
        tab.on_conn_type_changed()
        tab.refresh_serial_ports()
        tab.serial_port_combo.set(port)
        tab.baudrate_combo.set(baudrate)
        tab.connect()
        return bool(tab.connector and tab.connector.connected)
    
    return _run_on_ui_thread(tab, action)


def disconnect():
    """断开当前连接"""
    tab = _require_active_tab()
    
    def action():
        tab.disconnect()
        return True
    
    return _run_on_ui_thread(tab, action)


def pop(message):
    """在pop文本框中显示消息，每次显示会替换原来的内容"""
    tab = _require_active_tab()
    
    def action():
        tab.pop(str(message))
        return None
    
    return _run_on_ui_thread(tab, action)


def wait_for_confirmation(message):
    """显示消息并等待用户点击"已确认，继续操作"按钮后继续执行
    
    支持多次调用，每次调用都会暂停执行，等待用户点击按钮后继续。
    可以用于分段执行脚本，让用户在每个关键步骤确认后再继续。
    """
    tab = _require_active_tab()
    # 确保事件对象存在
    if not hasattr(tab, 'pop_confirmation_event'):
        raise RuntimeError("pop_confirmation_event 未初始化")
    
    # 先清除事件（确保从清除状态开始等待）
    tab.pop_confirmation_event.clear()
    
    # 显示消息（在UI线程中执行）
    def show_message():
        tab.pop(str(message))
    
    if threading.current_thread() == threading.main_thread():
        # 如果在主线程，直接显示（虽然不应该在主线程调用，但为了安全）
        show_message()
    else:
        # 在后台线程中，通过 after 在UI线程中显示消息
        tab.root.after(0, show_message)
        # 给UI线程一点时间显示消息
        time.sleep(0.1)
    
    # 等待用户确认（在后台线程中等待，不会阻塞UI）
    # 每次调用都会等待，直到用户点击按钮
    tab.pop_confirmation_event.wait(timeout=300)  # 最多等待300秒


def get_ip_address():
    """获取本机所有IPv4地址，返回列表"""
    try:
        hostname = socket.gethostname()
        ip_list = socket.gethostbyname_ex(hostname)[2]
        ipv4_only = [ip for ip in ip_list if '.' in ip and not ip.startswith("127.")]
        return ipv4_only
    except Exception:
        return []


import json


class DeviceConnector:
    """设备连接器基类"""
    
    def __init__(self, output_callback, raw_callback=None):
        self.output_callback = output_callback
        self.raw_callback = raw_callback
        self.connected = False
        self.socket = None
        self.read_thread = None
        self.stop_flag = False
        self.line_ending = "\n"
    
    def connect(self, **kwargs):
        """连接设备"""
        raise NotImplementedError
    
    def disconnect(self):
        """断开连接"""
        self.stop_flag = True
        self.connected = False
        if self.read_thread and self.read_thread.is_alive():
            self.read_thread.join(timeout=1)
    
    def send_command(self, command):
        """发送命令"""
        raise NotImplementedError
    
    def _read_data(self):
        """读取数据（在子线程中运行）"""
        raise NotImplementedError
    
    def log_raw_data(self, data):
        """记录原始数据"""
        if self.raw_callback and data:
            try:
                self.raw_callback(data)
            except Exception:
                pass


class TCPConnector(DeviceConnector):
    """TCP网口连接器"""
    
    def connect(self, host, port, timeout=5):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            self.socket.connect((host, int(port)))
            self.socket.settimeout(None)
            self.socket.setblocking(False)
            self.connected = True
            self.stop_flag = False
            self.read_thread = threading.Thread(target=self._read_data, daemon=True)
            self.read_thread.start()
            return True
        except Exception as e:
            self.output_callback(f"[错误] TCP连接失败: {str(e)}\n")
            return False
    
    def disconnect(self):
        super().disconnect()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def send_command(self, command):
        """发送命令或字符（自动按配置追加行尾）"""
        if not self.connected or not self.socket:
            return False
        try:
            # 临时设置为阻塞模式以确保数据发送完成
            was_blocking = self.socket.getblocking()
            self.socket.setblocking(True)
            
            line_ending = getattr(self, "line_ending", "\n")
            # 如果是换行符（或用户主动发送\r\n），按照当前配置发送
            if command in ['\n', '\r\n']:
                data = line_ending.encode('utf-8')
            # 对于单独的回车/退格，直接发送
            elif command in ['\r', '\b', '\x08']:
                data = command.encode('utf-8')
            else:
                # 其他命令统一添加换行符
                data = (command + line_ending).encode('utf-8')
            
            self.socket.sendall(data)
            # 恢复原来的阻塞模式
            self.socket.setblocking(was_blocking)
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送失败: {str(e)}\n")
            # 尝试恢复阻塞模式
            try:
                self.socket.setblocking(False)
            except:
                pass
            return False

    def send_raw_command(self, command):
        """原样发送，不自动追加行尾"""
        if not self.connected or not self.socket:
            return False
        try:
            was_blocking = self.socket.getblocking()
            self.socket.setblocking(True)
            self.socket.sendall(command.encode('utf-8'))
            self.socket.setblocking(was_blocking)
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送失败: {str(e)}\n")
            try:
                self.socket.setblocking(False)
            except:
                pass
            return False
    
    def _read_data(self):
        import socket
        import sys
        import time
        
        # Windows上select可能不可用，使用轮询方式
        if sys.platform == 'win32':
            # Windows使用轮询方式
            while not self.stop_flag and self.connected:
                try:
                    # 尝试接收数据（非阻塞）
                    try:
                        data = self.socket.recv(4096)
                        if data:
                            self.log_raw_data(data)
                            self.output_callback(data.decode('utf-8', errors='ignore'))
                        else:
                            # 连接被关闭
                            break
                    except socket.error as e:
                        if e.errno == 10035:  # WSAEWOULDBLOCK on Windows
                            # 没有数据可读，等待一下
                            time.sleep(0.1)
                            continue
                        else:
                            raise
                except socket.timeout:
                    # 超时是正常的，继续等待数据
                    continue
                except OSError as e:
                    # 连接错误，中断连接
                    if not self.stop_flag:
                        self.output_callback(f"[错误] 连接错误: {str(e)}\n")
                    break
                except Exception as e:
                    # 其他错误，检查是否是连接相关
                    error_str = str(e).lower()
                    if 'timeout' in error_str or 'timed out' in error_str:
                        # 超时错误，继续等待
                        continue
                    elif 'broken pipe' in error_str or 'connection' in error_str or '10054' in str(e):
                        # 连接断开，中断
                        if not self.stop_flag:
                            self.output_callback(f"[错误] 连接断开: {str(e)}\n")
                        break
                    else:
                        # 其他错误，继续尝试
                        time.sleep(0.1)
                        continue
        else:
            # Linux/macOS使用select
            import select
            while not self.stop_flag and self.connected:
                try:
                    ready, _, _ = select.select([self.socket], [], [], 0.1)
                    if ready:
                        data = self.socket.recv(4096)
                        if data:
                            self.log_raw_data(data)
                            self.output_callback(data.decode('utf-8', errors='ignore'))
                        else:
                            # 连接被关闭
                            break
                except socket.timeout:
                    # 超时是正常的，继续等待数据
                    continue
                except OSError as e:
                    # 连接错误，中断连接
                    if not self.stop_flag:
                        self.output_callback(f"[错误] 连接错误: {str(e)}\n")
                    break
                except Exception as e:
                    # 其他错误，检查是否是连接相关
                    error_str = str(e).lower()
                    if 'timeout' in error_str or 'timed out' in error_str:
                        # 超时错误，继续等待
                        continue
                    elif 'broken pipe' in error_str or 'connection' in error_str:
                        # 连接断开，中断
                        if not self.stop_flag:
                            self.output_callback(f"[错误] 连接断开: {str(e)}\n")
                        break
                    else:
                        # 其他错误，继续尝试
                        continue
        self.connected = False


class TelnetConnector(DeviceConnector):
    """Telnet连接器"""
    
    def connect(self, host, port, timeout=5):
        try:
            self.socket = telnetlib.Telnet(host, int(port), timeout=timeout)
            self.connected = True
            self.stop_flag = False
            self.read_thread = threading.Thread(target=self._read_data, daemon=True)
            self.read_thread.start()
            return True
        except Exception as e:
            self.output_callback(f"[错误] Telnet连接失败: {str(e)}\n")
            return False
    
    def disconnect(self):
        super().disconnect()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def send_command(self, command):
        """发送命令或字符（自动按配置追加行尾）"""
        if not self.connected or not self.socket:
            return False
        try:
            line_ending = getattr(self, "line_ending", "\n")
            # 如果是换行符（或用户主动发送\r\n），按照当前配置发送
            if command in ['\n', '\r\n']:
                data = line_ending.encode('utf-8')
            elif command in ['\r', '\b', '\x08']:
                data = command.encode('utf-8')
            else:
                # 其他命令统一添加换行符
                data = (command + line_ending).encode('utf-8')
            self.socket.write(data)
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送失败: {str(e)}\n")
            return False

    def send_raw_command(self, command):
        """原样发送，不自动追加行尾"""
        if not self.connected or not self.socket:
            return False
        try:
            self.socket.write(command.encode('utf-8'))
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送失败: {str(e)}\n")
            return False
    
    def _read_data(self):
        import socket
        while not self.stop_flag and self.connected:
            try:
                data = self.socket.read_some()
                if data:
                    self.log_raw_data(data)
                    self.output_callback(data.decode('utf-8', errors='ignore'))
                else:
                    # 连接被关闭
                    break
            except socket.timeout:
                # 超时是正常的，继续等待数据
                continue
            except EOFError:
                # 连接结束
                if not self.stop_flag:
                    self.output_callback("[提示] 连接已关闭\n")
                break
            except OSError as e:
                # 连接错误，中断连接
                if not self.stop_flag:
                    self.output_callback(f"[错误] 连接错误: {str(e)}\n")
                break
            except Exception as e:
                # 其他错误，检查是否是超时或连接相关
                error_str = str(e).lower()
                if 'timeout' in error_str or 'timed out' in error_str:
                    # 超时错误，继续等待
                    continue
                elif 'broken pipe' in error_str or 'connection' in error_str or 'eof' in error_str:
                    # 连接断开，中断
                    if not self.stop_flag:
                        self.output_callback(f"[错误] 连接断开: {str(e)}\n")
                    break
                else:
                    # 其他错误，继续尝试
                    continue
        self.connected = False


class SerialConnector(DeviceConnector):
    """串口连接器"""
    
    def connect(self, port, baudrate=115200, timeout=1):
        try:
            self.socket = serial.Serial(
                port=port,
                baudrate=int(baudrate),
                timeout=timeout,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE
            )
            self.connected = True
            self.stop_flag = False
            self.read_thread = threading.Thread(target=self._read_data, daemon=True)
            self.read_thread.start()
            return True
        except Exception as e:
            self.output_callback(f"[错误] 串口连接失败: {str(e)}\n")
            return False
    
    def disconnect(self):
        super().disconnect()
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def send_command(self, command):
        """发送命令或字符（自动按配置追加行尾）"""
        if not self.connected or not self.socket:
            return False
        try:
            line_ending = getattr(self, "line_ending", "\n")
            # 如果是换行符（或用户主动发送\r\n），按照当前配置发送
            if command in ['\n', '\r\n']:
                data = line_ending.encode('utf-8')
            elif command in ['\r', '\b', '\x08']:
                data = command.encode('utf-8')
            else:
                # 其他命令统一添加换行符
                data = (command + line_ending).encode('utf-8')
            self.socket.write(data)
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送失败: {str(e)}\n")
            return False

    def send_raw_command(self, command):
        """原样发送，不自动追加行尾"""
        if not self.connected or not self.socket:
            return False
        try:
            self.socket.write(command.encode('utf-8'))
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送失败: {str(e)}\n")
            return False
    
    def _read_data(self):
        import time
        import serial
        while not self.stop_flag and self.connected:
            try:
                if self.socket.in_waiting > 0:
                    data = self.socket.read(self.socket.in_waiting)
                    if data:
                        self.log_raw_data(data)
                        self.output_callback(data.decode('utf-8', errors='ignore'))
                else:
                    time.sleep(0.1)
            except serial.SerialTimeoutException:
                # 串口超时是正常的，继续等待
                continue
            except serial.SerialException as e:
                # 串口错误，中断连接
                if not self.stop_flag:
                    self.output_callback(f"[错误] 串口错误: {str(e)}\n")
                break
            except OSError as e:
                # 系统错误，检查是否是连接相关
                error_str = str(e).lower()
                if 'timeout' in error_str:
                    # 超时错误，继续等待
                    continue
                else:
                    # 其他系统错误，中断
                    if not self.stop_flag:
                        self.output_callback(f"[错误] 系统错误: {str(e)}\n")
                    break
            except Exception as e:
                # 其他错误，检查是否是超时
                error_str = str(e).lower()
                if 'timeout' in error_str or 'timed out' in error_str:
                    # 超时错误，继续等待
                    continue
                else:
                    # 其他错误，继续尝试（串口可能暂时不可用）
                    time.sleep(0.1)
                    continue
        self.connected = False


class SFTPConnector:
    """SFTP连接器"""
    
    def __init__(self):
        self.client = None
        self.sftp = None
        self.connected = False
    
    def connect(self, host, port, username, password, timeout=10):
        """连接SFTP服务器"""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=host,
                port=int(port),
                username=username,
                password=password,
                timeout=timeout
            )
            self.sftp = self.client.open_sftp()
            self.connected = True
            return (True, "连接成功")
        except Exception as e:
            return (False, str(e))
    
    def disconnect(self):
        """断开连接"""
        try:
            if self.sftp:
                self.sftp.close()
            if self.client:
                self.client.close()
        except:
            pass
        self.connected = False
        self.sftp = None
        self.client = None
    
    def list_files(self, remote_path="."):
        """列出远程目录文件"""
        if not self.connected or not self.sftp:
            return []
        try:
            files = []
            for item in self.sftp.listdir_attr(remote_path):
                files.append({
                    'name': item.filename,
                    'size': item.st_size,
                    'is_dir': item.st_mode & 0o040000 != 0,
                    'mode': item.st_mode
                })
            return files
        except Exception as e:
            return []
    
    def upload_file(self, local_path, remote_path):
        """上传文件"""
        if not self.connected or not self.sftp:
            return False, "未连接"
        try:
            self.sftp.put(local_path, remote_path)
            return True, "上传成功"
        except Exception as e:
            return False, str(e)
    
    def download_file(self, remote_path, local_path):
        """下载文件"""
        if not self.connected or not self.sftp:
            return False, "未连接"
        try:
            self.sftp.get(remote_path, local_path)
            return True, "下载成功"
        except Exception as e:
            return False, str(e)
    
    def change_directory(self, remote_path):
        """改变远程目录"""
        if not self.connected or not self.sftp:
            return False, "未连接"
        try:
            self.sftp.chdir(remote_path)
            return True, "切换成功"
        except Exception as e:
            return False, str(e)
    
    def get_current_directory(self):
        """获取当前远程目录"""
        if not self.connected or not self.sftp:
            return "."
        try:
            return self.sftp.getcwd()
        except:
            return "."


class FTPConnector:
    """FTP连接器"""
    
    def __init__(self):
        self.ftp = None
        self.connected = False
    
    def connect(self, host, port, username, password, timeout=10):
        """连接FTP服务器"""
        try:
            self.ftp = ftplib.FTP()
            self.ftp.connect(host, int(port), timeout=timeout)
            self.ftp.login(user=username, passwd=password)
            self.connected = True
            return True, "连接成功"
        except Exception as e:
            self.disconnect()
            return False, str(e)
    
    def disconnect(self):
        """断开连接"""
        try:
            if self.ftp:
                try:
                    self.ftp.quit()
                except Exception:
                    self.ftp.close()
        except:
            pass
        self.connected = False
        self.ftp = None
    
    def list_files(self, remote_path="."):
        """列出远程目录"""
        if not self.connected or not self.ftp:
            return []
        files = []
        try:
            current = self.ftp.pwd()
            self.ftp.cwd(remote_path)
            try:
                entries = list(self.ftp.mlsd())
                for name, facts in entries:
                    is_dir = facts.get('type') == 'dir'
                    size = int(facts.get('size', 0)) if facts.get('size') else 0
                    files.append({
                        'name': name,
                        'size': size,
                        'is_dir': is_dir,
                        'mode': facts.get('perm', '')
                    })
            except Exception:
                names = self.ftp.nlst()
                for name in names:
                    is_dir = False
                    size = 0
                    try:
                        current_pos = self.ftp.pwd()
                        self.ftp.cwd(name)
                        is_dir = True
                        self.ftp.cwd(current_pos)
                    except Exception:
                        try:
                            size = self.ftp.size(name) or 0
                        except Exception:
                            size = 0
                    files.append({
                        'name': name,
                        'size': size,
                        'is_dir': is_dir,
                        'mode': ''
                    })
            self.ftp.cwd(current)
            return files
        except Exception:
            return []
    
    def upload_file(self, local_path, remote_path):
        if not self.connected or not self.ftp:
            return False, "未连接"
        try:
            with open(local_path, 'rb') as f:
                self.ftp.storbinary(f"STOR {remote_path}", f)
            return True, "上传成功"
        except Exception as e:
            return False, str(e)
    
    def download_file(self, remote_path, local_path):
        if not self.connected or not self.ftp:
            return False, "未连接"
        try:
            with open(local_path, 'wb') as f:
                self.ftp.retrbinary(f"RETR {remote_path}", f.write)
            return True, "下载成功"
        except Exception as e:
            return False, str(e)
    
    def change_directory(self, remote_path):
        if not self.connected or not self.ftp:
            return False, "未连接"
        try:
            self.ftp.cwd(remote_path)
            return True, "切换成功"
        except Exception as e:
            return False, str(e)
    
    def get_current_directory(self):
        if not self.connected or not self.ftp:
            return "."
        try:
            return self.ftp.pwd()
        except Exception:
            return "."


class TabPage:
    """单个标签页，包含完整的连接功能"""
    
    def __init__(self, parent, tab_name, root_window):
        self.parent = parent
        self.tab_name = tab_name
        self.root = root_window
        self.connector = None
        self.output_queue = queue.Queue()
        # 用于等待用户确认的事件对象
        self.pop_confirmation_event = threading.Event()
        
        # 创建可滚动的容器
        # 创建Canvas和滚动条
        canvas = tk.Canvas(parent, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # 绑定鼠标滚轮事件（支持Windows和macOS）
        def _on_mousewheel(event):
            # Windows和Linux
            if event.num == 4 or event.delta > 0:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5 or event.delta < 0:
                canvas.yview_scroll(1, "units")
        
        # Windows和Linux
        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        # macOS
        canvas.bind_all("<Button-4>", _on_mousewheel)
        canvas.bind_all("<Button-5>", _on_mousewheel)
        
        # 布局Canvas和滚动条
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
        # 创建主框架（放在可滚动框架内）
        self.frame = ttk.Frame(scrollable_frame, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollable_frame.columnconfigure(0, weight=1)
        scrollable_frame.rowconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=1)
        self.frame.rowconfigure(3, weight=1)
        
        # 保存canvas引用以便后续使用
        self.canvas = canvas
        
        # 文件传输（SFTP/FTP）相关
        self.file_connector = None
        self.active_file_protocol = None
        self.local_path = os.path.expanduser("~")
        self.remote_path = "/"
        
        # 日志记录相关
        self.log_enabled = False
        self.log_file = None
        self.log_file_path = None
        self.raw_log_file = None
        self.raw_log_file_path = None
        self.partial_output = ""
        
        # 命令历史
        self.command_history = []
        self.history_index = -1
        self.capture_text = None
        self.capture_lock = threading.Lock()
        self.use_crlf = tk.BooleanVar(value=False)
        self.input_buffer = []
        self.input_cursor = 0
        self.redrawing_input = False
        
        # 智能命令模板
        self.smart_templates = {
            "系统信息检查": "uname -a\nuptime\nwho\nfree -h\nvmstat 1 5",
            "网络诊断": "ifconfig -a\nnetstat -rn\nping -c 4 8.8.8.8\ntraceroute 8.8.8.8",
            "日志采集": "dmesg | tail -n 50\njournalctl -xe --no-pager\ntail -n 100 /var/log/syslog"
        }
        self.current_template_name = ""
        self.last_smart_code = ""
        self.smart_script_thread = None
        self.smart_stop_event = None
        self.smart_run_id = 0
        
        # 配置信息
        self.config = {
            "connection": {},
            "commands": [],
            "file_transfer": {},
            "smart_templates": self.smart_templates.copy(),
            "smart_code": "",
            "line_ending_crlf": False,
            "show_output_display": True,
            "show_std_output": False
        }
        
        # 初始化显示控制变量（需要在config初始化之后）
        self.show_output_display = tk.BooleanVar(value=self.config.get("show_output_display", True))
        self.show_std_output = tk.BooleanVar(value=self.config.get("show_std_output", False))
        
        # 初始化文件图标
        self.init_file_icons()
        
        # ANSI颜色解析相关 - 预编译所有常用的正则表达式以减少开销
        self.ansi_pattern = re.compile(r'\033(?:\033\[|\[)([0-9;]*)m')
        # 日志清理用的ANSI序列移除
        self.ansi_clean_pattern = re.compile(r'\033\[[0-9;]*m')
        # 检测未完成的CSI序列
        self.incomplete_csi_pattern = re.compile(r'\033\[[0-9;?]*$')
        # 检测未完成的OSC序列
        self.incomplete_osc_pattern = re.compile(r'\033\][^\007]*$')
        # 清屏和清行控制序列（合并为一个正则）
        self.clear_sequences_pattern = re.compile(r'\033\[\d*[JK]')
        # 智能命令代码补全用的函数名匹配
        self.function_name_pattern = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)$')
        # 标签页名称数字提取
        self.tab_number_pattern = re.compile(r'(\d+)$')
        
        self.current_fg_color = "#FFFFFF"  # 默认白色
        self.current_bg_color = None  # 默认背景色
        
        self.setup_ui()
        self.check_output_queue()
        
        # 更新滚动区域
        self.update_scroll_region()
    
    def setup_ansi_colors(self):
        """设置ANSI颜色tag"""
        # ANSI颜色映射（前景色）
        ansi_fg_colors = {
            30: "#000000",  # 黑色
            31: "#FF0000",  # 红色
            32: "#00FF00",  # 绿色
            33: "#FFFF00",  # 黄色
            34: "#0000FF",  # 蓝色
            35: "#FF00FF",  # 紫色
            36: "#00FFFF",  # 青色
            37: "#FFFFFF",  # 白色
            90: "#808080",  # 亮黑（灰色）
            91: "#FF8080",  # 亮红
            92: "#80FF80",  # 亮绿
            93: "#FFFF80",  # 亮黄
            94: "#8080FF",  # 亮蓝
            95: "#FF80FF",  # 亮紫
            96: "#80FFFF",  # 亮青
            97: "#FFFFFF",  # 亮白
        }
        
        # ANSI颜色映射（背景色）
        ansi_bg_colors = {
            40: "#000000",  # 黑色
            41: "#FF0000",  # 红色
            42: "#00FF00",  # 绿色
            43: "#FFFF00",  # 黄色
            44: "#0000FF",  # 蓝色
            45: "#FF00FF",  # 紫色
            46: "#00FFFF",  # 青色
            47: "#FFFFFF",  # 白色
        }
        
        # 创建颜色tag
        for code, color in ansi_fg_colors.items():
            tag_name = f"ansi_fg_{code}"
            self.output_text.tag_config(tag_name, foreground=color)
        
        for code, color in ansi_bg_colors.items():
            tag_name = f"ansi_bg_{code}"
            self.output_text.tag_config(tag_name, background=color)
        
        # 保存颜色映射供后续使用
        self.ansi_fg_colors = ansi_fg_colors
        self.ansi_bg_colors = ansi_bg_colors
    
    def init_file_icons(self):
        """初始化文件图标"""
        # 使用Unicode字符作为图标（简单方法）
        self.icons = {
            'folder': '📁',
            'file': '📄',
            'image': '🖼️',
            'video': '🎬',
            'audio': '🎵',
            'pdf': '📕',
            'zip': '📦',
            'code': '💻',
            'text': '📝',
            'executable': '⚙️',
        }
        
        # 文件扩展名到图标类型的映射
        self.extension_map = {
            # 图片
            'jpg': 'image', 'jpeg': 'image', 'png': 'image', 'gif': 'image',
            'bmp': 'image', 'svg': 'image', 'ico': 'image', 'webp': 'image',
            # 视频
            'mp4': 'video', 'avi': 'video', 'mkv': 'video', 'mov': 'video',
            'wmv': 'video', 'flv': 'video', 'webm': 'video',
            # 音频
            'mp3': 'audio', 'wav': 'audio', 'flac': 'audio', 'aac': 'audio',
            'ogg': 'audio', 'm4a': 'audio', 'wma': 'audio',
            # 文档
            'pdf': 'pdf',
            'doc': 'text', 'docx': 'text', 'txt': 'text', 'rtf': 'text',
            'md': 'text', 'log': 'text',
            # 压缩文件
            'zip': 'zip', 'rar': 'zip', '7z': 'zip', 'tar': 'zip',
            'gz': 'zip', 'bz2': 'zip',
            # 代码文件
            'py': 'code', 'js': 'code', 'html': 'code', 'css': 'code',
            'java': 'code', 'cpp': 'code', 'c': 'code', 'h': 'code',
            'xml': 'code', 'json': 'code', 'yaml': 'code', 'yml': 'code',
            'sh': 'code', 'bat': 'code', 'cmd': 'code',
            # 可执行文件
            'exe': 'executable', 'app': 'executable', 'deb': 'executable',
            'rpm': 'executable', 'dmg': 'executable',
        }
    
    def get_file_icon(self, filename, is_dir=False):
        """根据文件名获取图标"""
        if is_dir:
            return self.icons['folder']
        
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        icon_type = self.extension_map.get(ext, 'file')
        return self.icons.get(icon_type, self.icons['file'])
    
    def update_scroll_region(self):
        """更新滚动区域"""
        self.root.after(100, lambda: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
    
    def setup_ui(self):
        """设置用户界面"""
        # 使用PanedWindow实现可调整大小的布局
        # 从配置加载布局比例，如果没有则使用默认值
        layout_config = self.config.get("ui_layout", {})
        h_pane1_size = layout_config.get("horizontal_pane1", 600)  # 左侧列宽度
        h_pane2_size = layout_config.get("horizontal_pane2", 400)  # 中间列宽度
        h_pane3_size = layout_config.get("horizontal_pane3", 200)   # 右侧列宽度
        
        # 水平PanedWindow：分割左侧、中间、右侧三列
        self.h_paned = ttk.PanedWindow(self.frame, orient=tk.HORIZONTAL)
        self.h_paned.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.frame.columnconfigure(0, weight=1)
        self.frame.rowconfigure(0, weight=1)
        
        # 左侧列容器（连接设置、输出显示、快速命令、文件传输）
        left_container = ttk.Frame(self.h_paned)
        self.h_paned.add(left_container, weight=3)
        
        # 中间列容器（智能命令编辑）
        middle_container = ttk.Frame(self.h_paned)
        self.h_paned.add(middle_container, weight=2)
        
        # 右侧列容器（STD输出）
        right_container = ttk.Frame(self.h_paned)
        self.h_paned.add(right_container, weight=1)
        
        # 绑定PanedWindow大小变化事件，保存布局
        self.h_paned.bind("<ButtonRelease-1>", self.on_pane_resize)
        
        # 设置左侧列布局
        left_container.columnconfigure(0, weight=1)
        for i in range(4):
            left_container.rowconfigure(i, weight=0)
        left_container.rowconfigure(1, weight=1)  # 输出显示区域可扩展
        left_container.rowconfigure(3, weight=1)  # 文件传输区域可扩展
        
        conn_frame = ttk.LabelFrame(left_container, text="连接设置", padding="10")
        conn_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        conn_frame.columnconfigure(1, weight=1)
        
        ttk.Label(conn_frame, text="连接方式:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.conn_type = ttk.Combobox(conn_frame, values=["TCP网口", "Telnet", "串口"], state="readonly", width=15)
        self.conn_type.current(0)
        self.conn_type.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.conn_type.bind("<<ComboboxSelected>>", self.on_conn_type_changed)
        
        # TCP/Telnet 参数
        self.tcp_frame = ttk.Frame(conn_frame)
        self.tcp_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(self.tcp_frame, text="主机地址:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.host_entry = ttk.Entry(self.tcp_frame, width=20)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.host_entry.insert(0, "192.168.1.100")
        
        ttk.Label(self.tcp_frame, text="端口:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.port_entry = ttk.Entry(self.tcp_frame, width=10)
        self.port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        self.port_entry.insert(0, "23")
        
        # 串口参数
        self.serial_frame = ttk.Frame(conn_frame)
        self.serial_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        self.serial_frame.grid_remove()
        
        ttk.Label(self.serial_frame, text="串口:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.serial_port_combo = ttk.Combobox(self.serial_frame, width=20, state="readonly")
        self.serial_port_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.refresh_serial_ports()
        
        ttk.Label(self.serial_frame, text="波特率:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.baudrate_combo = ttk.Combobox(self.serial_frame, values=["9600", "19200", "38400", "57600", "115200", "230400"], 
                                           state="readonly", width=10)
        self.baudrate_combo.current(4)  # 默认115200
        self.baudrate_combo.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        
        ttk.Button(self.serial_frame, text="刷新", command=self.refresh_serial_ports).grid(row=0, column=4, padx=5, pady=5)
        
        # 连接按钮
        self.connect_btn = ttk.Button(conn_frame, text="连接", command=self.toggle_connection)
        self.connect_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # 状态显示
        self.status_label = ttk.Label(conn_frame, text="状态: 未连接", foreground="red")
        self.status_label.grid(row=3, column=0, columnspan=2, pady=5)
        
        # 输出显示区域
        output_frame = ttk.LabelFrame(left_container, text="输出显示", padding="10")
        output_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=12, width=80, wrap=tk.WORD)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        # 设置蓝底白字
        self.output_text.config(
            bg="#000080",  # 深蓝色背景
            fg="#FFFFFF",  # 白色文字
            insertbackground="#FFFFFF",  # 光标颜色为白色
            selectbackground="#4169E1",  # 选中文本背景色（浅蓝色）
            selectforeground="#FFFFFF"  # 选中文本前景色（白色）
        )
        
        # 配置ANSI颜色tag
        self.setup_ansi_colors()
        
        # 初始化输入提示符（不使用硬编码，由单板返回的实际提示符决定）
        self.input_prompt = ""
        self.input_start_mark = "input_start"
        self.input_enabled = True  # 永远允许输入
        
        # 绑定键盘事件
        self.output_text.bind("<Key>", self.on_output_key)
        self.output_text.bind("<Button-1>", self.on_output_click)
        self.output_text.bind("<B1-Motion>", self.on_output_drag)
        self.output_text.bind("<ButtonRelease-1>", self.on_output_release)
        self.output_text.bind("<Return>", self.on_output_return)
        self.output_text.bind("<BackSpace>", self.on_output_backspace)
        self.output_text.bind("<Delete>", self.on_output_delete)
        self.output_text.bind("<Control-v>", self.on_paste)  # 支持粘贴
        self.output_text.bind("<Command-v>", self.on_paste)  # macOS粘贴
        
        # 用于跟踪拖动状态
        self.dragging = False
        
        # 初始化输入区域（不插入提示符，等待单板返回）
        self.output_text.config(state=tk.NORMAL)
        self.output_text.mark_set(self.input_start_mark, tk.END)
        self.output_text.mark_gravity(self.input_start_mark, tk.LEFT)
        self.input_line_range = (self.output_text.index(tk.END), self.output_text.index(tk.END))
        self.output_text.config(state=tk.NORMAL)
        
        # 输出控制按钮
        output_buttons = ttk.Frame(output_frame)
        output_buttons.grid(row=1, column=0, pady=5)
        
        ttk.Button(output_buttons, text="清空输出", command=self.clear_output).pack(side=tk.LEFT, padx=5)
        
        # 日志记录开关
        self.log_checkbox = ttk.Checkbutton(output_buttons, text="记录日志", command=self.toggle_log)
        self.log_checkbox.pack(side=tk.LEFT, padx=5)
        self.output_display_checkbox = ttk.Checkbutton(
            output_buttons,
            text="显示输出",
            variable=self.show_output_display,
            command=self.on_show_output_toggle
        )
        self.output_display_checkbox.pack(side=tk.LEFT, padx=5)
        self.input_line_range = (self.output_text.index(tk.END), self.output_text.index(tk.END))
        
        # 命令发送区域
        cmd_send_frame = ttk.LabelFrame(left_container, text="快速命令发送", padding="10")
        cmd_send_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        cmd_send_frame.columnconfigure(0, weight=1)
        
        cmd_input_frame = ttk.Frame(cmd_send_frame)
        cmd_input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        cmd_input_frame.columnconfigure(1, weight=1)
        
        ttk.Label(cmd_input_frame, text="命令:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.quick_cmd_entry = ttk.Entry(cmd_input_frame, width=50)
        self.quick_cmd_entry.grid(row=0, column=1, padx=5, pady=5, sticky=(tk.W, tk.E))
        self.quick_cmd_entry.bind("<Return>", lambda e: self.send_quick_command())
        self.quick_cmd_entry.bind("<Up>", lambda e: self.history_up())
        self.quick_cmd_entry.bind("<Down>", lambda e: self.history_down())
        
        ttk.Button(cmd_input_frame, text="发送", command=self.send_quick_command).grid(row=0, column=2, padx=5, pady=5)
        
        ttk.Checkbutton(
            cmd_input_frame,
            text="使用CRLF换行 (\\r\\n)",
            variable=self.use_crlf,
            command=self.on_line_ending_toggle
        ).grid(row=1, column=0, columnspan=3, sticky=tk.W, padx=5, pady=(0, 5))
        
        # 常用命令按钮
        common_cmds_frame = ttk.Frame(cmd_send_frame)
        common_cmds_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # 从配置加载常用命令，如果没有则使用默认值
        default_commands = ["ls", "pwd", "ifconfig", "ps", "df -h"]
        common_commands = self.config.get("common_commands", default_commands)
        # 确保至少有一个命令
        if not common_commands:
            common_commands = default_commands
        
        # 保存按钮引用以便后续编辑
        self.common_cmd_buttons = []
        self.common_commands = common_commands
        
        # 创建右键菜单
        self.common_cmd_menu = tk.Menu(self.root, tearoff=0)
        self.common_cmd_menu.add_command(label="编辑命令", command=self.edit_common_command)
        self.editing_cmd_index = None
        
        for i, cmd in enumerate(common_commands):
            btn = ttk.Button(common_cmds_frame, text=cmd, width=10, 
                           command=lambda c=cmd: self.send_quick_command_text(c))
            btn.grid(row=0, column=i, padx=2)
            # 绑定右键事件
            btn.bind("<Button-3>", lambda e, idx=i: self.on_common_cmd_right_click(e, idx))
            self.common_cmd_buttons.append(btn)
        
        # 文件传输区域（支持SFTP/FTP）
        file_frame = ttk.LabelFrame(left_container, text="文件传输 (SFTP/FTP)", padding="10")
        file_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        file_frame.columnconfigure(0, weight=1)
        file_frame.columnconfigure(1, weight=1)
        file_frame.rowconfigure(1, weight=1)
        
        # 智能命令编辑区域（中间列）
        smart_frame = ttk.LabelFrame(middle_container, text="智能命令编辑", padding="10")
        smart_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        middle_container.columnconfigure(0, weight=1)
        middle_container.rowconfigure(0, weight=1)
        smart_frame.columnconfigure(0, weight=1)
        smart_frame.rowconfigure(2, weight=1)

        header_frame = ttk.Frame(smart_frame)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        ttk.Label(header_frame, text="说明：可以编辑命令或Python脚本，点击下方按钮执行。").pack(side=tk.LEFT)
        ttk.Button(header_frame, text="帮助", command=self.show_smart_help).pack(side=tk.RIGHT)

        title_frame = ttk.Frame(smart_frame)
        title_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 2))
        ttk.Label(title_frame, text="模板标题:").grid(row=0, column=0, sticky=tk.W)
        self.smart_title_entry = ttk.Entry(title_frame)
        self.smart_title_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(5, 0))
        ttk.Label(title_frame, text="选择模板:").grid(row=1, column=0, sticky=tk.W, pady=(2, 0))
        combo_inner = ttk.Frame(title_frame)
        combo_inner.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(5, 0))
        self.smart_template_combo = ttk.Combobox(
            combo_inner,
            state="readonly", width=18)
        self.smart_template_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.smart_template_combo.bind("<<ComboboxSelected>>", self.apply_smart_template)
        ttk.Button(combo_inner, text="保存为模板", command=self.save_smart_template).pack(side=tk.LEFT, padx=5)
        title_frame.columnconfigure(1, weight=1)
        
        # Pop消息显示区域
        pop_frame = ttk.Frame(title_frame)
        pop_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(2, 0))
        pop_frame.columnconfigure(0, weight=1)
        self.pop_entry = ttk.Entry(pop_frame, state="readonly")
        self.pop_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(pop_frame, text="已确认，继续操作", command=self.clear_pop).grid(row=0, column=1)

        self.smart_text = scrolledtext.ScrolledText(
            smart_frame,
            height=12,
            wrap=tk.WORD,
            font=("Consolas", 11),
            background="#1e1e1e",
            foreground="#dcdcdc",
            insertbackground="#ffd700"
        )
        self.smart_text.grid(row=2, column=0, sticky=(tk.N, tk.S, tk.E, tk.W), pady=2)
        self.smart_text.bind("<Tab>", self.smart_text_tab)
        self.smart_text.bind("<KeyRelease>", self.smart_text_key_release)
        self.smart_text.bind("<Button-1>", lambda e: self.smart_text_clear_completion())
        self.smart_text.bind("<FocusOut>", lambda e: self.smart_text_clear_completion())
        
        # 定义可用的函数名列表（用于代码补全）
        self.smart_functions = [
            "send", "send_raw", "tcp", "telnet", "com", "disconnect", "get_ip_address", "pop",
            "wait_for_confirmation",
            "start_receive", "get_receive", "end_receive",
            "send_file", "sftp_connect", "sftp_disconnect",
            "ftp_connect", "ftp_disconnect", "list_remote_files",
            "print", "wait"
        ]
        
        # 创建补全提示的 tag（灰色、斜体）
        self.smart_text.tag_config("completion", foreground="#808080", font=("Consolas", 11, "italic"))
        self.smart_text.tag_bind("completion", "<Button-1>", lambda e: self.smart_text_complete())
        
        # 当前补全提示信息
        self.smart_completion = None  # (start_pos, end_pos, completion_text)

        smart_btn_frame = ttk.Frame(smart_frame)
        smart_btn_frame.grid(row=3, column=0, sticky=tk.EW, pady=(2, 0))
        ttk.Button(smart_btn_frame, text="发送智能命令", command=self.send_smart_command).pack(
            side=tk.LEFT, padx=5)
        self.smart_run_btn = ttk.Button(smart_btn_frame, text="以Python执行", command=self.run_smart_python)
        self.smart_run_btn.pack(
            side=tk.LEFT, padx=5)
        self.smart_stop_btn = ttk.Button(
            smart_btn_frame, text="停止执行", command=self.stop_smart_python, state=tk.DISABLED
        )
        self.smart_stop_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(smart_btn_frame, text="清空", command=lambda: self.smart_text.delete("1.0", tk.END)).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(smart_btn_frame, text="保存代码", command=self.manual_save_smart_code).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(smart_btn_frame, text="保存到文件", command=self.save_smart_code_to_file).pack(
            side=tk.LEFT, padx=5)
        ttk.Button(smart_btn_frame, text="读取文件", command=self.load_smart_code_from_file).pack(
            side=tk.LEFT, padx=5)
        
        self.refresh_smart_templates()
        
        # 智能脚本回显
        echo_frame = ttk.LabelFrame(smart_frame, text="脚本输出", padding="5")
        echo_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=(4, 0))
        self.smart_output = scrolledtext.ScrolledText(echo_frame, height=5, wrap=tk.WORD, state=tk.DISABLED)
        self.smart_output.pack(fill=tk.BOTH, expand=True)

        # STD调试输出窗口（右侧列）
        std_frame = ttk.LabelFrame(right_container, text="STD输出", padding="10")
        std_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        right_container.columnconfigure(0, weight=1)
        right_container.rowconfigure(0, weight=1)
        std_frame.columnconfigure(0, weight=1)
        std_frame.rowconfigure(0, weight=1)

        self.std_output = scrolledtext.ScrolledText(
            std_frame,
            height=30,
            wrap=tk.NONE,
            state=tk.DISABLED,
            font=("Consolas", 10)
        )
        self.std_output.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        std_options = ttk.Frame(std_frame)
        std_options.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        ttk.Checkbutton(
            std_options,
            text="打印STD输出",
            variable=self.show_std_output,
            command=self.on_show_std_output_toggle
        ).pack(side=tk.LEFT)
        
        # 文件连接设置
        file_conn_frame = ttk.Frame(file_frame)
        file_conn_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(file_conn_frame, text="协议:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.file_protocol = tk.StringVar(value="SFTP")
        self.file_protocol_combo = ttk.Combobox(
            file_conn_frame,
            width=6,
            state="readonly",
            values=("SFTP", "FTP"),
            textvariable=self.file_protocol
        )
        self.file_protocol_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.file_protocol_combo.bind("<<ComboboxSelected>>", self.on_file_protocol_change)
        
        ttk.Label(file_conn_frame, text="主机:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.sftp_host_entry = ttk.Entry(file_conn_frame, width=15)
        self.sftp_host_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        self.sftp_host_entry.insert(0, "192.168.1.100")
        
        ttk.Label(file_conn_frame, text="端口:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.sftp_port_entry = ttk.Entry(file_conn_frame, width=8)
        self.sftp_port_entry.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)
        self.sftp_port_entry.insert(0, "22")
        
        ttk.Label(file_conn_frame, text="用户名:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.sftp_user_entry = ttk.Entry(file_conn_frame, width=12)
        self.sftp_user_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        self.sftp_user_entry.insert(0, "root")
        
        ttk.Label(file_conn_frame, text="密码:").grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.sftp_pass_entry = ttk.Entry(file_conn_frame, width=12, show="*")
        self.sftp_pass_entry.grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)
        
        self.file_connect_btn = ttk.Button(file_conn_frame, text="连接", command=self.toggle_file_connection)
        self.file_connect_btn.grid(row=1, column=4, padx=5, pady=5)
        
        self.file_status_label = ttk.Label(file_conn_frame, text="SFTP: 未连接", foreground="red")
        self.file_status_label.grid(row=1, column=5, padx=5, pady=5, sticky=tk.W)
        
        # 文件列表区域（左右分栏）
        files_container = ttk.Frame(file_frame)
        files_container.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        files_container.columnconfigure(0, weight=1)
        files_container.columnconfigure(1, weight=1)
        files_container.rowconfigure(0, weight=1)
        
        # 本地文件列表
        local_files_frame = ttk.LabelFrame(files_container, text="本地文件", padding="5")
        local_files_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        local_files_frame.columnconfigure(0, weight=1)
        local_files_frame.rowconfigure(1, weight=1)
        
        local_path_frame = ttk.Frame(local_files_frame)
        local_path_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        local_path_frame.columnconfigure(0, weight=1)
        
        self.local_path_entry = ttk.Entry(local_path_frame)
        self.local_path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.local_path_entry.insert(0, self.local_path)
        self.local_path_entry.bind("<Return>", lambda e: self.refresh_local_files())
        
        ttk.Button(local_path_frame, text="浏览", command=self.browse_local_path).grid(row=0, column=1, padx=2)
        ttk.Button(local_path_frame, text="刷新", command=self.refresh_local_files).grid(row=0, column=2, padx=2)
        
        # 使用Treeview替代Listbox以支持图标
        self.local_files_tree = ttk.Treeview(local_files_frame, height=8, show="tree", selectmode="browse")
        self.local_files_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.local_files_tree.bind("<Double-Button-1>", lambda e: self.on_local_file_double_click())
        self.local_files_tree.bind("<Button-3>", lambda e: self.on_local_file_right_click(e))
        
        local_scrollbar = ttk.Scrollbar(local_files_frame, orient=tk.VERTICAL, command=self.local_files_tree.yview)
        local_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        self.local_files_tree.config(yscrollcommand=local_scrollbar.set)
        
        # 远程文件列表
        remote_files_frame = ttk.LabelFrame(files_container, text="远程文件", padding="5")
        remote_files_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        remote_files_frame.columnconfigure(0, weight=1)
        remote_files_frame.rowconfigure(1, weight=1)
        
        remote_path_frame = ttk.Frame(remote_files_frame)
        remote_path_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        remote_path_frame.columnconfigure(0, weight=1)
        
        self.remote_path_entry = ttk.Entry(remote_path_frame)
        self.remote_path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.remote_path_entry.insert(0, self.remote_path)
        self.remote_path_entry.bind("<Return>", lambda e: self.change_remote_directory())
        
        ttk.Button(remote_path_frame, text="刷新", command=self.refresh_remote_files).grid(row=0, column=1, padx=2)
        
        # 使用Treeview替代Listbox以支持图标
        self.remote_files_tree = ttk.Treeview(remote_files_frame, height=8, show="tree", selectmode="browse")
        self.remote_files_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.remote_files_tree.bind("<Double-Button-1>", lambda e: self.on_remote_file_double_click())
        self.remote_files_tree.bind("<Button-3>", lambda e: self.on_remote_file_right_click(e))
        
        remote_scrollbar = ttk.Scrollbar(remote_files_frame, orient=tk.VERTICAL, command=self.remote_files_tree.yview)
        remote_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        self.remote_files_tree.config(yscrollcommand=remote_scrollbar.set)
        
        # 操作按钮
        buttons_frame = ttk.Frame(file_frame)
        buttons_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(buttons_frame, text="上传 →", command=self.upload_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="← 下载", command=self.download_file).pack(side=tk.LEFT, padx=5)
        
        # 初始化显示TCP参数和文件列表
        self.on_conn_type_changed()
        self.refresh_local_files()
        
        # 恢复布局配置
        self.root.after(100, self._restore_layout)
        
        # 更新滚动区域
        self.update_scroll_region()
        
        # ANSI tag计数器（确保tag名称全局唯一）
        self.ansi_tag_counter = 0
    
    def _restore_layout(self):
        """恢复布局配置"""
        try:
            if hasattr(self, 'h_paned') and self.h_paned:
                layout_config = self.config.get("ui_layout", {})
                if layout_config:
                    pane1_size = layout_config.get("horizontal_pane1")
                    pane2_size = layout_config.get("horizontal_pane2")
                    if pane1_size:
                        try:
                            # 设置第一个分割线位置
                            self.h_paned.sashpos(0, pane1_size)
                            # 设置第二个分割线位置（如果存在）
                            if pane2_size and self.h_paned.index("end") > 2:
                                self.h_paned.sashpos(1, pane2_size)
                        except Exception:
                            pass
        except Exception:
            pass
    
    def on_conn_type_changed(self, event=None):
        """连接方式改变时的处理"""
        conn_type = self.conn_type.get()
        if conn_type == "串口":
            self.tcp_frame.grid_remove()
            self.serial_frame.grid()
        else:
            self.serial_frame.grid_remove()
            self.tcp_frame.grid()
    
    def refresh_serial_ports(self):
        """刷新串口列表"""
        ports = serial.tools.list_ports.comports()
        port_list = [port.device for port in ports]
        self.serial_port_combo['values'] = port_list
        if port_list:
            self.serial_port_combo.current(0)
    
    def toggle_connection(self):
        """切换连接状态"""
        if self.connector and self.connector.connected:
            self.disconnect()
        else:
            self.connect()
    
    def connect(self):
        """连接设备"""
        conn_type_display = self.conn_type.get()
        conn_type = conn_type_display.strip()
        if conn_type in ("TCP网口", "TCP连接", "TCP网路"):
            conn_type = "TCP"
        success = False
        host = ""
        port = ""
        
        try:
            if conn_type == "TCP":
                host = self.host_entry.get().strip()
                port = self.port_entry.get().strip()
                if not host or not port:
                    messagebox.showerror("错误", "请输入主机地址和端口")
                    return
                self.connector = TCPConnector(self.append_output, self.write_raw_log)
                self.apply_line_ending_to_connector()
                success = self.connector.connect(host=host, port=port)
                
            elif conn_type == "Telnet":
                host = self.host_entry.get().strip()
                port = self.port_entry.get().strip()
                if not host or not port:
                    messagebox.showerror("错误", "请输入主机地址和端口")
                    return
                self.connector = TelnetConnector(self.append_output, self.write_raw_log)
                self.apply_line_ending_to_connector()
                success = self.connector.connect(host=host, port=port)
                
            elif conn_type == "串口":
                port = self.serial_port_combo.get()
                baudrate = self.baudrate_combo.get()
                if not port:
                    messagebox.showerror("错误", "请选择串口")
                    return
                self.connector = SerialConnector(self.append_output, self.write_raw_log)
                self.apply_line_ending_to_connector()
                success = self.connector.connect(port=port, baudrate=baudrate)
                # 串口连接也保存配置（port作为host，baudrate作为port）
                if success:
                    self.save_connection_config(conn_type, port, baudrate)
            
            if success:
                self.connect_btn.config(text="断开")
                self.status_label.config(text="状态: 已连接", foreground="green")
                self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 连接成功\n")
                # 连接成功后确保输入提示符存在
                self.enable_input()
                
                if conn_type in ("TCP", "Telnet"):
                    self.save_connection_config(conn_type, host, port)
            else:
                self.status_label.config(text="状态: 连接失败", foreground="red")
                
        except Exception as e:
            messagebox.showerror("错误", f"连接失败: {str(e)}")
            self.status_label.config(text="状态: 连接失败", foreground="red")
    
    def disconnect(self):
        """断开连接"""
        if self.connector:
            self.connector.disconnect()
            self.connector = None
        self.connect_btn.config(text="连接")
        self.status_label.config(text="状态: 未连接", foreground="red")
        self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 已断开连接\n")
        # 断开连接后保持输入功能（但发送会失败）
        self.enable_input()
    
    def send_command(self, command=None):
        """发送命令"""
        if not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return False
        
        # 如果没有提供命令，从输入区域获取
        if command is None:
            command = self.get_input_command()
            if not command:
                return False
        
        # 发送命令到单板
        return self.connector.send_command(command)

    def send_raw_command(self, command):
        """发送原始命令（不自动追加行尾）"""
        if not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return False
        if command is None:
            return False
        return self.connector.send_raw_command(command)
    
    
    def get_input_command(self):
        """获取输入区域的命令（从输入提示符到文本末尾的所有内容）"""
        try:
            start_pos = self.output_text.index(self.input_start_mark)
            end_pos = self.output_text.index(tk.END)
            # 获取从输入提示符到末尾的所有文本
            full_text = self.output_text.get(start_pos, end_pos)
            # 移除提示符和换行符，获取实际命令
            if full_text.startswith(self.input_prompt):
                command = full_text[len(self.input_prompt):]
            else:
                command = full_text
            # 移除末尾的换行符和空白字符
            command = command.rstrip('\n\r').strip()
            return command
        except Exception as e:
            # 如果获取失败，尝试从最后一行获取
            try:
                end_pos = self.output_text.index(tk.END)
                if end_pos == "1.0":
                    return ""
                last_line_start = self.output_text.index(f"{end_pos} linestart")
                last_line = self.output_text.get(last_line_start, end_pos)
                # 移除提示符
                if last_line.startswith(self.input_prompt):
                    command = last_line[len(self.input_prompt):]
                else:
                    command = last_line
                # 移除换行符和空白字符
                command = command.rstrip('\n\r').strip()
                return command
            except:
                return ""
    
    def add_input_prompt(self):
        """更新输入区域标记（不再插入提示符，由单板返回）"""
        self.output_text.config(state=tk.NORMAL)
        # 设置输入区域标记到当前末尾（单板返回的提示符之后）
        end_pos = self.output_text.index(tk.END)
        self.output_text.mark_set(self.input_start_mark, end_pos)
        self.output_text.mark_gravity(self.input_start_mark, tk.LEFT)
        # 将光标移动到输入区域末尾
        self.output_text.mark_set(tk.INSERT, tk.END)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.NORMAL)
    
    def enable_input(self):
        """启用输入功能（现在永远启用，此方法保留用于兼容性）"""
        self.input_enabled = True
        self.output_text.config(state=tk.NORMAL)
        # 如果还没有输入提示符，添加一个
        try:
            # 检查标记是否存在
            self.output_text.index(self.input_start_mark)
            # 标记存在，确保光标在输入区域
            self.output_text.mark_set(tk.INSERT, tk.END)
        except:
            # 标记不存在，添加输入提示符
            self.add_input_prompt()
        # 确保文本框是可编辑的
        self.output_text.config(state=tk.NORMAL)
        # 将焦点设置到输出文本框
        self.output_text.focus_set()
    
    def disable_input(self):
        """禁用输入功能（现在不再禁用，此方法保留用于兼容性）"""
        # 不再禁用输入，但确保有输入提示符
        self.input_enabled = True
        self.output_text.config(state=tk.NORMAL)
        try:
            self.output_text.index(self.input_start_mark)
        except:
            self.add_input_prompt()
    
    def on_output_key(self, event):
        """输出框按键事件"""
        # 确保文本框是可编辑的
        if self.output_text.cget("state") == tk.DISABLED:
            self.output_text.config(state=tk.NORMAL)
        
        # 检查是否有选中文本，如果有选中文本在输入区域之前，不允许输入
        try:
            sel_start = self.output_text.index(tk.SEL_FIRST)
            sel_end = self.output_text.index(tk.SEL_LAST)
            input_start = self.output_text.index(self.input_start_mark)
            if sel_start and sel_end:
                # 如果选中的文本在输入区域之前，不允许输入
                if self.output_text.compare(sel_start, "<", input_start):
                    # 只允许复制等操作，不允许输入
                    if event.char and event.char.isprintable():
                        return "break"
        except:
            # 没有选中文本，继续处理
            pass
        
        # 检查光标位置是否在输入区域内
        try:
            cursor_pos = self.output_text.index(tk.INSERT)
            input_start = self.output_text.index(self.input_start_mark)
            if self.output_text.compare(cursor_pos, "<", input_start):
                # 光标在输入区域之前，移动到输入区域末尾
                self.output_text.mark_set(tk.INSERT, tk.END)
        except:
            # 如果没有输入标记，添加一个
            try:
                self.add_input_prompt()
            except:
                pass
        
        # 处理普通字符输入（实时发送，仅依赖单板回显）
        if event.char and event.char.isprintable() and len(event.char) == 1:
            if self.connector and self.connector.connected:
                try:
                    self.connector.send_command(event.char)
                except Exception:
                    pass
                return "break"  # 不在本地插入字符，等待单板回显
            else:
                messagebox.showwarning("警告", "请先连接设备")
                return "break"
        
        # 其他特殊键由专门的处理函数处理
        return None
    
    def on_paste(self, event):
        """粘贴事件处理"""
        # 确保文本框是可编辑的
        if self.output_text.cget("state") == tk.DISABLED:
            self.output_text.config(state=tk.NORMAL)
        
        # 确保光标在输入区域内
        try:
            cursor_pos = self.output_text.index(tk.INSERT)
            input_start = self.output_text.index(self.input_start_mark)
            if self.output_text.compare(cursor_pos, "<", input_start):
                self.output_text.mark_set(tk.INSERT, tk.END)
        except:
            self.add_input_prompt()
        
        # 允许默认粘贴行为
        return None
    
    def on_output_click(self, event):
        """输出框点击事件（鼠标按下）"""
        # 确保文本框是可编辑的
        if self.output_text.cget("state") == tk.DISABLED:
            self.output_text.config(state=tk.NORMAL)
        
        # 记录点击位置，用于判断是否是拖动
        self.dragging = False
        self.click_start_pos = self.output_text.index(f"@{event.x},{event.y}")
        
        # 如果点击在输入区域之前，允许选择文本但不允许编辑
        try:
            click_pos = self.output_text.index(f"@{event.x},{event.y}")
            input_start = self.output_text.index(self.input_start_mark)
            if self.output_text.compare(click_pos, "<", input_start):
                # 允许在只读区域选择文本，但不移动光标到输入区域
                # 让Tkinter处理正常的文本选择
                return None
        except:
            # 如果没有输入标记，添加一个
            try:
                self.add_input_prompt()
            except:
                pass
        
        # 允许正常的点击和选择行为
        return None
    
    def on_output_drag(self, event):
        """输出框拖动事件"""
        # 标记正在拖动
        self.dragging = True
        
        # 允许正常的文本选择行为
        return None
    
    def on_output_release(self, event):
        """输出框鼠标释放事件"""
        # 如果是在输入区域之前选择文本，确保光标不会停留在那里
        if self.dragging:
            try:
                cursor_pos = self.output_text.index(tk.INSERT)
                input_start = self.output_text.index(self.input_start_mark)
                # 如果选择结束在输入区域之前，将光标移动到输入区域
                if self.output_text.compare(cursor_pos, "<", input_start):
                    # 检查是否有选中文本
                    try:
                        sel_start = self.output_text.index(tk.SEL_FIRST)
                        sel_end = self.output_text.index(tk.SEL_LAST)
                        # 如果有选中文本，保持选择，但光标移到输入区域
                        if sel_start and sel_end:
                            self.output_text.mark_set(tk.INSERT, tk.END)
                    except:
                        # 没有选中文本，移动光标到输入区域
                        self.output_text.mark_set(tk.INSERT, tk.END)
            except:
                pass
        
        self.dragging = False
        return None
    
    def on_output_return(self, event):
        """输出框回车事件"""
        if not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return "break"

        if self.output_text.cget("state") == tk.DISABLED:
            self.output_text.config(state=tk.NORMAL)

        try:
            # 回车只发送换行符，避免逐字实时发送后再次整行发送导致重复回显/空行
            self.connector.send_command('\n')
        except Exception:
            pass
        self.reset_input_buffer()
        return "break"
    
    def on_output_backspace(self, event):
        """输出框退格事件"""
        if not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return "break"

        if self.output_text.cget("state") == tk.DISABLED:
            self.output_text.config(state=tk.NORMAL)

        if self.input_cursor > 0:
            self.input_cursor -= 1
            self.input_buffer.pop(self.input_cursor)
            self.redraw_input_line()
        elif self.connector:
            try:
                self.connector.send_command('\x7f')
            except Exception:
                pass
        return "break"
    
    def on_output_delete(self, event):
        """输出框删除事件"""
        if not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return "break"

        if self.output_text.cget("state") == tk.DISABLED:
            self.output_text.config(state=tk.NORMAL)
        
        if self.input_cursor < len(self.input_buffer):
            self.input_buffer.pop(self.input_cursor)
            self.redraw_input_line()
        elif self.connector:
            try:
                self.connector.send_command('\x04')  # Ctrl-D
            except Exception:
                pass
                return "break"
    
    def append_output(self, text):
        """添加输出文本（线程安全）"""
        self.output_queue.put(text)
        # 如果启用了日志记录，写入日志文件
        if self.log_enabled and self.log_file:
            try:
                # 移除ANSI转义序列后写入日志（使用预编译的正则）
                clean_text = self.ansi_clean_pattern.sub('', text)
                self.log_file.write(clean_text)
                self.log_file.flush()  # 实时写入
            except Exception as e:
                # 日志写入失败，不影响程序运行
                pass
    
    def check_output_queue(self):
        """检查输出队列并更新显示 - 简化版本：单板返回什么就显示什么，只处理ANSI颜色编码"""
        max_chars_per_frame = 10000  # 每帧最多处理的字符数
        max_chunks_per_frame = 50    # 每帧最多处理的chunk数
        processed_chars = 0
        processed_chunks = 0
        
        # 先记录当前是否接近底部。必须在插入新内容前判断，否则新增多行后会误判。
        should_autoscroll = False
        if self.is_output_display_enabled():
            try:
                _, visible_bottom = self.output_text.yview()
                should_autoscroll = visible_bottom >= 0.98
            except Exception:
                should_autoscroll = True
        
        self.output_text.config(state=tk.NORMAL)
        
        # 批量收集chunks
        chunks_to_process = []
        try:
            while processed_chunks < max_chunks_per_frame:
                chunk = self.output_queue.get_nowait()
                chunk_size = len(chunk)
                
                # 如果累计字符数超过限制，停止收集
                if processed_chars + chunk_size > max_chars_per_frame:
                    # 将当前chunk放回队列
                    self.output_queue.put(chunk)
                    break
                
                chunks_to_process.append(chunk)
                processed_chars += chunk_size
                processed_chunks += 1
        except queue.Empty:
            pass
        
        # 批量处理收集到的chunks
        if chunks_to_process:
            # 合并所有chunks
            combined_chunk = ''.join(chunks_to_process)
            
            # 记录所有原始chunks到STD输出
            for chunk in chunks_to_process:
                self.log_std_message(chunk)
                self.append_capture(chunk)
            
            # 与partial_output合并（处理不完整的ANSI序列）
            combined_text = (self.partial_output or "") + combined_chunk
            self.partial_output = ""
            text, remainder = self.split_incomplete_sequences(combined_text)
            if remainder:
                self.partial_output = remainder
            
            if text and self.is_output_display_enabled():
                # 移除清除屏幕的控制序列（如 \033[J, \033[K）
                text = self.strip_control_sequences(text)
                
                # 处理回车符：将 \r\n 或单独的 \r 转换为 \n
                text = text.replace('\r\n', '\n').replace('\r', '\n')
                
                # 处理退格字符：按照单板规则处理
                # 单板返回格式：[新输入][光标后的内容][退格数量等于光标后内容长度]
                # 例如：光标在2和3中间，输入4，返回 "43\x08"（4是新输入，3是光标后的内容，\x08是退格）
                # 处理逻辑：先插入所有文本（包含新输入和光标后的内容），然后退格删除光标后的内容
                
                # 从文本末尾提取退格字符，统计退格数量
                backspace_count = 0
                text_without_backspace = text
                # 从末尾开始，连续统计退格字符
                while text_without_backspace and text_without_backspace[-1] in ('\x08', '\b', '\x7f'):
                    backspace_count += 1
                    text_without_backspace = text_without_backspace[:-1]
                
                # 先插入文本（包含新输入和光标后的内容）
                if text_without_backspace:
                    insert_pos = self.output_text.index(tk.END)
                    self.insert_ansi_text(insert_pos, text_without_backspace)
                
                # 然后处理退格：删除刚插入的文本末尾的字符（数量等于光标后内容长度，即退格数量）
                if backspace_count > 0:
                    try:
                        # 使用 end-1c 获取最后一个字符的位置（而不是末尾之后的位置）
                        current_end = self.output_text.index("end-1c")
                        if self.output_text.compare(current_end, ">=", "1.0"):
                            # 删除末尾的字符（数量等于退格数量）
                            delete_count = min(backspace_count, 10000)  # 限制删除数量
                            # 计算删除起始位置：从最后一个字符往前数 delete_count 个字符
                            if self.output_text.compare(f"{current_end} - {delete_count} chars", ">=", "1.0"):
                                delete_start = self.output_text.index(f"{current_end} - {delete_count} chars")
                            else:
                                delete_start = "1.0"
                            # 删除范围：从 delete_start 到 current_end 之后（包含 current_end）
                            delete_end = self.output_text.index(f"{current_end} + 1 chars")
                            self.output_text.delete(delete_start, delete_end)
                    except Exception as e:
                        # 忽略错误
                        pass
        
        if self.is_output_display_enabled():
            # 检查并限制最大行数（最多保留1000行）
            try:
                line_count = int(self.output_text.index(tk.END).split('.')[0])
                max_lines = 1000
                if line_count > max_lines:
                    # 计算需要删除的行数
                    lines_to_delete = line_count - max_lines
                    # 删除最前面的行
                    delete_end = self.output_text.index(f"{lines_to_delete + 1}.0")
                    self.output_text.delete("1.0", delete_end)
            except:
                pass
            
            # 只在插入前已经在底部时，才自动跟随到最新输出
            if should_autoscroll:
                self.output_text.see(tk.END)
        
        self.output_text.config(state=tk.NORMAL)
        
        # 如果队列还有数据，缩短下次检查间隔；否则恢复正常间隔
        if not self.output_queue.empty():
            self.root.after(10, self.check_output_queue)  # 队列有数据时更频繁检查
        else:
            self.root.after(100, self.check_output_queue)  # 队列空时正常间隔
    
    def process_control_chars(self, insert_pos, text):
        """处理控制字符（如BS、DEL）"""
        cleaned_chars = []
        current_pos = insert_pos if insert_pos else self.input_line_range[0]
        i = 0
        length = len(text)
        
        while i < length:
            ch = text[i]
            if ch in ('\x08', '\b', '\x7f'):
                if self.input_cursor > 0:
                    self.input_cursor -= 1
                    if self.input_cursor < len(self.input_buffer):
                        self.input_buffer.pop(self.input_cursor)
                i += 1
                continue
            if text.startswith('\033[D', i):  # CSI 左移
                if self.input_cursor > 0:
                    self.input_cursor -= 1
                i += 3
                continue
            if text.startswith('\033[C', i):  # CSI 右移
                if self.input_cursor < len(self.input_buffer):
                    self.input_cursor += 1
                i += 3
                continue
            if ch == '\r':
                self.input_cursor = 0
                i += 1
                continue
            if ch == '\n':
                self.input_buffer = []
                self.input_cursor = 0
                cleaned_chars.append(ch)
                i += 1
                continue
            cleaned_chars.append(ch)
            if self.input_cursor >= len(self.input_buffer):
                self.input_buffer.append(ch)
            else:
                self.input_buffer.insert(self.input_cursor, ch)
            self.input_cursor += 1
            i += 1
        
        cleaned_text = ''.join(cleaned_chars)
        return cleaned_text, current_pos

    def redraw_input_line(self):
        if self.redrawing_input:
            return
        self.redrawing_input = True
        try:
            self.draw_input_line()
        finally:
            self.redrawing_input = False

    def draw_input_line(self):
        """绘制输入行（根据新的简化逻辑，不删除输出内容，只更新输入行显示）"""
        # 根据新的简化逻辑，输入应该由单板返回显示
        # 但为了用户体验，我们仍然在本地显示输入缓冲（作为预览）
        # 注意：这个函数不应该删除任何输出内容
        
        # 使用 input_start_mark 作为输入行的起始位置
        try:
            start = self.output_text.index(self.input_start_mark)
        except:
            # 如果标记不存在，使用末尾
            start = self.output_text.index(tk.END)
            if hasattr(self, 'input_start_mark'):
                self.output_text.mark_set(self.input_start_mark, start)
                self.output_text.mark_gravity(self.input_start_mark, tk.LEFT)
        
        # 只删除输入行的内容（如果有 input_line_range 且有效）
        # 注意：不能删除输出内容，只能删除之前绘制的输入行内容
        if hasattr(self, 'input_line_range') and self.input_line_range:
            input_start_range, input_end_range = self.input_line_range
            try:
                # 确保 range 有效，并且只删除输入行的内容（不能超过 start 到 END 的范围）
                if (self.output_text.compare(input_start_range, ">=", start) and 
                    self.output_text.compare(input_end_range, ">", input_start_range)):
                    # 只删除输入行的内容（从 input_start_range 到 input_end_range）
                    self.output_text.delete(input_start_range, input_end_range)
                    # 更新 start 为删除后的位置
                    start = input_start_range
            except:
                # 如果 range 无效，不删除任何内容
                pass
        
        # 插入输入缓冲内容（作为预览，不插入提示符，由单板返回）
        input_content = ''.join(self.input_buffer)
        if input_content:
            self.output_text.insert(start, input_content)
        
        # 更新 input_line_range（输入行的范围）
        if input_content:
            new_end = self.output_text.index(f"{start} + {len(input_content)} chars")
        else:
            new_end = start
        self.input_line_range = (start, new_end)
        
        # 更新 input_start_mark（保持 LEFT gravity）
        self.output_text.mark_set(self.input_start_mark, start)
        self.output_text.mark_gravity(self.input_start_mark, tk.LEFT)
        
        # 设置光标位置
        cursor_pos = self.output_text.index(f"{start} + {self.input_cursor} chars")
        self.output_text.mark_set(tk.INSERT, cursor_pos)
        self.output_text.see(cursor_pos)

    def reset_input_buffer(self):
        """重置输入缓冲（根据新的简化逻辑，不删除输出内容）"""
        # 根据新的简化逻辑，输入应该由单板返回显示，不在本地显示
        # 所以这里只清空输入缓冲，不删除任何输出内容
        self.input_buffer = []
        self.input_cursor = 0
        # 更新标记位置到末尾（用于其他功能，但不影响显示）
        new_pos = self.output_text.index(tk.END)
        if hasattr(self, 'input_line_range'):
            self.input_line_range = (new_pos, new_pos)
        if hasattr(self, 'input_start_mark'):
            self.output_text.mark_set(self.input_start_mark, new_pos)
            self.output_text.mark_gravity(self.input_start_mark, tk.LEFT)
        self.output_text.mark_set(tk.INSERT, new_pos)

    def format_raw_text(self, raw_text):
        """将原始文本转换为可读的转义形式"""
        result = []
        for ch in raw_text:
            code = ord(ch)
            if ch == '\x1b':
                result.append(r"\033")
            elif ch == '\n':
                result.append(r"\n")
            elif ch == '\r':
                result.append(r"\r")
            elif ch == '\t':
                result.append(r"\t")
            elif 32 <= code <= 126:
                result.append(ch)
            else:
                result.append(f"\\x{code:02x}")
        return ''.join(result)

    def log_std_message(self, raw_text):
        """在STD输出窗口中记录调试信息"""
        if not hasattr(self, "std_output"):
            return
        try:
            if hasattr(self, "show_std_output") and not self.show_std_output.get():
                return
        except Exception:
            pass
        formatted = self.format_raw_text(raw_text)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.std_output.config(state=tk.NORMAL)
        self.std_output.insert(tk.END, f"[{timestamp}] {formatted}\n")
        self.std_output.see(tk.END)
        self.std_output.config(state=tk.DISABLED)

    def split_incomplete_sequences(self, text):
        """拆分末尾未完整的ANSI序列，返回可处理文本和剩余缓冲"""
        if not text:
            return "", ""
        # 如果以 ESC 结尾，直接缓冲
        if text.endswith("\033"):
            return text[:-1], "\033"
        # 匹配未完成的CSI序列（以 \033[ 开头但尚未有终止符）
        match = self.incomplete_csi_pattern.search(text)
        if match:
            return text[:match.start()], text[match.start():]
        # 匹配未完成的OSC序列（\033] ... 尚未遇到BEL或ESC\\）
        match = self.incomplete_osc_pattern.search(text)
        if match:
            return text[:match.start()], text[match.start():]
        return text, ""

    def strip_control_sequences(self, text):
        """移除无需显示的控制序列（例如清屏）"""
        if not text:
            return text
        # 去掉 \033[J / \033[0J / \033[1J / \033[2J 和 \033[K 等清行命令（使用预编译的正则）
        text = self.clear_sequences_pattern.sub('', text)
        return text
    
    def insert_ansi_text(self, start_pos, text):
        """插入带ANSI颜色编码的文本"""
        # 使用实例变量保持颜色状态
        current_fg = self.current_fg_color
        current_bg = self.current_bg_color
        
        # 查找所有ANSI转义序列
        last_pos = 0
        insert_pos = start_pos
        
        for match in self.ansi_pattern.finditer(text):
            # 插入ANSI序列之前的文本
            if match.start() > last_pos:
                plain_text = text[last_pos:match.start()]
                if plain_text:
                    self.output_text.insert(insert_pos, plain_text)
                    # 应用当前颜色（如果与默认不同，或者有背景色）
                    if current_fg != "#FFFFFF" or current_bg:
                        end_pos = self.output_text.index(f"{insert_pos} + {len(plain_text)} chars")
                        tag_name = f"ansi_seg_{self.ansi_tag_counter}"
                        self.ansi_tag_counter += 1
                        self.output_text.tag_add(tag_name, insert_pos, end_pos)
                        # 明确设置前景色（即使与默认相同，也要设置以确保tag生效）
                        if current_fg != "#FFFFFF":
                            self.output_text.tag_config(tag_name, foreground=current_fg)
                        elif current_bg:
                            # 如果有背景色但前景色是白色，也要设置前景色以确保tag生效
                            self.output_text.tag_config(tag_name, foreground=current_fg)
                        if current_bg:
                            self.output_text.tag_config(tag_name, background=current_bg)
                        insert_pos = end_pos
                    else:
                        insert_pos = self.output_text.index(f"{insert_pos} + {len(plain_text)} chars")
            
            # 解析ANSI代码
            code_str = match.group(1)
            # 如果没有代码（如 \033[m），视为重置（相当于 \033[0m）
            if not code_str:
                current_fg = "#FFFFFF"
                current_bg = None
            else:
                codes = code_str.split(';')
                for code_item in codes:
                    if not code_item:
                        continue
                    try:
                        code = int(code_item)
                        if code == 0:
                            # 重置所有属性
                            current_fg = "#FFFFFF"
                            current_bg = None
                        elif code == 1:
                            # 粗体（暂时忽略）
                            pass
                        elif 30 <= code <= 37:
                            # 标准前景色（30-37）
                            current_fg = self.ansi_fg_colors.get(code, "#FFFFFF")
                        elif 40 <= code <= 47:
                            # 标准背景色（40-47）
                            current_bg = self.ansi_bg_colors.get(code)
                        elif code in self.ansi_fg_colors:
                            # 其他前景色（如90-97）
                            current_fg = self.ansi_fg_colors[code]
                        elif code in self.ansi_bg_colors:
                            # 其他背景色
                            current_bg = self.ansi_bg_colors[code]
                    except ValueError:
                        pass
            
            last_pos = match.end()
        
        # 插入剩余的文本
        if last_pos < len(text):
            plain_text = text[last_pos:]
            if plain_text:
                self.output_text.insert(insert_pos, plain_text)
                # 应用当前颜色（如果与默认不同，或者有背景色）
                if current_fg != "#FFFFFF" or current_bg:
                    end_pos = self.output_text.index(f"{insert_pos} + {len(plain_text)} chars")
                    tag_name = f"ansi_seg_{self.ansi_tag_counter}"
                    self.ansi_tag_counter += 1
                    self.output_text.tag_add(tag_name, insert_pos, end_pos)
                    # 明确设置前景色（即使与默认相同，也要设置以确保tag生效）
                    if current_fg != "#FFFFFF":
                        self.output_text.tag_config(tag_name, foreground=current_fg)
                    elif current_bg:
                        # 如果有背景色但前景色是白色，也要设置前景色以确保tag生效
                        self.output_text.tag_config(tag_name, foreground=current_fg)
                    if current_bg:
                        self.output_text.tag_config(tag_name, background=current_bg)
                    insert_pos = end_pos
                else:
                    insert_pos = self.output_text.index(f"{insert_pos} + {len(plain_text)} chars")
        
        # 更新实例变量，保持颜色状态
        self.current_fg_color = current_fg
        self.current_bg_color = current_bg
    
    def clear_output(self):
        """清空输出"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        # 重置颜色状态
        self.current_fg_color = "#FFFFFF"
        self.current_bg_color = None
        # 重新添加输入提示符
        self.add_input_prompt()
        self.output_text.config(state=tk.NORMAL)
    
    def toggle_log(self):
        """切换日志记录状态"""
        if self.log_checkbox.instate(['selected']):
            # 启用日志记录
            self.start_logging()
        else:
            # 禁用日志记录
            self.stop_logging()
    
    def on_show_output_toggle(self):
        """切换是否显示输出"""
        self.config["show_output_display"] = bool(self.show_output_display.get())
        top = self.root.winfo_toplevel()
        if hasattr(top, 'save_config'):
            top.save_config()
    
    def is_output_display_enabled(self):
        try:
            return bool(self.show_output_display.get())
        except Exception:
            return True
    
    def on_show_std_output_toggle(self):
        """切换是否打印STD输出"""
        self.config["show_std_output"] = bool(self.show_std_output.get())
        top = self.root.winfo_toplevel()
        if hasattr(top, 'save_config'):
            top.save_config()
    
    def start_logging(self):
        """开始记录日志"""
        try:
            # 创建日志目录
            log_dir = os.path.join(os.path.expanduser("~"), "单板连接日志")
            if not os.path.exists(log_dir):
                os.makedirs(log_dir)
            
            # 生成日志文件名（带时间戳）
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"{self.tab_name}_{timestamp}.txt"
            self.log_file_path = os.path.join(log_dir, log_filename)
            
            # 打开日志文件（追加模式）
            self.log_file = open(self.log_file_path, 'a', encoding='utf-8')
            
            # 原始日志文件（保留未处理内容）
            raw_log_filename = f"{self.tab_name}_{timestamp}_raw.log"
            self.raw_log_file_path = os.path.join(log_dir, raw_log_filename)
            self.raw_log_file = open(self.raw_log_file_path, 'ab')
            
            self.log_enabled = True
            self.append_output(f"[日志] 开始记录日志到: {self.log_file_path}\n")
            self.append_output(f"[日志] 原始日志记录到: {self.raw_log_file_path}\n")
        except Exception as e:
            messagebox.showerror("错误", f"启动日志记录失败: {str(e)}")
            self.log_checkbox.state(['!selected'])
            self.log_enabled = False
    
    def stop_logging(self):
        """停止记录日志"""
        if self.log_file:
            try:
                self.log_file.close()
                self.append_output(f"[日志] 日志已保存到: {self.log_file_path}\n")
            except:
                pass
            self.log_file = None
        if self.raw_log_file:
            try:
                self.raw_log_file.close()
                self.append_output(f"[日志] 原始日志已保存到: {self.raw_log_file_path}\n")
            except:
                pass
            self.raw_log_file = None
        self.log_enabled = False
    
    def write_raw_log(self, data):
        """写入原始日志"""
        if self.raw_log_file and data:
            try:
                self.raw_log_file.write(data)
                self.raw_log_file.flush()
            except Exception:
                pass
    
    def send_quick_command(self):
        """发送快速命令"""
        command = self.quick_cmd_entry.get().strip()
        if not command:
            return
        
        if not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return
        
        # 添加到命令历史
        if not self.command_history or self.command_history[-1] != command:
            self.command_history.append(command)
            if len(self.command_history) > 100:  # 限制历史记录数量
                self.command_history.pop(0)
        self.history_index = -1
        
        # 保存命令历史到配置
        self.save_commands_config()
        
        # 发送命令（会自动添加换行符）
        if self.connector.send_command(command):
            self.append_output(f"[快速发送] {command}\n")
            self.quick_cmd_entry.delete(0, tk.END)
            # 确保输出显示区域可以继续输入
            self.output_text.focus_set()
            self.enable_input()
        else:
            messagebox.showerror("错误", "发送命令失败")
    
    def send_quick_command_text(self, command):
        """发送快速命令文本（从按钮）"""
        self.quick_cmd_entry.delete(0, tk.END)
        self.quick_cmd_entry.insert(0, command)
        self.send_quick_command()
    
    def on_common_cmd_right_click(self, event, index):
        """快速命令按钮右键点击事件"""
        self.editing_cmd_index = index
        try:
            self.common_cmd_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.common_cmd_menu.grab_release()
    
    def edit_common_command(self):
        """编辑常用命令"""
        if self.editing_cmd_index is None:
            return
        
        if self.editing_cmd_index >= len(self.common_commands):
            return
        
        current_cmd = self.common_commands[self.editing_cmd_index]
        new_cmd = simpledialog.askstring(
            "编辑命令",
            "请输入新的命令：",
            initialvalue=current_cmd,
            parent=self.root
        )
        
        if new_cmd is not None:
            new_cmd = new_cmd.strip()
            if new_cmd:
                # 更新命令列表
                self.common_commands[self.editing_cmd_index] = new_cmd
                # 更新按钮文本
                if self.editing_cmd_index < len(self.common_cmd_buttons):
                    self.common_cmd_buttons[self.editing_cmd_index].config(text=new_cmd)
                    # 更新按钮命令
                    self.common_cmd_buttons[self.editing_cmd_index].config(
                        command=lambda c=new_cmd: self.send_quick_command_text(c)
                    )
                # 保存到配置
                self.config["common_commands"] = self.common_commands.copy()
                top = self.root.winfo_toplevel()
                if hasattr(top, 'save_config'):
                    top.save_config()
    
    def on_pane_resize(self, event=None):
        """PanedWindow大小调整时保存布局"""
        try:
            if not hasattr(self, 'h_paned') or not self.h_paned:
                return
            # 获取各个pane的大小
            total_width = self.h_paned.winfo_width()
            if total_width > 0:
                # 获取分割线位置
                try:
                    sash0_pos = self.h_paned.sashpos(0)
                    sash1_pos = self.h_paned.sashpos(1) if self.h_paned.index("end") > 2 else None
                    
                    # 保存到配置
                    if "ui_layout" not in self.config:
                        self.config["ui_layout"] = {}
                    self.config["ui_layout"]["horizontal_pane1"] = sash0_pos
                    if sash1_pos is not None:
                        self.config["ui_layout"]["horizontal_pane2"] = sash1_pos
                    
                    # 延迟保存，避免频繁写入
                    if not hasattr(self, '_layout_save_timer'):
                        self._layout_save_timer = None
                    if self._layout_save_timer:
                        self.root.after_cancel(self._layout_save_timer)
                    self._layout_save_timer = self.root.after(500, self._save_layout_config)
                except Exception:
                    pass
        except Exception:
            pass
    
    def _save_layout_config(self):
        """保存布局配置"""
        top = self.root.winfo_toplevel()
        if hasattr(top, 'save_config'):
            top.save_config()
        self._layout_save_timer = None

    def get_line_ending(self):
        """根据当前设置返回换行符"""
        return "\r\n" if self.use_crlf.get() else "\n"

    def apply_line_ending_to_connector(self):
        """将当前换行设置应用到连接器"""
        if self.connector:
            self.connector.line_ending = self.get_line_ending()

    def on_line_ending_toggle(self):
        """切换换行符设置"""
        self.config["line_ending_crlf"] = self.use_crlf.get()
        self.apply_line_ending_to_connector()
        top = self.root.winfo_toplevel()
        if hasattr(top, "save_config"):
            top.save_config()
    
    def history_up(self):
        """命令历史向上"""
        if not self.command_history:
            return "break"
        
        if self.history_index == -1:
            self.history_index = len(self.command_history) - 1
        elif self.history_index > 0:
            self.history_index -= 1
        
        self.quick_cmd_entry.delete(0, tk.END)
        self.quick_cmd_entry.insert(0, self.command_history[self.history_index])
        return "break"
    
    def history_down(self):
        """命令历史向下"""
        if not self.command_history:
            return "break"
        
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.quick_cmd_entry.delete(0, tk.END)
            self.quick_cmd_entry.insert(0, self.command_history[self.history_index])
        else:
            self.history_index = -1
            self.quick_cmd_entry.delete(0, tk.END)
        
        return "break"
    
    def start_capture(self):
        with self.capture_lock:
            self.capture_text = ""
    
    def append_capture(self, chunk):
        with self.capture_lock:
            if self.capture_text is not None:
                self.capture_text += chunk
    
    def get_capture(self):
        with self.capture_lock:
            if self.capture_text is None:
                return ""
            return self.capture_text
    
    def end_capture(self):
        with self.capture_lock:
            if self.capture_text is None:
                return ""
            data = self.capture_text
            self.capture_text = None
            return data
    
    def refresh_smart_templates(self, select_title=""):
        titles = [""] + list(self.smart_templates.keys())
        self.smart_template_combo['values'] = titles
        if select_title:
            self.smart_template_combo.set(select_title)
        else:
            self.smart_template_combo.set("")
        self.smart_title_entry.delete(0, tk.END)
        if select_title:
            self.smart_title_entry.insert(0, select_title)
            self.smart_text.delete("1.0", tk.END)
            self.smart_text.insert(tk.END, self.smart_templates.get(select_title, ""))
    
    def apply_smart_template(self, event=None):
        """应用智能命令模板"""
        template_name = self.smart_template_combo.get()
        content = self.smart_templates.get(template_name, "")
        if content:
            self.current_template_name = template_name
            self.smart_title_entry.delete(0, tk.END)
            self.smart_title_entry.insert(0, template_name)
            self.smart_text.delete("1.0", tk.END)
            self.smart_text.insert(tk.END, content)
    
    def save_smart_template(self):
        """保存或更新当前智能命令模板"""
        title = self.smart_title_entry.get().strip()
        if not title:
            messagebox.showwarning("警告", "请先输入模板标题")
            return
        content = self.smart_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("警告", "模板内容为空，无法保存")
            return
        
        # 如果重命名，删除旧模板
        if self.current_template_name and self.current_template_name != title:
            self.smart_templates.pop(self.current_template_name, None)
        
        self.smart_templates[title] = content
        self.current_template_name = title
        self.refresh_smart_templates(select_title=title)
        self.save_smart_templates()
        messagebox.showinfo("提示", f"模板「{title}」已保存")
    
    def pop(self, message):
        """在pop文本框中显示消息，每次显示会替换原来的内容"""
        if hasattr(self, 'pop_entry'):
            self.pop_entry.config(state=tk.NORMAL)
            self.pop_entry.delete(0, tk.END)
            self.pop_entry.insert(0, str(message))
            self.pop_entry.config(state="readonly")
    
    def wait_for_confirmation(self, message):
        """显示消息并等待用户点击"已确认，继续操作"按钮"""
        # 重置事件（清除之前的状态）
        if hasattr(self, 'pop_confirmation_event'):
            self.pop_confirmation_event.clear()
        # 显示消息
        self.pop(message)
        # 等待用户确认（在UI线程中执行）
        if threading.current_thread() == threading.main_thread():
            # 如果在主线程，需要特殊处理，避免阻塞UI
            # 这种情况下应该抛出异常，因为不应该在主线程中等待
            raise RuntimeError("wait_for_confirmation 不能在UI主线程中调用")
        # 等待事件被设置（最多等待300秒，避免永久阻塞）
        self.pop_confirmation_event.wait(timeout=300)
    
    def clear_pop(self):
        """清空pop文本框，并通知等待确认的线程继续执行
        
        每次点击"已确认，继续操作"按钮时，会设置事件以唤醒正在等待的线程。
        支持多次调用 wait_for_confirmation，每次点击按钮都会让下一个等待继续执行。
        """
        if hasattr(self, 'pop_entry'):
            self.pop_entry.config(state=tk.NORMAL)
            self.pop_entry.delete(0, tk.END)
            self.pop_entry.config(state="readonly")
        # 通知等待确认的线程继续执行
        # 每次点击按钮都会设置事件，让当前正在等待的 wait_for_confirmation 继续
        if hasattr(self, 'pop_confirmation_event'):
            self.pop_confirmation_event.set()
    
    def send_smart_command(self):
        """发送智能命令编辑区的命令"""
        if not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return
        
        content = self.smart_text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("提示", "请先输入需要发送的命令")
            return
        
        commands = [line.strip() for line in content.splitlines() if line.strip()]
        if not commands:
            messagebox.showinfo("提示", "没有可发送的命令")
            return
        
        sent = 0
        for cmd in commands:
            if self.connector.send_command(cmd):
                self.append_output(f"[智能命令] {cmd}\n")
                sent += 1
            else:
                self.append_output(f"[错误] 智能命令发送失败: {cmd}\n")
                break
        self.smart_text.focus_set()
        self.save_current_smart_code()
        messagebox.showinfo("提示", f"智能命令发送完成，共发送 {sent} 条。")
    
    def smart_print(self, message):
        """打印到智能脚本输出框"""
        self.smart_output.config(state=tk.NORMAL)
        self.smart_output.insert(tk.END, message + "\n")
        self.smart_output.see(tk.END)
        self.smart_output.config(state=tk.DISABLED)
    
    def smart_text_tab(self, event):
        """智能命令编辑区的Tab键处理：如果有补全提示则补全，否则插入缩进"""
        if self.smart_completion:
            # 有补全提示，执行补全
            self.smart_text_complete()
            return "break"
        else:
            # 没有补全提示，插入缩进
            self.smart_text.insert(tk.INSERT, "    ")
            return "break"
    
    def smart_text_key_release(self, event):
        """智能命令编辑区按键释放事件：检测并显示代码补全提示"""
        # 忽略某些按键（如方向键、功能键等）
        if event.keysym in ('Up', 'Down', 'Left', 'Right', 'Return', 'Tab', 'Escape', 
                           'Shift_L', 'Shift_R', 'Control_L', 'Control_R', 
                           'Alt_L', 'Alt_R', 'Meta_L', 'Meta_R'):
            # 如果是方向键或回车，清除补全提示
            if event.keysym in ('Up', 'Down', 'Left', 'Right', 'Return', 'Escape'):
                self.smart_text_clear_completion()
            return
        
        # 如果是删除键，清除补全提示
        if event.keysym in ('BackSpace', 'Delete'):
            self.smart_text_clear_completion()
            return
        
        # 先获取当前光标位置（在清除补全之前，因为清除可能会改变位置）
        try:
            current_cursor = self.smart_text.index(tk.INSERT)
        except:
            current_cursor = None
        
        # 清除之前的补全提示（必须在获取光标位置之后）
        self.smart_text_clear_completion()
        
        # 如果光标位置发生了变化（因为清除了补全），使用新的光标位置
        try:
            if current_cursor:
                # 确保光标在正确位置
                self.smart_text.mark_set(tk.INSERT, current_cursor)
            cursor_pos = self.smart_text.index(tk.INSERT)
            line_start = self.smart_text.index(f"{cursor_pos} linestart")
            
            # 获取当前行的文本（从行首到光标位置）
            line_text = self.smart_text.get(line_start, cursor_pos)
            
            # 使用正则表达式匹配函数名（字母、数字、下划线）
            # 匹配最后一个可能的函数名（从字母或下划线开始，使用预编译的正则）
            match = self.function_name_pattern.search(line_text)
            if match:
                partial_name = match.group(1)
                
                # 查找匹配的函数名
                matches = [func for func in self.smart_functions if func.startswith(partial_name)]
                
                if matches and matches[0] != partial_name:
                    # 找到匹配的函数名，显示补全提示
                    completion = matches[0]
                    completion_text = completion[len(partial_name):]
                    
                    if completion_text:
                        # 在光标位置插入灰色补全提示
                        self.smart_text.insert(tk.INSERT, completion_text, "completion")
                        # 记录补全信息
                        end_pos = self.smart_text.index(tk.INSERT)
                        self.smart_completion = (cursor_pos, end_pos, completion_text)
                        # 将光标移回插入位置（白色和灰色之间）
                        self.smart_text.mark_set(tk.INSERT, cursor_pos)
        except:
            # 如果出错，清除补全提示
            self.smart_text_clear_completion()
    
    def smart_text_clear_completion(self):
        """清除代码补全提示（通过 tag 删除，更可靠）"""
        if self.smart_completion:
            # 通过 tag 删除所有带有 "completion" tag 的文本
            # 这样即使中间插入了字符，也能正确删除补全提示
            try:
                ranges = self.smart_text.tag_ranges("completion")
                # ranges 是成对的 (start1, end1, start2, end2, ...)
                for i in range(0, len(ranges), 2):
                    if i + 1 < len(ranges):
                        start = ranges[i]
                        end = ranges[i + 1]
                        self.smart_text.delete(start, end)
            except:
                pass
            self.smart_completion = None
    
    def smart_text_complete(self):
        """执行代码补全"""
        if self.smart_completion:
            start_pos, end_pos, completion_text = self.smart_completion
            try:
                # 删除补全提示（灰色文本）
                self.smart_text.delete(start_pos, end_pos)
                # 插入实际的补全文本（正常颜色）
                self.smart_text.insert(start_pos, completion_text)
            except:
                pass
            self.smart_completion = None
    
    def show_smart_help(self):
        """显示智能命令功能帮助"""
        help_text = (
            "智能命令编辑支持以下内置函数：\n"
            "• send(cmd): 发送字符串命令到当前连接\n"
            "• send_raw(cmd): 原样发送字符串，不自动追加行尾\n"
            "• tcp(host, port): 使用TCP网口连接单板\n"
            "• telnet(host, port): 使用Telnet连接单板\n"
            "• com(port, baudrate=115200): 使用串口连接单板\n"
            "• disconnect(): 断开当前连接\n"
            "• get_ip_address(): 获取当前电脑的IPv4地址列表\n"
            "• pop(message): 在pop文本框中显示消息，每次显示会替换原来的内容\n"
            "• wait_for_confirmation(message): 显示消息并暂停执行，等待用户点击「已确认，继续操作」按钮后继续\n"
            "• start_receive(): 开始捕获单板回显\n"
            "• get_receive(): 获取捕获内容但不结束\n"
            "• end_receive(): 结束捕获并返回文本\n"
            "• send_file(src, dst): 传输文件（本地<->远程），返回True/False\n"
            "• sftp_connect(host, port, user, pwd): 建立SFTP连接，返回True/False\n"
            "• sftp_disconnect(): 关闭SFTP连接，返回True/False\n"
            "• ftp_connect(host, port, user, pwd): 建立FTP连接，返回True/False\n"
            "• ftp_disconnect(): 关闭FTP连接，返回True/False\n"
            "• list_remote_files(path=None): 获取远程目录文件列表，返回包含name/size/is_dir的字典列表\n"
            "• print(...): 将信息输出到脚本输出窗口\n"
            "• wait(seconds): 等同于 time.sleep，用于延时\n\n"
            "可以编写多行 Python 代码，例如循环发送命令、等待回显等。"
        )
        messagebox.showinfo("智能命令帮助", help_text)
    
    def run_smart_python(self):
        """以Python脚本执行智能命令"""
        code = self.smart_text.get("1.0", tk.END).strip()
        if not code:
            messagebox.showinfo("提示", "请先输入需要执行的Python代码")
            return
        self.save_current_smart_code()
        
        # 若已有脚本在运行，先请求停止旧线程
        if self.smart_script_thread and self.smart_script_thread.is_alive():
            self.request_stop_smart_python(reason="检测到新的执行请求，正在停止旧脚本")
            self.smart_script_thread.join(timeout=1.0)
            if self.smart_script_thread.is_alive():
                self.smart_print("[脚本] 旧脚本仍在退出中，新脚本将继续启动")
        
        self.smart_run_id += 1
        run_id = self.smart_run_id
        stop_event = threading.Event()
        self.smart_stop_event = stop_event
        self.set_smart_running_state(True)
        
        def worker():
            def ensure_not_stopped():
                if stop_event.is_set():
                    raise RuntimeError("脚本已停止")
            
            def _wait(seconds):
                seconds = float(seconds)
                if seconds <= 0:
                    ensure_not_stopped()
                    return
                deadline = time.time() + seconds
                while True:
                    ensure_not_stopped()
                    remain = deadline - time.time()
                    if remain <= 0:
                        break
                    time.sleep(min(0.1, remain))
            
            def _send(command):
                ensure_not_stopped()
                return send(command)
            
            def _send_raw(command):
                ensure_not_stopped()
                return send_raw(command)
            
            def _wait_for_confirmation(message):
                ensure_not_stopped()
                wait_for_confirmation(message)
                ensure_not_stopped()
            
            local_context = {
                "send": _send,
                "send_raw": _send_raw,
                "tcp": tcp,
                "telnet": telnet,
                "com": com,
                "disconnect": disconnect,
                "get_ip_address": get_ip_address,
                "pop": pop,
                "wait_for_confirmation": _wait_for_confirmation,
                "start_receive": start_receive,
                "end_receive": end_receive,
                "get_receive": get_receive,
                "send_file": send_file,
                "sftp_connect": sftp_connect,
                "sftp_disconnect": sftp_disconnect,
                "ftp_connect": ftp_connect,
                "ftp_disconnect": ftp_disconnect,
                "list_remote_files": list_remote_files,
                "wait": _wait,
                "sleep": _wait
            }
            try:
                def _print(*args, **kwargs):
                    msg = " ".join(str(arg) for arg in args)
                    self.smart_print(msg)
                local_context["print"] = _print
                ensure_not_stopped()
                exec(code, {"__builtins__": __builtins__}, local_context)
                ensure_not_stopped()
                self.smart_print("[脚本] 执行完成")
            except Exception as e:
                self.smart_print(f"[错误] {e}")
            finally:
                self.root.after(0, lambda: self.finish_smart_python_run(run_id))
        
        self.smart_script_thread = threading.Thread(target=worker, daemon=True)
        self.smart_script_thread.start()
    
    def set_smart_running_state(self, is_running):
        """更新智能脚本运行态按钮状态"""
        if hasattr(self, "smart_run_btn"):
            self.smart_run_btn.config(state=tk.DISABLED if is_running else tk.NORMAL)
        if hasattr(self, "smart_stop_btn"):
            self.smart_stop_btn.config(state=tk.NORMAL if is_running else tk.DISABLED)
    
    def request_stop_smart_python(self, reason=None):
        """请求停止当前智能脚本线程（协作式）"""
        if self.smart_stop_event:
            self.smart_stop_event.set()
        # 如果脚本在等待用户确认，主动唤醒等待以便尽快退出
        if hasattr(self, "pop_confirmation_event"):
            self.pop_confirmation_event.set()
        if reason:
            self.smart_print(f"[脚本] {reason}")
    
    def stop_smart_python(self):
        """手动停止智能脚本执行"""
        if self.smart_script_thread and self.smart_script_thread.is_alive():
            self.request_stop_smart_python(reason="已请求停止")
        else:
            self.smart_print("[脚本] 当前没有正在执行的脚本")
            self.set_smart_running_state(False)
    
    def finish_smart_python_run(self, run_id):
        """线程结束后的清理，避免旧线程覆盖新线程状态"""
        if run_id != self.smart_run_id:
            return
        self.set_smart_running_state(False)
        self.smart_script_thread = None
        self.smart_stop_event = None
    
    def save_smart_templates(self):
        """保存智能模板到配置"""
        self.config["smart_templates"] = self.smart_templates.copy()
        root = self.root.winfo_toplevel()
        if hasattr(root, "save_config"):
            root.save_config()
    
    def save_current_smart_code(self):
        """保存智能命令编辑区当前内容"""
        content = self.smart_text.get("1.0", tk.END).rstrip()
        self.last_smart_code = content
        self.config["smart_code"] = content
        top = self.root.winfo_toplevel()
        if hasattr(top, "save_config"):
            top.save_config()
        return content
    
    def manual_save_smart_code(self):
        """手动保存智能命令编辑区内容"""
        content = self.save_current_smart_code()
        messagebox.showinfo("提示", "代码块内容已保存" if content else "当前代码块为空，已保存为空内容")
    
    def save_smart_code_to_file(self):
        """将当前代码块保存到txt文件"""
        content = self.smart_text.get("1.0", tk.END).rstrip()
        if not content:
            messagebox.showwarning("警告", "当前代码块为空，无法保存")
            return
        
        # 选择保存位置
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="保存代码到文件"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("成功", f"代码已保存到: {file_path}")
        except Exception as e:
            messagebox.showerror("错误", f"保存文件失败: {str(e)}")
    
    def load_smart_code_from_file(self):
        """从txt文件读取代码到当前代码块，并根据文件名自动生成模板标题"""
        # 选择文件
        file_path = filedialog.askopenfilename(
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
            title="从文件读取代码"
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 读取代码到编辑区
            self.smart_text.delete("1.0", tk.END)
            self.smart_text.insert("1.0", content)
            
            # 根据文件名生成模板标题（去掉路径和扩展名）
            file_name = os.path.basename(file_path)
            template_title = os.path.splitext(file_name)[0]
            
            # 设置模板标题
            self.smart_title_entry.delete(0, tk.END)
            self.smart_title_entry.insert(0, template_title)
            self.current_template_name = template_title
            
            messagebox.showinfo("成功", f"代码已从文件加载: {file_path}\n模板标题已自动设置为: {template_title}")
        except Exception as e:
            messagebox.showerror("错误", f"读取文件失败: {str(e)}")
    
    def on_file_protocol_change(self, event=None):
        """协议切换时更新端口默认值和状态显示"""
        protocol = self.file_protocol.get()
        default_port = "22" if protocol == "SFTP" else "21"
        current_port = self.sftp_port_entry.get().strip()
        if not current_port or current_port in ("22", "21"):
            self.sftp_port_entry.delete(0, tk.END)
            self.sftp_port_entry.insert(0, default_port)
        if not (self.file_connector and self.file_connector.connected):
            self.file_status_label.config(text=f"{protocol}: 未连接", foreground="red")
        self.save_file_transfer_config(protocol, self.sftp_host_entry.get().strip(),
                                       self.sftp_port_entry.get().strip(),
                                       self.sftp_user_entry.get().strip(),
                                       self.sftp_pass_entry.get().strip())
    
    def toggle_file_connection(self):
        """切换文件传输连接状态"""
        if self.file_connector and self.file_connector.connected:
            self.disconnect_file_transfer()
        else:
            self.connect_file_transfer()
    
    def connect_file_transfer(self):
        """连接SFTP或FTP"""
        host = self.sftp_host_entry.get().strip()
        port = self.sftp_port_entry.get().strip()
        username = self.sftp_user_entry.get().strip()
        password = self.sftp_pass_entry.get().strip()
        protocol = self.file_protocol.get()
        
        if not all([host, port, username]):
            messagebox.showerror("错误", f"请填写完整的{protocol}连接信息")
            return
        
        if self.file_connector and self.file_connector.connected:
            self.file_connector.disconnect()
            self.file_connector = None
        
        connector = SFTPConnector() if protocol == "SFTP" else FTPConnector()
        result = connector.connect(host, port, username, password)
        
        if isinstance(result, tuple):
            success, error_msg = result
        else:
            success = result
            error_msg = ""
        
        if success:
            self.file_connector = connector
            self.active_file_protocol = protocol
            self.file_connect_btn.config(text="断开")
            self.file_status_label.config(text=f"{protocol}: 已连接", foreground="green")
            self.remote_path = self.file_connector.get_current_directory() or "/"
            self.remote_path_entry.delete(0, tk.END)
            self.remote_path_entry.insert(0, self.remote_path)
            self.refresh_remote_files()
            self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {protocol}连接成功\n")
            self.save_file_transfer_config(protocol, host, port, username, password)
        else:
            self.file_status_label.config(text=f"{protocol}: 连接失败", foreground="red")
            messagebox.showerror("错误", f"{protocol}连接失败: {error_msg}")
    
    def disconnect_file_transfer(self):
        """断开文件传输连接"""
        protocol = self.active_file_protocol or self.file_protocol.get()
        if self.file_connector:
            self.file_connector.disconnect()
            self.file_connector = None
        self.active_file_protocol = None
        self.file_connect_btn.config(text="连接")
        self.file_status_label.config(text=f"{protocol}: 未连接", foreground="red")
        for item in self.remote_files_tree.get_children():
            self.remote_files_tree.delete(item)
        self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {protocol}已断开连接\n")
    
    def refresh_local_files(self):
        """刷新本地文件列表"""
        path = self.local_path_entry.get().strip()
        if not path:
            path = os.path.expanduser("~")
        
        if not os.path.exists(path):
            messagebox.showerror("错误", f"路径不存在: {path}")
            return
        
        if not os.path.isdir(path):
            path = os.path.dirname(path)
        
        self.local_path = path
        self.local_path_entry.delete(0, tk.END)
        self.local_path_entry.insert(0, self.local_path)
        
        # 清空Treeview
        for item in self.local_files_tree.get_children():
            self.local_files_tree.delete(item)
        
        # 添加父目录
        if path != os.path.dirname(path):
            icon = self.get_file_icon("..", is_dir=True)
            self.local_files_tree.insert("", tk.END, text=f"{icon} ..", values=("..", True))
        
        try:
            items = sorted(os.listdir(path))
            for item in items:
                item_path = os.path.join(path, item)
                is_dir = os.path.isdir(item_path)
                icon = self.get_file_icon(item, is_dir=is_dir)
                
                if is_dir:
                    display_text = f"{icon} {item}"
                    self.local_files_tree.insert("", tk.END, text=display_text, values=(item, True))
                else:
                    size = os.path.getsize(item_path)
                    size_str = self.format_size(size)
                    display_text = f"{icon} {item} ({size_str})"
                    self.local_files_tree.insert("", tk.END, text=display_text, values=(item, False, size))
        except Exception as e:
            messagebox.showerror("错误", f"读取目录失败: {str(e)}")
    
    def refresh_remote_files(self):
        """刷新远程文件列表"""
        if not self.file_connector or not self.file_connector.connected:
            for item in self.remote_files_tree.get_children():
                self.remote_files_tree.delete(item)
            return
        
        path = self.remote_path_entry.get().strip() or "/"
        
        for item in self.remote_files_tree.get_children():
            self.remote_files_tree.delete(item)
        
        try:
            if path != self.remote_path:
                result = self.file_connector.change_directory(path)
                if isinstance(result, tuple):
                    success, msg = result
                else:
                    success = bool(result)
                    msg = ""
                if not success:
                    messagebox.showerror("错误", f"切换目录失败: {msg}")
                    self.remote_path_entry.delete(0, tk.END)
                    self.remote_path_entry.insert(0, self.remote_path)
                    path = self.remote_path
                else:
                    self.remote_path = self.file_connector.get_current_directory() or path
                    self.remote_path_entry.delete(0, tk.END)
                    self.remote_path_entry.insert(0, self.remote_path)
            
            if self.remote_path not in ("", "/"):
                icon = self.get_file_icon("..", is_dir=True)
                self.remote_files_tree.insert("", tk.END, text=f"{icon} ..", values=("..", True))
            
            files = self.file_connector.list_files(self.remote_path)
            files.sort(key=lambda x: (not x.get('is_dir', False), x.get('name', '').lower()))
            
            for file_info in files:
                name = file_info.get('name', '')
                is_dir = file_info.get('is_dir', False)
                icon = self.get_file_icon(name, is_dir=is_dir)
                if is_dir:
                    display_text = f"{icon} {name}"
                    self.remote_files_tree.insert("", tk.END, text=display_text, values=(name, True))
                else:
                    size_str = self.format_size(file_info.get('size', 0))
                    display_text = f"{icon} {name} ({size_str})"
                    self.remote_files_tree.insert("", tk.END, text=display_text, values=(name, False, file_info.get('size', 0)))
        except Exception as e:
            messagebox.showerror("错误", f"读取远程目录失败: {str(e)}")
    
    def format_size(self, size):
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def browse_local_path(self):
        """浏览本地路径"""
        path = filedialog.askdirectory(initialdir=self.local_path)
        if path:
            self.local_path = path
            self.local_path_entry.delete(0, tk.END)
            self.local_path_entry.insert(0, self.local_path)
            self.refresh_local_files()
    
    def change_remote_directory(self):
        """改变远程目录"""
        self.refresh_remote_files()
    
    def on_local_file_double_click(self):
        """本地文件双击事件"""
        selection = self.local_files_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        values = self.local_files_tree.item(item_id, "values")
        if not values:
            return
        
        name = values[0]
        is_dir = values[1] if len(values) > 1 else False
        
        if name == "..":
            self.local_path = os.path.dirname(self.local_path)
        elif is_dir:
            new_path = os.path.join(self.local_path, name)
            if os.path.isdir(new_path):
                self.local_path = new_path
        else:
            return  # 文件双击不处理
        
        self.local_path_entry.delete(0, tk.END)
        self.local_path_entry.insert(0, self.local_path)
        self.refresh_local_files()
    
    def on_remote_file_double_click(self):
        """远程文件双击事件"""
        if not self.file_connector or not self.file_connector.connected:
            return
        
        selection = self.remote_files_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        values = self.remote_files_tree.item(item_id, "values")
        if not values:
            return
        
        name = values[0]
        is_dir = values[1] if len(values) > 1 else False
        
        if name == "..":
            new_path = os.path.dirname(self.remote_path.rstrip("/")) or "/"
        elif is_dir:
            new_path = os.path.join(self.remote_path, name).replace("\\", "/")
        else:
            return  # 文件双击不处理
        
        try:
            files = self.file_connector.list_files(new_path)
            if files is not None:
                self.remote_path = new_path
                self.remote_path_entry.delete(0, tk.END)
                self.remote_path_entry.insert(0, self.remote_path)
                self.refresh_remote_files()
        except Exception:
            pass
    
    def on_local_file_right_click(self, event):
        """本地文件右键事件"""
        pass
    
    def on_remote_file_right_click(self, event):
        """远程文件右键事件"""
        pass
    
    def upload_file(self):
        """上传文件"""
        if not self.file_connector or not self.file_connector.connected:
            messagebox.showwarning("警告", "请先建立SFTP/FTP连接")
            return
        
        selection = self.local_files_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请选择要上传的文件")
            return
        
        item_id = selection[0]
        values = self.local_files_tree.item(item_id, "values")
        if not values:
            return
        
        name = values[0]
        is_dir = values[1] if len(values) > 1 else False
        
        if is_dir:
            messagebox.showinfo("提示", "请选择文件，不能上传目录")
            return
        
        if name == "..":
            messagebox.showinfo("提示", "请选择文件")
            return
        
        local_path = os.path.join(self.local_path, name)
        
        if not os.path.isfile(local_path):
            messagebox.showerror("错误", "选择的不是文件")
            return
        
        remote_file = os.path.join(self.remote_path, name).replace("\\", "/")
        
        try:
            success, msg = self.file_connector.upload_file(local_path, remote_file)
            if success:
                messagebox.showinfo("成功", f"文件上传成功: {name}")
                self.refresh_remote_files()
                self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 上传文件: {name} -> {remote_file}\n")
            else:
                messagebox.showerror("错误", f"上传失败: {msg}")
        except Exception as e:
            messagebox.showerror("错误", f"上传失败: {str(e)}")
    
    def download_file(self):
        """下载文件"""
        if not self.file_connector or not self.file_connector.connected:
            messagebox.showwarning("警告", "请先建立SFTP/FTP连接")
            return
        
        selection = self.remote_files_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请选择要下载的文件")
            return
        
        item_id = selection[0]
        values = self.remote_files_tree.item(item_id, "values")
        if not values:
            return
        
        name = values[0]
        is_dir = values[1] if len(values) > 1 else False
        
        if is_dir:
            messagebox.showinfo("提示", "请选择文件，不能下载目录")
            return
        
        if name == "..":
            messagebox.showinfo("提示", "请选择文件")
            return
        
        remote_path = os.path.join(self.remote_path, name).replace("\\", "/")
        
        # 选择保存位置
        local_file = filedialog.asksaveasfilename(
            initialdir=self.local_path,
            initialfile=name,
            title="保存文件"
        )
        
        if not local_file:
            return
        
        try:
            success, msg = self.file_connector.download_file(remote_path, local_file)
            if success:
                messagebox.showinfo("成功", f"文件下载成功: {name}")
                self.refresh_local_files()
                self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 下载文件: {remote_path} -> {local_file}\n")
            else:
                messagebox.showerror("错误", f"下载失败: {msg}")
        except Exception as e:
            messagebox.showerror("错误", f"下载失败: {str(e)}")
    
    def save_connection_config(self, conn_type, host, port):
        """保存连接配置"""
        # 统一连接类型名称
        if conn_type == "TCP网口":
            conn_type = "TCP"
        self.config["connection"] = {
            "type": conn_type,
            "host": host,
            "port": port
        }
        # 通知主窗口保存配置
        if hasattr(self.root, 'winfo_toplevel'):
            top = self.root.winfo_toplevel()
            if hasattr(top, 'save_config'):
                top.save_config()
    
    def save_commands_config(self):
        """保存命令历史配置"""
        self.config["commands"] = self.command_history.copy()
        # 通知主窗口保存配置
        if hasattr(self.root, 'winfo_toplevel'):
            top = self.root.winfo_toplevel()
            if hasattr(top, 'save_config'):
                top.save_config()
    
    def save_file_transfer_config(self, protocol, host, port, username, password):
        """保存文件传输配置"""
        if not protocol:
            protocol = "SFTP"
        self.config["file_transfer"] = {
            "type": protocol,
            "host": host,
            "port": port,
            "username": username,
            "password": password  # 注意：密码以明文保存
        }
        # 通知主窗口保存配置
        if hasattr(self.root, 'winfo_toplevel'):
            top = self.root.winfo_toplevel()
            if hasattr(top, 'save_config'):
                top.save_config()
    
    def load_config(self, config):
        """加载配置"""
        if not config:
            return
        
        # 恢复连接配置
        if "connection" in config:
            conn_config = config["connection"]
            conn_type = conn_config.get("type", "TCP")
            host = conn_config.get("host", "")
            port = conn_config.get("port", "")
            
            # 设置连接方式
            if conn_type == "TCP":
                self.conn_type.set("TCP网口")
                if host:
                    self.host_entry.delete(0, tk.END)
                    self.host_entry.insert(0, host)
                if port:
                    self.port_entry.delete(0, tk.END)
                    self.port_entry.insert(0, port)
            elif conn_type == "Telnet":
                self.conn_type.set("Telnet")
                if host:
                    self.host_entry.delete(0, tk.END)
                    self.host_entry.insert(0, host)
                if port:
                    self.port_entry.delete(0, tk.END)
                    self.port_entry.insert(0, port)
            elif conn_type == "串口":
                self.conn_type.set("串口")
                if host:  # 串口的host是端口名
                    self.serial_port_combo.set(host)
                if port:  # 串口的port是波特率
                    self.baudrate_combo.set(port)
            self.on_conn_type_changed()
        
        # 恢复命令历史
        if "commands" in config:
            self.command_history = config["commands"].copy()
        
        # 恢复智能模板
        if "smart_templates" in config:
            self.smart_templates = config["smart_templates"].copy()
            self.config["smart_templates"] = self.smart_templates.copy()
            self.refresh_smart_templates()
        
        # 恢复智能命令代码块
        if "smart_code" in config:
            self.last_smart_code = config.get("smart_code", "")
            self.smart_text.delete("1.0", tk.END)
            self.smart_text.insert(tk.END, self.last_smart_code)

        # 恢复换行符设置
        if "line_ending_crlf" in config:
            line_ending_crlf = bool(config.get("line_ending_crlf", False))
        else:
            line_ending_crlf = False
        self.use_crlf.set(line_ending_crlf)
        self.config["line_ending_crlf"] = line_ending_crlf
        self.apply_line_ending_to_connector()
        
        # 恢复快速命令
        if "common_commands" in config:
            common_commands = config.get("common_commands", [])
            if common_commands:
                self.common_commands = common_commands.copy()
                self.config["common_commands"] = self.common_commands.copy()
                # 更新按钮
                for i, cmd in enumerate(self.common_commands):
                    if i < len(self.common_cmd_buttons):
                        self.common_cmd_buttons[i].config(text=cmd)
                        self.common_cmd_buttons[i].config(
                            command=lambda c=cmd: self.send_quick_command_text(c)
                        )
        
        if "show_output_display" in config:
            self.show_output_display.set(bool(config.get("show_output_display", True)))
        if "show_std_output" in config:
            self.show_std_output.set(bool(config.get("show_std_output", False)))
        
        # 恢复文件传输配置
        file_config = config.get("file_transfer") or config.get("sftp")
        if file_config:
            protocol = file_config.get("type", "SFTP")
            self.file_protocol.set(protocol)
            self.file_protocol_combo.set(protocol)
            host = file_config.get("host", "")
            port = file_config.get("port", "22" if protocol == "SFTP" else "21")
            username = file_config.get("username", "")
            password = file_config.get("password", "")
            
            if host:
                self.sftp_host_entry.delete(0, tk.END)
                self.sftp_host_entry.insert(0, host)
            if port:
                self.sftp_port_entry.delete(0, tk.END)
                self.sftp_port_entry.insert(0, port)
            if username:
                self.sftp_user_entry.delete(0, tk.END)
                self.sftp_user_entry.insert(0, username)
            if password:
                self.sftp_pass_entry.delete(0, tk.END)
                self.sftp_pass_entry.insert(0, password)
            self.on_file_protocol_change()
    
    def cleanup(self):
        """清理资源"""
        self.request_stop_smart_python()
        # 停止日志记录
        if self.log_enabled:
            self.stop_logging()
        
        if self.connector and self.connector.connected:
            self.disconnect()
        if self.file_connector and self.file_connector.connected:
            self.disconnect_file_transfer()


class DebugWindow:
    """调试窗口 - 用于测试输出显示功能"""
    
    def __init__(self, parent, app):
        self.parent = parent
        self.app = app
        self.test_cases = []
        
        # 创建调试窗口
        self.window = tk.Toplevel(parent)
        self.window.title("调试模式 - 测试用例")
        self.window.geometry("1200x800")
        
        # 主框架
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 顶部：加载测试用例按钮
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(top_frame, text="加载测试用例", command=self.load_test_cases).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="运行选中测试", command=self.run_selected_test).pack(side=tk.LEFT, padx=5)
        
        # 左侧：测试用例列表
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False, padx=(0, 10))
        left_frame.config(width=300)
        
        ttk.Label(left_frame, text="测试用例列表:").pack(anchor=tk.W, pady=(0, 5))
        list_frame = ttk.Frame(left_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.test_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        self.test_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.test_listbox.yview)
        
        # 右侧：结果显示区域
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # 创建标签页显示实际输出和预期输出
        notebook = ttk.Notebook(right_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # 实际输出标签页
        actual_frame = ttk.Frame(notebook)
        notebook.add(actual_frame, text="实际输出")
        
        actual_scroll = ttk.Scrollbar(actual_frame)
        actual_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.actual_text = tk.Text(actual_frame, yscrollcommand=actual_scroll.set, wrap=tk.NONE, font=("Consolas", 10))
        self.actual_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        actual_scroll.config(command=self.actual_text.yview)
        
        # 预期输出标签页
        expected_frame = ttk.Frame(notebook)
        notebook.add(expected_frame, text="预期输出")
        
        expected_scroll = ttk.Scrollbar(expected_frame)
        expected_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.expected_text = tk.Text(expected_frame, yscrollcommand=expected_scroll.set, wrap=tk.NONE, font=("Consolas", 10))
        self.expected_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        expected_scroll.config(command=self.expected_text.yview)
        
        # 差异对比标签页
        diff_frame = ttk.Frame(notebook)
        notebook.add(diff_frame, text="差异对比")
        
        diff_scroll = ttk.Scrollbar(diff_frame)
        diff_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.diff_text = tk.Text(diff_frame, yscrollcommand=diff_scroll.set, wrap=tk.NONE, font=("Consolas", 10))
        self.diff_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        diff_scroll.config(command=self.diff_text.yview)
        
        # 状态栏
        self.status_label = ttk.Label(main_frame, text="就绪")
        self.status_label.pack(fill=tk.X, pady=(10, 0))
        
        # 自动加载测试用例
        self.load_test_cases()
    
    def decode_escape_sequences(self, text):
        """解码转义序列（如 \\x08, \\033 等）
        在 JSON 中，这些已经写成 \\x08, \\033 等，解析后会变成 \x08, \033（字符串）
        需要将它们转换为实际的字符
        """
        if not isinstance(text, str):
            return text
        try:
            import re
            import codecs
            
            # 方法：将字符串转换为原始字符串，然后使用 codecs.decode
            # 但需要先处理特殊字符，避免与常见转义冲突
            
            # 先处理常见的转义序列（这些在 JSON 中已经是 \\n 等格式）
            common_escapes = {
                '\\n': '\n',
                '\\r': '\r',
                '\\t': '\t',
                '\\b': '\b',
                '\\f': '\f',
                '\\v': '\v',
                '\\a': '\a',
                "\\'": "'",
                '\\"': '"',
            }
            
            # 临时替换常见转义，避免后续处理时冲突
            temp_map = {}
            for i, (old, new) in enumerate(common_escapes.items()):
                temp_key = f'__TEMP_ESCAPE_{i}__'
                temp_map[temp_key] = new
                text = text.replace(old, temp_key)
            
            # 处理十六进制转义 \xHH
            def replace_hex(match):
                hex_str = match.group(1)
                try:
                    return chr(int(hex_str, 16))
                except:
                    return match.group(0)
            text = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, text)
            
            # 处理八进制转义 \OOO（1-3位八进制数字，但排除已处理的常见转义）
            def replace_oct(match):
                oct_str = match.group(1)
                try:
                    # 确保是有效的八进制数字
                    if all(c in '01234567' for c in oct_str):
                        return chr(int(oct_str, 8))
                except:
                    pass
                return match.group(0)
            # 匹配 \ 后跟1-3位八进制数字
            text = re.sub(r'\\([0-7]{1,3})(?![0-9a-fA-Fx])', replace_oct, text)
            
            # 恢复常见转义
            for temp_key, new in temp_map.items():
                text = text.replace(temp_key, new)
            
            # 最后处理反斜杠本身（必须是最后）
            text = text.replace('\\\\', '\\')
            
            return text
        except Exception as e:
            # 如果解码失败，返回原字符串
            import traceback
            traceback.print_exc()
            return text
    
    def load_test_cases(self):
        """加载测试用例文件"""
        test_file = "test_cases.json"
        if not os.path.exists(test_file):
            self.status_label.config(text=f"测试用例文件不存在: {test_file}")
            return
        
        try:
            with open(test_file, 'r', encoding='utf-8') as f:
                self.test_cases = json.load(f)
            
            # 解码转义序列
            for test_case in self.test_cases:
                # 解码 device_outputs
                if 'device_outputs' in test_case:
                    test_case['device_outputs'] = [
                        self.decode_escape_sequences(output) 
                        for output in test_case['device_outputs']
                    ]
                # 解码 expected_display
                if 'expected_display' in test_case:
                    test_case['expected_display'] = self.decode_escape_sequences(
                        test_case['expected_display']
                    )
            
            # 更新列表
            self.test_listbox.delete(0, tk.END)
            for i, test_case in enumerate(self.test_cases):
                name = test_case.get('name', f'测试用例 {i+1}')
                self.test_listbox.insert(tk.END, name)
            
            self.status_label.config(text=f"已加载 {len(self.test_cases)} 个测试用例")
        except Exception as e:
            self.status_label.config(text=f"加载测试用例失败: {e}")
            messagebox.showerror("错误", f"加载测试用例失败: {e}")
    
    def run_selected_test(self):
        """运行选中的测试用例"""
        selection = self.test_listbox.curselection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个测试用例")
            return
        
        test_index = selection[0]
        test_case = self.test_cases[test_index]
        
        self.status_label.config(text=f"正在运行: {test_case.get('name', '测试用例')}")
        
        # 创建一个临时的 TabPage 来模拟
        # 我们需要创建一个模拟的 TabPage，不实际连接设备
        try:
            # 创建临时标签页用于测试
            temp_tab = self.app.add_tab(f"调试-{test_case.get('name', '测试')}")
            temp_tab_page = self.app.tabs[list(self.app.tabs.keys())[-1]]
            
            # 创建一个模拟的 connector，避免连接检查错误
            class MockConnector:
                def __init__(self):
                    self.connected = True
                def send_command(self, cmd):
                    pass  # 调试模式下不实际发送
            
            if not hasattr(temp_tab_page, 'connector') or temp_tab_page.connector is None:
                temp_tab_page.connector = MockConnector()
            
            # 清空输出区域
            temp_tab_page.clear_output()
            
            # 模拟执行测试用例
            self.execute_test_case(temp_tab_page, test_case)
            
            # 等待所有处理完成
            self.window.update()
            time.sleep(0.1)
            
            # 显示结果
            self.show_test_results(temp_tab_page, test_case)
            
            self.status_label.config(text=f"测试完成: {test_case.get('name', '测试用例')}")
        except Exception as e:
            self.status_label.config(text=f"测试失败: {e}")
            messagebox.showerror("错误", f"测试执行失败: {e}")
            import traceback
            traceback.print_exc()
    
    def execute_test_case(self, tab_page, test_case):
        """执行测试用例，模拟输入和输出"""
        inputs = test_case.get('inputs', [])
        device_outputs = test_case.get('device_outputs', [])
        
        # 先处理所有输入（模拟用户操作）
        # 注意：根据新的简化逻辑，输入应该由设备返回显示，不在本地显示
        # 所以这里只更新 input_buffer，不调用 redraw_input_line()
        for input_item in inputs:
            if input_item['type'] == 'key':
                # 模拟按键（只更新缓冲，不显示）
                tab_page.input_buffer.append(input_item['value'])
                tab_page.input_cursor = len(tab_page.input_buffer)
                self.window.update()
                time.sleep(0.01)
            elif input_item['type'] == 'left':
                # 模拟光标左移（只更新光标位置，不显示）
                for _ in range(input_item.get('count', 1)):
                    if tab_page.input_cursor > 0:
                        tab_page.input_cursor -= 1
                self.window.update()
                time.sleep(0.01)
            elif input_item['type'] == 'return':
                # 模拟回车（清空缓冲，不显示）
                line = ''.join(tab_page.input_buffer)
                tab_page.reset_input_buffer()
                self.window.update()
                time.sleep(0.01)
        
        # 然后处理所有设备输出（模拟设备响应）
        # 设备输出可能分多次到达，需要逐个处理
        for idx, device_output in enumerate(device_outputs):
            if device_output:
                # 将输出放入队列
                tab_page.output_queue.put(device_output)
                # 直接处理输出队列（同步处理，不使用 after）
                # 每次只处理一个 chunk，避免重复处理
                self.process_output_queue_sync(tab_page, max_chunks=1)
                # 更新界面
                self.window.update()
                time.sleep(0.01)  # 短暂延迟确保处理完成
        
        # 处理剩余的队列数据
        while not tab_page.output_queue.empty():
            self.process_output_queue_sync(tab_page)
            self.window.update()
            time.sleep(0.01)
    
    def process_output_queue_sync(self, tab_page, max_chunks=1):
        """同步处理输出队列（用于调试模式）
        max_chunks: 每次处理的最大chunk数量，默认为1以避免重复处理
        """
        max_chars_per_frame = 10000
        max_chunks_per_frame = max_chunks
        processed_chars = 0
        processed_chunks = 0
        
        tab_page.output_text.config(state=tk.NORMAL)
        
        # 批量收集chunks
        chunks_to_process = []
        try:
            while processed_chunks < max_chunks_per_frame:
                chunk = tab_page.output_queue.get_nowait()
                chunk_size = len(chunk)
                
                if processed_chars + chunk_size > max_chars_per_frame:
                    tab_page.output_queue.put(chunk)
                    break
                
                chunks_to_process.append(chunk)
                processed_chars += chunk_size
                processed_chunks += 1
        except queue.Empty:
            pass
        
        # 批量处理收集到的chunks - 简化版本：单板返回什么就显示什么，只处理ANSI颜色编码
        if chunks_to_process:
            combined_chunk = ''.join(chunks_to_process)
            
            for chunk in chunks_to_process:
                tab_page.log_std_message(chunk)
                tab_page.append_capture(chunk)
            
            # 与partial_output合并（处理不完整的ANSI序列）
            combined_text = (tab_page.partial_output or "") + combined_chunk
            tab_page.partial_output = ""
            text, remainder = tab_page.split_incomplete_sequences(combined_text)
            if remainder:
                tab_page.partial_output = remainder
            
            if text and tab_page.is_output_display_enabled():
                # 移除清除屏幕的控制序列（如 \033[J, \033[K）
                text = tab_page.strip_control_sequences(text)
                
                # 处理回车符：将 \r\n 或单独的 \r 转换为 \n
                text = text.replace('\r\n', '\n').replace('\r', '\n')
                
                # 处理退格字符：按照单板规则处理
                # 单板返回格式：[新输入][光标后的内容][退格数量等于光标后内容长度]
                # 例如：光标在2和3中间，输入4，返回 "43\x08"（4是新输入，3是光标后的内容，\x08是退格）
                # 处理逻辑：先插入所有文本（包含新输入和光标后的内容），然后退格删除光标后的内容
                
                # 从文本末尾提取退格字符，统计退格数量
                backspace_count = 0
                text_without_backspace = text
                # 从末尾开始，连续统计退格字符
                while text_without_backspace and text_without_backspace[-1] in ('\x08', '\b', '\x7f'):
                    backspace_count += 1
                    text_without_backspace = text_without_backspace[:-1]
                
                # 先插入文本（包含新输入和光标后的内容）
                if text_without_backspace:
                    insert_pos = tab_page.output_text.index(tk.END)
                    tab_page.insert_ansi_text(insert_pos, text_without_backspace)
                
                # 然后处理退格：删除刚插入的文本末尾的字符（数量等于光标后内容长度，即退格数量）
                if backspace_count > 0:
                    try:
                        # 使用 end-1c 获取最后一个字符的位置（而不是末尾之后的位置）
                        current_end = tab_page.output_text.index("end-1c")
                        if tab_page.output_text.compare(current_end, ">=", "1.0"):
                            # 删除末尾的字符（数量等于退格数量）
                            delete_count = min(backspace_count, 10000)  # 限制删除数量
                            # 计算删除起始位置：从最后一个字符往前数 delete_count 个字符
                            if tab_page.output_text.compare(f"{current_end} - {delete_count} chars", ">=", "1.0"):
                                delete_start = tab_page.output_text.index(f"{current_end} - {delete_count} chars")
                            else:
                                delete_start = "1.0"
                            # 删除范围：从 delete_start 到 current_end 之后（包含 current_end）
                            delete_end = tab_page.output_text.index(f"{current_end} + 1 chars")
                            tab_page.output_text.delete(delete_start, delete_end)
                    except Exception as e:
                        # 忽略错误
                        pass
        
        if tab_page.is_output_display_enabled():
            # 检查并限制最大行数（最多保留1000行）
            try:
                line_count = int(tab_page.output_text.index(tk.END).split('.')[0])
                max_lines = 1000
                if line_count > max_lines:
                    # 计算需要删除的行数
                    lines_to_delete = line_count - max_lines
                    # 删除最前面的行
                    delete_end = tab_page.output_text.index(f"{lines_to_delete + 1}.0")
                    tab_page.output_text.delete("1.0", delete_end)
            except:
                pass
            
            tab_page.output_text.see(tk.END)
        tab_page.output_text.config(state=tk.NORMAL)
    
    def show_test_results(self, tab_page, test_case):
        """显示测试结果"""
        # 获取实际输出（所有内容，因为现在单板返回什么就显示什么）
        try:
            actual_display = tab_page.output_text.get("1.0", tk.END).rstrip('\n')
        except:
            actual_display = ""
        
        # 获取预期输出
        expected_display = test_case.get('expected_display', '').rstrip('\n')
        
        # 显示实际输出
        self.actual_text.delete("1.0", tk.END)
        self.actual_text.insert("1.0", actual_display)
        
        # 显示预期输出
        self.expected_text.delete("1.0", tk.END)
        self.expected_text.insert("1.0", expected_display)
        
        # 显示差异
        self.diff_text.delete("1.0", tk.END)
        
        # 规范化比较（移除末尾空白）
        actual_normalized = actual_display.rstrip()
        expected_normalized = expected_display.rstrip()
        
        if actual_normalized == expected_normalized:
            self.diff_text.insert("1.0", "✓ 测试通过：实际输出与预期输出一致\n\n")
            self.diff_text.tag_add("success", "1.0", "1.end")
            self.diff_text.tag_config("success", foreground="green")
            self.diff_text.insert(tk.END, "实际输出:\n")
            self.diff_text.insert(tk.END, actual_display)
        else:
            self.diff_text.insert("1.0", "✗ 测试失败：实际输出与预期输出不一致\n\n")
            self.diff_text.tag_add("error", "1.0", "1.end")
            self.diff_text.tag_config("error", foreground="red")
            self.diff_text.insert(tk.END, "实际输出:\n")
            self.diff_text.insert(tk.END, actual_display)
            self.diff_text.insert(tk.END, "\n\n预期输出:\n")
            self.diff_text.insert(tk.END, expected_display)
            
            # 显示字符级别的差异
            self.diff_text.insert(tk.END, "\n\n字符差异分析:\n")
            self.diff_text.insert(tk.END, f"实际长度: {len(actual_display)}, 预期长度: {len(expected_display)}\n")
            
            # 逐字符比较
            min_len = min(len(actual_display), len(expected_display))
            diff_count = 0
            for i in range(min_len):
                if actual_display[i] != expected_display[i]:
                    diff_count += 1
                    if diff_count <= 10:  # 只显示前10个差异
                        self.diff_text.insert(tk.END, f"位置 {i}: 实际='{repr(actual_display[i])}', 预期='{repr(expected_display[i])}'\n")
            
            if len(actual_display) != len(expected_display):
                self.diff_text.insert(tk.END, f"长度不同: 实际多出 {len(actual_display) - min_len} 个字符，预期多出 {len(expected_display) - min_len} 个字符\n")


class DeviceConnectionApp:
    """设备连接应用程序主窗口"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("单板连接工具 - 多标签页")
        self.root.geometry("1000x900")
        
        self.tabs = {}  # 存储标签页对象
        self.tab_counter = 1  # 标签页计数器
        self.plus_tab_frame = None  # "+"标签页框架
        self.ignore_tab_change = False  # 是否忽略标签页切换事件
        self.loading_tabs = False  # 是否处于加载配置阶段
        
        # 配置文件路径
        self.config_file = os.path.join(os.path.expanduser("~"), ".单板连接工具_config.json")
        
        # 预编译正则表达式以减少开销
        self.tab_number_pattern = re.compile(r'(\d+)$')
        
        # 加载配置
        self.config = self.load_config()
        
        self.setup_ui()
        
        # 窗口关闭时保存配置
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # 将save_config方法绑定到root，方便TabPage调用
        self.root.save_config = self.save_config
    
    def load_config(self):
        """加载配置文件"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"加载配置失败: {e}")
        return {}
    
    def save_config(self):
        """保存配置文件"""
        try:
            config = {}
            for tab_name, tab_page in self.tabs.items():
                if hasattr(tab_page, 'config'):
                    config[tab_name] = tab_page.config
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            # 同步内存中的配置
            self.config = config
        except Exception as e:
            print(f"保存配置失败: {e}")
    
    def setup_ui(self):
        """设置用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
        
        # 标签页控件
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        self.notebook.bind("<Button-3>", self.on_tab_right_click)
        self.notebook.bind("<Double-Button-1>", self.on_tab_double_click)
        self.tab_menu = tk.Menu(self.root, tearoff=0)
        self.tab_menu.add_command(label="重命名标签页", command=self.rename_selected_tab)
        self.context_menu_tab_id = None
        
        # 工具栏（只保留关闭按钮）
        toolbar = ttk.Frame(main_frame)
        toolbar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Button(toolbar, text="关闭当前标签页", command=self.close_current_tab).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="调试模式", command=self.open_debug_window).pack(side=tk.LEFT, padx=5)
        
        # 每次启动时记录已有标签计数
        self.tab_counter = 1
        
        # 根据配置恢复标签页，如果没有配置则创建默认标签页
        saved_tab_names = [name for name in self.config.keys() if name != "+"]
        self.loading_tabs = True
        if saved_tab_names:
            for name in saved_tab_names:
                self.add_tab(name, self.config.get(name))
            # 默认选中第一个已保存的标签页
            self.select_tab_by_name(saved_tab_names[0])
        else:
            self.add_tab("单板 1")
        self.loading_tabs = False
        
        # 添加"+"标签页
        self.add_plus_tab()
        # 保存一次配置，确保标签集合记录最新状态
        self.save_config()
    
    def add_tab(self, tab_name=None, config=None):
        """添加新标签页"""
        if tab_name is None:
            tab_name = f"单板 {self.tab_counter}"
            self.tab_counter += 1
        else:
            match = self.tab_number_pattern.search(tab_name.strip())
            if match:
                next_idx = int(match.group(1)) + 1
                if next_idx > self.tab_counter:
                    self.tab_counter = next_idx
        
        # 设置标志，忽略标签页切换事件
        self.ignore_tab_change = True
        
        # 如果存在"+"标签页，先移除它
        if self.plus_tab_frame:
            try:
                self.notebook.forget(self.plus_tab_frame)
                self.plus_tab_frame = None
            except:
                pass
        
        # 创建标签页框架
        tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(tab_frame, text=tab_name)
        
        # 创建标签页对象
        tab_page = TabPage(tab_frame, tab_name, self.root)
        self.tabs[tab_name] = tab_page
        
        # 如果提供了配置，加载配置
        if config:
            try:
                tab_page.load_config(config)
            except Exception as e:
                print(f"加载标签页 {tab_name} 配置失败: {e}")
        
        # 切换到新标签页
        self.notebook.select(tab_frame)
        self.set_active_tab(tab_name)
        
        # 重新添加"+"标签页到末尾
        self.add_plus_tab()
        
        # 恢复标志
        self.ignore_tab_change = False
        # 保存当前配置（确保新标签页被记录）
        if not self.loading_tabs:
            self.save_config()
    
    def add_plus_tab(self):
        """添加"+"标签页"""
        # 如果已经存在"+"标签页，先移除
        if self.plus_tab_frame:
            try:
                self.notebook.forget(self.plus_tab_frame)
            except:
                pass
        
        # 创建"+"标签页框架
        self.plus_tab_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.plus_tab_frame, text="+")
        
        # 在框架中添加提示信息
        info_label = ttk.Label(self.plus_tab_frame, text="点击此标签页创建新的单板连接", font=("", 12))
        info_label.pack(expand=True, fill=tk.BOTH, padx=50, pady=50)
    
    def close_current_tab(self):
        """关闭当前标签页"""
        current_tab = self.notebook.select()
        if not current_tab:
            return
        
        # 获取标签页名称
        tab_name = self.notebook.tab(current_tab, "text")
        
        # 如果是"+"标签页，不允许关闭
        if tab_name == "+":
            return
        
        # 如果只有一个普通标签页，不允许关闭
        if len(self.tabs) <= 1:
            messagebox.showinfo("提示", "至少需要保留一个标签页")
            return
        
        # 确认关闭
        if messagebox.askyesno("确认", f"确定要关闭标签页 '{tab_name}' 吗？"):
            # 设置标志，忽略标签页切换事件
            self.ignore_tab_change = True
            
            # 清理标签页资源
            if tab_name in self.tabs:
                self.tabs[tab_name].cleanup()
                del self.tabs[tab_name]
            
            # 移除标签页
            self.notebook.forget(current_tab)
            
            # 确保"+"标签页在最后
            if self.plus_tab_frame:
                try:
                    # 移除并重新添加"+"标签页到末尾
                    self.notebook.forget(self.plus_tab_frame)
                    self.plus_tab_frame = None
                except:
                    pass
            
            # 重新添加"+"标签页
            self.add_plus_tab()
            
            # 切换到第一个普通标签页（如果存在）
            if self.tabs:
                first_tab_name = list(self.tabs.keys())[0]
                for i in range(self.notebook.index("end")):
                    if self.notebook.tab(i, "text") == first_tab_name:
                        self.notebook.select(i)
                        self.set_active_tab(first_tab_name)
                        break
            
            # 恢复标志
            self.ignore_tab_change = False
            self.save_config()
    
    def on_tab_changed(self, event=None):
        """标签页切换时的处理"""
        # 如果设置了忽略标志，直接返回
        if self.ignore_tab_change:
            return
        
        current_tab = self.notebook.select()
        if not current_tab:
            return
        
        # 获取当前标签页名称
        tab_name = self.notebook.tab(current_tab, "text")
        
        # 如果点击了"+"标签页，创建新标签页
        if tab_name == "+":
            # 延迟执行，避免在事件处理中修改Notebook
            self.root.after(10, self.add_tab)
        else:
            self.set_active_tab(tab_name)
    
    def select_tab_by_name(self, tab_name):
        """根据名称选中标签页"""
        for tab_id in self.notebook.tabs():
            if self.notebook.tab(tab_id, "text") == tab_name:
                self.notebook.select(tab_id)
                self.set_active_tab(tab_name)
                break

    def get_tab_id_at(self, x, y):
        """根据坐标获取标签ID"""
        try:
            return self.notebook.index(f"@{x},{y}")
        except tk.TclError:
            return None

    def on_tab_right_click(self, event):
        """右键点击标签页，弹出菜单"""
        tab_id = self.get_tab_id_at(event.x, event.y)
        if tab_id is None:
            return
        tab_text = self.notebook.tab(tab_id, "text")
        if tab_text == "+":
            return
        self.context_menu_tab_id = tab_id
        try:
            self.tab_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.tab_menu.grab_release()

    def on_tab_double_click(self, event):
        """双击标签页触发重命名"""
        tab_id = self.get_tab_id_at(event.x, event.y)
        if tab_id is None:
            return
        self.rename_tab_by_id(tab_id)

    def rename_selected_tab(self):
        """重命名当前选中的标签页"""
        if self.context_menu_tab_id is not None:
            tab_id = self.context_menu_tab_id
            self.context_menu_tab_id = None
        else:
            current = self.notebook.select()
            if not current:
                return
            tab_id = self.notebook.index(current)
        self.rename_tab_by_id(tab_id)

    def rename_tab_by_id(self, tab_id):
        """执行标签页重命名"""
        try:
            tab_text = self.notebook.tab(tab_id, "text")
        except tk.TclError:
            return
        if tab_text == "+":
            return
        new_name = simpledialog.askstring(
            "重命名标签页",
            "请输入新的标签页名称：",
            initialvalue=tab_text,
            parent=self.root
        )
        if new_name is None:
            return
        new_name = new_name.strip()
        if not new_name:
            messagebox.showwarning("警告", "标签页名称不能为空")
            return
        if new_name == tab_text:
            return
        if new_name in self.tabs:
            messagebox.showwarning("警告", f"已存在名称为“{new_name}”的标签页，请换一个名称。")
            return
        tab_page = self.tabs.get(tab_text)
        if not tab_page:
            return
        tab_page.tab_name = new_name
        # 重建 tabs 字典保持原有顺序
        updated_tabs = {}
        for name, page in self.tabs.items():
            if name == tab_text:
                updated_tabs[new_name] = page
            else:
                updated_tabs[name] = page
        self.tabs = updated_tabs
        # 更新配置字典，使其引用最新的 TabPage 配置对象
        new_config = {}
        for name, page in self.tabs.items():
            if hasattr(page, 'config'):
                new_config[name] = page.config
        self.config = new_config
        # 更新Notebook显示
        try:
            self.notebook.tab(tab_id, text=new_name)
        except tk.TclError:
            pass
        self.set_active_tab(new_name)
        self.save_config()
    
    def set_active_tab(self, tab_name):
        """设置当前活动标签页供 send() 使用"""
        tab_page = self.tabs.get(tab_name)
        if tab_page:
            register_send_handler(tab_page.send_command)
            register_send_raw_handler(tab_page.send_raw_command)
            register_active_tab(tab_page)
    
    def open_debug_window(self):
        """打开调试窗口"""
        debug_window = DebugWindow(self.root, self)
    
    def on_closing(self):
        """窗口关闭时的处理"""
        # 保存配置
        self.save_config()
        
        # 清理所有标签页
        for tab_name, tab_page in self.tabs.items():
            tab_page.cleanup()
        self.root.destroy()


def run_test_cases():
    """运行测试用例（类似 test_run.py 的功能）"""
    import json
    import time
    
    # 加载测试用例
    test_file = "test_cases.json"
    if not os.path.exists(test_file):
        print(f"测试用例文件不存在: {test_file}")
        return
    
    with open(test_file, 'r', encoding='utf-8') as f:
        test_cases = json.load(f)
    
    # 创建根窗口和TabPage（隐藏窗口）
    root = tk.Tk()
    root.withdraw()
    
    # 创建应用实例
    try:
        app = DeviceConnectionApp(root)
    except Exception as e:
        print(f"创建应用实例失败: {e}")
        import traceback
        traceback.print_exc()
        root.destroy()
        return
    
    # 创建临时的 DebugWindow 实例用于解码
    temp_debug = DebugWindow(root, app)
    temp_debug.window.destroy()  # 销毁窗口，只保留实例用于调用方法
    
    # 解码转义序列
    for test_case in test_cases:
        if 'device_outputs' in test_case:
            test_case['device_outputs'] = [
                temp_debug.decode_escape_sequences(output) 
                for output in test_case['device_outputs']
            ]
        if 'expected_display' in test_case:
            test_case['expected_display'] = temp_debug.decode_escape_sequences(
                test_case['expected_display']
            )
    
    # 获取第一个标签页
    tab_name = list(app.tabs.keys())[0]
    tab_page = app.tabs[tab_name]
    
    # 创建模拟的 connector
    class MockConnector:
        def __init__(self):
            self.connected = True
        def send_command(self, cmd):
            pass
    
    tab_page.connector = MockConnector()
    
    # 运行第一个测试用例
    test_case = test_cases[0]
    print("=" * 70)
    print(f"测试用例: {test_case.get('name', '测试用例')}")
    print("=" * 70)
    print()
    
    # 清空输出
    tab_page.clear_output()
    
    # 执行测试用例（使用 DebugWindow 中的方法）
    debug_window = DebugWindow(root, app)
    debug_window.execute_test_case(tab_page, test_case)
    
    # 等待处理完成
    root.update()
    time.sleep(0.1)
    
    # 获取实际输出
    try:
        input_start = tab_page.output_text.index(tab_page.input_start_mark)
        actual_display = tab_page.output_text.get("1.0", input_start)
        actual_display = actual_display.rstrip('\n')
    except:
        actual_display = tab_page.output_text.get("1.0", tk.END).rstrip('\n')
    
    # 获取预期输出
    expected_display = test_case.get('expected_display', '').rstrip('\n')
    
    # 显示结果
    print("实际输出:")
    print("-" * 70)
    print(repr(actual_display))
    print()
    print("实际输出 (可读形式):")
    print("-" * 70)
    print(actual_display)
    print()
    
    print("预期输出:")
    print("-" * 70)
    print(repr(expected_display))
    print()
    print("预期输出 (可读形式):")
    print("-" * 70)
    print(expected_display)
    print()
    
    print("=" * 70)
    
    # 比较结果
    actual_normalized = actual_display.rstrip()
    expected_normalized = expected_display.rstrip()
    
    if actual_normalized == expected_normalized:
        print("✓ 测试通过：实际输出与预期输出一致")
    else:
        print("✗ 测试失败：实际输出与预期输出不一致")
        print()
        print("字符差异分析:")
        print(f"实际长度: {len(actual_display)}, 预期长度: {len(expected_display)}")
        
        # 逐字符比较
        min_len = min(len(actual_display), len(expected_display))
        diff_count = 0
        for i in range(min_len):
            if actual_display[i] != expected_display[i]:
                diff_count += 1
                if diff_count <= 20:
                    print(f"位置 {i}: 实际='{repr(actual_display[i])}', 预期='{repr(expected_display[i])}'")
        
        if len(actual_display) != len(expected_display):
            print(f"长度不同: 实际多出 {len(actual_display) - min_len} 个字符，预期多出 {len(expected_display) - min_len} 个字符")
    
    print("=" * 70)
    root.destroy()


def main():
    # Windows兼容性设置
    if sys.platform == 'win32':
        # 设置控制台编码为UTF-8（如果从命令行运行）
        try:
            import codecs
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
        except:
            pass
    
    # 检查是否以测试模式运行
    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        run_test_cases()
        return
    
    try:
        root = tk.Tk()
        app = DeviceConnectionApp(root)
        root.protocol("WM_DELETE_WINDOW", app.on_closing)
        root.mainloop()
    except Exception as e:
        # 显示错误信息
        import traceback
        error_msg = f"程序启动失败: {str(e)}\n\n{traceback.format_exc()}"
        print(error_msg)
        try:
            messagebox.showerror("错误", error_msg)
        except:
            pass


if __name__ == "__main__":
    main()

