#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单板连接工具 - 支持网口/Telnet/串口连接
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import socket
import telnetlib
import serial
import serial.tools.list_ports
from datetime import datetime
import sys
import os
import paramiko
from pathlib import Path
import re


class DeviceConnector:
    """设备连接器基类"""
    
    def __init__(self, output_callback):
        self.output_callback = output_callback
        self.connected = False
        self.socket = None
        self.read_thread = None
        self.stop_flag = False
    
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
        if not self.connected or not self.socket:
            return False
        try:
            # 临时设置为阻塞模式以确保数据发送完成
            was_blocking = self.socket.getblocking()
            self.socket.setblocking(True)
            data = (command + '\n').encode('utf-8')
            self.socket.sendall(data)
            # 恢复原来的阻塞模式
            self.socket.setblocking(was_blocking)
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送命令失败: {str(e)}\n")
            # 尝试恢复阻塞模式
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
        if not self.connected or not self.socket:
            return False
        try:
            self.socket.write((command + '\n').encode('utf-8'))
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送命令失败: {str(e)}\n")
            return False
    
    def _read_data(self):
        import socket
        while not self.stop_flag and self.connected:
            try:
                data = self.socket.read_some()
                if data:
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
        if not self.connected or not self.socket:
            return False
        try:
            data = (command + '\n').encode('utf-8')
            self.socket.write(data)
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送命令失败: {str(e)}\n")
            return False
    
    def _read_data(self):
        import time
        import serial
        while not self.stop_flag and self.connected:
            try:
                if self.socket.in_waiting > 0:
                    data = self.socket.read(self.socket.in_waiting)
                    if data:
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


class TabPage:
    """单个标签页，包含完整的连接功能"""
    
    def __init__(self, parent, tab_name, root_window):
        self.parent = parent
        self.tab_name = tab_name
        self.root = root_window
        self.connector = None
        self.output_queue = queue.Queue()
        
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
        
        # SFTP相关变量
        self.sftp_connector = None
        self.local_path = os.path.expanduser("~")
        self.remote_path = "/"
        
        # 日志记录相关
        self.log_enabled = False
        self.log_file = None
        self.log_file_path = None
        
        # 命令历史
        self.command_history = []
        self.history_index = -1
        
        # 初始化文件图标
        self.init_file_icons()
        
        # ANSI颜色解析相关
        self.ansi_pattern = re.compile(r'\033\[([0-9;]*)m')
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
        # 连接方式选择
        conn_frame = ttk.LabelFrame(self.frame, text="连接设置", padding="10")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
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
        output_frame = ttk.LabelFrame(self.frame, text="输出显示", padding="10")
        output_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
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
        
        # 初始化输入提示符
        self.input_prompt = "> "
        self.input_start_mark = "input_start"
        self.input_enabled = False  # 只有连接成功后才允许输入
        
        # 绑定键盘事件
        self.output_text.bind("<Key>", self.on_output_key)
        self.output_text.bind("<Button-1>", self.on_output_click)
        self.output_text.bind("<Return>", self.on_output_return)
        self.output_text.bind("<BackSpace>", self.on_output_backspace)
        self.output_text.bind("<Delete>", self.on_output_delete)
        self.output_text.bind("<Control-v>", self.on_paste)  # 支持粘贴
        self.output_text.bind("<Command-v>", self.on_paste)  # macOS粘贴
        
        # 初始化输入区域（但不允许输入，直到连接成功）
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "请先连接设备...\n")
        self.output_text.config(state=tk.DISABLED)
        
        # 输出控制按钮
        output_buttons = ttk.Frame(output_frame)
        output_buttons.grid(row=1, column=0, pady=5)
        
        ttk.Button(output_buttons, text="清空输出", command=self.clear_output).pack(side=tk.LEFT, padx=5)
        
        # 日志记录开关
        self.log_checkbox = ttk.Checkbutton(output_buttons, text="记录日志", command=self.toggle_log)
        self.log_checkbox.pack(side=tk.LEFT, padx=5)
        
        # 命令发送区域
        cmd_send_frame = ttk.LabelFrame(self.frame, text="快速命令发送", padding="10")
        cmd_send_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
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
        
        # 常用命令按钮
        common_cmds_frame = ttk.Frame(cmd_send_frame)
        common_cmds_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        common_commands = ["ls", "pwd", "ifconfig", "ps", "df -h"]
        for i, cmd in enumerate(common_commands):
            btn = ttk.Button(common_cmds_frame, text=cmd, width=10, 
                           command=lambda c=cmd: self.send_quick_command_text(c))
            btn.grid(row=0, column=i, padx=2)
        
        # SFTP文件传输区域
        sftp_frame = ttk.LabelFrame(self.frame, text="SFTP文件传输", padding="10")
        sftp_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        sftp_frame.columnconfigure(0, weight=1)
        sftp_frame.columnconfigure(1, weight=1)
        sftp_frame.rowconfigure(1, weight=1)
        
        # SFTP连接设置
        sftp_conn_frame = ttk.Frame(sftp_frame)
        sftp_conn_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(sftp_conn_frame, text="SFTP主机:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.sftp_host_entry = ttk.Entry(sftp_conn_frame, width=15)
        self.sftp_host_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.sftp_host_entry.insert(0, "192.168.1.100")
        
        ttk.Label(sftp_conn_frame, text="端口:").grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.sftp_port_entry = ttk.Entry(sftp_conn_frame, width=8)
        self.sftp_port_entry.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        self.sftp_port_entry.insert(0, "22")
        
        ttk.Label(sftp_conn_frame, text="用户名:").grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.sftp_user_entry = ttk.Entry(sftp_conn_frame, width=12)
        self.sftp_user_entry.grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)
        self.sftp_user_entry.insert(0, "root")
        
        ttk.Label(sftp_conn_frame, text="密码:").grid(row=0, column=6, padx=5, pady=5, sticky=tk.W)
        self.sftp_pass_entry = ttk.Entry(sftp_conn_frame, width=12, show="*")
        self.sftp_pass_entry.grid(row=0, column=7, padx=5, pady=5, sticky=tk.W)
        
        self.sftp_connect_btn = ttk.Button(sftp_conn_frame, text="连接SFTP", command=self.toggle_sftp_connection)
        self.sftp_connect_btn.grid(row=0, column=8, padx=5, pady=5)
        
        self.sftp_status_label = ttk.Label(sftp_conn_frame, text="SFTP: 未连接", foreground="red")
        self.sftp_status_label.grid(row=0, column=9, padx=5, pady=5)
        
        # 文件列表区域（左右分栏）
        files_container = ttk.Frame(sftp_frame)
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
        buttons_frame = ttk.Frame(sftp_frame)
        buttons_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(buttons_frame, text="上传 →", command=self.upload_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="← 下载", command=self.download_file).pack(side=tk.LEFT, padx=5)
        
        # 初始化显示TCP参数和文件列表
        self.on_conn_type_changed()
        self.refresh_local_files()
        
        # 更新滚动区域
        self.update_scroll_region()
    
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
        conn_type = self.conn_type.get()
        
        try:
            if conn_type == "TCP网口":
                host = self.host_entry.get().strip()
                port = self.port_entry.get().strip()
                if not host or not port:
                    messagebox.showerror("错误", "请输入主机地址和端口")
                    return
                self.connector = TCPConnector(self.append_output)
                success = self.connector.connect(host=host, port=port)
                
            elif conn_type == "Telnet":
                host = self.host_entry.get().strip()
                port = self.port_entry.get().strip()
                if not host or not port:
                    messagebox.showerror("错误", "请输入主机地址和端口")
                    return
                self.connector = TelnetConnector(self.append_output)
                success = self.connector.connect(host=host, port=port)
                
            elif conn_type == "串口":
                port = self.serial_port_combo.get()
                baudrate = self.baudrate_combo.get()
                if not port:
                    messagebox.showerror("错误", "请选择串口")
                    return
                self.connector = SerialConnector(self.append_output)
                success = self.connector.connect(port=port, baudrate=baudrate)
            
            if success:
                self.connect_btn.config(text="断开")
                self.status_label.config(text="状态: 已连接", foreground="green")
                self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 连接成功\n")
                # 连接成功后启用输入
                self.enable_input()
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
        # 断开连接后禁用输入
        self.disable_input()
    
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
        """添加输入提示符"""
        self.output_text.config(state=tk.NORMAL)
        # 检查是否已经有提示符，避免重复添加
        try:
            end_pos = self.output_text.index(tk.END)
            if end_pos != "1.0":
                # 获取最后一行内容
                last_line_start = self.output_text.index(f"{end_pos} linestart")
                last_line = self.output_text.get(last_line_start, end_pos)
                if not last_line.rstrip().endswith(self.input_prompt.rstrip()):
                    self.output_text.insert(tk.END, self.input_prompt)
        except:
            self.output_text.insert(tk.END, self.input_prompt)
        
        # 设置输入区域标记
        self.output_text.mark_set(self.input_start_mark, tk.END)
        self.output_text.mark_gravity(self.input_start_mark, tk.LEFT)
        # 将光标移动到输入区域
        self.output_text.mark_set(tk.INSERT, tk.END)
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.NORMAL)
    
    def enable_input(self):
        """启用输入功能"""
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
        """禁用输入功能"""
        self.input_enabled = False
        self.output_text.config(state=tk.DISABLED)
    
    def on_output_key(self, event):
        """输出框按键事件"""
        # 如果未连接，不允许输入
        if not self.input_enabled:
            return "break"
        
        # 确保文本框是可编辑的
        if self.output_text.cget("state") == tk.DISABLED:
            self.output_text.config(state=tk.NORMAL)
        
        # 检查光标位置是否在输入区域内
        try:
            cursor_pos = self.output_text.index(tk.INSERT)
            input_start = self.output_text.index(self.input_start_mark)
            if self.output_text.compare(cursor_pos, "<", input_start):
                # 光标在输入区域之前，移动到输入区域末尾
                self.output_text.mark_set(tk.INSERT, tk.END)
                # 对于某些特殊键，允许继续处理
                if event.keysym in ['Return', 'BackSpace', 'Delete', 'Up', 'Down', 'Left', 'Right']:
                    return None
                # 对于普通字符，移动到输入区域后允许输入
                return None
        except:
            # 如果没有输入标记，添加一个，但不阻止输入
            try:
                self.add_input_prompt()
            except:
                pass
            # 允许输入继续
            return None
        
        # 允许正常输入
        return None
    
    def on_paste(self, event):
        """粘贴事件处理"""
        if not self.input_enabled:
            return "break"
        
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
        """输出框点击事件"""
        # 如果未连接，不允许点击编辑
        if not self.input_enabled:
            return "break"
        
        # 如果点击在输入区域之前，将光标移动到输入区域末尾
        try:
            click_pos = self.output_text.index(f"@{event.x},{event.y}")
            input_start = self.output_text.index(self.input_start_mark)
            if self.output_text.compare(click_pos, "<", input_start):
                self.output_text.mark_set(tk.INSERT, tk.END)
                return "break"
        except:
            # 如果没有输入标记，添加一个
            self.add_input_prompt()
            return "break"
        return None
    
    def on_output_return(self, event):
        """输出框回车事件"""
        # 如果未连接，不允许发送命令
        if not self.input_enabled or not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return "break"
        
        # 确保文本框是可编辑的
        if self.output_text.cget("state") == tk.DISABLED:
            self.output_text.config(state=tk.NORMAL)
        
        # 先获取当前输入的命令（在删除之前）
        command = self.get_input_command()
        
        # 移除当前输入提示符和命令
        try:
            start_pos = self.output_text.index(self.input_start_mark)
            end_pos = self.output_text.index(tk.END)
            self.output_text.delete(start_pos, end_pos)
        except:
            # 如果获取位置失败，尝试从最后一行获取
            try:
                end_pos = self.output_text.index(tk.END)
                last_line_start = self.output_text.index(f"{end_pos} linestart")
                self.output_text.delete(last_line_start, end_pos)
            except:
                pass
        
        # 显示发送的命令
        if command:
            self.output_text.insert(tk.END, f"{self.input_prompt}{command}\n")
        else:
            self.output_text.insert(tk.END, f"{self.input_prompt}\n")
        self.output_text.see(tk.END)
        
        # 发送命令到单板
        if command and self.connector and self.connector.connected:
            try:
                success = self.connector.send_command(command)
                if not success:
                    self.append_output(f"[错误] 发送命令失败: {command}\n")
            except Exception as e:
                self.append_output(f"[错误] 发送命令异常: {str(e)}\n")
        
        # 添加新的输入提示符
        self.add_input_prompt()
        
        return "break"
    
    def on_output_backspace(self, event):
        """输出框退格事件"""
        if not self.input_enabled:
            return "break"
        
        cursor_pos = self.output_text.index(tk.INSERT)
        try:
            input_start = self.output_text.index(self.input_start_mark)
            if self.output_text.compare(cursor_pos, "<=", input_start):
                # 不允许删除输入提示符
                return "break"
        except:
            return "break"
        return None
    
    def on_output_delete(self, event):
        """输出框删除事件"""
        if not self.input_enabled:
            return "break"
        
        cursor_pos = self.output_text.index(tk.INSERT)
        try:
            input_start = self.output_text.index(self.input_start_mark)
            if self.output_text.compare(cursor_pos, "<", input_start):
                # 不允许删除输入区域之前的内容
                return "break"
        except:
            return "break"
        return None
    
    def append_output(self, text):
        """添加输出文本（线程安全）"""
        self.output_queue.put(text)
        # 如果启用了日志记录，写入日志文件
        if self.log_enabled and self.log_file:
            try:
                # 移除ANSI转义序列后写入日志
                clean_text = re.sub(r'\033\[[0-9;]*m', '', text)
                self.log_file.write(clean_text)
                self.log_file.flush()  # 实时写入
            except Exception as e:
                # 日志写入失败，不影响程序运行
                pass
    
    def check_output_queue(self):
        """检查输出队列并更新显示"""
        try:
            while True:
                text = self.output_queue.get_nowait()
                self.output_text.config(state=tk.NORMAL)
                # 在输入提示符之前插入输出内容
                input_start = self.output_text.index(self.input_start_mark)
                # 处理ANSI颜色编码
                self.insert_ansi_text(input_start, text)
                # 更新输入提示符位置
                self.output_text.mark_set(self.input_start_mark, tk.END)
                self.output_text.see(tk.END)
                self.output_text.config(state=tk.NORMAL)
        except queue.Empty:
            pass
        
        self.root.after(100, self.check_output_queue)
    
    def insert_ansi_text(self, start_pos, text):
        """插入带ANSI颜色编码的文本"""
        # 重置当前颜色
        current_fg = "#FFFFFF"
        current_bg = None
        
        # 查找所有ANSI转义序列
        last_pos = 0
        insert_pos = start_pos
        tag_counter = 0  # 用于创建唯一的tag名称
        
        for match in self.ansi_pattern.finditer(text):
            # 插入ANSI序列之前的文本
            if match.start() > last_pos:
                plain_text = text[last_pos:match.start()]
                if plain_text:
                    self.output_text.insert(insert_pos, plain_text)
                    # 应用当前颜色
                    if current_fg != "#FFFFFF" or current_bg:
                        end_pos = self.output_text.index(f"{insert_pos} + {len(plain_text)} chars")
                        tag_name = f"ansi_seg_{tag_counter}"
                        tag_counter += 1
                        self.output_text.tag_add(tag_name, insert_pos, end_pos)
                        if current_fg != "#FFFFFF":
                            self.output_text.tag_config(tag_name, foreground=current_fg)
                        if current_bg:
                            self.output_text.tag_config(tag_name, background=current_bg)
                    insert_pos = self.output_text.index(tk.END)
            
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
                        elif code in self.ansi_fg_colors:
                            # 前景色
                            current_fg = self.ansi_fg_colors[code]
                        elif code in self.ansi_bg_colors:
                            # 背景色
                            current_bg = self.ansi_bg_colors[code]
                        elif 30 <= code <= 37:
                            # 标准前景色
                            current_fg = self.ansi_fg_colors.get(code, "#FFFFFF")
                        elif 40 <= code <= 47:
                            # 标准背景色
                            current_bg = self.ansi_bg_colors.get(code)
                    except ValueError:
                        pass
            
            last_pos = match.end()
        
        # 插入剩余的文本
        if last_pos < len(text):
            plain_text = text[last_pos:]
            if plain_text:
                self.output_text.insert(insert_pos, plain_text)
                # 应用当前颜色
                if current_fg != "#FFFFFF" or current_bg:
                    end_pos = self.output_text.index(f"{insert_pos} + {len(plain_text)} chars")
                    tag_name = f"ansi_seg_{tag_counter}"
                    self.output_text.tag_add(tag_name, insert_pos, end_pos)
                    if current_fg != "#FFFFFF":
                        self.output_text.tag_config(tag_name, foreground=current_fg)
                    if current_bg:
                        self.output_text.tag_config(tag_name, background=current_bg)
    
    def clear_output(self):
        """清空输出"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
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
            self.log_enabled = True
            self.append_output(f"[日志] 开始记录日志到: {self.log_file_path}\n")
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
        self.log_enabled = False
    
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
        
        # 发送命令
        if self.connector.send_command(command):
            self.append_output(f"[快速发送] {command}\n")
            self.quick_cmd_entry.delete(0, tk.END)
        else:
            messagebox.showerror("错误", "发送命令失败")
    
    def send_quick_command_text(self, command):
        """发送快速命令文本（从按钮）"""
        self.quick_cmd_entry.delete(0, tk.END)
        self.quick_cmd_entry.insert(0, command)
        self.send_quick_command()
    
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
    
    def toggle_sftp_connection(self):
        """切换SFTP连接状态"""
        if self.sftp_connector and self.sftp_connector.connected:
            self.disconnect_sftp()
        else:
            self.connect_sftp()
    
    def connect_sftp(self):
        """连接SFTP"""
        host = self.sftp_host_entry.get().strip()
        port = self.sftp_port_entry.get().strip()
        username = self.sftp_user_entry.get().strip()
        password = self.sftp_pass_entry.get().strip()
        
        if not all([host, port, username]):
            messagebox.showerror("错误", "请填写完整的SFTP连接信息")
            return
        
        self.sftp_connector = SFTPConnector()
        result = self.sftp_connector.connect(host, port, username, password)
        
        if isinstance(result, tuple):
            success, error_msg = result
        else:
            success = result
            error_msg = ""
        
        if success:
            self.sftp_connect_btn.config(text="断开SFTP")
            self.sftp_status_label.config(text="SFTP: 已连接", foreground="green")
            self.remote_path = self.sftp_connector.get_current_directory()
            self.remote_path_entry.delete(0, tk.END)
            self.remote_path_entry.insert(0, self.remote_path)
            self.refresh_remote_files()
            self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SFTP连接成功\n")
        else:
            self.sftp_status_label.config(text="SFTP: 连接失败", foreground="red")
            messagebox.showerror("错误", f"SFTP连接失败: {error_msg}")
    
    def disconnect_sftp(self):
        """断开SFTP连接"""
        if self.sftp_connector:
            self.sftp_connector.disconnect()
            self.sftp_connector = None
        self.sftp_connect_btn.config(text="连接SFTP")
        self.sftp_status_label.config(text="SFTP: 未连接", foreground="red")
        # 清空Treeview
        for item in self.remote_files_tree.get_children():
            self.remote_files_tree.delete(item)
        self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] SFTP已断开连接\n")
    
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
        if not self.sftp_connector or not self.sftp_connector.connected:
            # 清空Treeview
            for item in self.remote_files_tree.get_children():
                self.remote_files_tree.delete(item)
            return
        
        path = self.remote_path_entry.get().strip()
        if not path:
            path = "/"
        
        # 清空Treeview
        for item in self.remote_files_tree.get_children():
            self.remote_files_tree.delete(item)
        
        try:
            # 尝试切换目录
            if path != self.remote_path:
                result = self.sftp_connector.change_directory(path)
                if isinstance(result, tuple):
                    success, msg = result
                    if not success:
                        messagebox.showerror("错误", f"切换目录失败: {msg}")
                        self.remote_path_entry.delete(0, tk.END)
                        self.remote_path_entry.insert(0, self.remote_path)
                        path = self.remote_path
                    else:
                        self.remote_path = self.sftp_connector.get_current_directory()
                        self.remote_path_entry.delete(0, tk.END)
                        self.remote_path_entry.insert(0, self.remote_path)
            
            # 添加父目录
            if self.remote_path != "/":
                icon = self.get_file_icon("..", is_dir=True)
                self.remote_files_tree.insert("", tk.END, text=f"{icon} ..", values=("..", True))
            
            # 列出文件
            files = self.sftp_connector.list_files(self.remote_path)
            files.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
            
            for file_info in files:
                name = file_info['name']
                is_dir = file_info['is_dir']
                icon = self.get_file_icon(name, is_dir=is_dir)
                
                if is_dir:
                    display_text = f"{icon} {name}"
                    self.remote_files_tree.insert("", tk.END, text=display_text, values=(name, True))
                else:
                    size_str = self.format_size(file_info['size'])
                    display_text = f"{icon} {name} ({size_str})"
                    self.remote_files_tree.insert("", tk.END, text=display_text, values=(name, False, file_info['size']))
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
        if not self.sftp_connector or not self.sftp_connector.connected:
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
        
        # 检查是否是目录
        try:
            files = self.sftp_connector.list_files(new_path)
            self.remote_path = new_path
            self.remote_path_entry.delete(0, tk.END)
            self.remote_path_entry.insert(0, self.remote_path)
            self.refresh_remote_files()
        except:
            pass  # 不是目录，忽略
    
    def on_local_file_right_click(self, event):
        """本地文件右键事件"""
        pass
    
    def on_remote_file_right_click(self, event):
        """远程文件右键事件"""
        pass
    
    def upload_file(self):
        """上传文件"""
        if not self.sftp_connector or not self.sftp_connector.connected:
            messagebox.showwarning("警告", "请先连接SFTP")
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
            success, msg = self.sftp_connector.upload_file(local_path, remote_file)
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
        if not self.sftp_connector or not self.sftp_connector.connected:
            messagebox.showwarning("警告", "请先连接SFTP")
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
            success, msg = self.sftp_connector.download_file(remote_path, local_file)
            if success:
                messagebox.showinfo("成功", f"文件下载成功: {name}")
                self.refresh_local_files()
                self.append_output(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 下载文件: {remote_path} -> {local_file}\n")
            else:
                messagebox.showerror("错误", f"下载失败: {msg}")
        except Exception as e:
            messagebox.showerror("错误", f"下载失败: {str(e)}")
    
    def cleanup(self):
        """清理资源"""
        # 停止日志记录
        if self.log_enabled:
            self.stop_logging()
        
        if self.connector and self.connector.connected:
            self.disconnect()
        if self.sftp_connector and self.sftp_connector.connected:
            self.disconnect_sftp()


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
        
        self.setup_ui()
    
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
        
        # 工具栏（只保留关闭按钮）
        toolbar = ttk.Frame(main_frame)
        toolbar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Button(toolbar, text="关闭当前标签页", command=self.close_current_tab).pack(side=tk.LEFT, padx=5)
        
        # 创建第一个标签页
        self.add_tab()
        
        # 添加"+"标签页
        self.add_plus_tab()
    
    def add_tab(self, tab_name=None):
        """添加新标签页"""
        if tab_name is None:
            tab_name = f"单板 {self.tab_counter}"
            self.tab_counter += 1
        
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
        
        # 切换到新标签页
        self.notebook.select(tab_frame)
        
        # 重新添加"+"标签页到末尾
        self.add_plus_tab()
        
        # 恢复标志
        self.ignore_tab_change = False
    
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
                        break
            
            # 恢复标志
            self.ignore_tab_change = False
    
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
    
    def on_closing(self):
        """窗口关闭时的处理"""
        # 清理所有标签页
        for tab_name, tab_page in self.tabs.items():
            tab_page.cleanup()
        self.root.destroy()


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

