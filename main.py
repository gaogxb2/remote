#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
单板连接工具 - 支持网口/Telnet/串口连接
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import socket
import telnetlib
import serial
import serial.tools.list_ports
from datetime import datetime
import sys


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
            data = (command + '\n').encode('utf-8')
            self.socket.sendall(data)
            return True
        except Exception as e:
            self.output_callback(f"[错误] 发送命令失败: {str(e)}\n")
            return False
    
    def _read_data(self):
        import select
        while not self.stop_flag and self.connected:
            try:
                ready, _, _ = select.select([self.socket], [], [], 0.1)
                if ready:
                    data = self.socket.recv(4096)
                    if data:
                        self.output_callback(data.decode('utf-8', errors='ignore'))
                    else:
                        break
            except Exception as e:
                if not self.stop_flag:
                    self.output_callback(f"[错误] 接收数据失败: {str(e)}\n")
                break
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
        while not self.stop_flag and self.connected:
            try:
                data = self.socket.read_some()
                if data:
                    self.output_callback(data.decode('utf-8', errors='ignore'))
                else:
                    break
            except Exception as e:
                if not self.stop_flag:
                    self.output_callback(f"[错误] 接收数据失败: {str(e)}\n")
                break
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
        while not self.stop_flag and self.connected:
            try:
                if self.socket.in_waiting > 0:
                    data = self.socket.read(self.socket.in_waiting)
                    if data:
                        self.output_callback(data.decode('utf-8', errors='ignore'))
                else:
                    import time
                    time.sleep(0.1)
            except Exception as e:
                if not self.stop_flag:
                    self.output_callback(f"[错误] 接收数据失败: {str(e)}\n")
                break
        self.connected = False


class DeviceConnectionApp:
    """设备连接应用程序主窗口"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("单板连接工具")
        self.root.geometry("900x700")
        
        self.connector = None
        self.output_queue = queue.Queue()
        
        self.setup_ui()
        self.check_output_queue()
    
    def setup_ui(self):
        """设置用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # 连接方式选择
        conn_frame = ttk.LabelFrame(main_frame, text="连接设置", padding="10")
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
        output_frame = ttk.LabelFrame(main_frame, text="输出显示", padding="10")
        output_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=20, width=80, wrap=tk.WORD)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.output_text.config(state=tk.DISABLED)
        
        # 清空按钮
        ttk.Button(output_frame, text="清空输出", command=self.clear_output).grid(row=1, column=0, pady=5)
        
        # 命令输入区域
        cmd_frame = ttk.LabelFrame(main_frame, text="命令输入", padding="10")
        cmd_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        cmd_frame.columnconfigure(0, weight=1)
        
        self.cmd_entry = ttk.Entry(cmd_frame, width=60)
        self.cmd_entry.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E))
        self.cmd_entry.bind("<Return>", lambda e: self.send_command())
        
        ttk.Button(cmd_frame, text="发送", command=self.send_command).grid(row=0, column=1, padx=5, pady=5)
        
        # 初始化显示TCP参数
        self.on_conn_type_changed()
    
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
    
    def send_command(self):
        """发送命令"""
        if not self.connector or not self.connector.connected:
            messagebox.showwarning("警告", "请先连接设备")
            return
        
        command = self.cmd_entry.get().strip()
        if not command:
            return
        
        if self.connector.send_command(command):
            self.append_output(f"[发送] {command}\n")
            self.cmd_entry.delete(0, tk.END)
        else:
            messagebox.showerror("错误", "发送命令失败")
    
    def append_output(self, text):
        """添加输出文本（线程安全）"""
        self.output_queue.put(text)
    
    def check_output_queue(self):
        """检查输出队列并更新显示"""
        try:
            while True:
                text = self.output_queue.get_nowait()
                self.output_text.config(state=tk.NORMAL)
                self.output_text.insert(tk.END, text)
                self.output_text.see(tk.END)
                self.output_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        
        self.root.after(100, self.check_output_queue)
    
    def clear_output(self):
        """清空输出"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def on_closing(self):
        """窗口关闭时的处理"""
        if self.connector and self.connector.connected:
            self.disconnect()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = DeviceConnectionApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()

