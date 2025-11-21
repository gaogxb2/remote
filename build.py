#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
打包脚本 - 将程序打包成可执行文件
使用: python build.py
"""

import subprocess
import sys
import os

def build_executable():
    """使用PyInstaller打包程序"""
    try:
        # 检查PyInstaller是否安装
        import PyInstaller
    except ImportError:
        print("正在安装PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller"])
    
    # 打包命令
    cmd = [
        "pyinstaller",
        "--onefile",  # 打包成单个可执行文件
        "--windowed",  # Windows下不显示控制台窗口（macOS/Linux下会忽略）
        "--name=单板连接工具",  # 可执行文件名称
        "--icon=NONE",  # 可以指定图标文件路径
        "main.py"
    ]
    
    print("开始打包...")
    subprocess.check_call(cmd)
    print("\n打包完成！可执行文件位于 dist/ 目录下")

if __name__ == "__main__":
    build_executable()

