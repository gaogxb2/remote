#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""完整测试脚本 - 模拟输出处理逻辑并运行测试用例"""

import json
import os
import re

def decode_escape_sequences(text):
    """解码转义序列"""
    if not isinstance(text, str):
        return text
    try:
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
        
        temp_map = {}
        for i, (old, new) in enumerate(common_escapes.items()):
            temp_key = f'__TEMP_ESCAPE_{i}__'
            temp_map[temp_key] = new
            text = text.replace(old, temp_key)
        
        def replace_hex(match):
            hex_str = match.group(1)
            try:
                return chr(int(hex_str, 16))
            except:
                return match.group(0)
        text = re.sub(r'\\x([0-9a-fA-F]{2})', replace_hex, text)
        
        def replace_oct(match):
            oct_str = match.group(1)
            try:
                if all(c in '01234567' for c in oct_str):
                    return chr(int(oct_str, 8))
            except:
                pass
            return match.group(0)
        text = re.sub(r'\\([0-7]{1,3})(?![0-9a-fA-Fx])', replace_oct, text)
        
        for temp_key, new in temp_map.items():
            text = text.replace(temp_key, new)
        
        text = text.replace('\\\\', '\\')
        return text
    except:
        return text

def split_incomplete_sequences(text):
    """分离不完整的ANSI序列"""
    # 匹配完整的ANSI序列
    # ESC [ ... [0-9;]* [A-Za-z] 或 ESC ] ... ESC \
    pattern = r'\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b\][^\x1b]*\x1b\\'
    
    # 找到最后一个可能的完整序列的结束位置
    matches = list(re.finditer(pattern, text))
    if matches:
        last_match = matches[-1]
        end_pos = last_match.end()
        if end_pos < len(text):
            # 检查后面是否还有不完整的序列
            remainder = text[end_pos:]
            # 如果remainder以ESC开头但不是完整序列，则是不完整的
            if remainder.startswith('\x1b'):
                return text[:end_pos], remainder
    else:
        # 检查是否以ESC开头
        if text.endswith('\x1b') or (len(text) > 1 and text[-2] == '\x1b' and text[-1] == '['):
            # 找到最后一个ESC的位置
            last_esc = text.rfind('\x1b')
            if last_esc >= 0:
                return text[:last_esc], text[last_esc:]
    
    return text, ""

def strip_control_sequences(text):
    """移除控制序列（如 \033[J, \033[K）"""
    # 移除 CSI 清除序列
    text = re.sub(r'\x1b\[[0-9;]*[JK]', '', text)
    return text

def process_control_chars(text, input_buffer, input_cursor, output_text):
    """处理控制字符，更新输入缓冲、光标位置和输出文本"""
    result = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in ('\x08', '\b', '\x7f'):  # 退格
            # 退格已经在外部处理（从 output_text_list 删除）
            # 这里只更新输入缓冲
            if input_cursor > 0:
                input_cursor -= 1
                if input_cursor < len(input_buffer):
                    input_buffer.pop(input_cursor)
            i += 1
            continue
        elif ch == '\r':  # 回车
            # 回车通常意味着输入完成
            input_cursor = 0
            i += 1
            continue
        elif ch == '\n':  # 换行
            # 换行意味着输入完成，但换行符要保留在输出中
            input_buffer = []
            input_cursor = 0
            result.append(ch)
            if output_text:
                output_text.append(ch)
            i += 1
            continue
        elif ch == '\x1b':  # ESC
            # 检查是否是光标移动序列
            if i + 1 < len(text) and text[i+1] == '[':
                # CSI 序列
                seq_end = i + 2
                while seq_end < len(text) and text[seq_end] not in 'ABCDEFGHJKSTfm':
                    seq_end += 1
                if seq_end < len(text):
                    seq = text[i:seq_end+1]
                    # 处理光标移动
                    if seq.endswith('D'):  # 左移
                        if input_cursor > 0:
                            input_cursor -= 1
                    elif seq.endswith('C'):  # 右移
                        if input_cursor < len(input_buffer):
                            input_cursor += 1
                    i = seq_end + 1
                    continue
        else:
            # 普通字符，添加到结果和输出
            result.append(ch)
            if output_text is not None:
                output_text.append(ch)
            # 更新输入缓冲
            if input_cursor >= len(input_buffer):
                input_buffer.append(ch)
            else:
                input_buffer.insert(input_cursor, ch)
            input_cursor += 1
        i += 1
    
    return ''.join(result), input_buffer, input_cursor

def strip_ansi_codes(text):
    """移除ANSI颜色代码，只保留文本内容"""
    # 移除所有ANSI序列
    text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)
    text = re.sub(r'\x1b\][^\x07]*\x07', '', text)
    text = re.sub(r'\x1b\][^\x1b]*\x1b\\', '', text)
    return text

def simulate_output_processing(device_outputs, inputs):
    """模拟输出处理过程"""
    # 模拟输入缓冲
    input_buffer = []
    input_cursor = 0
    
    # 存储所有输出文本（不包括输入缓冲）
    output_text_list = []  # 用于存储最终显示的文本
    output_buffer = []  # 用于 process_control_chars 处理退格
    partial_output = ""
    
    # 先处理输入（这些是用户操作，不直接产生输出）
    for input_item in inputs:
        if input_item['type'] == 'key':
            input_buffer.insert(input_cursor, input_item['value'])
            input_cursor += 1
        elif input_item['type'] == 'left':
            for _ in range(input_item.get('count', 1)):
                if input_cursor > 0:
                    input_cursor -= 1
        elif input_item['type'] == 'return':
            # 回车，清空输入缓冲
            input_buffer = []
            input_cursor = 0
    
    # 处理设备输出
    for idx, device_output in enumerate(device_outputs):
        if not device_output:
            continue
        
        # 与partial_output合并
        combined_text = partial_output + device_output
        partial_output = ""
        
        # 分离不完整的序列
        text, remainder = split_incomplete_sequences(combined_text)
        if remainder:
            partial_output = remainder
        
        if not text:
            continue
        
        # 先统计退格数量（在 strip_control_sequences 之前）
        # 注意：\x08 和 \b 是同一个字符，不要重复统计
        # 统计所有退格字符（\x08, \b, \x7f）
        backspace_count = 0
        for ch in text:
            if ch in ('\x08', '\b', '\x7f'):
                backspace_count += 1
        
        # 移除控制序列（如 \033[J）
        text = strip_control_sequences(text)
        
        # 处理控制字符（退格、回车、换行等）
        # 注意：这里 output_buffer 会被 process_control_chars 修改
        cleaned_text, input_buffer, input_cursor = process_control_chars(
            text, input_buffer, input_cursor, output_buffer
        )
        
        # 移除ANSI代码（只保留文本内容用于比较）
        # 从 output_buffer 中提取文本
        display_text = strip_ansi_codes(''.join(output_buffer))
        
        # 先添加新的显示文本
        if display_text:
            output_text_list.append(display_text)
            # 清空 output_buffer，因为已经添加到 output_text_list
            output_buffer = []
        
        # 然后处理退格：从累积的输出中删除字符（退格在添加文本之后处理）
        if backspace_count > 0:
            # 合并所有输出文本为一个字符串
            combined_output = ''.join(output_text_list)
            if len(combined_output) >= backspace_count:
                combined_output = combined_output[:-backspace_count]
                # 重新组织 output_text_list
                output_text_list = [combined_output] if combined_output else []
            else:
                output_text_list = []
        
        # 调试输出
        if idx < 6:  # 只显示前几个
            current_output = ''.join(output_text_list)
            print(f"步骤 {idx+1}: 输入={repr(device_output)}, display_text={repr(display_text)}, backspace={backspace_count}, current_output={repr(current_output)}")
    
    # 合并所有输出
    result = ''.join(output_text_list)
    return result

def run_test():
    """运行测试用例"""
    # 加载测试用例
    test_file = "test_cases.json"
    if not os.path.exists(test_file):
        print(f"测试用例文件不存在: {test_file}")
        return
    
    with open(test_file, 'r', encoding='utf-8') as f:
        test_cases = json.load(f)
    
    # 解码转义序列
    test_case = test_cases[0]
    device_outputs = [decode_escape_sequences(o) for o in test_case['device_outputs']]
    expected = decode_escape_sequences(test_case['expected_display'])
    inputs = test_case['inputs']
    
    print("=" * 70)
    print(f"测试用例: {test_case.get('name', '测试用例')}")
    print("=" * 70)
    print()
    
    # 运行模拟
    actual = simulate_output_processing(device_outputs, inputs)
    
    # 规范化（移除末尾换行）
    actual_normalized = actual.rstrip('\n')
    expected_normalized = expected.rstrip('\n')
    
    print("实际输出:")
    print("-" * 70)
    print(repr(actual_normalized))
    print()
    print("实际输出 (可读形式):")
    print("-" * 70)
    print(actual_normalized)
    print()
    
    print("预期输出:")
    print("-" * 70)
    print(repr(expected_normalized))
    print()
    print("预期输出 (可读形式):")
    print("-" * 70)
    print(expected_normalized)
    print()
    
    print("=" * 70)
    if actual_normalized == expected_normalized:
        print("✓ 测试通过：实际输出与预期输出一致")
    else:
        print("✗ 测试失败：实际输出与预期输出不一致")
        print()
        print("字符差异分析:")
        print(f"实际长度: {len(actual_normalized)}, 预期长度: {len(expected_normalized)}")
        print()
        
        # 逐字符比较
        min_len = min(len(actual_normalized), len(expected_normalized))
        diff_count = 0
        diff_positions = []
        for i in range(min_len):
            if actual_normalized[i] != expected_normalized[i]:
                diff_count += 1
                diff_positions.append(i)
                if diff_count <= 20:
                    print(f"位置 {i}: 实际='{repr(actual_normalized[i])}' ({ord(actual_normalized[i])}), 预期='{repr(expected_normalized[i])}' ({ord(expected_normalized[i])})")
        
        if len(actual_normalized) != len(expected_normalized):
            print()
            print(f"长度不同: 实际多出 {len(actual_normalized) - min_len} 个字符，预期多出 {len(expected_normalized) - min_len} 个字符")
            if len(actual_normalized) > min_len:
                print(f"实际多出的内容: {repr(actual_normalized[min_len:])}")
            if len(expected_normalized) > min_len:
                print(f"预期多出的内容: {repr(expected_normalized[min_len:])}")
    
    print("=" * 70)
    return actual_normalized, expected_normalized

if __name__ == "__main__":
    run_test()

