#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PDGSlicer - 程序依赖图切片器
从每个 Sink 点执行后向切片，保留数据依赖与控制依赖语句
输出精简代码片段作为 LLM 分析的 context
"""
import re
import ast as py_ast


class PDGSlicer:
    """
    程序依赖图切片器
    - 识别代码中的 Sink 点（危险函数调用）
    - 从 Sink 出发执行后向切片：保留数据依赖（变量赋值/传递）和控制依赖（if/while/for）
    - 输出精简代码片段，替代原始完整代码输入 LLM
    """

    SINK_SIGNATURES = {
        "strcpy": "C", "strcat": "C", "sprintf": "C", "memcpy": "C", "memmove": "C",
        "system": "C", "exec": "C", "popen": "C", "eval": "C",
        "scanf": "C", "gets": "C", "read": "C",
        "executeQuery": "Java", "executeUpdate": "Java", "execute": "Java",
        "getWriter().write": "Java", "out.print": "Java", "Runtime.getRuntime().exec": "Java",
        "readObject": "Java", "ObjectInputStream": "Java",
        "os.system": "Python", "os.popen": "Python", "subprocess.call": "Python",
        "eval": "Python", "exec": "Python",
        "pickle.loads": "Python", "yaml.load": "Python",
        "cursor.execute": "Python", "requests.get": "Python", "urllib.request.urlopen": "Python",
    }

    def __init__(self, language: str):
        self.language = language.lower()

    def slice(self, code: str, sink_line: int = None, sink_func: str = None) -> dict:
        lines = code.splitlines()
        if sink_line is not None:
            return {f"sink_at_line_{sink_line}": self._backward_slice(code, lines, sink_line)}
        slices = {}
        for i, line in enumerate(lines, 1):
            for sig, lang in self.SINK_SIGNATURES.items():
                if lang == self.language.title() and sig in line:
                    key = f"{sig}_line_{i}"
                    slices[key] = self._backward_slice(code, lines, i)
        return slices

    def _backward_slice(self, code: str, lines: list, sink_line: int) -> str:
        sink_idx = sink_line - 1
        sink_line_text = lines[sink_idx]
        relevant_vars = self._extract_variables(sink_line_text)
        kept_lines = {sink_idx}
        for i in range(sink_idx - 1, -1, -1):
            line = lines[i].strip()
            if not line or line.startswith('//') or line.startswith('#') or line.startswith('/*') or line.startswith('*'):
                continue
            if self._is_control_statement(line):
                if self._control_affects_sink(line, relevant_vars, sink_line_text):
                    kept_lines.add(i)
                    relevant_vars.update(self._extract_variables(line))
                continue
            if self._has_data_dependency(line, relevant_vars):
                kept_lines.add(i)
                new_vars = self._extract_variables(line)
                relevant_vars.update(new_vars)
        sorted_lines = sorted(kept_lines)
        sliced = '\n'.join(lines[i] for i in sorted_lines)
        return sliced

    def _extract_variables(self, line: str) -> set:
        line = re.sub(r'"[^"]*"', '""', line)
        line = re.sub(r"'[^']*'", "''", line)
        ids = re.findall(r'\b[a-zA-Z_]\w*\b', line)
        keywords = {
            'if', 'else', 'while', 'for', 'switch', 'case', 'break', 'continue',
            'return', 'void', 'int', 'char', 'float', 'double', 'long', 'short',
            'public', 'private', 'static', 'class', 'import', 'from', 'def',
            'try', 'except', 'finally', 'with', 'as', 'in', 'is', 'not', 'and', 'or',
            'True', 'False', 'None', 'null', 'sizeof', 'struct', 'union', 'enum',
            'const', 'unsigned', 'signed', 'typedef', 'extern', 'inline'
        }
        return {id_ for id_ in ids if id_ not in keywords and not id_.isdigit()}

    def _is_control_statement(self, line: str) -> bool:
        stripped = line.strip()
        control_keywords = ['if ', 'if(', 'while ', 'while(', 'for ', 'for(', 'switch ', 'switch(']
        return any(stripped.startswith(kw) for kw in control_keywords) or stripped.startswith('elif ') or stripped.startswith('else:')

    def _control_affects_sink(self, control_line: str, relevant_vars: set, sink_line: str) -> bool:
        control_vars = self._extract_variables(control_line)
        return bool(control_vars & relevant_vars)

    def _has_data_dependency(self, line: str, relevant_vars: set) -> bool:
        line_vars = self._extract_variables(line)
        return bool(line_vars & relevant_vars)

    def get_slice_for_llm(self, code: str, max_chars: int = 3000) -> str:
        slices = self.slice(code)
        if not slices:
            return code[:max_chars]
        all_lines = set()
        for sliced_code in slices.values():
            for i, line in enumerate(sliced_code.splitlines()):
                all_lines.add((i, line))
        sorted_lines = sorted(all_lines, key=lambda x: x[0])
        merged = '\n'.join(line for _, line in sorted_lines)
        if len(merged) > max_chars:
            merged = merged[:max_chars]
            last_newline = merged.rfind('\n')
            if last_newline > 0:
                merged = merged[:last_newline]
        return merged


if __name__ == "__main__":
    test_code = """
import os

def process_input(user_input):
    if user_input is None:
        return
    cmd = user_input.strip()
    result = os.system(cmd)
    return result

def main():
    data = input("Enter command: ")
    process_input(data)
"""
    slicer = PDGSlicer("Python")
    result = slicer.slice(test_code)
    for k, v in result.items():
        print(f"=== {k} ===")
        print(v)
        print()
