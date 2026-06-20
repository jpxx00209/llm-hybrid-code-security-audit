#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CallGraphBuilder - 轻量级跨过程调用图生成器
支持 Python（AST）、Java/C（正则表达式）三种语言
输出格式：dict[str, list[str]]  (caller -> list of callees)
"""
import ast as py_ast
import re


class CallGraphBuilder:
    """轻量级调用图构建器，为 Input Layer 新增模块"""

    def __init__(self, language: str):
        self.language = language.lower()

    def build(self, code: str) -> dict:
        """构建调用图，返回 {caller_name: [callee_name, ...]}"""
        if self.language == "python":
            return self._build_python(code)
        elif self.language == "java":
            return self._build_java(code)
        elif self.language == "c":
            return self._build_c(code)
        else:
            return {}

    def _build_python(self, code: str) -> dict:
        """基于 ast 模块提取 FunctionDef / Call 节点构建调用图"""
        try:
            tree = py_ast.parse(code)
        except SyntaxError:
            return {}

        func_map = {}
        for node in py_ast.walk(tree):
            if isinstance(node, py_ast.FunctionDef):
                func_map[node.name] = node

        call_graph = {name: [] for name in func_map}
        call_graph["<global>"] = []

        for func_name, func_node in func_map.items():
            for child in py_ast.walk(func_node):
                if isinstance(child, py_ast.Call):
                    if isinstance(child.func, py_ast.Name):
                        callee = child.func.id
                        if callee != func_name and callee not in call_graph[func_name]:
                            call_graph[func_name].append(callee)
                    elif isinstance(child.func, py_ast.Attribute):
                        callee = child.func.attr
                        if callee not in call_graph[func_name]:
                            call_graph[func_name].append(callee)

        top_level_calls = []
        for node in tree.body:
            if isinstance(node, py_ast.Expr) and isinstance(node.value, py_ast.Call):
                if isinstance(node.value.func, py_ast.Name):
                    top_level_calls.append(node.value.func.id)
                elif isinstance(node.value.func, py_ast.Attribute):
                    top_level_calls.append(node.value.func.attr)
        call_graph["<global>"] = list(set(top_level_calls))

        return call_graph

    def _build_java(self, code: str) -> dict:
        """基于正则表达式提取 Java 方法定义与调用"""
        call_graph = {}
        method_pattern = re.compile(
            r'(?:public|private|protected|static|\s)+[\w<>
# ... content continues as in the file above
