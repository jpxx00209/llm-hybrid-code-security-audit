#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AST Parser Stub - 支持C、Java、Python的代码解析与AST生成
实际生产环境可对接clang、javalang、ast模块
"""
import ast as py_ast
import re

class ASTParser:
    """轻量级代码解析器，生成基本AST与控制流信息"""
    
    def __init__(self, language: str):
        self.language = language.lower()
    
    def parse(self, code: str):
        """解析代码，返回结构化信息"""
        if self.language == "python":
            return self._parse_python(code)
        elif self.language == "java":
            return self._parse_java(code)
        elif self.language == "c":
            return self._parse_c(code)
        else:
            raise ValueError(f"Unsupported language: {self.language}")
    
    def _parse_python(self, code: str):
        """使用Python内置ast模块解析"""
        try:
            tree = py_ast.parse(code)
            functions = [node.name for node in py_ast.walk(tree) if isinstance(node, py_ast.FunctionDef)]
            calls = [node.func.id for node in py_ast.walk(tree) if isinstance(node, py_ast.Call) and isinstance(node.func, py_ast.Name)]
            return {
                "language": "Python",
                "functions": functions,
                "calls": calls,
                "imports": self._extract_python_imports(code),
                "control_flow": self._extract_python_control_flow(tree)
            }
        except SyntaxError as e:
            return {"error": str(e), "language": "Python"}
    
    def _extract_python_imports(self, code: str):
        imports = []
        for line in code.splitlines():
            line = line.strip()
            if line.startswith("import ") or line.startswith("from "):
                imports.append(line)
        return imports
    
    def _extract_python_control_flow(self, tree):
        flows = []
        for node in py_ast.walk(tree):
            if isinstance(node, py_ast.If):
                flows.append("if")
            elif isinstance(node, py_ast.For):
                flows.append("for")
            elif isinstance(node, py_ast.While):
                flows.append("while")
            elif isinstance(node, py_ast.Try):
                flows.append("try")
        return flows
    
    def _parse_java(self, code: str):
        """基于正则的Java轻量级解析"""
        classes = re.findall(r'class\s+(\w+)', code)
        methods = re.findall(r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*\{', code)
        imports = re.findall(r'import\s+([\w.]+);', code)
        return {
            "language": "Java",
            "classes": classes,
            "methods": methods,
            "imports": imports,
            "control_flow": self._extract_java_control_flow(code)
        }
    
    def _extract_java_control_flow(self, code: str):
        flows = []
        keywords = ["if", "for", "while", "switch", "try", "catch"]
        for kw in keywords:
            if re.search(r'\b' + kw + r'\b', code):
                flows.append(kw)
        return flows
    
    def _parse_c(self, code: str):
        """基于正则的C语言轻量级解析"""
        functions = re.findall(r'(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{', code)
        includes = re.findall(r'#include\s+[<"]([^>"]+)[>"]', code)
        return {
            "language": "C",
            "functions": functions,
            "includes": includes,
            "control_flow": self._extract_c_control_flow(code)
        }
    
    def _extract_c_control_flow(self, code: str):
        flows = []
        keywords = ["if", "for", "while", "switch", "do"]
        for kw in keywords:
            if re.search(r'\b' + kw + r'\b', code):
                flows.append(kw)
        return flows

if __name__ == "__main__":
    parser = ASTParser("Python")
    result = parser.parse("""
import os
def test():
    if True:
        os.system("ls")
""")
    print(result)
