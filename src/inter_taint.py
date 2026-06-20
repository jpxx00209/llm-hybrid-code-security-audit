#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
InterProceduralTaintAnalyzer - 跨过程污点追踪模块
维护全局污点状态表 global_taint_state，支持跨过程污点传播
"""
import re


class InterProceduralTaintAnalyzer:
    """
    跨过程污点分析器
    - 维护全局污点状态表: {函数名: {污点变量集合}}
    - 当污点数据作为实参传入函数时，沿调用图边传播污点标签
    - 当函数返回被污染数据时，反向传播至调用点
    - 支持 C 语言宏展开场景的预处理器常量传播
    """

    SOURCE_PATTERNS = [
        r'input\s*\(', r'request\.', r'args\[', r'argv\[',
        r'getParameter\s*\(', r'getParam\s*\(', r'fgets\s*\(',
        r'scanf\s*\(', r'read\s*\(', r'recv\s*\(', r'accept\s*\('
    ]

    SINK_PATTERNS = {
        "command_execution": [r'\bsystem\s*\(', r'\bexec\s*\(', r'\bpopen\s*\(', r'\beval\s*\(', r'os\.system\s*\(', r'subprocess\.call\s*\('],
        "sql_execution": [r'\bexecuteQuery\s*\(', r'\bexecute\s*\(', r'\bquery\s*\(', r'cursor\.execute\s*\('],
        "format_output": [r'\bprintf\s*\(', r'\bsprintf\s*\(', r'\bfprintf\s*\('],
        "deserialization": [r'\breadObject\s*\(', r'\bpickle\.loads\s*\(', r'\byaml\.load\s*\(', r'ObjectInputStream'],
        "buffer_write": [r'\bstrcpy\s*\(', r'\bstrcat\s*\(', r'\bsprintf\s*\(', r'\bmemcpy\s*\(', r'\bmemmove\s*\('],
        "network_request": [r'\burlopen\s*\(', r'\brequests\.(get|post)\s*\(', r'\bURL\s*\(', r'\bopenConnection\s*\('],
        "file_access": [r'\bfopen\s*\(', r'\bopen\s*\(', r'\bfile_get_contents\s*\('],
    }

    def __init__(self, language: str, call_graph: dict = None):
        self.language = language.lower()
        self.call_graph = call_graph or {}
        self.global_taint_state = {}
        self._macro_constants = {}

    def analyze(self, code: str) -> dict:
        lines = code.splitlines()
        func_sources = self._identify_sources_per_function(code, lines)
        self._propagate_taint_forward(func_sources)
        cross_paths = self._detect_cross_procedure_sinks(code, lines)
        if self.language == "c":
            self._propagate_macro_taint(code)
        return {
            "global_taint_state": self.global_taint_state,
            "cross_procedure_paths": cross_paths,
            "sources": list(set(v for func_vars in self.global_taint_state.values() for v in func_vars)),
            "sinks": self._identify_sinks(code)
        }

    def _identify_sources_per_function(self, code: str, lines: list) -> dict:
        func_sources = {}
        if self.language == "python":
            import ast as py_ast
            try:
                tree = py_ast.parse(code)
            except SyntaxError:
                return func_sources
            for node in py_ast.walk(tree):
                if isinstance(node, py_ast.FunctionDef):
                    func_name = node.name
                    local_sources = set()
                    for arg in node.args.args:
                        arg_name = arg.arg.lower()
                        if any(k in arg_name for k in ['user', 'input', 'cmd', 'data', 'param', 'raw']):
                            local_sources.add(arg.arg)
                    func_sources[func_name] = local_sources
                    self.global_taint_state[func_name] = local_sources.copy()
        elif self.language in ("java", "c"):
            func_pattern = re.compile(
                r'(?:public|private|protected|static|\s)*(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{'
                if self.language == "java" else
                r'(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{'
            )
            current_func = "<global>"
            for line in lines:
                match = func_pattern.search(line)
                if match:
                    current_func = match.group(1)
                    func_sources[current_func] = set()
                    self.global_taint_state[current_func] = set()
                    param_str = line[line.find('(')+1:line.find(')')]
                    for param in param_str.split(','):
                        param_name = param.strip().split()[-1] if param.strip() else ""
                        if param_name and any(k in param_name.lower() for k in ['user', 'input', 'cmd', 'data', 'param', 'raw', 'buf']):
                            func_sources[current_func].add(param_name)
                            self.global_taint_state[current_func].add(param_name)
                for pattern in self.SOURCE_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        if '=' in line:
                            lhs = line.split('=')[0].strip().split()[-1]
                            if lhs and not lhs.startswith('//'):
                                func_sources.setdefault(current_func, set()).add(lhs)
                                self.global_taint_state.setdefault(current_func, set()).add(lhs)
        return func_sources

    def _propagate_taint_forward(self, func_sources: dict):
        changed = True
        max_iter = 10
        iteration = 0
        while changed and iteration < max_iter:
            changed = False
            iteration += 1
            for caller, callees in self.call_graph.items():
                caller_taints = self.global_taint_state.get(caller, set())
                if not caller_taints:
                    continue
                for callee in callees:
                    if callee not in self.global_taint_state:
                        self.global_taint_state[callee] = set()
                    before = len(self.global_taint_state[callee])
                    self.global_taint_state[callee].update(caller_taints)
                    after = len(self.global_taint_state[callee])
                    if after > before:
                        changed = True

    def _detect_cross_procedure_sinks(self, code: str, lines: list) -> list:
        paths = []
        reverse_graph = self._get_reverse_graph()
        for sink_type, patterns in self.SINK_PATTERNS.items():
            for i, line in enumerate(lines, 1):
                for pattern in patterns:
                    if re.search(pattern, line):
                        current_func = self._find_function_at_line(lines, i)
                        tainted_vars = self.global_taint_state.get(current_func, set())
                        if tainted_vars:
                            chain = self._build_taint_chain(current_func, reverse_graph)
                            paths.append({
                                "sink_line": i,
                                "sink_type": sink_type,
                                "function": current_func,
                                "tainted_vars": list(tainted_vars),
                                "call_chain": chain
                            })
        return paths

    def _identify_sinks(self, code: str) -> list:
        sinks = []
        for sink_type, patterns in self.SINK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    sinks.append(sink_type)
                    break
        return sinks

    def _get_reverse_graph(self) -> dict:
        reverse = {}
        for caller, callees in self.call_graph.items():
            for callee in callees:
                reverse.setdefault(callee, []).append(caller)
        return reverse

    def _find_function_at_line(self, lines: list, target_line: int) -> str:
        func_pattern = re.compile(
            r'(?:public|private|protected|static|\s)*(?:\w+\s+)*(\w+)\s*\([^)]*\)\s*\{'
            if self.language == "java" else
            r'(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{'
        )
        current_func = "<global>"
        for i, line in enumerate(lines, 1):
            match = func_pattern.search(line)
            if match:
                current_func = match.group(1)
            if i == target_line:
                break
        return current_func

    def _build_taint_chain(self, sink_func: str, reverse_graph: dict) -> list:
        chain = [sink_func]
        visited = {sink_func}
        queue = [sink_func]
        while queue:
            current = queue.pop(0)
            callers = reverse_graph.get(current, [])
            for caller in callers:
                if caller not in visited and caller in self.global_taint_state:
                    if self.global_taint_state[caller]:
                        visited.add(caller)
                        chain.insert(0, caller)
                        queue.append(caller)
        return chain

    def _propagate_macro_taint(self, code: str):
        macro_pattern = re.compile(r'#define\s+(\w+)\s+(.+)', re.MULTILINE)
        macros = {}
        for match in macro_pattern.finditer(code):
            macro_name, macro_body = match.group(1), match.group(2)
            vars_in_macro = set(re.findall(r'\b([a-zA-Z_]\w*)\b', macro_body))
            funcs_in_macro = set(re.findall(r'\b(\w+)\s*\(', macro_body))
            macros[macro_name] = {"vars": vars_in_macro, "funcs": funcs_in_macro}
        for macro_name, info in macros.items():
            for func_name, tainted_vars in self.global_taint_state.items():
                if macro_name in tainted_vars:
                    for var in info["vars"]:
                        self.global_taint_state[func_name].add(var)


if __name__ == "__main__":
    test_code = """
import os

def run_cmd(cmd):
    os.system(cmd)

def process(user_input):
    run_cmd(user_input)

def main():
    data = input("Enter: ")
    process(data)
"""
    from call_graph import CallGraphBuilder
    cg = CallGraphBuilder("python")
    graph = cg.build(test_code)
    print("Call Graph:", graph)
    analyzer = InterProceduralTaintAnalyzer("python", graph)
    result = analyzer.analyze(test_code)
    print("Taint Result:", result)
