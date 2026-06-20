#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hybrid Analysis Engine - 混合分析引擎
整合传统程序分析（AST解析、污点追踪）与LLM Few-shot推理
"""
import os, json, time
from llm_adapter import LLMAdapter
from ast_parser import ASTParser

class HybridAnalysisEngine:
    """混合分析引擎：输入层 -> 分析层 -> 输出层"""
    
    def __init__(self, mode="local", api_key=None, base_url=None, model=None):
        self.input_layer = InputLayer()
        self.analysis_layer = AnalysisLayer(mode=mode, api_key=api_key, base_url=base_url, model=model)
        self.output_layer = OutputLayer()
    
    def analyze(self, code: str, language: str) -> dict:
        """完整分析流程"""
        # 输入层：解析与预处理
        ast_info = self.input_layer.parse(code, language)
        
        # 传统分析：污点追踪模拟
        taint_info = self.input_layer.taint_analysis(code, language)
        
        # 分析层：LLM混合分析
        context = {
            "ast": ast_info,
            "taint_sources": taint_info.get("sources", []),
            "taint_sinks": taint_info.get("sinks", []),
            "control_flow": ast_info.get("control_flow", [])
        }
        llm_result = self.analysis_layer.analyze(code, language, context)
        
        # 输出层：格式化与报告
        report = self.output_layer.format(code, language, ast_info, taint_info, llm_result)
        return report

class InputLayer:
    """输入层：代码解析与AST生成"""
    
    def parse(self, code: str, language: str) -> dict:
        parser = ASTParser(language)
        return parser.parse(code)
    
    def taint_analysis(self, code: str, language: str) -> dict:
        """模拟污点追踪分析"""
        sources = []
        sinks = []
        code_lower = code.lower()
        
        # 通用污点源
        if any(kw in code_lower for kw in ["input", "request", "args", "argv", "param", "user"]):
            sources.append("user_input")
        if "getparameter" in code_lower or "getparam" in code_lower:
            sources.append("http_param")
        
        # 通用污点汇
        if "system(" in code or "exec(" in code or "eval(" in code:
            sinks.append("command_execution")
        if "execute" in code_lower and "sql" in code_lower:
            sinks.append("sql_execution")
        if "printf(" in code and "format" not in code_lower:
            sinks.append("format_output")
        if "write(" in code_lower or "print(" in code_lower:
            sinks.append("output")
        if "readobject" in code_lower or "pickle.loads" in code_lower:
            sinks.append("deserialization")
        if "urlopen" in code_lower or "requests.get" in code_lower:
            sinks.append("network_request")
        
        return {
            "sources": sources,
            "sinks": sinks,
            "paths": self._find_taint_paths(code, sources, sinks)
        }
    
    def _find_taint_paths(self, code, sources, sinks):
        """模拟污点路径发现"""
        if not sources or not sinks:
            return []
        lines = code.splitlines()
        source_lines = [i+1 for i, l in enumerate(lines) if any(s in l.lower() for s in sources)]
        sink_lines = [i+1 for i, l in enumerate(lines) if any(s in l.lower() for s in sinks)]
        paths = []
        for s in source_lines[:1]:
            for k in sink_lines[:1]:
                paths.append(f"Line {s} -> Line {k}")
        return paths

class AnalysisLayer:
    """分析层：双模分析引擎"""
    
    def __init__(self, mode="local", api_key=None, base_url=None, model=None):
        self.adapter = LLMAdapter(mode=mode, api_key=api_key, base_url=base_url, model=model)
    
    def analyze(self, code: str, language: str, context: dict) -> dict:
        """调用LLM适配器进行分析"""
        return self.adapter.analyze(code, language, context)

class OutputLayer:
    """输出层：结果格式化与报告生成"""
    
    def format(self, code, language, ast_info, taint_info, llm_result) -> dict:
        findings = llm_result.get("findings", [])
        
        # 生成修复建议
        repair_suggestions = []
        for f in findings:
            repair_suggestions.append({
                "line": f.get("line", 0),
                "type": f.get("type", ""),
                "cwe": f.get("cwe", ""),
                "severity": f.get("severity", "中风险"),
                "suggestion": f.get("fix", ""),
                "confidence": 0.92 if f.get("severity") == "高风险" else 0.85
            })
        
        return {
            "language": language,
            "ast_summary": ast_info,
            "taint_analysis": taint_info,
            "findings": findings,
            "repair_suggestions": repair_suggestions,
            "total_findings": len(findings),
            "risk_score": min(10.0, len(findings) * 2.5)
        }

if __name__ == "__main__":
    engine = HybridAnalysisEngine()
    test_code = """
import os
import sqlite3

def process(user_input):
    os.system(user_input)
    conn = sqlite3.connect('db.sqlite')
    conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
"""
    result = engine.analyze(test_code, "Python")
    print(json.dumps(result, ensure_ascii=False, indent=2))
