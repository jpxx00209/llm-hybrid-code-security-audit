#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HybridAnalysisEngine - 混合分析引擎 v2.0
集成跨过程调用图、跨过程污点追踪、PDG 切片与 LLM 分析
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.input_layer import InputLayer
from core.analysis_layer import AnalysisLayer
from core.output_layer import OutputLayer
from core.input_layer.call_graph import CallGraphBuilder
from core.analysis_layer.inter_taint import InterProceduralTaintAnalyzer
from core.analysis_layer.pdg_slicer import PDGSlicer


class HybridAnalysisEngine:
    """
    混合分析引擎 v2.0
    - 输入层：AST 解析 + 调用图构建 + 跨过程污点分析
    - 分析层：PDG 切片 + LLM 分析（本地 Few-shot + RAG 检索）
    - 输出层：格式化报告生成
    """

    def __init__(self, llm_mode="local", api_key=None, base_url=None, model=None):
        self.input_layer = InputLayer()
        self.analysis_layer = AnalysisLayer(mode=llm_mode, api_key=api_key, base_url=base_url, model=model)
        self.output_layer = OutputLayer()

    def analyze(self, code: str, language: str) -> dict:
        """执行完整的混合分析流程"""
        # 1. 输入层：AST 解析 + 调用图 + 跨过程污点分析
        ast_info = self.input_layer.parse(code, language)
        call_graph = self.input_layer.build_call_graph(code, language)
        taint_info = self.input_layer.inter_taint_analysis(code, language, call_graph)

        # 2. 分析层：PDG 切片 + LLM 分析
        context = {
            "ast": ast_info,
            "call_graph": call_graph,
            "global_taint_state": taint_info.get("global_taint_state", {}),
            "cross_procedure_paths": taint_info.get("cross_procedure_paths", [])
        }
        llm_result = self.analysis_layer.analyze(code, language, context)

        # 3. 输出层：格式化报告
        report = self.output_layer.format(code, language, ast_info, taint_info, llm_result)
        report["meta"] = {"version": "2.0", "inter_taint_enabled": True}
        return report


class InputLayer:
    """输入层：解析 + 调用图 + 污点分析"""

    def parse(self, code: str, language: str) -> dict:
        """AST 解析（保留原有逻辑）"""
        return {"language": language, "code_length": len(code), "parsed": True}

    def build_call_graph(self, code: str, language: str) -> dict:
        """构建跨过程调用图"""
        builder = CallGraphBuilder(language)
        return builder.build(code)

    def inter_taint_analysis(self, code: str, language: str, call_graph: dict) -> dict:
        """跨过程污点分析"""
        analyzer = InterProceduralTaintAnalyzer(language, call_graph)
        return analyzer.analyze(code)


class AnalysisLayer:
    """分析层：PDG 切片 + LLM 分析"""

    def __init__(self, mode="local", api_key=None, base_url=None, model=None):
        from core.llm_adapter import LLMAdapter
        self.llm = LLMAdapter(mode=mode, api_key=api_key, base_url=base_url, model=model)

    def analyze(self, code: str, language: str, context: dict) -> dict:
        """先执行 PDG 切片，再送入 LLM 分析"""
        # PDG 切片
        slicer = PDGSlicer(language)
        sliced_code = slicer.get_slice_for_llm(code)
        context["sliced_code"] = sliced_code

        # LLM 分析（包含 RAG 检索和级联精检）
        return self.llm.analyze(sliced_code, language, context)


class OutputLayer:
    """输出层：格式化报告（保留原有逻辑）"""

    def format(self, code: str, language: str, ast_info: dict, taint_info: dict, llm_result: dict) -> dict:
        return {
            "language": language,
            "taint_info": taint_info,
            "llm_result": llm_result,
            "report": "formatted"
        }


if __name__ == "__main__":
    test_code = """
import os

def run_cmd(cmd):
    os.system(cmd)

def process_input(user_input):
    if user_input:
        run_cmd(user_input)

def main():
    data = input("Enter: ")
    process_input(data)
"""
    engine = HybridAnalysisEngine()
    result = engine.analyze(test_code, "python")
    print(result)
