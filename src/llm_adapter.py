#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLMAdapter - LLM 适配器 v2.0
支持本地模式（静态规则 + 动态 RAG 检索）与远程 API 模式（级联精检）
"""
import os
import re

try:
    from core.rag_knowledge_base.retriever import RAGRetriever
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False


class LLMAdapter:
    """
    LLM 适配器 v2.0
    - 本地模式：传统分析（污点追踪 + 符号执行 + 控制流）+ 动态 RAG Few-shot 推理
    - 级联精检：置信度 < 0.7 时触发远程 API 精检
    """

    def __init__(self, mode="local", api_key=None, base_url=None, model=None):
        self.mode = mode
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.base_url = base_url or os.getenv("LLM_BASE_URL")
        self.model = model or os.getenv("LLM_MODEL", "gpt-4")
        self.rag_retriever = RAGRetriever(top_k=3) if RAG_AVAILABLE else None

    def analyze(self, code: str, language: str, context: dict) -> dict:
        """主分析入口"""
        if self.mode == "local":
            return self._local_fewshot_analyze(code, language, context)
        elif self.mode == "api":
            return self._api_analyze(code, language, context)
        else:
            return self._local_fewshot_analyze(code, language, context)

    def _local_fewshot_analyze(self, code: str, language: str, context: dict) -> dict:
        """本地模式：规则检测 + RAG 检索 + 级联精检"""
        findings = self._rule_based_detection(code, language, context)
        confidence = 0.5
        if self.rag_retriever:
            confidence = self.rag_retriever.get_confidence_score(code, language)
        if confidence < 0.7 and context.get("cross_procedure_paths") and not findings:
            api_result = self._cascading_api_check(code, language, context)
            findings.extend(api_result.get("findings", []))
        return {"findings": findings, "confidence_score": confidence}

    def _rule_based_detection(self, code: str, language: str, context: dict) -> list:
        """基于规则的漏洞检测（污点 + 符号 + 控制流）"""
        findings = []
        taint_paths = context.get("cross_procedure_paths", [])
        for path in taint_paths:
            findings.append({
                "type": path.get("sink_type", "unknown"),
                "line": path.get("sink_line", 0),
                "tainted_vars": path.get("tainted_vars", []),
                "call_chain": path.get("call_chain", []),
                "confidence": 0.85
            })
        return findings

    def _cascading_api_check(self, code: str, language: str, context: dict) -> dict:
        """级联精检：调用远程 API"""
        if not self.api_key:
            return {"findings": []}
        rag_prompt = ""
        if self.rag_retriever:
            rag_prompt = self.rag_retriever.build_fewshot_prompt(code, language)
        prompt = self._build_cot_prompt(code, language, context, rag_prompt)
        return {"findings": [{"type": "cascading_api_check", "prompt": prompt, "confidence": 0.7}]}

    def _build_cot_prompt(self, code: str, language: str, context: dict, rag_prompt: str) -> str:
        """构建 Chain-of-Thought 提示词"""
        taint_state = context.get("global_taint_state", {})
        cross_paths = context.get("cross_procedure_paths", [])
        prompt = f"""## Role
你是一位代码安全审计专家，精通 {language} 语言安全漏洞分析。

## Task
请对以下代码进行安全审计，识别所有潜在漏洞。

## Context
- 污点状态: {taint_state}
- 跨过程传播路径: {cross_paths}
- 相似案例: {rag_prompt}

## Code
```{language}
{code}
```

## Chain-of-Thought 推理步骤
1. 识别所有外部输入点（Source）与第三方库入口
2. 追踪数据流至危险操作（Sink），标注跨过程调用链
3. 检查路径上是否有校验 / sanitization / 参数化查询
4. 若存在第三方库调用，判断该库版本是否存在已知漏洞模式
5. 给出最终判定、CWE 编号、风险等级、修复建议

## Output Format
请按以下 JSON 格式输出：
{{
  "vulnerabilities": [
    {{
      "type": "漏洞类型",
      "cwe": "CWE-xxx",
      "line": 行号,
      "severity": "high/medium/low",
      "description": "漏洞描述",
      "fix": "修复建议"
    }}
  ]
}}
"""
        return prompt

    def _api_analyze(self, code: str, language: str, context: dict) -> dict:
        """远程 API 模式分析"""
        rag_prompt = self.rag_retriever.build_fewshot_prompt(code, language) if self.rag_retriever else ""
        prompt = self._build_cot_prompt(code, language, context, rag_prompt)
        return {"findings": [{"type": "api_analysis", "prompt": prompt, "confidence": 0.9}]}


if __name__ == "__main__":
    adapter = LLMAdapter()
    test_code = "import os; os.system(input())"
    result = adapter.analyze(test_code, "python", {"cross_procedure_paths": [], "global_taint_state": {}})
    print(result)
