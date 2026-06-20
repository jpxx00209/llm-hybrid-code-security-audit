#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py - 系统入口 v2.0
支持命令行参数、环境变量配置，展示如何初始化新的 CallGraph 和 RAG 模块
"""
import os
import sys
import argparse

from src.hybrid_engine import HybridAnalysisEngine


def main():
    parser = argparse.ArgumentParser(description="LLM Hybrid Code Security Audit System v2.0")
    parser.add_argument("--code", type=str, help="待检测代码字符串或文件路径")
    parser.add_argument("--language", type=str, default="python", choices=["python", "java", "c"], help="代码语言")
    parser.add_argument("--llm-mode", type=str, default=os.getenv("LLM_MODE", "local"), choices=["local", "api"], help="LLM 模式")
    parser.add_argument("--api-key", type=str, default=os.getenv("LLM_API_KEY"), help="API 密钥")
    parser.add_argument("--base-url", type=str, default=os.getenv("LLM_BASE_URL"), help="API 基础 URL")
    parser.add_argument("--model", type=str, default=os.getenv("LLM_MODEL", "gpt-4"), help="模型名称")
    parser.add_argument("--file", type=str, help="从文件读取代码")
    args = parser.parse_args()

    code = args.code
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            code = f.read()
    if not code:
        print("错误: 请提供 --code 或 --file 参数")
        sys.exit(1)

    engine = HybridAnalysisEngine(
        llm_mode=args.llm_mode,
        api_key=args.api_key,
        base_url=args.base_url,
        model=args.model
    )
    result = engine.analyze(code, args.language)
    print(result)


if __name__ == "__main__":
    main()
