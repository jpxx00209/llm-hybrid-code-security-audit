#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main Entry Point - 代码安全审计系统主入口
"""
import sys, os, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hybrid_engine import HybridAnalysisEngine
from batch_analyzer import analyze_all_samples

def main():
    parser = argparse.ArgumentParser(description="基于LLM与混合分析的代码安全审计系统")
    parser.add_argument("--mode", choices=["local", "api"], default="local", help="分析模式")
    parser.add_argument("--api-key", default=None, help="远程API Key")
    parser.add_argument("--base-url", default=None, help="远程API Base URL")
    parser.add_argument("--model", default=None, help="远程模型名称")
    parser.add_argument("--batch", action="store_true", help="运行批量分析")
    parser.add_argument("--file", default=None, help="单个代码文件路径")
    parser.add_argument("--lang", default="Python", help="代码语言 (C/Java/Python)")
    args = parser.parse_args()
    
    if args.batch:
        print("[+] 启动批量分析...")
        summary = analyze_all_samples()
        print("\n[+] 批量分析完成，统计摘要:")
        print(f"    总样本: {summary['total_samples']}")
        print(f"    检出率: {summary['detection_rate']:.2%}")
        print(f"    误报率: {summary['false_positive_rate']:.2%}")
        print(f"    F1-Score: {summary['f1_score']:.4f}")
        return
    
    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            code = f.read()
        engine = HybridAnalysisEngine(mode=args.mode, api_key=args.api_key, base_url=args.base_url, model=args.model)
        report = engine.analyze(code, args.lang)
        print(report)
        return
    
    print("[*] 使用方式:")
    print("    python main.py --batch              # 批量分析")
    print("    python main.py --file code.py --lang Python  # 单文件分析")

if __name__ == "__main__":
    main()
