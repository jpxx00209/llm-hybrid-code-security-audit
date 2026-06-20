# 基于大语言模型与混合程序分析的代码安全审计系统

> 竞赛级作品 | 覆盖 C / Java / Python 三语言 | 150个漏洞样本验证 | 双模架构（本地推理 + 远程API）

## 项目概述

本项目构建了一套**可扩展、可插拔的代码安全审计系统**，将传统程序分析（污点追踪、符号执行、控制流分析）与大语言模型（LLM）Few-shot上下文学习进行深度混合，实现高精确率、低误报率的漏洞检测与自动化修复。

**核心特点**：
- **双模架构**：支持"本地推理引擎"与"远程API适配层"无缝切换
- **三语言覆盖**：C、Java、Python，各50个代表性漏洞样本（总计150个）
- **零误报**：精确率 Precision = 1.0，F1-Score = 0.673
- **超量修复**：累计修复代码 **1,789 行**（远超1,000行约束）
- **交互式网页**：单文件离线运行，支持语法高亮、漏洞可视化、API配置
- **标准化接口**：预留 OpenAI-compatible API，支持 deepseek / qwen / glm 等模型

## 仓库结构

```
llm-hybrid-code-security-audit/
├── dataset/                    # 数据集与样本
│   ├── generate_samples.py     # 150个样本生成器
│   ├── samples_manifest.csv    # 样本清单（150条记录）
│   ├── dataset_stats.json      # 数据集统计
│   ├── fewshot_c.json          # C语言Few-shot模板
│   ├── fewshot_java.json       # Java语言Few-shot模板
│   ├── fewshot_python.json     # Python语言Few-shot模板
│   ├── samples_c/              # 50个C样本（含修复版）
│   ├── samples_java/           # 50个Java样本（含修复版）
│   └── samples_python/         # 50个Python样本（含修复版）
├── src/                        # 核心系统源码
│   ├── main.py                 # 主入口
│   ├── llm_adapter.py          # LLM适配器（可插拔）
│   ├── ast_parser.py           # 多语言AST解析器
│   ├── hybrid_engine.py        # 混合分析引擎
│   └── batch_analyzer.py       # 批量分析器
├── web/                        # 交互式网页
│   └── index.html              # 单文件离线审计系统
├── report/                     # 实验报告
│   ├── competition_report.md   # 竞赛作品报告（~5800字）
│   ├── batch_analysis_report.md# 批量分析详细报告
│   └── batch_analysis_summary.json # 统计摘要
└── README.md                   # 本文件
```

## 快速启动

### 1. 环境要求

- Python 3.10+
- 浏览器（Chrome 120+ 推荐）

### 2. 批量分析

```bash
# 安装依赖（仅需标准库）
cd src
python main.py --batch
```

### 3. 单文件分析

```bash
python main.py --file ../dataset/samples_python/python_sample_001.py --lang Python
```

### 4. 启动交互式网页

直接用浏览器打开 `web/index.html` 即可离线运行，无需服务器。

## 实验结果

| 指标 | 数值 |
|------|------|
| 总样本数 | 150 |
| 总修复行数 | **1,789** |
| 检出率 | 50.67% |
| 误报率 | **0.00%** |
| 修复成功率 | 50.67% |
| **Precision** | **1.0000** |
| **Recall** | 0.5067 |
| **F1-Score** | **0.6726** |

## 技术架构

```
输入层（AST解析 + 污点追踪）
        ↓
分析层（双模引擎：本地推理 / 远程API）
        ↓
输出层（漏洞高亮 + 修复建议 + 统计报告）
```

## 许可证

MIT License

## 联系方式

如有问题或建议，欢迎通过 GitHub Issues 交流。
