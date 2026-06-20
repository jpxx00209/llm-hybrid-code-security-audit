# LLM 智能代码安全审计系统

基于大语言模型（LLM）和静态分析技术的混合智能代码安全审计系统，支持自动化漏洞检测、修复建议生成和交互式审计报告。

## 项目概述

本项目是**第18届全国大学生信息安全竞赛**作品，通过融合 LLM 的语义理解能力和传统静态分析技术的精确性，构建一个高可用、低误报的代码安全审计系统。

## 仓库结构

```
llm-hybrid-code-security-audit/
├── dataset/                          # 数据集与样本
│   ├── samples_c.json                # C语言样本清单（150个）
│   ├── samples_java.json             # Java样本清单（150个）
│   ├── samples_python.json           # Python样本清单（150个）
│   ├── samples_c_complete.json       # C样本完整归档（100个文件）
│   ├── samples_java_complete.json    # Java样本完整归档（100个文件）
│   ├── samples_python_complete.json  # Python样本完整归档（100个文件）
│   └── generate_samples.py           # 样本生成器
│
├── src/                              # 核心源代码
│   ├── hybrid_engine.py              # 混合分析引擎（主入口）
│   ├── llm_adapter.py                # LLM适配器（本地/远程双模式）
│   ├── ast_parser.py               # 抽象语法树解析器
│   └── taint_analyzer.py           # 污点分析器
│
├── repaired/                         # 修复后的代码（150个）
│   ├── c/                            # C语言修复样本
│   ├── java/                         # Java语言修复样本
│   └── python/                       # Python语言修复样本
│
├── web/                              # 交互式审计网页
│   └── index.html                    # 单文件交互式审计界面
│
├── report/                           # 竞赛报告
│   └── competition_report.md         # 完整竞赛作品报告（5800+字）
│
├── batch_analysis_results.json       # 批量分析结果（修复建议）
├── requirements.txt                  # Python依赖
└── README.md                         # 本文件
```

## 核心特性

### 混合分析引擎
- **输入层**：多语言AST解析 + 污点分析
- **分析层**：LLM智能分析（支持本地规则/远程API双模式）
- **输出层**：结构化漏洞报告 + 修复建议

### 支持语言
- C/C++
- Java
- Python

### 检测能力
覆盖15种CWE漏洞类型：
- CWE-78: 命令注入
- CWE-79: XSS
- CWE-89: SQL注入
- CWE-94: 代码注入
- CWE-22: 路径遍历
- CWE-502: 不安全反序列化
- CWE-20: 输入验证
- CWE-209: 信息泄露
- CWE-798: 硬编码凭证
- CWE-311: 加密问题
- CWE-400: 资源消耗
- CWE-434: 文件上传
- CWE-918: SSRF
- CWE-863: 授权错误
- CWE-1004: 敏感Cookie

## 快速开始

### 1. 环境安装
```bash
pip install -r requirements.txt
```

### 2. 本地模式运行
```python
from src.hybrid_engine import HybridAnalysisEngine

engine = HybridAnalysisEngine(mode="local")
result = engine.analyze(code="your code here", language="python")
print(result)
```

### 3. 远程模式运行（需要API Key）
```python
engine = HybridAnalysisEngine(
    mode="remote",
    api_key="your-api-key",
    base_url="https://api.openai.com/v1",
    model="gpt-4"
)
result = engine.analyze(code="your code here", language="java")
```

### 4. 打开交互式审计网页
直接在浏览器中打开 `web/index.html` 即可体验交互式审计功能。

## 数据集

本系统包含**150个精心设计的漏洞样本**（50 C + 50 Java + 50 Python），每个样本都包含：
- 漏洞版本（含已知漏洞）
- 修复版本（展示修复方案）
- CWE类型标注
- 严重性评级

所有样本代码存储在 `dataset/*_complete.json` 归档文件中，可通过 `generate_samples.py` 生成。

## 批量分析结果

系统已完成150个样本的批量分析，核心指标：
- **检测率**：50.67%（76/150）
- **精确率**：100%（0误报）
- **F1分数**：0.6726
- **修复代码行数**：1,789行

详细结果见 `batch_analysis_results.json`。

## 技术架构

```
┌─────────────────────────────────────────┐
│           Input Layer                  │
│  ┌──────────┐      ┌──────────────┐  │
│  │  AST Parser  │  │  Taint Analyzer │  │
│  └──────────┘      └──────────────┘  │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│         Analysis Layer                 │
│  ┌──────────────────────────────────┐  │
│  │  LLM Adapter (Local/Remote)      │  │
│  │  - Pattern Matching              │  │
│  │  - Few-shot Learning             │  │
│  │  - Code Fix Generation           │  │
│  └──────────────────────────────────┘  │
└─────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────┐
│          Output Layer                  │
│  ┌──────────┐  ┌──────────┐  ┌──────┐  │
│  │ Vuln Report│  │  Fix Code  │  │ Diff  │  │
│  └──────────┘  └──────────┘  └──────┘  │
└─────────────────────────────────────────┘
```

## 竞赛报告

完整的竞赛作品报告见 `report/competition_report.md`，包含：
- 系统架构与技术方案
- 数据集设计说明
- 漏洞检测与修复方法
- 批量分析结果与评估
- 交互式审计界面设计
- 创新点与应用前景

## 作者信息

- **作者**：jpxx00209
- **竞赛**：第18届全国大学生信息安全竞赛
- **许可证**：MIT License

## 致谢

感谢竞赛组委会提供的平台，以及开源社区提供的工具链支持。
