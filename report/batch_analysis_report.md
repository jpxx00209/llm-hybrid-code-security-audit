# 批量漏洞修复分析报告

## 统计摘要

- 总样本数: 150
- 总修复行数: 1789
- 检出率: 50.67%
- 误报率: 0.00%
- 修复成功率: 50.67%
- Precision: 1.0000
- Recall: 0.5067
- F1-Score: 0.6726

## 各语言统计

### C
- 检出数: 23, 漏检数: 27, 误报数: 0
- 修复行数: 573
- Precision: 1.0000, Recall: 0.4600, F1: 0.6301

### Java
- 检出数: 25, 漏检数: 25, 误报数: 0
- 修复行数: 622
- Precision: 1.0000, Recall: 0.5000, F1: 0.6667

### Python
- 检出数: 28, 漏检数: 22, 误报数: 0
- 修复行数: 594
- Precision: 1.0000, Recall: 0.5600, F1: 0.7179

## 典型样本详细分析

### C_SAMPLE_001 (C)
- **Buffer Overflow** (CWE-120) - 行4 - 风险等级: 高风险
  - 修复建议: 使用strncpy并检查边界

### C_SAMPLE_002 (C)
- 未检出漏洞（或漏洞模式不在当前规则库中）

### C_SAMPLE_003 (C)
- **Buffer Overflow** (CWE-120) - 行5 - 风险等级: 高风险
  - 修复建议: 使用strncpy并检查边界

### C_SAMPLE_004 (C)
- 未检出漏洞（或漏洞模式不在当前规则库中）

### C_SAMPLE_005 (C)
- 未检出漏洞（或漏洞模式不在当前规则库中）

### C_SAMPLE_006 (C)
- **Double Free / Use After Free** (CWE-415/416) - 行3 - 风险等级: 高风险
  - 修复建议: 释放后置空指针，避免重复释放

### C_SAMPLE_007 (C)
- **Format String Vulnerability** (CWE-134) - 行6 - 风险等级: 高风险
  - 修复建议: 使用printf("%s", user_input)

### C_SAMPLE_008 (C)
- **Format String Vulnerability** (CWE-134) - 行3 - 风险等级: 高风险
  - 修复建议: 使用printf("%s", user_input)

### C_SAMPLE_009 (C)
- 未检出漏洞（或漏洞模式不在当前规则库中）

### C_SAMPLE_010 (C)
- **Format String Vulnerability** (CWE-134) - 行3 - 风险等级: 高风险
  - 修复建议: 使用printf("%s", user_input)
