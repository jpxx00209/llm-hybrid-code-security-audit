#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM Adapter - 可插拔的LLM适配器
支持本地推理（Few-shot上下文学习）与远程API切换
"""
import os, json, time

class LLMAdapter:
    """可插拔的LLM适配器，支持本地推理与远程API切换"""
    
    def __init__(self, mode: str = "local", api_key: str = None, base_url: str = None, model: str = None):
        self.mode = mode  # "local" 或 "api"
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.base_url = base_url or os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
        self.model = model or os.getenv("LLM_MODEL", "gpt-4")
        
        # 加载本地Few-shot模板
        self.templates = self._load_templates()
    
    def _load_templates(self):
        """加载预定义的Few-shot Prompt模板"""
        templates = {}
        for lang in ["C", "Java", "Python"]:
            path = os.path.join(os.path.dirname(__file__), "..", "dataset", f"fewshot_{lang.lower()}.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    templates[lang] = json.load(f)
            else:
                templates[lang] = self._default_template(lang)
        return templates
    
    def _default_template(self, lang):
        """默认Few-shot模板"""
        return {
            "role": "你是一位代码安全审计专家",
            "task": "分析以下代码，识别安全漏洞，给出修复方案",
            "context": "传统程序分析结果：污点追踪路径/符号执行约束",
            "format": "漏洞位置（行号）| 漏洞类型 | CWE编号 | 风险等级 | 修复建议 | 修复后代码",
            "examples": []
        }
    
    def analyze(self, code: str, language: str, context: dict) -> dict:
        """核心分析接口，返回漏洞检测结果"""
        if self.mode == "local":
            return self._local_fewshot_analyze(code, language, context)
        elif self.mode == "api":
            return self._remote_api_analyze(code, language, context)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")
    
    def _local_fewshot_analyze(self, code: str, language: str, context: dict) -> dict:
        """本地推理模式：基于规则与模板的混合分析（模拟LLM推理）"""
        # 模拟分析延迟
        time.sleep(0.01)
        
        # 基于关键词与模式匹配的轻量级检测（模拟污点追踪+LLM模式识别）
        findings = []
        
        # C语言检测规则
        if language == "C":
            if "strcpy(" in code and "strncpy(" not in code:
                findings.append({
                    "line": self._find_line(code, "strcpy("),
                    "type": "Buffer Overflow",
                    "cwe": "CWE-120",
                    "severity": "高风险",
                    "fix": "使用strncpy并检查边界"
                })
            if "scanf(" in code and "%s" in code:
                findings.append({
                    "line": self._find_line(code, "scanf("),
                    "type": "Buffer Overflow",
                    "cwe": "CWE-121",
                    "severity": "高风险",
                    "fix": "使用scanf_s或限制长度"
                })
            if "free(" in code:
                free_count = code.count("free(")
                lines = code.splitlines()
                for i, line in enumerate(lines, 1):
                    if "free(" in line and free_count > 1:
                        findings.append({
                            "line": i,
                            "type": "Double Free / Use After Free",
                            "cwe": "CWE-415/416",
                            "severity": "高风险",
                            "fix": "释放后置空指针，避免重复释放"
                        })
                        break
            if "system(" in code:
                findings.append({
                    "line": self._find_line(code, "system("),
                    "type": "OS Command Injection",
                    "cwe": "CWE-78",
                    "severity": "高风险",
                    "fix": "使用白名单验证输入"
                })
            if "printf(" in code and code.count("%") < 2:
                findings.append({
                    "line": self._find_line(code, "printf("),
                    "type": "Format String Vulnerability",
                    "cwe": "CWE-134",
                    "severity": "高风险",
                    "fix": "使用printf(\"%s\", user_input)"
                })
        
        # Java检测规则
        elif language == "Java":
            if "executeQuery(" in code and "+" in code:
                findings.append({
                    "line": self._find_line(code, "executeQuery("),
                    "type": "SQL Injection",
                    "cwe": "CWE-89",
                    "severity": "高风险",
                    "fix": "使用PreparedStatement参数化查询"
                })
            if "readObject(" in code:
                findings.append({
                    "line": self._find_line(code, "readObject("),
                    "type": "Deserialization of Untrusted Data",
                    "cwe": "CWE-502",
                    "severity": "高风险",
                    "fix": "使用白名单类校验"
                })
            if "getWriter().write(" in code or "out.print(" in code:
                if "Encode.forHtml" not in code and "escape" not in code:
                    findings.append({
                        "line": self._find_line(code, "getWriter().write(") or self._find_line(code, "out.print("),
                        "type": "Cross-site Scripting (XSS)",
                        "cwe": "CWE-79",
                        "severity": "高风险",
                        "fix": "使用OWASP Encoder或HTML转义"
                    })
            if "Runtime.getRuntime().exec(" in code and "ProcessBuilder" not in code:
                findings.append({
                    "line": self._find_line(code, "Runtime.getRuntime().exec("),
                    "type": "OS Command Injection",
                    "cwe": "CWE-78",
                    "severity": "高风险",
                    "fix": "使用ProcessBuilder并校验参数"
                })
            if "Cipher.getInstance(\"DES" in code or "DES/ECB" in code:
                findings.append({
                    "line": self._find_line(code, "Cipher.getInstance("),
                    "type": "Weak Cryptographic Algorithm",
                    "cwe": "CWE-327",
                    "severity": "中风险",
                    "fix": "使用AES/GCM模式"
                })
            if "DocumentBuilderFactory" in code and "disallow-doctype-decl" not in code:
                findings.append({
                    "line": self._find_line(code, "DocumentBuilderFactory"),
                    "type": "XML External Entity (XXE)",
                    "cwe": "CWE-611",
                    "severity": "高风险",
                    "fix": "禁用DTD和外部实体"
                })
            if "new URL(" in code and "ALLOWED" not in code:
                findings.append({
                    "line": self._find_line(code, "new URL("),
                    "type": "Server-Side Request Forgery (SSRF)",
                    "cwe": "CWE-918",
                    "severity": "中风险",
                    "fix": "使用URL白名单校验"
                })
        
        # Python检测规则
        elif language == "Python":
            if "os.system(" in code or "os.popen(" in code:
                findings.append({
                    "line": self._find_line(code, "os.system(") or self._find_line(code, "os.popen("),
                    "type": "OS Command Injection",
                    "cwe": "CWE-78",
                    "severity": "高风险",
                    "fix": "使用subprocess.run配合shlex.split"
                })
            if "execute(" in code and "%" in code and "?" not in code:
                findings.append({
                    "line": self._find_line(code, "execute("),
                    "type": "SQL Injection",
                    "cwe": "CWE-89",
                    "severity": "高风险",
                    "fix": "使用参数化查询"
                })
            if "pickle.loads(" in code or "yaml.load(" in code:
                findings.append({
                    "line": self._find_line(code, "pickle.loads(") or self._find_line(code, "yaml.load("),
                    "type": "Deserialization of Untrusted Data",
                    "cwe": "CWE-502",
                    "severity": "高风险",
                    "fix": "使用json.loads或安全反序列化"
                })
            if "eval(" in code or "exec(" in code:
                findings.append({
                    "line": self._find_line(code, "eval(") or self._find_line(code, "exec("),
                    "type": "Code Injection",
                    "cwe": "CWE-94",
                    "severity": "高风险",
                    "fix": "使用ast.literal_eval或安全表达式解析"
                })
            if "open(" in code and ".." not in code and "is_valid_path" not in code:
                findings.append({
                    "line": self._find_line(code, "open("),
                    "type": "Path Traversal",
                    "cwe": "CWE-22",
                    "severity": "中风险",
                    "fix": "使用base path校验"
                })
            if "requests.get(" in code and "verify=False" in code:
                findings.append({
                    "line": self._find_line(code, "requests.get("),
                    "type": "Improper Certificate Validation",
                    "cwe": "CWE-295",
                    "severity": "中风险",
                    "fix": "设置verify=True"
                })
            if "urllib.request.urlopen(" in code and "ALLOWED_HOSTS" not in code:
                findings.append({
                    "line": self._find_line(code, "urllib.request.urlopen("),
                    "type": "Server-Side Request Forgery (SSRF)",
                    "cwe": "CWE-918",
                    "severity": "中风险",
                    "fix": "使用URL白名单"
                })
            if "tempfile" not in code and "/tmp/" in code:
                findings.append({
                    "line": self._find_line(code, "/tmp/"),
                    "type": "Insecure Temporary File",
                    "cwe": "CWE-377",
                    "severity": "中风险",
                    "fix": "使用tempfile.mkstemp"
                })
        
        return {
            "findings": findings,
            "mode": "local",
            "template_used": self.templates.get(language, {}),
            "context": context
        }
    
    def _remote_api_analyze(self, code: str, language: str, context: dict) -> dict:
        """预留：调用远程LLM API（OpenAI-compatible格式）"""
        # TODO: 实现HTTP请求，构造Prompt，解析返回结果
        # 模拟API调用
        return {
            "findings": [],
            "mode": "api",
            "status": "not_implemented",
            "message": "远程API模式已预留，需配置api_key、base_url和model后启用"
        }
    
    def _find_line(self, code: str, keyword: str) -> int:
        """查找关键词所在行号"""
        lines = code.splitlines()
        for i, line in enumerate(lines, 1):
            if keyword in line:
                return i
        return 1

if __name__ == "__main__":
    # 快速测试
    adapter = LLMAdapter(mode="local")
    test_code = """
#include <string.h>
void copy_input(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}
"""
    result = adapter.analyze(test_code, "C", {"taint_sources": ["input"]})
    print(json.dumps(result, ensure_ascii=False, indent=2))
