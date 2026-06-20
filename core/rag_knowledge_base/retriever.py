#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAG Retriever - 轻量级漏洞知识检索器
使用 TfidfVectorizer + cosine_similarity 实现相似度检索
动态召回 Top-K 相似案例，拼接为 Few-shot Prompt
"""
import os
import json
import time

# 尝试导入 scikit-learn，如果不可用则回退到简单词袋模型
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class RAGRetriever:
    """
    轻量级 RAG 检索器
    - 从 vul_examples.json 加载知识库
    - 使用 TF-IDF + 余弦相似度进行检索
    - 若 scikit-learn 不可用，回退到简单词袋 + Jaccard 相似度
    """

    def __init__(self, kb_path: str = None, top_k: int = 3):
        self.top_k = top_k
        self.kb_path = kb_path or self._default_kb_path()
        self.examples = []
        self.vectorizer = None
        self.vectors = None
        self._load_kb()

    def _default_kb_path(self) -> str:
        return os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "vul_examples.json"
        )

    def _load_kb(self):
        """加载知识库并构建索引（支持分片文件）"""
        base_dir = os.path.dirname(self.kb_path)
        self.examples = []
        
        # 先尝试加载分片文件 vul_examples_01.json 到 vul_examples_15.json
        for i in range(1, 16):
            chunk_path = os.path.join(base_dir, f"vul_examples_{i:02d}.json")
            if os.path.exists(chunk_path):
                with open(chunk_path, "r", encoding="utf-8") as f:
                    self.examples.extend(json.load(f))
        
        # 如果没有分片，尝试加载完整文件
        if not self.examples and os.path.exists(self.kb_path):
            with open(self.kb_path, "r", encoding="utf-8") as f:
                self.examples = json.load(f)
        
        # 如果仍然为空，尝试构建知识库
        if not self.examples and not os.path.exists(self.kb_path):
            build_script = os.path.join(base_dir, "build_kb.py")
            if os.path.exists(build_script):
                import subprocess
                subprocess.run(["python", build_script], check=False)
            if os.path.exists(self.kb_path):
                with open(self.kb_path, "r", encoding="utf-8") as f:
                    self.examples = json.load(f)

        texts = [ex["text"] for ex in self.examples]

        if SKLEARN_AVAILABLE and texts:
            self.vectorizer = TfidfVectorizer(
                max_features=5000,
                stop_words="english",
                ngram_range=(1, 2),
                min_df=1
            )
            self.vectors = self.vectorizer.fit_transform(texts)
        else:
            # 回退：简单词袋 + 预计算
            self.vectorizer = None
            self.vectors = None

    def retrieve(self, code: str, language: str = None) -> list:
        """
        检索与输入代码最相似的 Top-K 漏洞案例
        返回: [{id, language, cwe, vuln_type, vuln_code, fixed_code, similarity}]
        """
        if not self.examples:
            return []

        if SKLEARN_AVAILABLE and self.vectorizer is not None:
            return self._retrieve_sklearn(code, language)
        else:
            return self._retrieve_fallback(code, language)

    def _retrieve_sklearn(self, code: str, language: str) -> list:
        """使用 scikit-learn TF-IDF + cosine_similarity 检索"""
        query_vec = self.vectorizer.transform([code])
        similarities = cosine_similarity(query_vec, self.vectors).flatten()

        # 过滤语言（若指定）
        candidate_indices = list(range(len(self.examples)))
        if language:
            candidate_indices = [
                i for i in candidate_indices
                if self.examples[i].get("language", "").lower() == language.lower()
            ]

        if not candidate_indices:
            candidate_indices = list(range(len(self.examples)))

        # 按相似度排序，取 Top-K
        scored = [(i, similarities[i]) for i in candidate_indices]
        scored.sort(key=lambda x: x[1], reverse=True)
        top = scored[:self.top_k]

        results = []
        for idx, sim in top:
            ex = self.examples[idx]
            results.append({
                "id": ex["id"],
                "language": ex["language"],
                "cwe": ex["cwe"],
                "vuln_type": ex["vuln_type"],
                "vuln_code": ex["vuln_code"],
                "fixed_code": ex["fixed_code"],
                "similarity": round(float(sim), 4)
            })
        return results

    def _retrieve_fallback(self, code: str, language: str) -> list:
        """回退：基于词袋 Jaccard 相似度"""
        query_tokens = set(self._tokenize(code))

        scored = []
        for i, ex in enumerate(self.examples):
            if language and ex.get("language", "").lower() != language.lower():
                continue
            ex_tokens = set(self._tokenize(ex["text"]))
            intersection = query_tokens & ex_tokens
            union = query_tokens | ex_tokens
            sim = len(intersection) / len(union) if union else 0.0
            scored.append((i, sim))

        scored.sort(key=lambda x: x[1], reverse=True)
        top = scored[:self.top_k]

        results = []
        for idx, sim in top:
            ex = self.examples[idx]
            results.append({
                "id": ex["id"],
                "language": ex["language"],
                "cwe": ex["cwe"],
                "vuln_type": ex["vuln_type"],
                "vuln_code": ex["vuln_code"],
                "fixed_code": ex["fixed_code"],
                "similarity": round(float(sim), 4)
            })
        return results

    def _tokenize(self, text: str) -> list:
        """简单分词：保留字母数字和 CWE 模式"""
        import re
        text = text.lower()
        # 保留 CWE-XXX 模式
        text = re.sub(r'cwe-(\d+)', r'cwe_\1', text)
        tokens = re.findall(r'\b[a-zA-Z_]\w*\b', text)
        # 过滤常见停用词
        stop_words = {
            'the', 'and', 'for', 'def', 'return', 'if', 'else', 'import',
            'from', 'class', 'void', 'int', 'char', 'public', 'private',
            'static', 'this', 'new', 'try', 'catch', 'finally', 'with',
            'as', 'in', 'is', 'not', 'or', 'and', 'pass', 'break', 'continue'
        }
        return [t for t in tokens if t not in stop_words and len(t) > 2]

    def build_fewshot_prompt(self, code: str, language: str) -> str:
        """
        根据检索结果动态构建 Few-shot Prompt
        返回可直接用于 LLM 的 Few-shot 上下文文本
        """
        results = self.retrieve(code, language)
        if not results:
            return ""

        prompt_parts = ["## 相似漏洞案例（动态检索）\n"]
        for i, r in enumerate(results, 1):
            prompt_parts.append(f"### 案例 {i}: {r['vuln_type']} ({r['cwe']}) [相似度: {r['similarity']}]\n")
            prompt_parts.append(f"**漏洞代码**:\n```\n{r['vuln_code'][:300]}\n```\n")
            prompt_parts.append(f"**修复代码**:\n```\n{r['fixed_code'][:300]}\n```\n")

        return "\n".join(prompt_parts)

    def get_confidence_score(self, code: str, language: str) -> float:
        """
        基于检索结果计算置信度分数（0.0-1.0）
        用于级联精检策略：若 confidence < 0.7 则触发远程 API
        """
        results = self.retrieve(code, language)
        if not results:
            return 0.0

        # 加权平均相似度
        total = sum(r["similarity"] for r in results)
        avg = total / len(results)

        # 若最高相似度案例的 CWE 与代码中检测到的 Sink 类型匹配，增加置信度
        max_sim = results[0]["similarity"]

        # 综合置信度：0.6 * avg + 0.4 * max_sim
        confidence = 0.6 * avg + 0.4 * max_sim
        return min(1.0, max(0.0, confidence))


if __name__ == "__main__":
    retriever = RAGRetriever(top_k=3)
    test_code = """
import os

def run_cmd(cmd):
    os.system(cmd)
"""
    results = retriever.retrieve(test_code, "python")
    print("Retrieved examples:")
    for r in results:
        print(f"  {r['id']} {r['cwe']} sim={r['similarity']}")

    prompt = retriever.build_fewshot_prompt(test_code, "python")
    print("\nFew-shot prompt length:", len(prompt))

    conf = retriever.get_confidence_score(test_code, "python")
    print(f"Confidence score: {conf:.4f}")
