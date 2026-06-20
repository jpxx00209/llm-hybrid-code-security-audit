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

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class RAGRetriever:
    def __init__(self, kb_path: str = None, top_k: int = 3):
        self.top_k = top_k
        self.kb_path = kb_path or self._default_kb_path()
        self.examples = []
        self.vectorizer = None
        self.vectors = None
        self._load_kb()

    def _default_kb_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "vul_examples.json")

    def _load_kb(self):
        if not os.path.exists(self.kb_path):
            build_script = os.path.join(os.path.dirname(self.kb_path), "build_kb.py")
            if os.path.exists(build_script):
                import subprocess
                subprocess.run(["python", build_script], check=False)
        if not os.path.exists(self.kb_path):
            self.examples = []
            return
        with open(self.kb_path, "r", encoding="utf-8") as f:
            self.examples = json.load(f)
        texts = [ex["text"] for ex in self.examples]
        if SKLEARN_AVAILABLE and texts:
            self.vectorizer = TfidfVectorizer(max_features=5000, stop_words="english", ngram_range=(1, 2), min_df=1)
            self.vectors = self.vectorizer.fit_transform(texts)
        else:
            self.vectorizer = None
            self.vectors = None

    def retrieve(self, code: str, language: str = None) -> list:
        if not self.examples:
            return []
        if SKLEARN_AVAILABLE and self.vectorizer is not None:
            return self._retrieve_sklearn(code, language)
        else:
            return self._retrieve_fallback(code, language)

    def _retrieve_sklearn(self, code: str, language: str) -> list:
        query_vec = self.vectorizer.transform([code])
        similarities = cosine_similarity(query_vec, self.vectors).flatten()
        candidate_indices = list(range(len(self.examples)))
        if language:
            candidate_indices = [i for i in candidate_indices if self.examples[i].get("language", "").lower() == language.lower()]
        if not candidate_indices:
            candidate_indices = list(range(len(self.examples)))
        scored = [(i, similarities[i]) for i in candidate_indices]
        scored.sort(key=lambda x: x[1], reverse=True)
        top = scored[:self.top_k]
        results = []
        for idx, sim in top:
            ex = self.examples[idx]
            results.append({
                "id": ex["id"], "language": ex["language"], "cwe": ex["cwe"],
                "vuln_type": ex["vuln_type"], "vuln_code": ex["vuln_code"],
                "fixed_code": ex["fixed_code"], "similarity": round(float(sim), 4)
            })
        return results

    def _retrieve_fallback(self, code: str, language: str) -> list:
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
                "id": ex["id"], "language": ex["language"], "cwe": ex["cwe"],
                "vuln_type": ex["vuln_type"], "vuln_code": ex["vuln_code"],
                "fixed_code": ex["fixed_code"], "similarity": round(float(sim), 4)
            })
        return results

    def _tokenize(self, text: str) -> list:
        import re
        text = text.lower()
        text = re.sub(r'cwe-(\d+)', r'cwe_\1', text)
        tokens = re.findall(r'\b[a-zA-Z_]\w*\b', text)
        stop_words = {'the', 'and', 'for', 'def', 'return', 'if', 'else', 'import', 'from', 'class', 'void', 'int', 'char', 'public', 'private', 'static', 'this', 'new', 'try', 'catch', 'finally', 'with', 'as', 'in', 'is', 'not', 'or', 'and', 'pass', 'break', 'continue'}
        return [t for t in tokens if t not in stop_words and len(t) > 2]

    def build_fewshot_prompt(self, code: str, language: str) -> str:
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
        results = self.retrieve(code, language)
        if not results:
            return 0.0
        total = sum(r["similarity"] for r in results)
        avg = total / len(results)
        max_sim = results[0]["similarity"]
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
