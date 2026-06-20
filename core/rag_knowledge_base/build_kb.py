#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VulKnowledgeBase - 漏洞知识库构建器
从现有 dataset 样本归档生成 vul_examples.json 知识库
"""
import os
import json
import csv


def build_knowledge_base():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_dir = os.path.join(base_dir, "..", "..", "dataset")
    vul_examples = []
    manifest_path = os.path.join(dataset_dir, "samples_manifest.csv")
    with open(manifest_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    for row in rows:
        sample_id = row["编号"]
        lang = row["语言"].lower()
        cwe = row["CWE编号"]
        vuln_type = row["漏洞类型"]
        desc = row["函数/文件描述"]
        idx = sample_id.split("_")[-1]
        num = int(idx)
        ext_map = {"c": "c", "java": "java", "python": "py"}
        ext = ext_map[lang]
        archive_path = os.path.join(dataset_dir, f"samples_{lang}_complete.json")
        vuln_code = ""
        fixed_code = ""
        if os.path.exists(archive_path):
            with open(archive_path, "r", encoding="utf-8") as f:
                archive = json.load(f)
            vuln_key = f"{lang}_sample_{num:03d}.{ext}"
            fixed_key = f"{lang}_sample_{num:03d}.fixed.{ext}"
            vuln_code = archive.get(vuln_key, "")
            fixed_code = archive.get(fixed_key, "")
        if not vuln_code:
            sample_dir = os.path.join(dataset_dir, f"samples_{lang}")
            vuln_file = os.path.join(sample_dir, f"{lang}_sample_{num:03d}.{ext}")
            fixed_file = os.path.join(sample_dir, f"{lang}_sample_{num:03d}.fixed.{ext}")
            if os.path.exists(vuln_file):
                with open(vuln_file, "r", encoding="utf-8") as f:
                    vuln_code = f.read()
            if os.path.exists(fixed_file):
                with open(fixed_file, "r", encoding="utf-8") as f:
                    fixed_code = f.read()
        text_repr = f"{vuln_type} {cwe} {desc} {vuln_code[:500]}"
        vul_examples.append({
            "id": sample_id, "language": lang, "cwe": cwe,
            "vuln_type": vuln_type, "description": desc,
            "vuln_code": vuln_code, "fixed_code": fixed_code,
            "text": text_repr
        })
    output_path = os.path.join(base_dir, "vul_examples.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(vul_examples, f, ensure_ascii=False, indent=2)
    print(f"[+] Knowledge base built: {len(vul_examples)} examples -> {output_path}")
    return vul_examples


if __name__ == "__main__":
    build_knowledge_base()
