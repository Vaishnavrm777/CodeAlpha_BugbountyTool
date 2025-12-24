#!/usr/bin/env python3
"""
Bug Bounty Helper – Lightweight Static Analysis Tool

Purpose:
- Identify common security vulnerabilities
- Flag logic flaws and risky patterns
- Detect basic security misconfigurations in source code

DISCLAIMER:
This tool is for defensive security testing and code review only.
It does NOT exploit systems and should be used on code you own or are authorized to test.

Supported (initial version):
- Python source code

Behavior:
- Can be run as a CLI tool with a file path
- Can also be imported and tested without raising SystemExit
"""

import ast
import re
import sys
from pathlib import Path
from typing import List

# -----------------------------
# Issue model
# -----------------------------
class Issue:
    def __init__(self, severity: str, category: str, message: str, line: int):
        self.severity = severity
        self.category = category
        self.message = message
        self.line = line

    def __str__(self):
        return f"[{self.severity}] {self.category} (line {self.line}): {self.message}"

# -----------------------------
# Static Analyzer
# -----------------------------
class BugBountyAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.issues: List[Issue] = []
        self.source_code = source_code
        self.lines = source_code.splitlines()

    # ---------- VULNERABILITY CHECKS ----------

    def visit_Call(self, node):
        # Detect use of eval / exec
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            self.issues.append(Issue(
                "HIGH",
                "Code Injection",
                f"Use of dangerous function '{node.func.id}'",
                node.lineno,
            ))

        # Detect subprocess with shell=True
        if isinstance(node.func, ast.Attribute) and node.func.attr == "Popen":
            for kw in node.keywords:
                if (
                    kw.arg == "shell"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True
                ):
                    self.issues.append(Issue(
                        "HIGH",
                        "Command Injection",
                        "subprocess.Popen called with shell=True",
                        node.lineno,
                    ))

        self.generic_visit(node)

    def visit_Assign(self, node):
        # Detect hardcoded secrets
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id.lower()
                if any(k in name for k in {"password", "secret", "token", "apikey", "api_key"}):
                    self.issues.append(Issue(
                        "MEDIUM",
                        "Hardcoded Secret",
                        f"Possible hardcoded secret assigned to '{target.id}'",
                        node.lineno,
                    ))
        self.generic_visit(node)

    def visit_Compare(self, node):
        # Detect logic flaw: comparing to None using ==
        if any(isinstance(c, ast.Constant) and c.value is None for c in node.comparators):
            self.issues.append(Issue(
                "LOW",
                "Logic Flaw",
                "Comparison to None should use 'is' instead of '=='",
                node.lineno,
            ))
        self.generic_visit(node)

    # ---------- CONFIGURATION CHECKS ----------

    def check_debug_mode(self):
        for idx, line in enumerate(self.lines, start=1):
            if re.search(r"\bdebug\s*=\s*True\b", line):
                self.issues.append(Issue(
                    "HIGH",
                    "Security Misconfiguration",
                    "Debug mode enabled in production code",
                    idx,
                ))

    def check_weak_crypto(self):
        weak_algos = {"md5", "sha1"}
        for idx, line in enumerate(self.lines, start=1):
            for algo in weak_algos:
                if algo in line.lower():
                    self.issues.append(Issue(
                        "MEDIUM",
                        "Weak Cryptography",
                        f"Usage of weak hashing algorithm '{algo}'",
                        idx,
                    ))

# -----------------------------
# Core analysis API (safe for import)
# -----------------------------

def analyze_source(source_code: str) -> List[Issue]:
    tree = ast.parse(source_code)
    analyzer = BugBountyAnalyzer(source_code)
    analyzer.visit(tree)
    analyzer.check_debug_mode()
    analyzer.check_weak_crypto()
    return analyzer.issues


def analyze_file(file_path: Path) -> List[Issue]:
    source = file_path.read_text(encoding="utf-8")
    return analyze_source(source)

# -----------------------------
# CLI Runner (no SystemExit on non-critical errors)
# -----------------------------

def main(argv=None) -> int:
    argv = argv or sys.argv[1:]

    if len(argv) != 1:
        print("Usage: python bugbounty_analyzer.py <source_file.py>")
        return 0

    file_path = Path(argv[0])
    if not file_path.exists():
        print("File not found")
        return 0

    issues = analyze_file(file_path)

    if not issues:
        print("No issues detected.")
        return 0

    print("\nSecurity Findings:\n" + "-" * 50)
    for issue in issues:
        print(issue)

    return 0


if __name__ == "__main__":
    main()

# -----------------------------
# Basic self-tests
# -----------------------------

def _test_eval_detection():
    code = """
user_input = "2+2"
result = eval(user_input)
"""
    issues = analyze_source(code)
    assert any(i.category == "Code Injection" for i in issues)


def _test_hardcoded_secret():
    code = "API_KEY = '12345'"
    issues = analyze_source(code)
    assert any(i.category == "Hardcoded Secret" for i in issues)


def _test_none_comparison():
    code = """
if value == None:
    pass
"""
    issues = analyze_source(code)
    assert any(i.category == "Logic Flaw" for i in issues)


def _test_no_findings():
    code = "x = 1 + 1"
    issues = analyze_source(code)
    assert issues == []


def run_tests():
    _test_eval_detection()
    _test_hardcoded_secret()
    _test_none_comparison()
    _test_no_findings()
    print("All tests passed.")
