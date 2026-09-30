#!/usr/bin/env python3
"""
Intelligent Security Assistant
------------------------------
A command-line assistant that answers security questions and runs basic
security analyses. Standard library only (Python 3.9+).

Capabilities
  1. Log analysis     - brute-force logins, port scans, suspicious IPs
  2. Password check   - strength scoring with feedback
  3. Config audit     - flags risky settings in JSON/key=value config files
  4. Risk scoring     - combines findings into a single 0-100 score
  5. Knowledge base   - answers common security questions
  6. Chat interface   - simple intent detection to route requests

Usage
  python intelligent_security_assistant.py                # interactive chat
  python intelligent_security_assistant.py analyze-logs auth.log
  python intelligent_security_assistant.py audit-config app.json
  python intelligent_security_assistant.py check-password "MyP@ssw0rd!"
"""

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

SEVERITY_WEIGHT = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}


@dataclass
class Finding:
    title: str
    severity: str
    detail: str
    recommendation: str


@dataclass
class Report:
    source: str
    findings: list = field(default_factory=list)

    def add(self, *args, **kwargs):
        self.findings.append(Finding(*args, **kwargs))

    @property
    def risk_score(self) -> int:
        return min(100, sum(SEVERITY_WEIGHT[f.severity] for f in self.findings))

    @property
    def risk_level(self) -> str:
        s = self.risk_score
        if s >= 75:
            return "CRITICAL"
        if s >= 50:
            return "HIGH"
        if s >= 20:
            return "MEDIUM"
        return "LOW"

    def render(self) -> str:
        lines = [f"=== Security Report: {self.source} ===",
                 f"Risk score: {self.risk_score}/100 ({self.risk_level})", ""]
        if not self.findings:
            lines.append("No issues found.")
        for i, f in enumerate(
            sorted(self.findings, key=lambda x: -SEVERITY_WEIGHT[x.severity]), 1
        ):
            lines += [f"{i}. [{f.severity}] {f.title}",
                      f"   Detail: {f.detail}",
                      f"   Fix:    {f.recommendation}", ""]
        return "\n".join(lines)


# --------------------------------------------------------------------------
# 1. Log analyzer
# --------------------------------------------------------------------------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_LOGIN_RE = re.compile(r"(failed password|authentication failure|invalid user|login failed)", re.I)
PORT_RE = re.compile(r"(?:DPT|dport|port)[=: ]+(\d{1,5})", re.I)
SQLI_RE = re.compile(r"(union\s+select|or\s+1=1|drop\s+table|--\s|;--)", re.I)
TRAVERSAL_RE = re.compile(r"(\.\./|%2e%2e%2f)", re.I)


class LogAnalyzer:
    BRUTE_FORCE_THRESHOLD = 5
    PORT_SCAN_THRESHOLD = 10

    def analyze(self, path: str) -> Report:
        report = Report(source=path)
        failed = Counter()
        ports = defaultdict(set)
        web_attacks = Counter()

        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                ips = IP_RE.findall(line)
                ip = ips[0] if ips else "unknown"
                if FAILED_LOGIN_RE.search(line):
                    failed[ip] += 1
                m = PORT_RE.search(line)
                if m and ips:
                    ports[ip].add(int(m.group(1)))
                if SQLI_RE.search(line) or TRAVERSAL_RE.search(line):
                    web_attacks[ip] += 1

        for ip, n in failed.items():
            if n >= self.BRUTE_FORCE_THRESHOLD:
                sev = "CRITICAL" if n >= 50 else "HIGH"
                report.add("Possible brute-force attack", sev,
                           f"{ip} had {n} failed login attempts.",
                           "Block the IP, enforce MFA, and add account lockout / rate limiting.")
        for ip, p in ports.items():
            if len(p) >= self.PORT_SCAN_THRESHOLD:
                report.add("Possible port scan", "MEDIUM",
                           f"{ip} touched {len(p)} distinct ports.",
                           "Rate-limit or block the source; review firewall exposure.")
        for ip, n in web_attacks.items():
            report.add("Web attack signatures (SQLi / path traversal)", "HIGH",
                       f"{ip} sent {n} suspicious requests.",
                       "Block the source, enable a WAF, and validate/parameterize all inputs.")
        return report


# --------------------------------------------------------------------------
# 2. Password checker
# --------------------------------------------------------------------------

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "admin", "welcome", "iloveyou", "monkey", "password1", "passw0rd",
}


class PasswordChecker:
    def check(self, pw: str) -> Report:
        report = Report(source="password check")
        if pw.lower() in COMMON_PASSWORDS:
            report.add("Common password", "CRITICAL",
                       "This password appears in common-password lists.",
                       "Choose a unique passphrase.")
        if len(pw) < 12:
            report.add("Too short", "HIGH" if len(pw) < 8 else "MEDIUM",
                       f"Length is {len(pw)}; 12+ is recommended.",
                       "Use a passphrase of 14+ characters.")
        classes = sum(bool(re.search(p, pw)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w\s]"))
        if classes < 3:
            report.add("Low character variety", "MEDIUM",
                       f"Only {classes} of 4 character classes used.",
                       "Mix upper/lower case, digits, and symbols, or use a long passphrase.")
        if re.search(r"(.)\1{2,}", pw) or re.search(r"(?:012|123|234|345|456|567|678|789|abc|qwe)", pw.lower()):
            report.add("Predictable pattern", "MEDIUM",
                       "Contains repeated characters or simple sequences.",
                       "Avoid keyboard runs and repeats.")
        return report

    @staticmethod
    def entropy_bits(pw: str) -> float:
        pool = 0
        pool += 26 if re.search(r"[a-z]", pw) else 0
        pool += 26 if re.search(r"[A-Z]", pw) else 0
        pool += 10 if re.search(r"\d", pw) else 0
        pool += 32 if re.search(r"[^\w\s]", pw) else 0
        return round(len(pw) * math.log2(pool), 1) if pool else 0.0


# --------------------------------------------------------------------------
# 3. Config auditor
# --------------------------------------------------------------------------

# (key regex, predicate on value, title, severity, recommendation)
CONFIG_RULES = [
    (r"debug", lambda v: str(v).lower() in {"true", "1", "yes", "on"},
     "Debug mode enabled", "MEDIUM", "Disable debug in production."),
    (r"ssl|tls|https", lambda v: str(v).lower() in {"false", "0", "no", "off"},
     "Encryption in transit disabled", "HIGH", "Enable TLS for all connections."),
    (r"verify_?ssl|verify_?cert", lambda v: str(v).lower() in {"false", "0", "no", "off"},
     "Certificate verification disabled", "HIGH", "Never disable certificate verification."),
    (r"host|bind|listen", lambda v: str(v).strip() == "0.0.0.0",
     "Service bound to all interfaces", "MEDIUM", "Bind to specific interfaces or place behind a gateway."),
    (r"cors.*origin|allowed_?origins", lambda v: str(v).strip() == "*",
     "Wildcard CORS origin", "MEDIUM", "Restrict CORS to trusted origins."),
    (r"password|passwd|secret|api_?key|token", lambda v: isinstance(v, str) and len(v) > 0
     and not v.startswith(("${", "env:", "vault:")),
     "Hard-coded secret", "CRITICAL", "Move secrets to a vault or environment variables; rotate this one."),
    (r"mfa|2fa", lambda v: str(v).lower() in {"false", "0", "no", "off"},
     "MFA disabled", "HIGH", "Require MFA for all users."),
    (r"session.*timeout|token.*ttl", lambda v: _num(v) is not None and _num(v) > 86400,
     "Very long session lifetime", "LOW", "Shorten session/token lifetime."),
]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _flatten(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _flatten(v, f"{prefix}{i}.")
    else:
        yield prefix.rstrip("."), obj


class ConfigAuditor:
    def audit(self, path: str) -> Report:
        report = Report(source=path)
        text = Path(path).read_text(errors="ignore")
        try:
            items = list(_flatten(json.loads(text)))
        except json.JSONDecodeError:
            items = []
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", ";")) and "=" in line:
                    k, v = line.split("=", 1)
                    items.append((k.strip(), v.strip().strip("\"'")))

        for key, value in items:
            for key_re, pred, title, sev, fix in CONFIG_RULES:
                if re.search(key_re, key, re.I) and pred(value):
                    report.add(title, sev, f"Setting '{key}' looks risky.", fix)
        return report


# --------------------------------------------------------------------------
# 4. Knowledge base
# --------------------------------------------------------------------------

KNOWLEDGE = {
    ("zero trust",): "Zero Trust means 'never trust, always verify': every request is authenticated, "
                     "authorized, and continuously evaluated regardless of network location.",
    ("mfa", "multi-factor", "2fa"): "MFA requires two or more independent factors (knowledge, possession, "
                                    "inherence). Prefer phishing-resistant methods such as FIDO2/passkeys.",
    ("phishing",): "Phishing tricks users into revealing credentials. Defend with MFA, email filtering, "
                   "user training, and DMARC/SPF/DKIM.",
    ("sql injection", "sqli"): "SQL injection inserts malicious SQL via user input. Use parameterized "
                               "queries, least-privilege DB accounts, and input validation.",
    ("xss", "cross-site scripting"): "XSS injects scripts into pages viewed by others. Encode output, use "
                                     "a strict Content-Security-Policy, and sanitize HTML.",
    ("least privilege", "rbac"): "Least privilege grants only the access needed. Implement with RBAC/ABAC, "
                                 "just-in-time access, and regular access reviews.",
    ("ransomware",): "Ransomware encrypts data for extortion. Keep offline immutable backups, patch quickly, "
                     "segment networks, and practice incident response.",
    ("encryption", "tls"): "Encrypt data in transit (TLS 1.2+/1.3) and at rest (AES-256), and manage keys "
                           "in a KMS/HSM with rotation.",
    ("devsecops", "ci/cd"): "DevSecOps embeds security in CI/CD: SAST, dependency scanning, secret scanning, "
                            "IaC checks, and container scanning as pipeline gates.",
}


def lookup(question: str):
    q = question.lower()
    for keys, answer in KNOWLEDGE.items():
        if any(k in q for k in keys):
            return answer
    return None


# --------------------------------------------------------------------------
# 5. Assistant (intent routing)
# --------------------------------------------------------------------------

HELP = """Commands:
  analyze logs <file>        Detect brute force, port scans, web attacks
  audit config <file>        Find risky settings in a JSON / key=value config
  check password <password>  Score password strength
  help                       Show this message
  exit                       Quit
Or just ask a security question (e.g. 'what is zero trust?')."""


class SecurityAssistant:
    def __init__(self):
        self.logs = LogAnalyzer()
        self.passwords = PasswordChecker()
        self.config = ConfigAuditor()

    def handle(self, text: str) -> str:
        t = text.strip()
        low = t.lower()
        try:
            if re.match(r"(analy[sz]e|scan)\s+logs?\b", low):
                return self.logs.analyze(t.split(None, 2)[2]).render()
            if re.match(r"(audit|check)\s+config\b", low):
                return self.config.audit(t.split(None, 2)[2]).render()
            if re.match(r"(check|test)\s+password\b", low):
                pw = t.split(None, 2)[2]
                rep = self.passwords.check(pw)
                return rep.render() + f"\nEstimated entropy: {self.passwords.entropy_bits(pw)} bits"
        except IndexError:
            return "Missing argument. Type 'help' for usage."
        except FileNotFoundError as e:
            return f"File not found: {e.filename}"

        if low in {"help", "?"}:
            return HELP
        answer = lookup(t)
        if answer:
            return answer
        return "I don't have an answer for that yet. Type 'help' to see what I can do."


def chat():
    bot = SecurityAssistant()
    print("Intelligent Security Assistant - type 'help' for commands, 'exit' to quit.")
    while True:
        try:
            msg = input("\nyou> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if msg.lower() in {"exit", "quit"}:
            break
        if msg:
            print("\n" + bot.handle(msg))


def main():
    parser = argparse.ArgumentParser(description="Intelligent Security Assistant")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("chat", help="interactive mode (default)")
    for name in ("analyze-logs", "audit-config", "check-password"):
        p = sub.add_parser(name)
        p.add_argument("target")
    args = parser.parse_args()

    bot = SecurityAssistant()
    if args.cmd == "analyze-logs":
        print(bot.handle(f"analyze logs {args.target}"))
    elif args.cmd == "audit-config":
        print(bot.handle(f"audit config {args.target}"))
    elif args.cmd == "check-password":
        print(bot.handle(f"check password {args.target}"))
    else:
        chat()


if __name__ == "__main__":
    sys.exit(main())
