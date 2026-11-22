"""Deliberately insecure code. The SAST gate MUST fail on this file.

It lives outside the scanned packages and is excluded from the main Semgrep run; the
gate-self-test job scans it on purpose to prove the gate has teeth.
"""

import subprocess

import yaml


def load_untrusted(text: str):
    return yaml.load(text)  # unsafe loader on untrusted input


def run(cmd: str) -> None:
    subprocess.run(cmd, shell=True)  # command injection


def find_service(session, name: str):
    return session.run(f"MATCH (n {{name: '{name}'}}) RETURN n")  # Cypher injection
