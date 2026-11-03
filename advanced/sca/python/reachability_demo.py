"""
Python Reachability Demo for SCA Analysis
Demonstrates vulnerable API call vs unreachable/safe API call.
"""

import yaml

def parse_with_vulnerable_call(untrusted_yaml: str):
    # Vulnerable pyyaml function actively called
    return yaml.load(untrusted_yaml, Loader=yaml.Loader)

def parse_with_safe_call(untrusted_yaml: str):
    # Unreachable / safe API call: safe_load does not trigger arbitrary code execution
    return yaml.safe_load(untrusted_yaml)

