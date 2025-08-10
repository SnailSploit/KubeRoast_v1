import json
from typing import List
from ..utils.findings import Finding

def emit(findings: List[Finding]) -> str:
    return json.dumps([f.model_dump() for f in findings], indent=2)
