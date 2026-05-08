from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    id: str
    title: str
    description: str
    severity: Severity = "medium"
    category: str = "general"
    namespace: Optional[str] = None
    resource: Optional[str] = None
    metadata: Dict[str, str] = Field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    cis_controls: List[str] = Field(default_factory=list)
    mitre_attack: List[str] = Field(default_factory=list)
    cwe: List[str] = Field(default_factory=list)


SEVERITY_TO_CVSS: Dict[str, float] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}
