from pydantic import BaseModel, Field
from typing import List, Optional, Literal, Dict

Severity = Literal["info","low","medium","high","critical"]

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
