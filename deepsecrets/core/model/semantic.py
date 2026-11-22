from typing import List, Optional
from deepsecrets.core.model.token import Token


class Variable:
    name: Token
    value: Token
    span: List[int]
    found_by: 'VaribleDetector'
    generation: Optional[int] = None


from deepsecrets.core.tokenizers.helpers.semantic.var_detection.detector import (
    VaribleDetector,
)
