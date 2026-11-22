from __future__ import annotations

from enum import Enum
from typing import Dict, Iterator, List, Optional, Type

from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.hashing import HashingAlgorithm
from deepsecrets.core.utils.hashing import get_hash


class SemanticType(Enum):
    VAR = 1


class Semantic:
    type: SemanticType
    name: str
    creds_probability: int

    def __init__(self, type: SemanticType, name: str, creds_probability: int = 0) -> None:
        self.type = type
        self.name = name
        self.creds_probability = creds_probability


class HashedValues(dict):
    """
    Mapping of algorithm to digest.

    Besides enum keys it also accepts string aliases, which makes the cache
    convenient to inspect and keeps it compatible with rule files that store
    algorithm names as plain strings.
    """

    def __getitem__(self, key: HashingAlgorithm) -> str:  # type: ignore[override]
        return super().__getitem__(HashingAlgorithm.from_value(key))

    def __setitem__(self, key: HashingAlgorithm, value: str) -> None:  # type: ignore[override]
        super().__setitem__(HashingAlgorithm.from_value(key), value)

    def __contains__(self, key: object) -> bool:  # type: ignore[override]
        if isinstance(key, (HashingAlgorithm, str)):
            try:
                key = HashingAlgorithm.from_value(key)
            except ValueError:
                return False
        return super().__contains__(key)

    def get(self, key: HashingAlgorithm, default: Optional[str] = None) -> Optional[str]:  # type: ignore[override]
        try:
            return self[key]
        except (KeyError, ValueError):
            return default

    def __iter__(self) -> Iterator[HashingAlgorithm]:
        return super().__iter__()


class Token:
    content: str
    uncovered_content: List[str]
    span: List[int]
    file: 'File'
    type: List[Type]
    length: int
    hashed_value: Optional[str]
    hashed_values: Dict[HashingAlgorithm, str]
    hash_generation: Optional[str]
    semantic: Optional[Semantic]
    previous: Optional['Token']
    next: Optional['Token']

    def __init__(self, file: File, content: Optional[str] = None, span: Optional[List[int]] = None) -> None:
        self.file = file
        self.content = content
        self.span = span
        self.length = len(content) if self.content else 0
        self.hashed_value = None
        self.hashed_values = HashedValues()
        self.hash_generation = None
        self._hashed_content: Optional[str] = None
        self.previous = None
        self.next = None
        self.type: List[Type] = []  # type: ignore
        self.semantic = None
        self.uncovered_content = []

    def set_type(self, type: List[Type]) -> None:
        self.type = type  # type: ignore

    def val_hash(self) -> int:
        return hash(self.content)

    def calculate_hashed_value(self, algorithm: HashingAlgorithm) -> str:
        """
        Calculate (and cache) the digest for a specific algorithm.

        The cache is keyed by algorithm, not by token.  A rule set may contain
        rules from several migration generations (SHA-1, SHA-256, SHA-512) for
        the same token length, and each rule must see the digest calculated by
        its own algorithm.
        """
        algorithm = HashingAlgorithm.from_value(algorithm)

        if self._hashed_content != self.content:
            self.hashed_values.clear()
            self.hashed_value = None
            self._hashed_content = self.content

        hashed_value = self.hashed_values.get(algorithm)
        if hashed_value is None:
            hashed_value = get_hash(payload=self.content, algorithm=algorithm)
            self.hashed_values[algorithm] = hashed_value

        # Keep the historical attribute meaningful for callers that only know
        # about a single algorithm.  It always points at the most recently
        # requested digest.
        self.hashed_value = hashed_value
        return hashed_value

    def get_hashed_value(self, algorithm: HashingAlgorithm) -> str:
        return self.calculate_hashed_value(algorithm)

    def hash_for(self, algorithm: HashingAlgorithm) -> str:
        """Alias for calculating/retrieving one algorithm's digest."""
        return self.calculate_hashed_value(algorithm)

    @property
    def hashes(self) -> Dict[HashingAlgorithm, str]:
        """Alias for the per-algorithm digest cache."""
        return self.hashed_values

    def calculate_hashed_values(self, algorithms: List[HashingAlgorithm]) -> Dict[HashingAlgorithm, str]:
        return {
            HashingAlgorithm.from_value(algorithm): self.calculate_hashed_value(algorithm)
            for algorithm in algorithms
        }

    def reset_hashed_values(self) -> None:
        """Drop every cached generation (used when a scan generation ends)."""
        self.hashed_values.clear()
        self.hashed_value = None
        self.hash_generation = None
        self._hashed_content = None

    @property
    def generation(self) -> Optional[str]:
        """Rule generation that produced the cached hashes, when known."""
        return self.hash_generation

    def __repr__(self) -> str:  # pragma: no cover
        if self.semantic is None and self.type is not None:
            return f'{self.content} | {self.type[0]}\n'

        out = f'======== VAR: {self.semantic.name} = {self.content}'  # type: ignore
        if self.type is not None:
            out += f' | {self.type[0]}\n'

        return out
