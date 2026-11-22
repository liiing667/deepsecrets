from __future__ import annotations

from hashlib import sha256
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, PrivateAttr, root_validator

from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.hashing import HashingAlgorithm
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.utils.hashing import ruleset_generation


class Finding(BaseModel):
    file: Optional['File'] = Field(default=None)
    rules: List[Rule] = Field(default=[])
    detection: str
    full_line: Optional[str] = Field(default=None)
    linum: Optional[int] = Field(default=None)
    start_pos: int
    end_pos: int
    # Provenance for hashed-secret findings.  These fields are intentionally
    # not part of FindingApiModel: legacy report consumers keep exactly the
    # same API shape while internal consumers can attribute a finding to the
    # rule algorithm, token digest and migration generation.
    algorithm: Optional[HashingAlgorithm] = Field(default=None)
    hashed_value: Optional[str] = Field(default=None)
    hashed_values: Dict[HashingAlgorithm, str] = Field(default_factory=dict)
    rule_generation: Optional[str] = Field(default=None)
    reason: str = Field(default='')
    final_rule: Optional[Rule] = Field(default=None)
    _mapped_on_file: bool = PrivateAttr(default=False)

    @root_validator(pre=True)
    def normalize_provenance_aliases(cls, values: Dict) -> Dict:
        for alias in ('generation', 'scan_generation', 'migration_generation'):
            if alias in values and 'rule_generation' not in values:
                values['rule_generation'] = values.pop(alias)

        if 'token_hash' in values and 'hashed_value' not in values:
            values['hashed_value'] = values.pop('token_hash')
        if 'token_hashes' in values and 'hashed_values' not in values:
            values['hashed_values'] = values.pop('token_hashes')

        return values

    def map_on_file(self, relative_start: int, file: Optional['File'] = None) -> None:
        if self._mapped_on_file:
            return

        if file is None and self.file is None:
            raise Exception('No file to match on')
        if self.file is None:
            self.file = file

        self.start_pos += relative_start
        self.end_pos += relative_start
        self.linum = self.file.get_line_number(self.end_pos)
        if not self.full_line:
            self.full_line = self.file.get_line_contents(self.linum)
        self._mapped_on_file = True

    def get_reason(self) -> str:
        if self.final_rule is None:
            self.choose_final_rule()

        return f'{self.final_rule.name} | {self.get_fingerprint()}'  # type: ignore

    def get_fingerprint(self, algorithm: Optional[HashingAlgorithm] = None) -> str:
        # The fingerprint is deliberately based on the detected secret only.
        # It must not change when the same secret rotates from SHA-1 to
        # SHA-256 (or when both rule generations coexist), otherwise existing
        # suppression/baseline entries would disappear.
        return sha256(self.detection.encode('utf-8')).hexdigest()[23:33]

    @property
    def fingerprint(self) -> str:
        return self.get_fingerprint()

    @property
    def token_hash(self) -> Optional[str]:
        return self.hashed_value

    @property
    def token_hashes(self) -> Dict[HashingAlgorithm, str]:
        return self.hashed_values

    @property
    def algorithms(self) -> List[HashingAlgorithm]:
        algorithms: List[HashingAlgorithm] = []
        for rule in self.rules:
            algorithm = getattr(rule, 'algorithm', None)
            if algorithm is not None and algorithm not in algorithms:
                algorithms.append(algorithm)
        return algorithms

    @property
    def rule_algorithms(self) -> List[HashingAlgorithm]:
        return self.algorithms

    @property
    def rule_hashes(self) -> Dict[str, str]:
        """Map each matching hashed rule id to the digest recorded for it."""
        hashes: Dict[str, str] = {}
        for rule in self.rules:
            hashed_val = getattr(rule, 'hashed_val', None)
            if hashed_val is None:
                continue
            hashes[rule.id] = hashed_val
        return hashes

    @property
    def generation(self) -> Optional[str]:
        if self.rule_generation is not None:
            return self.rule_generation
        if len(self.rules) == 0:
            return None
        if not any(getattr(rule, 'algorithm', None) is not None for rule in self.rules):
            return None
        return ruleset_generation(self.rules)

    @property
    def migration_generation(self) -> Optional[str]:
        return self.generation

    class Config:
        arbitrary_types_allowed = True

    def choose_final_rule(self) -> None:
        self.final_rule = sorted(
            self.rules, key=lambda r: r.confidence,
            reverse=True
        )[0]

        algorithm = getattr(self.final_rule, 'algorithm', None)
        if algorithm is not None:
            self.algorithm = algorithm
            self.hashed_value = self.hashed_values.get(algorithm, self.hashed_value)

    def __hash__(self) -> int:  # pragma: nocover
        file_path = self.file.path if self.file is not None else ''
        return hash(f'{file_path}{self.detection}{self.start_pos}{self.end_pos}')

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return False

        # Findings from different rule generations describe different scan
        # states.  They may carry the same secret (and therefore the same
        # fingerprint), but merging them would silently combine two complete
        # generations.  A missing generation (e.g. a regex-only finding) stays
        # compatible with any generation.
        if (
            other.rule_generation is not None
            and self.rule_generation is not None
            and other.rule_generation != self.rule_generation
        ):
            return False

        if other.file and self.file:
            if other.file.path != self.file.path:
                return False

        if other.detection and self.detection:
            if other.detection != self.detection:
                return False

        if other.start_pos and self.start_pos:
            if other.start_pos != self.start_pos:
                return False

        if other.end_pos and self.end_pos:
            if other.end_pos != self.end_pos:
                return False

        return True

    def merge(self, other: Any) -> bool:
        if not isinstance(other, Finding):
            return False

        if other != self:
            return False

        if other is self:
            return True

        # Deduplicate while preserving the original order.  During a hashed
        # secret migration the same detection is legitimately produced by an
        # old SHA-1 rule and a new SHA-256 rule; the oldest rule must stay
        # first so the existing finding identity/fingerprint remains stable.
        for rule in other.rules:
            if rule not in self.rules:
                self.rules.append(rule)

        if self.algorithm is None:
            self.algorithm = other.algorithm
        if self.hashed_value is None:
            self.hashed_value = other.hashed_value
        for algorithm, digest in other.hashed_values.items():
            if algorithm not in self.hashed_values:
                self.hashed_values[algorithm] = digest
        if self.rule_generation is None:
            self.rule_generation = other.rule_generation

        return True


class FindingMerger:
    all: List[Finding]

    def __init__(self, full_list: List[Finding]) -> None:
        self.all = full_list

    def merge(self) -> List[Finding]:
        merged: List[Finding] = []
        buckets: Dict[int, List[Finding]] = {}

        for elem in self.all:
            bucket = buckets.setdefault(elem.__hash__(), [])
            target = None
            for candidate in bucket:
                if candidate == elem:
                    target = candidate
                    break

            if target is None or not target.merge(elem):
                bucket.append(elem)
                merged.append(elem)

        return merged


class FindingResponse:
    @classmethod
    def from_list(cls, list: List[Finding]) -> Dict[str, List[Dict]]:
        resp: Dict[str, List[Dict]] = {}
        for finding in list:
            if finding.file is None:
                continue

            if finding.file.path not in resp:
                resp[finding.file.path] = []

            resp[finding.file.path].append(FindingApiModel.from_finding(finding).dict())
        return resp


class FindingApiModel(BaseModel):
    line: str
    string: str
    line_number: int
    rule: str
    reason: str
    confidence: int
    fingerprint: str

    @classmethod
    def from_finding(cls, finding: Finding) -> FindingApiModel:
        finding.choose_final_rule()
        return FindingApiModel(
            line=finding.full_line,
            string=finding.detection,
            line_number=finding.linum,
            rule=finding.final_rule.id,
            reason=finding.get_reason(),
            confidence=finding.final_rule.confidence,
            fingerprint=finding.get_fingerprint(),
        )
