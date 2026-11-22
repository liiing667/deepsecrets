from typing import List, Optional, Sequence, Set

from deepsecrets.core.engines.iengine import IEngine
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.rules.hashing import HashingAlgorithm
from deepsecrets.core.model.rules.hashed_secret import HashedSecretRule
from deepsecrets.core.model.token import Token
from deepsecrets.core.utils.hashing import ruleset_generation


class HashedSecretEngine(IEngine):
    name = 'hashed'
    description = 'Scans by regex patterns provided by HashedSecretRules'
    ruleset: Sequence[HashedSecretRule]

    def __init__(
        self,
        ruleset: Optional[Sequence[HashedSecretRule]] = None,
        generation: Optional[str] = None,
    ) -> None:
        # Take an immutable-ish snapshot.  Rotating the builder's rules later
        # must not silently change an engine that belongs to an older scan
        # generation.
        super().__init__(list(ruleset or []))
        self._generation = (
            generation if generation is not None else ruleset_generation(self.ruleset)
        )

    @property
    def algorithms(self) -> Set[HashingAlgorithm]:
        return {
            rule.algorithm for rule in self.ruleset
            if getattr(rule, 'algorithm', None) is not None
        }

    @property
    def algorithm_set(self) -> Set[HashingAlgorithm]:
        return self.algorithms

    @property
    def generation(self) -> str:
        return self._generation

    @property
    def ruleset_identity(self) -> str:
        return self.generation

    @property
    def identity(self) -> str:
        return self.generation

    @property
    def ruleset_generation(self) -> str:
        return self.generation

    @property
    def rule_generation(self) -> str:
        return self.generation

    def search(self, token: Token) -> List[Finding]:
        results: List[Finding] = []

        # Bind all digests produced during this scan to one rule generation.
        # A later ruleset rotation must not reuse hashes/findings from here.
        generation = self.generation
        if self.ruleset:
            previous_generation = getattr(token, 'hash_generation', None)
            if previous_generation is not None and previous_generation != generation:
                reset = getattr(token, 'reset_hashed_values', None)
                if reset is not None:
                    reset()
            if hasattr(token, 'hash_generation'):
                token.hash_generation = generation

        applicable_rules = [
            rule for rule in self.ruleset
            if self.is_rule_applicable(token=token, rule=rule)
        ]

        # A failed/partial migration commonly leaves SHA-1 and SHA-256 rules
        # side by side for tokens of the same length.  Compute the complete
        # algorithm set for this token first, so every finding observes the
        # same token-hash state regardless of which rule happens to match.
        algorithms: List[HashingAlgorithm] = []
        for rule in applicable_rules:
            if rule.algorithm not in algorithms:
                algorithms.append(rule.algorithm)
        token.calculate_hashed_values(algorithms)

        for rule in applicable_rules:
            results.extend(self._check_rule(token, rule))

        return results

    def is_rule_applicable(self, token: Token, rule: HashedSecretRule) -> bool:
        if rule.token_length != token.length:
            return False
        return super().is_rule_applicable(token=token, rule=rule)

    def _check_rule(self, token: Token, rule: HashedSecretRule) -> List[Finding]:
        findings: List[Finding] = []

        hashed_values = getattr(token, 'hashed_values', None)
        hashed_value = hashed_values.get(rule.algorithm) if hashed_values is not None else None
        if hashed_value is None:
            calculate = getattr(token, 'calculate_hashed_value', None)
            if calculate is not None:
                hashed_value = calculate(rule.algorithm)
            else:
                hashed_value = getattr(token, 'hashed_value', None)

        if hashed_value is None or not rule.matches_hash(hashed_value, rule.algorithm):
            return findings

        findings.append(
            Finding(
                rules=[rule],
                detection=token.content,
                start_pos=0,
                end_pos=token.length,
                algorithm=rule.algorithm,
                hashed_value=hashed_value,
                hashed_values=dict(token.hashed_values),
                rule_generation=self.generation,
                file=None,  # filled higher
                final_rule=None,  # filled higher,
                full_line=None,  # filled higher
                linum=None,  # filled higher
            )
        )

        return findings
