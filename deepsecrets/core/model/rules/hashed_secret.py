from typing import Any, Dict

import mmh3
from pydantic import root_validator

from deepsecrets.core.model.rules.hashing import HashingAlgorithm
from deepsecrets.core.model.rules.rule import Rule


class HashedSecretRule(Rule):
    hashed_val: str
    token_length: int
    algorithm: HashingAlgorithm

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, HashedSecretRule):
            return False

        if other.hashed_val == self.hashed_val and other.algorithm == self.algorithm:
            return True

        if other.id == self.id and other.algorithm == self.algorithm:
            return True

        return False

    def __hash__(self) -> int:  # pragma: nocover
        # ``self.id`` is derived from ``hashed_val``; including the algorithm
        # keeps equal-by-id rules in one bucket while separating migration
        # generations that use the same digest text.
        return hash((self.id, self.algorithm.value))

    @root_validator(pre=True)
    def fill_id(cls, values: Dict) -> Dict:
        hashed_val = values.get('hashed_val', None)
        if hashed_val is None:
            return values

        algorithm = values.get('algorithm', None)

        if algorithm is None:
            # Keep compatibility with rules written before the ``algorithm``
            # field existed: they were calculated with SHA-512.
            values['algorithm'] = HashingAlgorithm.SHA_512
        else:
            try:
                values['algorithm'] = HashingAlgorithm.from_value(algorithm)
            except Exception:
                raise Exception(f'Unsupported hashing algorithm: {algorithm}')

        if values.get('id', None) is None:
            int_hash = abs(mmh3.hash(hashed_val))
            first_3 = str(int_hash)[:3]
            last_2 = str(int_hash)[-2:]
            values['id'] = f'S{first_3}{last_2}'

        return values

    def matches_hash(self, hashed_value: str, algorithm: HashingAlgorithm) -> bool:
        """
        Compare a digest with this rule.

        The algorithm check is deliberate: a hash produced for one algorithm
        must never be compared with a rule belonging to another algorithm.
        """
        algorithm = HashingAlgorithm.from_value(algorithm)
        if algorithm != self.algorithm:
            return False

        return hashed_value.casefold() == self.hashed_val.casefold()

    @property
    def hash_value(self) -> str:
        """Alias used by evidence consumers."""
        return self.hashed_val

    @property
    def hashed_value(self) -> str:
        """Alias used by evidence consumers."""
        return self.hashed_val

    @property
    def algorithm_value(self) -> str:
        """String form of the rule algorithm."""
        return self.algorithm.value
