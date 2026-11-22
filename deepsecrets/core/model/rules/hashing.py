from enum import Enum
from typing import Union


class HashingAlgorithm(str, Enum):
    SHA_1 = 'sha1'
    SHA_256 = 'sha256'
    SHA_512 = 'sha512'

    @classmethod
    def _missing_(cls, value: object) -> 'HashingAlgorithm':
        try:
            return cls.from_value(value)  # type: ignore[arg-type]
        except ValueError:
            return None  # type: ignore[return-value]

    @property
    def digest_size(self) -> int:
        """Size of the raw digest in bytes."""
        return {
            HashingAlgorithm.SHA_1: 20,
            HashingAlgorithm.SHA_256: 32,
            HashingAlgorithm.SHA_512: 64,
        }[self]

    @property
    def hex_length(self) -> int:
        """Length of the hexadecimal representation of the digest."""
        return self.digest_size * 2

    @classmethod
    def from_value(cls, value: Union['HashingAlgorithm', str]) -> 'HashingAlgorithm':
        """
        Normalize an algorithm name.

        Rule files in the wild contain values such as ``sha1``, ``SHA-256``
        and ``SHA_256``.  They all identify the same algorithm and therefore
        must be treated as one migration generation instead of as separate
        (and possibly mixed) hashing states.
        """
        if isinstance(value, cls):
            return value

        if not isinstance(value, str):
            raise ValueError(f'Unsupported hashing algorithm: {value!r}')

        normalized = (
            value.strip()
            .lower()
            .replace('-', '')
            .replace('_', '')
            .replace(' ', '')
        )
        aliases = {
            'sha1': cls.SHA_1,
            'sha256': cls.SHA_256,
            'sha512': cls.SHA_512,
        }
        algorithm = aliases.get(normalized)
        if algorithm is None:
            raise ValueError(f'Unsupported hashing algorithm: {value}')

        return algorithm
