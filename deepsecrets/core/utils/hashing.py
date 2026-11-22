import json
from hashlib import sha1, sha256, sha512
from typing import Any, Dict, Iterable, List, Union

from deepsecrets.core.model.rules.hashing import HashingAlgorithm


def c_sha1(payload: str) -> str:
    return sha1(payload.encode('UTF-8')).hexdigest()


def c_sha256(payload: str) -> str:
    return sha256(payload.encode('UTF-8')).hexdigest()


def c_sha512(payload: str) -> str:
    return sha512(payload.encode('UTF-8')).hexdigest()


algorithm_to_method = {
    HashingAlgorithm.SHA_512: c_sha512,
    HashingAlgorithm.SHA_256: c_sha256,
    HashingAlgorithm.SHA_1: c_sha1
}


def get_hash(payload: str, algorithm: Union[HashingAlgorithm, str]) -> str:
    try:
        algorithm = HashingAlgorithm.from_value(algorithm)
    except ValueError:
        raise Exception(f'Unable to calculate hash for algorithm {algorithm}')

    method = algorithm_to_method.get(algorithm)
    if method is None:
        raise Exception(f'Unable to calculate hash for algorithm {algorithm.name}')

    return method(payload)


def get_hashes(payload: str, algorithms: Iterable[HashingAlgorithm]) -> Dict[HashingAlgorithm, str]:
    """
    Calculate one digest per algorithm.

    Keeping the results separate is what prevents a token hash calculated for
    an old (e.g. SHA-1) rule from being reused by a new SHA-256 rule.
    """
    return {algorithm: get_hash(payload, algorithm) for algorithm in algorithms}


def ruleset_generation(rules: Iterable[Any]) -> str:
    """
    Return a stable identity for one complete hashed-rule generation.

    The identity covers the rule algorithm set and every rule that takes part
    in the scan.  It deliberately uses a canonical, sorted representation so
    that loading the same rule files in a different order cannot make two
    workers believe they own different generations.
    """
    canonical: List[Dict[str, Any]] = []
    for rule in rules:
        algorithm = getattr(rule, 'algorithm', None)
        canonical.append(
            {
                'algorithm': getattr(algorithm, 'value', str(algorithm) if algorithm is not None else ''),
                'hash': str(getattr(rule, 'hashed_val', '')).casefold(),
                'length': int(getattr(rule, 'token_length', 0) or 0),
                'id': str(getattr(rule, 'id', '') or ''),
                'name': str(getattr(rule, 'name', '') or ''),
            }
        )

    canonical.sort(
        key=lambda item: (
            item['algorithm'],
            item['hash'],
            item['length'],
            item['id'],
            item['name'],
        )
    )
    encoded = json.dumps(canonical, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return sha256(encoded.encode('utf-8')).hexdigest()
