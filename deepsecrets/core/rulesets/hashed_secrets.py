import gzip
import json
import tarfile
from collections.abc import Iterable
from hashlib import sha256
from os.path import exists
from typing import Any, Dict, List, Set, Tuple

from deepsecrets.core.model.rules.hashing import HashingAlgorithm
from deepsecrets.core.model.rules.hashed_secret import HashedSecretRule
from deepsecrets.core.rulesets.ibuilder import IRulesetBuilder
from deepsecrets.core.utils.hashing import ruleset_generation


class HashedSecretsRulesetBuilder(IRulesetBuilder):
    rule_model = HashedSecretRule
    ruleset_name = 'hashed'

    def __init__(self) -> None:
        super().__init__()
        # Provenance for the complete generation currently published by this
        # builder.  A failed or interrupted file never enters these records.
        self.sources: List[str] = []
        self.file_digests: Dict[str, str] = {}
        self._rules_by_source: Dict[str, List[HashedSecretRule]] = {}

    def with_rules_from_file(self, file: str, compressed: bool = False) -> object:
        file = str(file)
        if not exists(file):
            if compressed:
                return
            raise FileNotFoundError(file)

        raw = self._read_raw(file=file, compressed=compressed)
        digest = sha256(raw).hexdigest()
        rules_raw = self._decode_rules(raw=raw, file=file)

        default_algorithm = None
        if isinstance(rules_raw, dict):
            default_algorithm = rules_raw.get('algorithm')
            rules_raw = rules_raw.get('rules', rules_raw.get('secrets', []))

        if not isinstance(rules_raw, Iterable) or isinstance(rules_raw, (str, bytes, dict)):
            raise ValueError(f'Unsupported hashed secrets rules format in {file}')
        if len(rules_raw) == 0:
            # An empty/truncated file is the most common shape of an
            # interrupted migration.  Do not publish it as a successful new
            # generation and do not let it erase the complete previous one.
            raise ValueError(f'Empty hashed secrets ruleset in {file}')

        # Build the new generation completely before mutating ``self.rules``.
        # An interrupted/failed file must not leave a half-loaded ruleset.
        new_rules: List[HashedSecretRule] = []
        seen: Set[Tuple[HashingAlgorithm, str, int]] = set()
        hash_lengths: Dict[Tuple[HashingAlgorithm, str], int] = {}
        for secret in rules_raw:
            if not isinstance(secret, dict):
                raise ValueError(f'Invalid hashed secret rule in {file}: expected an object')

            path = secret.get('path')
            if path is not None:
                path = '/'.join(path.split('/')[1:3])
                if 'non-prod' in path:
                    continue

            algorithm = secret.get('algorithm')
            if algorithm is None:
                algorithm = default_algorithm
            if algorithm is None:
                algorithm = HashingAlgorithm.SHA_512

            try:
                normalized_algorithm = HashingAlgorithm.from_value(algorithm)
            except ValueError:
                raise ValueError(f'Unsupported hashing algorithm: {algorithm}')

            hashed_val = secret.get('hash')
            token_length = secret.get('length')
            if not isinstance(hashed_val, str) or len(hashed_val.strip()) == 0:
                raise ValueError(f'Empty hashed value in {file}')
            hashed_val = hashed_val.strip()
            try:
                token_length = int(token_length)
            except (TypeError, ValueError):
                raise ValueError(f'Invalid token length for hashed value in {file}')
            if token_length <= 0:
                raise ValueError(f'Invalid token length for hashed value in {file}')

            hash_key = (normalized_algorithm, hashed_val.casefold())
            previous_length = hash_lengths.get(hash_key)
            if previous_length is not None and previous_length != token_length:
                raise ValueError(
                    f'Conflicting token lengths for hashed value in {file}: '
                    f'{previous_length} != {token_length}'
                )
            hash_lengths[hash_key] = token_length

            rule = HashedSecretRule(
                id=None,  # calculated inside the constructor  # type: ignore
                name=f'{path}:{secret["name"]}',
                hashed_val=hashed_val,
                algorithm=normalized_algorithm,
                token_length=token_length,
                confidence=9,
            )
            key = (rule.algorithm, rule.hashed_val.casefold(), rule.token_length)
            if key in seen:
                continue

            seen.add(key)
            new_rules.append(rule)

        # A digest may not claim two different token lengths, even when the
        # conflicting rules come from different files/generations.
        for existing_rule in self.rules:
            hash_key = (existing_rule.algorithm, existing_rule.hashed_val.casefold())
            previous_length = hash_lengths.get(hash_key)
            if (
                previous_length is not None
                and previous_length != existing_rule.token_length
            ):
                raise ValueError(
                    f'Conflicting token lengths for hashed value in {file}: '
                    f'{previous_length} != {existing_rule.token_length}'
                )

        # A source path is a generation slot.  Re-loading the same file (the
        # usual shape of a completed migration/rotation) replaces the rules
        # previously contributed by that file.  Different files still union,
        # which is what lets a legacy SHA-1 file and a new SHA-256 file coexist
        # during a staged migration.
        self._rules_by_source[file] = new_rules
        if file not in self.sources:
            self.sources.append(file)
        self.file_digests[file] = digest
        self._rebuild_rules()
        return self

    def with_rules_from_files(self, files: List[str], compressed: bool = False) -> object:
        """
        Load a whole rule-file list as one atomic generation.

        This is used by callers that rotate a complete rule source.  If any
        member fails, none of the candidate files are published and the
        previous complete generation remains active.
        """
        for file in files:
            file = str(file)
            if not exists(file):
                raise FileNotFoundError(file)

        candidate = HashedSecretsRulesetBuilder()
        for file in files:
            candidate.with_rules_from_file(str(file), compressed=compressed)

        # A successful whole-source load publishes exactly the candidate
        # generation; files that disappeared from the rotated source list must
        # not survive as stale rules.
        self._rules_by_source = {
            source: list(rules) for source, rules in candidate._rules_by_source.items()
        }
        self.sources = list(candidate.sources)
        self.file_digests = dict(candidate.file_digests)
        self._rebuild_rules()
        return self

    def _rebuild_rules(self) -> None:
        """Publish the exact union of the current per-source generations."""
        published: List[HashedSecretRule] = []
        seen: Set[Tuple[HashingAlgorithm, str, int]] = set()
        for source in self.sources:
            for rule in self._rules_by_source.get(source, []):
                key = (rule.algorithm, rule.hashed_val.casefold(), rule.token_length)
                if key in seen:
                    continue
                seen.add(key)
                published.append(rule)
        self.rules = published

    @staticmethod
    def _read_raw(file: str, compressed: bool = False) -> bytes:
        if compressed or HashedSecretsRulesetBuilder._looks_compressed(file):
            try:
                with tarfile.open(file, 'r:*') as tar:
                    try:
                        member = tar.extractfile('secrets')
                    except KeyError:
                        member = None
                    if member is None:
                        for tar_member in tar.getmembers():
                            if tar_member.isfile():
                                member = tar.extractfile(tar_member)
                                break

                    if member is None:
                        raise ValueError(f'No rules file found inside archive {file}')

                    return member.read()
            except tarfile.TarError:
                # Also accept a plain gzip-compressed JSON document.
                with gzip.open(file, 'rb') as sec:
                    return sec.read()

        with open(file, 'rb') as sec:
            return sec.read()

    @staticmethod
    def _decode_rules(raw: bytes, file: str) -> Any:
        try:
            return json.loads(raw.decode('utf-8-sig'))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f'Invalid hashed secrets rules file {file}: {e}')

    @staticmethod
    def _read_rules(file: str, compressed: bool = False) -> Any:
        """Compatibility wrapper for the original private helper."""
        return HashedSecretsRulesetBuilder._decode_rules(
            HashedSecretsRulesetBuilder._read_raw(file=file, compressed=compressed),
            file=file,
        )

    @staticmethod
    def _looks_compressed(file: str) -> bool:
        lower = file.lower()
        return (
            lower.endswith('.tar.gz')
            or lower.endswith('.tgz')
            or lower.endswith('.tar.bz2')
            or lower.endswith('.tbz2')
            or lower.endswith('.tar.xz')
            or lower.endswith('.txz')
            or lower.endswith('.gz')
        )

    @property
    def algorithms(self) -> Set[HashingAlgorithm]:
        return {
            rule.algorithm for rule in self.rules
            if getattr(rule, 'algorithm', None) is not None
        }

    @property
    def algorithm_set(self) -> Set[HashingAlgorithm]:
        return self.algorithms

    @property
    def generation(self) -> str:
        """
        Stable identity of the currently loaded rule generation.

        All algorithms/algorithms hashes/findings that belong to one scan use
        the same rule snapshot, so this value changes only when the rules
        change.
        """
        return ruleset_generation(self.rules)

    @property
    def version(self) -> str:
        """Alias for the rule generation identity."""
        return self.generation

    @property
    def ruleset_identity(self) -> str:
        """Alias for the rule generation identity."""
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

    @property
    def rule_files(self) -> List[str]:
        return list(self.sources)

    @property
    def source_generation(self) -> str:
        """Identity of the loaded file set (path + digest), independent of rule decoding."""
        digest = sha256()
        for source in self.sources:
            digest.update(source.encode('utf-8'))
            digest.update(b'\0')
            digest.update(self.file_digests.get(source, '').encode('utf-8'))
            digest.update(b'\n')
        return digest.hexdigest()

    def snapshot(self) -> 'HashedSecretsRulesetBuilder':
        """Return a detached builder containing the current complete generation."""
        snapshot = HashedSecretsRulesetBuilder()
        snapshot.rules = list(self.rules)
        snapshot.sources = list(self.sources)
        snapshot.file_digests = dict(self.file_digests)
        snapshot._rules_by_source = {
            source: list(rules) for source, rules in self._rules_by_source.items()
        }
        return snapshot

    def reset(self) -> None:
        """Drop the current generation before publishing a new complete one."""
        self.rules = []
        self.sources = []
        self.file_digests = {}
        self._rules_by_source = {}
