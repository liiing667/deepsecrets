"""Hashed-secret algorithm migration and generation consistency."""

import gzip
import io
import json
import tarfile
from hashlib import sha256
from pathlib import Path
from typing import Dict, Iterable, List

import pytest

from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import FindingMerger
from deepsecrets.core.model.rules.hashed_secret import HashedSecretRule
from deepsecrets.core.model.rules.hashing import HashingAlgorithm
from deepsecrets.core.model.token import Token
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.utils.hashing import get_hash
from deepsecrets.scan_modes.cli import CliScanMode


SECRET = 'MigrationSecret123'
FINGERPRINT = sha256(SECRET.encode('utf-8')).hexdigest()[23:33]


def _token(content: str = SECRET) -> Token:
    file = File(path='/tmp/migration-test.py', content=content)
    return Token(file=file, content=content, span=[0, len(content)])


def _rule(algorithm: HashingAlgorithm, name: str) -> HashedSecretRule:
    return HashedSecretRule(
        id=None,  # type: ignore[arg-type]
        name=name,
        hashed_val=get_hash(SECRET, algorithm),
        algorithm=algorithm,
        token_length=len(SECRET),
    )


def _write_rules(path: Path, entries: Iterable[Dict]) -> Path:
    path.write_text(json.dumps(list(entries)))
    return path


def _write_tar_rules(path: Path, entries: Iterable[Dict], member_name: str = 'secrets') -> Path:
    data = json.dumps(list(entries)).encode('utf-8')
    with tarfile.open(path, 'w:gz') as tar:
        info = tarfile.TarInfo(member_name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return path


def _scan(builder: HashedSecretsRulesetBuilder, content: str = SECRET):
    engine = HashedSecretEngine(builder.rules)
    token = _token(content)
    return engine, token, engine.search(token)


def test_token_hashes_are_cached_per_algorithm():
    token = _token()

    for algorithm in HashingAlgorithm:
        assert token.calculate_hashed_value(algorithm) == get_hash(SECRET, algorithm)
        assert token.hashed_values[algorithm] == get_hash(SECRET, algorithm)

    assert set(token.hashed_values) == set(HashingAlgorithm)
    # The legacy single-algorithm attribute keeps pointing at the latest
    # requested digest without ever reusing another algorithm's value.
    assert token.hashed_value == get_hash(SECRET, HashingAlgorithm.SHA_512)


def test_mixed_algorithms_merge_without_losing_rules_or_fingerprint(tmp_path: Path):
    rules_file = _write_rules(
        tmp_path / 'mixed.json',
        [
            {'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'},
            {'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'},
            {'name': 'legacy', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_512), 'length': len(SECRET), 'algorithm': 'sha512'},
        ],
    )
    builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(rules_file))
    engine, token, findings = _scan(builder)

    assert len(findings) == 3
    assert {finding.rules[0].algorithm for finding in findings} == {
        HashingAlgorithm.SHA_1,
        HashingAlgorithm.SHA_256,
        HashingAlgorithm.SHA_512,
    }
    assert token.hash_generation == builder.generation == engine.generation
    for finding in findings:
        rule = finding.rules[0]
        assert finding.algorithm == rule.algorithm
        assert finding.hashed_value == get_hash(SECRET, rule.algorithm)
        assert set(finding.hashed_values) == set(HashingAlgorithm)
        assert finding.rule_generation == builder.generation
        assert finding.get_fingerprint() == FINGERPRINT

    merged = FindingMerger(findings).merge()
    assert len(merged) == 1
    assert {rule.algorithm for rule in merged[0].rules} == {
        HashingAlgorithm.SHA_1,
        HashingAlgorithm.SHA_256,
        HashingAlgorithm.SHA_512,
    }
    assert set(merged[0].hashed_values) == set(HashingAlgorithm)
    assert merged[0].get_fingerprint() == FINGERPRINT
    assert merged[0].generation == builder.generation

    # Rotating the rule algorithm must not change the fingerprint of the
    # detected secret. Existing baselines/suppressions therefore survive.
    old_only = HashedSecretsRulesetBuilder()
    old_only.rules = [_rule(HashingAlgorithm.SHA_1, 'old')]
    new_only = HashedSecretsRulesetBuilder()
    new_only.rules = [_rule(HashingAlgorithm.SHA_256, 'new')]
    assert _scan(old_only)[2][0].get_fingerprint() == FINGERPRINT
    assert _scan(new_only)[2][0].get_fingerprint() == FINGERPRINT


def test_rule_files_share_one_migration_generation(tmp_path: Path):
    old_file = _write_rules(
        tmp_path / 'old.json',
        [{'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'}],
    )
    new_file = _write_rules(
        tmp_path / 'new.json',
        [{'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'}],
    )

    builder = HashedSecretsRulesetBuilder()
    builder.with_rules_from_file(str(old_file))
    builder.with_rules_from_file(str(new_file))

    engine, token, findings = _scan(builder)
    assert len(builder.rules) == 2
    assert builder.algorithms == {HashingAlgorithm.SHA_1, HashingAlgorithm.SHA_256}
    assert engine.algorithms == builder.algorithms
    assert engine.generation == builder.generation
    assert token.hash_generation == builder.generation
    assert len(findings) == 2
    assert set(builder.sources) == {str(old_file), str(new_file)}

    reversed_builder = HashedSecretsRulesetBuilder()
    reversed_builder.with_rules_from_file(str(new_file))
    reversed_builder.with_rules_from_file(str(old_file))
    assert reversed_builder.algorithms == builder.algorithms
    assert reversed_builder.generation == builder.generation


def test_failed_migration_keeps_the_previous_complete_generation(tmp_path: Path):
    old_file = _write_rules(
        tmp_path / 'stable.json',
        [{'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'}],
    )
    builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(old_file))
    stable_generation = builder.generation
    stable_algorithms = set(builder.algorithms)
    stable_rules = list(builder.rules)

    unknown_algorithm = _write_rules(
        tmp_path / 'unknown.json',
        [{'name': 'bad', 'hash': 'deadbeef', 'length': len(SECRET), 'algorithm': 'md5'}],
    )
    with pytest.raises(Exception):
        builder.with_rules_from_file(str(unknown_algorithm))

    empty_file = tmp_path / 'empty.json'
    empty_file.write_text('[]')
    with pytest.raises(ValueError):
        builder.with_rules_from_file(str(empty_file))

    corrupt_archive = tmp_path / 'corrupt.tar.gz'
    corrupt_archive.write_bytes(b'not a tar archive')
    with pytest.raises(Exception):
        builder.with_rules_from_file(str(corrupt_archive), compressed=True)

    with pytest.raises(Exception):
        builder.with_rules_from_files([str(old_file), str(unknown_algorithm)])

    assert builder.rules == stable_rules
    assert builder.algorithms == stable_algorithms
    assert builder.generation == stable_generation

    # A restart may publish the complete new rule source. It must not retain
    # the old SHA-1 rule as a hidden part of the new generation.
    new_file = _write_rules(
        tmp_path / 'new.json',
        [{'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'}],
    )
    restarted = HashedSecretsRulesetBuilder().with_rules_from_file(str(new_file))
    assert restarted.algorithms == {HashingAlgorithm.SHA_256}
    assert restarted.generation != stable_generation


def test_reloading_a_rotated_rule_file_replaces_its_previous_generation(tmp_path: Path):
    rules_file = _write_rules(
        tmp_path / 'rotating.json',
        [{'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'}],
    )
    builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(rules_file))
    old_generation = builder.generation
    assert builder.algorithms == {HashingAlgorithm.SHA_1}

    _write_rules(
        rules_file,
        [{'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'}],
    )
    builder.with_rules_from_file(str(rules_file))

    assert len(builder.rules) == 1
    assert builder.algorithms == {HashingAlgorithm.SHA_256}
    assert builder.generation != old_generation
    findings = _scan(builder)[2]
    assert len(findings) == 1
    assert findings[0].rules[0].algorithm == HashingAlgorithm.SHA_256
    assert findings[0].get_fingerprint() == FINGERPRINT

    # A failed replacement of the same source path keeps the complete prior
    # content of that path, not a half-written candidate.
    stable_generation = builder.generation
    rules_file.write_text('[{"name": "broken", "hash": "deadbeef"')
    with pytest.raises(Exception):
        builder.with_rules_from_file(str(rules_file))
    assert builder.algorithms == {HashingAlgorithm.SHA_256}
    assert builder.generation == stable_generation


def test_whole_source_rotation_drops_removed_rule_files(tmp_path: Path):
    old_file = _write_rules(
        tmp_path / 'old.json',
        [{'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'}],
    )
    new_file = _write_rules(
        tmp_path / 'new.json',
        [{'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'}],
    )
    replacement = _write_rules(
        tmp_path / 'replacement.json',
        [{'name': 'legacy', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_512), 'length': len(SECRET), 'algorithm': 'sha512'}],
    )

    builder = HashedSecretsRulesetBuilder()
    builder.with_rules_from_files([str(old_file), str(new_file)])
    assert builder.algorithms == {HashingAlgorithm.SHA_1, HashingAlgorithm.SHA_256}

    builder.with_rules_from_files([str(replacement)])
    assert builder.algorithms == {HashingAlgorithm.SHA_512}
    assert builder.sources == [str(replacement)]
    assert _scan(builder)[2][0].get_fingerprint() == FINGERPRINT


def test_legacy_rule_file_defaults_to_sha512(tmp_path: Path):
    legacy_file = _write_rules(
        tmp_path / 'legacy.json',
        [{'name': 'legacy', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_512), 'length': len(SECRET)}],
    )
    builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(legacy_file))
    assert builder.algorithms == {HashingAlgorithm.SHA_512}
    assert _scan(builder)[2][0].rules[0].algorithm == HashingAlgorithm.SHA_512


def test_compressed_rules_support_all_algorithms_and_aliases(tmp_path: Path):
    archive = _write_tar_rules(
        tmp_path / 'rules.tar.gz',
        [
            {'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'SHA-1'},
            {'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha_256'},
            {'name': 'legacy', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_512), 'length': len(SECRET), 'algorithm': 'SHA512'},
        ],
    )
    builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(archive), compressed=True)
    assert builder.algorithms == {
        HashingAlgorithm.SHA_1,
        HashingAlgorithm.SHA_256,
        HashingAlgorithm.SHA_512,
    }
    assert len(_scan(builder)[2]) == 3

    # Compressed sources are also detected by extension and may use any
    # member name, which keeps existing tar producers compatible.
    archive2 = _write_tar_rules(
        tmp_path / 'rules2.tar.gz',
        [{'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'}],
        member_name='rules.json',
    )
    assert HashedSecretsRulesetBuilder().with_rules_from_file(str(archive2)).algorithms == {
        HashingAlgorithm.SHA_256
    }

    gzip_file = tmp_path / 'rules.json.gz'
    with gzip.open(gzip_file, 'wt', encoding='utf-8') as f:
        json.dump(
            [{'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'}],
            f,
        )
    assert HashedSecretsRulesetBuilder().with_rules_from_file(str(gzip_file)).algorithms == {
        HashingAlgorithm.SHA_1
    }


def test_conflicting_hash_metadata_fails_closed(tmp_path: Path):
    rules_file = _write_rules(
        tmp_path / 'conflict.json',
        [
            {'name': 'one', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'},
            {'name': 'two', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET) + 1, 'algorithm': 'sha1'},
        ],
    )
    builder = HashedSecretsRulesetBuilder()
    with pytest.raises(ValueError):
        builder.with_rules_from_file(str(rules_file))
    assert builder.rules == []


def test_engine_keeps_its_rule_snapshot_when_builder_rotates(tmp_path: Path):
    old_file = _write_rules(
        tmp_path / 'old.json',
        [{'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'}],
    )
    new_file = _write_rules(
        tmp_path / 'new.json',
        [{'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'}],
    )
    builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(old_file))
    old_engine = HashedSecretEngine(builder.rules)
    old_generation = old_engine.generation

    builder.with_rules_from_file(str(new_file))
    new_engine = HashedSecretEngine(builder.rules)

    assert old_engine.algorithms == {HashingAlgorithm.SHA_1}
    assert new_engine.algorithms == {HashingAlgorithm.SHA_1, HashingAlgorithm.SHA_256}
    assert old_engine.generation == old_generation


def test_token_hash_cache_is_scoped_to_one_rule_generation(tmp_path: Path):
    old_file = _write_rules(
        tmp_path / 'old.json',
        [{'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'}],
    )
    new_file = _write_rules(
        tmp_path / 'new.json',
        [{'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'}],
    )
    old_builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(old_file))
    new_builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(new_file))
    old_engine = HashedSecretEngine(old_builder.rules)
    new_engine = HashedSecretEngine(new_builder.rules)

    token = _token()
    old_findings = old_engine.search(token)
    assert old_findings[0].get_fingerprint() == FINGERPRINT
    assert set(token.hashed_values) == {HashingAlgorithm.SHA_1}
    assert token.hash_generation == old_engine.generation

    new_findings = new_engine.search(token)
    assert new_findings[0].get_fingerprint() == FINGERPRINT
    assert set(token.hashed_values) == {HashingAlgorithm.SHA_256}
    assert token.hash_generation == new_engine.generation
    assert new_engine.generation != old_engine.generation

    # Findings from two complete generations must not be silently merged (or
    # dropped by the merger) even though they describe the same secret text.
    cross_generation = FindingMerger(old_findings + new_findings).merge()
    assert len(cross_generation) == 2
    assert {finding.rule_generation for finding in cross_generation} == {
        old_engine.generation,
        new_engine.generation,
    }
    assert {finding.get_fingerprint() for finding in cross_generation} == {FINGERPRINT}


def test_cli_hashed_scan_uses_the_same_rule_generation(tmp_path: Path):
    rules_file = _write_rules(
        tmp_path / 'cli.json',
        [
            {'name': 'old', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_1), 'length': len(SECRET), 'algorithm': 'sha1'},
            {'name': 'new', 'hash': get_hash(SECRET, HashingAlgorithm.SHA_256), 'length': len(SECRET), 'algorithm': 'sha256'},
        ],
    )
    tool = DeepSecretsCliTool(
        [
            '',
            '--target-dir',
            str(tmp_path),
            '--hashed-values',
            str(rules_file),
            '--regex-rules',
            'disable',
            '--semantic-analysis',
            'disable',
            '--outfile',
            str(tmp_path / 'out.json'),
        ]
    )
    tool.parse_arguments()

    assert tool.config.engines == [HashedSecretEngine]
    assert list(tool.config.rulesets) == [HashedSecretsRulesetBuilder]

    direct_builder = HashedSecretsRulesetBuilder().with_rules_from_file(str(rules_file))
    mode = CliScanMode(config=tool.config)
    meta = mode.ruleset_meta[HashedSecretsRulesetBuilder.ruleset_name]
    assert meta['algorithms'] == direct_builder.algorithms == {
        HashingAlgorithm.SHA_1,
        HashingAlgorithm.SHA_256,
    }
    assert meta['generation'] == direct_builder.generation
    assert mode.engines_enabled[HashedSecretEngine.name] is True

    # A failed refresh must keep the previous complete CLI generation rather
    # than publishing an empty/partial rule set to workers.
    previous_rulesets = mode.rulesets
    previous_meta = mode.ruleset_meta
    broken_rules = tmp_path / 'broken.json'
    broken_rules.write_text('{"rules": [')
    tool.config.add_ruleset(HashedSecretsRulesetBuilder, [str(broken_rules)])
    with pytest.raises(Exception):
        mode.prepare_for_scan()
    assert mode.rulesets == previous_rulesets
    assert mode.ruleset_meta == previous_meta
