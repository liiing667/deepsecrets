import json
import pickle

import pytest

from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.config import Config, Output
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.rules.hashed_secret import HashedSecretRule
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.scan_modes.cli import CliScanMode

SECRET_VALUE = '$ecRetT0F1nD'


def make_config(workdir: str, engines=(), rulesets=None) -> Config:
    config = Config()
    config.set_workdir(workdir)
    for engine in engines:
        config.engines.append(engine)
    for builder, paths in (rulesets or {}).items():
        config.add_ruleset(builder, paths)
    config.output = Output(type='json', path='report.json')
    return config


@pytest.fixture()
def secret_workdir(tmp_path):
    workdir = tmp_path / 'scan_target'
    workdir.mkdir()
    (workdir / 'config.py').write_text(f"password = '{SECRET_VALUE}'\n")
    return str(workdir)


@pytest.fixture()
def regex_and_hashed_rulesets():
    return {
        RegexRulesetBuilder: ['tests/fixtures/regexes.json'],
        HashedSecretsRulesetBuilder: ['tests/fixtures/hashed_secrets.json'],
    }


def test_per_file_analyzer_uses_bundled_generation(secret_workdir, regex_and_hashed_rulesets):
    config = make_config(
        secret_workdir,
        engines=[RegexEngine, HashedSecretEngine],
        rulesets=regex_and_hashed_rulesets,
    )
    mode = CliScanMode(config=config)

    findings = []
    bundle = mode.analyzer_bundle()
    for filepath in mode.filepaths:
        findings.extend(mode._per_file_analyzer(bundle, filepath))

    hashed_findings = [
        finding
        for finding in findings
        if any(isinstance(rule, HashedSecretRule) for rule in finding.rules)
    ]
    assert len(hashed_findings) == 1
    assert hashed_findings[0].detection == SECRET_VALUE


def test_workers_share_single_generation_via_run(secret_workdir, regex_and_hashed_rulesets):
    config = make_config(
        secret_workdir,
        engines=[RegexEngine, HashedSecretEngine],
        rulesets=regex_and_hashed_rulesets,
    )
    mode = CliScanMode(config=config)

    findings = mode.run()

    hashed_findings = [
        finding
        for finding in findings
        if any(isinstance(rule, HashedSecretRule) for rule in finding.rules)
    ]
    assert len(hashed_findings) == 1
    assert hashed_findings[0].detection == SECRET_VALUE


def test_engine_tokenizers_built_once_per_scan(secret_workdir, regex_and_hashed_rulesets):
    config = make_config(
        secret_workdir,
        engines=[RegexEngine, HashedSecretEngine, SemanticEngine],
        rulesets=regex_and_hashed_rulesets,
    )
    mode = CliScanMode(config=config)

    first_bundle = mode.analyzer_bundle()
    second_bundle = mode.analyzer_bundle()

    # the very same generation of combinations is handed to every worker
    assert first_bundle.engine_tokenizers is second_bundle.engine_tokenizers
    assert first_bundle.engine_tokenizers is mode.engine_tokenizers

    engines = [combination.engine for combination in mode.engine_tokenizers]
    tokenizers = [combination.tokenizer for combination in mode.engine_tokenizers]
    assert any(isinstance(engine, RegexEngine) for engine in engines)
    assert any(isinstance(engine, HashedSecretEngine) for engine in engines)
    assert any(isinstance(engine, SemanticEngine) for engine in engines)
    assert any(isinstance(tokenizer, FullContentTokenizer) for tokenizer in tokenizers)
    assert any(isinstance(tokenizer, LexerTokenizer) for tokenizer in tokenizers)

    hashed_combo = next(
        combination
        for combination in mode.engine_tokenizers
        if isinstance(combination.engine, HashedSecretEngine)
    )
    assert len(hashed_combo.engine.ruleset) == 2


def test_engine_tokenizer_combinations_survive_pickling(secret_workdir, regex_and_hashed_rulesets):
    config = make_config(
        secret_workdir,
        engines=[RegexEngine, HashedSecretEngine],
        rulesets=regex_and_hashed_rulesets,
    )
    mode = CliScanMode(config=config)

    restored_bundle = pickle.loads(pickle.dumps(mode.analyzer_bundle()))

    restored_combinations = restored_bundle.engine_tokenizers
    assert len(restored_combinations) == len(mode.engine_tokenizers)

    hashed_combo = next(
        combination
        for combination in restored_combinations
        if isinstance(combination.engine, HashedSecretEngine)
    )
    assert len(hashed_combo.engine.ruleset) == 2
    assert hashed_combo.tokenizer.settings.deep_token_inspection is True

    regex_combo = next(
        combination
        for combination in restored_combinations
        if isinstance(combination.engine, RegexEngine)
    )
    assert {rule.id for rule in regex_combo.engine.ruleset} == {'S0', 'S1'}


def test_scans_do_not_leak_generations_into_each_other(tmp_path):
    first_workdir = tmp_path / 'first'
    first_workdir.mkdir()
    (first_workdir / 'a.py').write_text('a = 1\n')

    second_workdir = tmp_path / 'second'
    second_workdir.mkdir()
    (second_workdir / 'b.py').write_text('b = 2\n')

    custom_rules = tmp_path / 'custom_regexes.json'
    custom_rules.write_text(json.dumps([{'id': 'S100', 'name': 'Custom', 'pattern': 'custom-secret'}]))

    first_mode = CliScanMode(
        config=make_config(
            str(first_workdir),
            engines=[RegexEngine],
            rulesets={RegexRulesetBuilder: ['tests/fixtures/regexes.json']},
        )
    )
    second_mode = CliScanMode(
        config=make_config(
            str(second_workdir),
            engines=[RegexEngine],
            rulesets={RegexRulesetBuilder: [str(custom_rules)]},
        )
    )

    assert first_mode.rulesets is not second_mode.rulesets
    assert first_mode.engine_tokenizers is not second_mode.engine_tokenizers
    assert {rule.id for rule in first_mode.rulesets['regex']} == {'S0', 'S1'}
    assert {rule.id for rule in second_mode.rulesets['regex']} == {'S100'}


def test_shared_tokenizer_tokenizes_each_file_independently():
    tokenizer = LexerTokenizer(deep_token_inspection=True)
    first_file = File(path='tests/fixtures/1.py', relative_path='1.py')
    second_file = File(path='tests/fixtures/2.py', relative_path='2.py')

    first_tokens = tokenizer.tokenize(first_file)
    second_tokens = tokenizer.tokenize(second_file)

    assert len(first_tokens) > 0
    assert len(second_tokens) > 0
    assert all(token.file is second_file for token in second_tokens)

    # tokenizing the first file again yields exactly the same tokens
    first_tokens_again = tokenizer.tokenize(first_file)
    assert [token.content for token in first_tokens_again] == [token.content for token in first_tokens]


def test_hashed_ruleset_builder_accumulates_rules_from_multiple_files(tmp_path):
    extra_rules = tmp_path / 'extra_secrets.json'
    extra_rules.write_text(
        json.dumps([{'name': 'Extra secret', 'hash': 'deadbeef', 'length': 3, 'algorithm': 'sha1'}])
    )

    builder = HashedSecretsRulesetBuilder()
    builder.with_rules_from_file('tests/fixtures/hashed_secrets.json')
    builder.with_rules_from_file(str(extra_rules))

    assert len(builder.rules) == 3


def test_cli_enables_hashed_secret_engine_for_hashed_values():
    tool = DeepSecretsCliTool(
        args=[
            '',
            '--target-dir',
            '/app/tests/fixtures/',
            '--hashed-values',
            '/app/tests/fixtures/hashed_secrets.json',
            '--outfile',
            './fdsafad.json',
        ]
    )
    tool.parse_arguments()

    assert HashedSecretEngine in tool.config.engines
    assert RegexEngine in tool.config.engines
    assert SemanticEngine in tool.config.engines
    assert HashedSecretsRulesetBuilder in tool.config.rulesets
    assert RegexRulesetBuilder in tool.config.rulesets
