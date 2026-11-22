import json
import os
from hashlib import sha256
from multiprocessing import get_context
from pathlib import Path
from typing import Any, List

import pytest

from deepsecrets.config import Config, Output
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding, FindingResponse
from deepsecrets.core.modes import iscan_mode
from deepsecrets.core.modes.iscan_mode import ScanMode
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.utils.file_analyzer import FileAnalyzer

RULES = [
    {
        'id': 'T0',
        'name': 'Test secret',
        'confidence': 9,
        'pattern': 'SECRET=[a-z0-9]+',
    }
]


class InlinePool:
    """Synchronous stand-in for multiprocessing.pool.Pool."""

    def __init__(self, processes: int = 0):
        self.processes = processes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def imap_unordered(self, func, iterable):
        for item in iterable:
            yield func(item)

    def map(self, func, iterable):
        return [func(item) for item in iterable]


class RegexOnlyScanMode(ScanMode):
    """ScanMode with the regex engine only, to keep the tests lightweight."""

    def prepare_for_scan(self) -> None:
        self.engines_enabled = {}
        self.rulesets = {}

        builder = RegexRulesetBuilder()
        for path in self.config.rulesets.get(RegexRulesetBuilder, []):
            builder.with_rules_from_file(path)

        self.rulesets[builder.ruleset_name] = builder.rules
        self.engines_enabled[RegexEngine.name] = True

    def analyzer_bundle(self):
        bundle = super().analyzer_bundle()
        bundle.update(
            workdir=self.config.workdir_path,
            engines=self.engines_enabled,
            rulesets=self.rulesets,
        )
        return bundle

    @staticmethod
    def _per_file_analyzer(bundle, file: Any) -> List[Finding]:
        results: List[Finding] = []

        file = File(path=file, relative_path=file.replace(f'{bundle.workdir}/', ''))
        if file.length == 0:
            return results

        file_analyzer = FileAnalyzer(file)
        regex_engine = RegexEngine(ruleset=bundle.rulesets.get(RegexRulesetBuilder.ruleset_name, []))
        file_analyzer.add_engine(regex_engine, [FullContentTokenizer()])
        return file_analyzer.process(threaded=False)


def _failing_analyzer(bundle, file: Any) -> List[Finding]:
    """Module-level analyzer that fails on demand (must stay picklable)."""
    if os.path.basename(file).startswith('failme'):
        raise ValueError('cannot scan this file')
    return RegexOnlyScanMode._per_file_analyzer(bundle, file)


def write_secret_file(path: Path, secret: str) -> None:
    path.write_text(f'line one\nSECRET={secret}\nline three\n')


def fingerprint_of(secret: str) -> str:
    return sha256(f'SECRET={secret}'.encode('utf-8')).hexdigest()[23:33]


def build_config(workdir: Path, rules: Path, outfile: Path, state_path=None, process_count: int = 2) -> Config:
    config = Config()
    config.set_workdir(str(workdir))
    config.engines.append(RegexEngine)
    config.add_ruleset(RegexRulesetBuilder, [str(rules)])
    config.output = Output(type='json', path=str(outfile))
    config.set_process_count(process_count)
    if state_path is not None:
        config.resume_state_path = str(state_path)
    return config


def findings_by_file(findings: List[Finding]):
    by_file = {}
    for finding in findings:
        by_file.setdefault(os.path.basename(finding.file.path), []).append(finding)
    return by_file


def test_cancel_then_retry_with_added_files_each_file_once(tmp_path, monkeypatch):
    workdir = tmp_path / 'work'
    workdir.mkdir()
    secrets = {'a.txt': 'aaa111', 'b.txt': 'bbb222', 'c.txt': 'ccc333'}
    for name, secret in secrets.items():
        write_secret_file(workdir / name, secret)

    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))
    state_path = tmp_path / 'state.json'
    config = build_config(workdir, rules, tmp_path / 'report.json', state_path)

    # run 1: cancelled by the user after the first file
    original = RegexOnlyScanMode._per_file_analyzer
    scanned_run1 = []

    def cancelling_analyzer(bundle, file):
        if len(scanned_run1) >= 1:
            raise KeyboardInterrupt()
        scanned_run1.append(os.path.basename(file))
        return original(bundle, file)

    mode = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    mode._per_file_analyzer = cancelling_analyzer
    with pytest.raises(KeyboardInterrupt):
        mode.run()

    assert len(scanned_run1) == 1
    cancelled_generation = mode.scan_session.generation_id
    assert mode.scan_session.completed is False

    persisted = json.loads(state_path.read_text())
    assert persisted['completed'] is False
    assert persisted['generation_id'] == cancelled_generation
    done = [rel for rel in persisted['manifest'] if persisted['files'][rel]['status'] == 'done']
    assert done == scanned_run1

    # a new file appears before the retry
    write_secret_file(workdir / 'd.txt', 'ddd444')
    secrets['d.txt'] = 'ddd444'

    # run 2: resumes the same generation, scans only what is missing
    scanned_run2 = []

    def counting_analyzer(bundle, file):
        scanned_run2.append(os.path.basename(file))
        return original(bundle, file)

    retry = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    retry._per_file_analyzer = counting_analyzer
    findings = retry.run()

    assert retry.scan_session.resumed is True
    assert retry.scan_session.generation_id == cancelled_generation
    assert retry.scan_session.completed is True
    assert retry.scan_session.failed_files == []

    # the already-scanned file is reused, not scanned again
    assert sorted(scanned_run2) == sorted(set(secrets) - set(scanned_run1))

    # every file appears exactly once in the response, with its fingerprint intact
    by_file = findings_by_file(findings)
    assert set(by_file) == set(secrets)
    for name, file_findings in by_file.items():
        assert len(file_findings) == 1
        assert file_findings[0].detection == f'SECRET={secrets[name]}'
        assert file_findings[0].get_fingerprint() == fingerprint_of(secrets[name])

    response = FindingResponse.from_list(findings)
    assert len(response) == len(secrets)

    # the persisted generation matches the final response
    persisted = json.loads(state_path.read_text())
    assert persisted['completed'] is True
    assert persisted['failed_files'] == []
    assert sorted(persisted['manifest']) == sorted(secrets)

    # a from-scratch run sees exactly the same findings
    state_path.unlink()
    reference = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    reference_findings = reference.run()
    assert sorted(f.get_fingerprint() for f in reference_findings) == sorted(
        f.get_fingerprint() for f in findings
    )


def test_failure_list_matches_final_state_with_real_pool(tmp_path):
    workdir = tmp_path / 'work'
    workdir.mkdir()
    write_secret_file(workdir / 'ok1.txt', 'ok1111')
    write_secret_file(workdir / 'failme.txt', 'will00')
    write_secret_file(workdir / 'ok2.txt', 'ok2222')

    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))
    state_path = tmp_path / 'state.json'
    config = build_config(workdir, rules, tmp_path / 'report.json', state_path)

    # run 1: one file fails inside a real worker process; the scan completes
    mode = RegexOnlyScanMode(config=config, pool_engine=get_context('fork').Pool)
    mode._per_file_analyzer = _failing_analyzer
    findings = mode.run()

    assert mode.scan_session.failed_files == ['failme.txt']
    assert findings_by_file(findings).keys() == {'ok1.txt', 'ok2.txt'}

    persisted = json.loads(state_path.read_text())
    assert persisted['completed'] is True
    assert persisted['failed_files'] == ['failme.txt']

    # run 2: the failed file is retried and now succeeds
    retry = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    findings = retry.run()

    assert retry.scan_session.failed_files == []
    by_file = findings_by_file(findings)
    assert set(by_file) == {'ok1.txt', 'ok2.txt', 'failme.txt'}
    assert by_file['failme.txt'][0].get_fingerprint() == fingerprint_of('will00')

    persisted = json.loads(state_path.read_text())
    assert persisted['failed_files'] == []


def test_modified_file_is_rescanned_and_old_findings_are_gone(tmp_path):
    workdir = tmp_path / 'work'
    workdir.mkdir()
    write_secret_file(workdir / 'a.txt', 'aaa111')
    write_secret_file(workdir / 'b.txt', 'bbb222')

    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))
    state_path = tmp_path / 'state.json'
    config = build_config(workdir, rules, tmp_path / 'report.json', state_path)

    first = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    first_findings = first.run()
    assert {f.get_fingerprint() for f in first_findings} == {
        fingerprint_of('aaa111'),
        fingerprint_of('bbb222'),
    }

    write_secret_file(workdir / 'b.txt', 'bbb999')

    second = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    second_findings = second.run()

    assert {f.get_fingerprint() for f in second_findings} == {
        fingerprint_of('aaa111'),
        fingerprint_of('bbb999'),
    }


def test_serial_mode_matches_pool_mode(tmp_path, monkeypatch):
    workdir = tmp_path / 'work'
    workdir.mkdir()
    write_secret_file(workdir / 'a.txt', 'aaa111')
    write_secret_file(workdir / 'b.txt', 'bbb222')

    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))

    pool_config = build_config(workdir, rules, tmp_path / 'pool-report.json', tmp_path / 'pool-state.json')
    pool_findings = RegexOnlyScanMode(config=pool_config, pool_engine=InlinePool).run()

    monkeypatch.setattr(iscan_mode, 'PROFILER_ON', True)
    serial_config = build_config(workdir, rules, tmp_path / 'serial-report.json', tmp_path / 'serial-state.json')
    serial_findings = RegexOnlyScanMode(config=serial_config, pool_engine=InlinePool).run()

    assert sorted(f.get_fingerprint() for f in serial_findings) == sorted(
        f.get_fingerprint() for f in pool_findings
    )


def test_process_count_semantics_are_kept(tmp_path):
    workdir = tmp_path / 'work'
    workdir.mkdir()
    for i in range(3):
        write_secret_file(workdir / f'f{i}.txt', f'sec{i}00')

    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))

    config = build_config(workdir, rules, tmp_path / 'report.json', tmp_path / 'state.json', process_count=2)
    mode = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    assert mode._get_process_count_for_runner() == 2

    config = build_config(workdir, rules, tmp_path / 'report.json', tmp_path / 'state.json', process_count=99)
    mode = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    assert mode._get_process_count_for_runner() == 3

    empty = tmp_path / 'empty'
    empty.mkdir()
    config = build_config(empty, rules, tmp_path / 'report.json', tmp_path / 'state.json')
    mode = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    assert mode._get_process_count_for_runner() == 0
    assert mode.run() == []


def test_excluded_paths_are_kept_out_of_the_generation(tmp_path):
    workdir = tmp_path / 'work'
    workdir.mkdir()
    write_secret_file(workdir / 'ok.txt', 'ok1111')
    write_secret_file(workdir / 'skipme.txt', 'skip00')

    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))
    exclusions = tmp_path / 'excluded.json'
    exclusions.write_text(json.dumps([{'name': 'skip', 'pattern': 'skipme'}]))

    state_path = tmp_path / 'state.json'
    config = build_config(workdir, rules, tmp_path / 'report.json', state_path)
    config.set_global_exclusion_paths([str(exclusions)])

    mode = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    assert [os.path.basename(path) for path in mode.filepaths] == ['ok.txt']

    findings = mode.run()
    assert {os.path.basename(f.file.path) for f in findings} == {'ok.txt'}

    persisted = json.loads(state_path.read_text())
    assert persisted['manifest'] == ['ok.txt']


def test_resume_can_be_disabled(tmp_path):
    workdir = tmp_path / 'work'
    workdir.mkdir()
    write_secret_file(workdir / 'a.txt', 'aaa111')

    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))
    state_path = tmp_path / 'state.json'
    config = build_config(workdir, rules, tmp_path / 'report.json', state_path)
    config.resume_enabled = False

    mode = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    findings = mode.run()

    assert mode.scan_session is None
    assert not state_path.exists()
    assert {f.get_fingerprint() for f in findings} == {fingerprint_of('aaa111')}


def test_state_file_next_to_report_inside_workdir_is_not_scanned(tmp_path):
    workdir = tmp_path / 'work'
    workdir.mkdir()
    write_secret_file(workdir / 'a.txt', 'aaa111')

    rules = tmp_path / 'rules.json'
    rules.write_text(json.dumps(RULES))

    # no explicit state path: the state lives next to the report, inside the workdir
    config = build_config(workdir, rules, workdir / 'report.json')

    mode = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    assert [os.path.basename(path) for path in mode.filepaths] == ['a.txt']
    mode.run()

    assert (workdir / 'report.json.dsresume').exists()

    # the persisted state file does not become a scan target on the next run
    followup = RegexOnlyScanMode(config=config, pool_engine=InlinePool)
    assert [os.path.basename(path) for path in followup.filepaths] == ['a.txt']
