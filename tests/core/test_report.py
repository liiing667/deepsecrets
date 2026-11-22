import json
import os
from hashlib import sha256

import pytest

from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding, FindingResponse
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.report import ScanResult, write_report
from deepsecrets.core.utils.exceptions import (
    FindingSerializationException,
    ReportWriteException,
)

DETECTION = 'TESTSECRET1234'
SECOND_DETECTION = 'S3_STORAGE_SECRET_KEY'
OTHER_FILE_DETECTION = '2TESTSECRET1234'


@pytest.fixture(scope='module')
def file() -> File:
    path = 'tests/fixtures/4.go'
    return File(path=path, relative_path=path)


@pytest.fixture(scope='module')
def other_file() -> File:
    path = 'tests/fixtures/3.py'
    return File(path=path, relative_path=path)


@pytest.fixture(scope='module')
def rule() -> Rule:
    return Rule(id='test-rule', name='Test Rule', confidence=9)


def make_finding(file: File, rule: Rule, detection: str) -> Finding:
    span = file.get_span_for_string(detection)
    assert span is not None
    finding = Finding(
        file=file,
        rules=[rule],
        detection=detection,
        start_pos=span[0],
        end_pos=span[1],
    )
    finding.map_on_file(relative_start=0)
    return finding


def test_response_keeps_legacy_fields_grouping_and_order(file: File, other_file: File, rule: Rule):
    f1 = make_finding(file, rule, DETECTION)
    f2 = make_finding(file, rule, SECOND_DETECTION)
    f3 = make_finding(other_file, rule, OTHER_FILE_DETECTION)

    response = FindingResponse.from_list([f1, f2, f3])

    assert list(response.keys()) == [file.path, other_file.path]

    entries = response[file.path]
    assert len(entries) == 2
    assert [entry['string'] for entry in entries] == [DETECTION, SECOND_DETECTION]

    fingerprint = sha256(DETECTION.encode('utf-8')).hexdigest()[23:33]
    assert entries[0] == {
        'line': f1.full_line,
        'string': DETECTION,
        'line_number': f1.linum,
        'rule': rule.id,
        'reason': f'{rule.name} | {fingerprint}',
        'confidence': rule.confidence,
        'fingerprint': fingerprint,
    }

    other_entries = response[other_file.path]
    assert len(other_entries) == 1
    assert other_entries[0]['string'] == OTHER_FILE_DETECTION
    assert other_entries[0]['fingerprint'] == sha256(OTHER_FILE_DETECTION.encode('utf-8')).hexdigest()[23:33]


def test_response_empty_findings():
    assert FindingResponse.from_list([]) == {}

    result = ScanResult([])
    assert result.response == {}
    assert len(result) == 0


def test_response_fails_on_finding_without_file(rule: Rule):
    finding = Finding(file=None, rules=[rule], detection=DETECTION, start_pos=0, end_pos=1)

    with pytest.raises(FindingSerializationException):
        FindingResponse.from_list([finding])


def test_response_fails_on_unmapped_finding(file: File, rule: Rule):
    finding = Finding(file=file, rules=[rule], detection=DETECTION, start_pos=94, end_pos=108)

    with pytest.raises(FindingSerializationException):
        FindingResponse.from_list([finding])


def test_response_fails_on_finding_without_rules(file: File):
    finding = Finding(file=file, rules=[], detection=DETECTION, start_pos=94, end_pos=108)
    finding.map_on_file(relative_start=0)

    with pytest.raises(FindingSerializationException):
        FindingResponse.from_list([finding])


def test_scan_result_is_a_single_generation(file: File, other_file: File, rule: Rule):
    findings = [
        make_finding(file, rule, DETECTION),
        make_finding(file, rule, SECOND_DETECTION),
        make_finding(other_file, rule, OTHER_FILE_DETECTION),
    ]

    result = ScanResult(findings)

    assert result.findings is findings
    assert len(result) == len(findings)
    assert sum(len(entries) for entries in result.response.values()) == len(findings)
    assert result.response == FindingResponse.from_list(findings)


def test_scan_result_serialization_failure(file: File, rule: Rule):
    findings = [
        make_finding(file, rule, DETECTION),
        Finding(file=None, rules=[rule], detection=DETECTION, start_pos=0, end_pos=1),
    ]

    with pytest.raises(FindingSerializationException):
        ScanResult(findings)


def test_write_report_success(tmp_path):
    response = {'/some/file.py': [{'line': 'a', 'string': 'b'}]}
    report_path = tmp_path / 'report.json'

    write_report(str(report_path), response)

    assert report_path.read_text() == json.dumps(response)
    assert json.loads(report_path.read_text()) == response
    assert not (tmp_path / 'report.json.tmp').exists()


def test_write_report_retries_after_failure(tmp_path, monkeypatch):
    response = {'/some/file.py': [{'line': 'a'}]}
    report_path = tmp_path / 'report.json'
    attempts_made = []
    real_replace = os.replace

    def flaky_replace(src, dst):
        attempts_made.append(1)
        if len(attempts_made) == 1:
            raise OSError('transient failure')
        return real_replace(src, dst)

    monkeypatch.setattr(os, 'replace', flaky_replace)

    write_report(str(report_path), response)

    assert len(attempts_made) == 2
    assert json.loads(report_path.read_text()) == response


def test_write_report_failure_leaves_no_partial_report(tmp_path, monkeypatch):
    response = {'/some/file.py': [{'line': 'a'}]}
    report_path = tmp_path / 'report.json'

    def always_failing_replace(src, dst):
        raise OSError('permanent failure')

    monkeypatch.setattr(os, 'replace', always_failing_replace)

    with pytest.raises(ReportWriteException):
        write_report(str(report_path), response, attempts=3)

    assert not report_path.exists()
    assert not (tmp_path / 'report.json.tmp').exists()


def test_write_report_failure_keeps_previous_report_untouched(tmp_path, monkeypatch):
    report_path = tmp_path / 'report.json'
    report_path.write_text('{"old": []}')

    def always_failing_replace(src, dst):
        raise OSError('permanent failure')

    monkeypatch.setattr(os, 'replace', always_failing_replace)

    with pytest.raises(ReportWriteException):
        write_report(str(report_path), {'/new': []})

    assert report_path.read_text() == '{"old": []}'
    assert not (tmp_path / 'report.json.tmp').exists()


def test_write_report_unserializable_response_leaves_no_file(tmp_path):
    response = {'/some/file.py': [{'line': {'not', 'json'}}]}
    report_path = tmp_path / 'report.json'

    with pytest.raises(ReportWriteException):
        write_report(str(report_path), response)

    assert not report_path.exists()
    assert not (tmp_path / 'report.json.tmp').exists()
