import json
import os

import pytest

from deepsecrets.cli import DeepSecretsCliTool
from deepsecrets.core.model.finding import FindingResponse
from deepsecrets.core.utils.exceptions import FindingSerializationException

LEGACY_API_FIELDS = {'line', 'string', 'line_number', 'rule', 'reason', 'confidence', 'fingerprint'}


@pytest.fixture()
def cli_args(tmp_path):
    return [
        '',
        '--target-dir',
        'tests/fixtures',
        '--outfile',
        str(tmp_path / 'report.json'),
    ]


def test_start_completes_and_writes_report(cli_args, tmp_path):
    tool = DeepSecretsCliTool(args=cli_args)
    tool.start()

    report_path = tmp_path / 'report.json'
    assert report_path.exists()

    response = json.loads(report_path.read_text())
    assert len(response) > 0
    for entries in response.values():
        for entry in entries:
            assert set(entry.keys()) == LEGACY_API_FIELDS


def test_start_serialization_failure_leaves_no_partial_and_no_false_completion(cli_args, tmp_path, monkeypatch):
    def broken_from_list(cls, findings):
        raise FindingSerializationException('serialization failed')

    monkeypatch.setattr(FindingResponse, 'from_list', classmethod(broken_from_list))

    tool = DeepSecretsCliTool(args=cli_args)
    with pytest.raises(SystemExit) as excinfo:
        tool.start()

    assert excinfo.value.code == 1
    assert not (tmp_path / 'report.json').exists()
    assert not (tmp_path / 'report.json.tmp').exists()


def test_start_report_retry_failure_leaves_no_partial_and_no_false_completion(cli_args, tmp_path, monkeypatch):
    real_replace = os.replace

    def always_failing_replace(src, dst):
        if str(src).endswith('.tmp'):
            raise OSError('permanent failure')
        return real_replace(src, dst)

    monkeypatch.setattr(os, 'replace', always_failing_replace)

    tool = DeepSecretsCliTool(args=cli_args)
    with pytest.raises(SystemExit) as excinfo:
        tool.start()

    assert excinfo.value.code == 1
    assert not (tmp_path / 'report.json').exists()
    assert not (tmp_path / 'report.json.tmp').exists()
