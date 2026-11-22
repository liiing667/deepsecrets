import json
import os

from deepsecrets.core.scan_state import (
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PENDING,
    ScanSession,
    file_fingerprint,
)


def make_file(path, content='x'):
    path.write_text(content)
    return str(path)


def manifest_of(*entries):
    return [(abs_path, rel) for abs_path, rel in entries]


def test_begin_marks_every_file_pending_once(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    b = make_file(tmp_path / 'b.txt', 'b')

    session = ScanSession(state_path=str(tmp_path / 'state.json'), workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt'), (b, 'b.txt'), (a, 'a.txt')))

    assert session.manifest == ['a.txt', 'b.txt']
    pending = session.pending_entries()
    assert pending == [(a, 'a.txt'), (b, 'b.txt')]
    assert session.completed is False
    assert session.failed_files == []


def test_record_and_finalize_roundtrip(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    b = make_file(tmp_path / 'b.txt', 'b')
    state_path = str(tmp_path / 'state.json')

    session = ScanSession(state_path=state_path, workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt'), (b, 'b.txt')))
    session.record_findings('a.txt', [{'detection': 'secret-a'}])
    session.record_findings('b.txt', [])

    assert session.pending_entries() == []

    finalized = session.finalize()
    assert [rel for rel, _, _ in finalized] == ['a.txt', 'b.txt']
    assert finalized[0][2] == [{'detection': 'secret-a'}]
    assert finalized[1][2] == []
    assert session.completed is True

    persisted = json.loads(open(state_path).read())
    assert persisted['completed'] is True
    assert persisted['failed_files'] == []
    assert persisted['manifest'] == ['a.txt', 'b.txt']
    assert persisted['files']['a.txt']['findings'] == [{'detection': 'secret-a'}]


def test_interrupted_generation_is_resumed_with_same_id(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    b = make_file(tmp_path / 'b.txt', 'b')
    state_path = str(tmp_path / 'state.json')

    session = ScanSession(state_path=state_path, workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt'), (b, 'b.txt')))
    session.record_findings('a.txt', [{'detection': 'secret-a'}])
    generation_id = session.generation_id
    # no finalize(): the run was cancelled midway

    # a new file shows up before the retry
    c = make_file(tmp_path / 'c.txt', 'c')

    resumed = ScanSession(state_path=state_path, workdir=str(tmp_path))
    resumed.begin(manifest_of((a, 'a.txt'), (b, 'b.txt'), (c, 'c.txt')))

    assert resumed.generation_id == generation_id
    assert resumed.resumed is True
    assert resumed.reused_files == ['a.txt']
    assert resumed.pending_entries() == [(b, 'b.txt'), (c, 'c.txt')]
    # every file appears exactly once in the reconciled manifest
    assert resumed.manifest == ['a.txt', 'b.txt', 'c.txt']


def test_completed_generation_starts_new_id_and_reuses_cache(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    state_path = str(tmp_path / 'state.json')

    session = ScanSession(state_path=state_path, workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt')))
    session.record_findings('a.txt', [{'detection': 'secret-a'}])
    session.finalize()
    old_generation = session.generation_id

    followup = ScanSession(state_path=state_path, workdir=str(tmp_path))
    followup.begin(manifest_of((a, 'a.txt')))

    assert followup.generation_id != old_generation
    assert followup.resumed is False
    assert followup.reused_files == ['a.txt']
    assert followup.pending_entries() == []


def test_changed_and_vanished_files_are_reconciled(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    b = make_file(tmp_path / 'b.txt', 'b')
    state_path = str(tmp_path / 'state.json')

    session = ScanSession(state_path=state_path, workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt'), (b, 'b.txt')))
    session.record_findings('a.txt', [{'detection': 'old'}])
    session.record_findings('b.txt', [{'detection': 'old'}])
    session.finalize()

    # b changes, a disappears
    make_file(tmp_path / 'b.txt', 'b-changed')
    os.unlink(a)

    followup = ScanSession(state_path=state_path, workdir=str(tmp_path))
    followup.begin(manifest_of((b, 'b.txt')))

    assert followup.manifest == ['b.txt']
    assert followup.reused_files == []
    assert followup.pending_entries() == [(b, 'b.txt')]


def test_failed_files_are_retried_and_failure_list_is_final(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    b = make_file(tmp_path / 'b.txt', 'b')
    state_path = str(tmp_path / 'state.json')

    session = ScanSession(state_path=state_path, workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt'), (b, 'b.txt')))
    session.record_findings('a.txt', [])
    session.record_failure('b.txt', 'ValueError: boom')
    session.finalize()

    persisted = json.loads(open(state_path).read())
    assert persisted['failed_files'] == ['b.txt']
    assert session.failed_files == ['b.txt']

    # the retry re-scans the failed file and the failure list catches up
    followup = ScanSession(state_path=state_path, workdir=str(tmp_path))
    followup.begin(manifest_of((a, 'a.txt'), (b, 'b.txt')))
    assert followup.pending_entries() == [(b, 'b.txt')]

    followup.record_findings('b.txt', [{'detection': 'secret-b'}])
    followup.finalize()

    persisted = json.loads(open(state_path).read())
    assert persisted['failed_files'] == []
    assert followup.failed_files == []


def test_corrupt_state_file_is_ignored(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    state_path = tmp_path / 'state.json'
    state_path.write_text('{not json')

    session = ScanSession(state_path=str(state_path), workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt')))

    assert session.pending_entries() == [(a, 'a.txt')]


def test_state_of_another_workdir_is_ignored(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    state_path = str(tmp_path / 'state.json')

    session = ScanSession(state_path=state_path, workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt')))
    session.record_findings('a.txt', [{'detection': 'secret-a'}])

    other = ScanSession(state_path=state_path, workdir='/somewhere/else')
    other.begin(manifest_of((a, 'a.txt')))

    assert other.reused_files == []
    assert other.pending_entries() == [(a, 'a.txt')]


def test_state_is_persisted_atomically_after_each_record(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'a')
    b = make_file(tmp_path / 'b.txt', 'b')
    state_path = str(tmp_path / 'state.json')

    session = ScanSession(state_path=state_path, workdir=str(tmp_path))
    session.begin(manifest_of((a, 'a.txt'), (b, 'b.txt')))
    session.record_findings('a.txt', [])

    # no tmp file is left behind and the state is always valid json
    assert not os.path.exists(f'{state_path}.tmp')
    persisted = json.loads(open(state_path).read())
    assert persisted['files']['a.txt']['status'] == STATUS_DONE
    assert persisted['files']['b.txt']['status'] == STATUS_PENDING


def test_file_fingerprint(tmp_path):
    a = make_file(tmp_path / 'a.txt', 'content-a')
    b = make_file(tmp_path / 'b.txt', 'content-a')
    c = make_file(tmp_path / 'c.txt', 'content-c')

    assert file_fingerprint(a) == file_fingerprint(b)
    assert file_fingerprint(a) != file_fingerprint(c)
    assert file_fingerprint(str(tmp_path)) is None
    assert file_fingerprint(str(tmp_path / 'missing')) is None


def test_status_constants_are_distinct():
    assert len({STATUS_PENDING, STATUS_DONE, STATUS_FAILED}) == 3
