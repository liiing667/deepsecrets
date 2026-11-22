"""
Resumable scan state.

A scan is executed as a *generation*. Exactly one generation binds together:

* the file manifest (the exclusion-filtered list of files to scan, each
*   pinned to a content fingerprint),
* the per-file findings produced by workers,
* the final response assembled by the CLI.

The generation is persisted to a single JSON state file so that a scan
interrupted midway (Ctrl-C, kill, worker crash) can be resumed by simply
running the tool again with the same output target:

* If the persisted generation is incomplete, it is resumed under the same
  ``generation_id``: the manifest is reconciled with the current file list
  (new files are appended, vanished files are dropped, changed files are
  re-scanned) and files already done are reused as-is.
* If the persisted generation is complete, a fresh generation is started
  and previous records are only kept as a per-file cache (same path + same
  content fingerprint).

Files that failed to scan are retried on the next run, and the persisted
``failed_files`` list always reflects the latest state of the generation.

The module intentionally depends on the standard library only; findings are
stored as opaque JSON-compatible payloads supplied by the caller.
"""

import json
import os
import uuid
from datetime import datetime
from hashlib import sha256
from typing import Any, Dict, List, Optional, Tuple

from deepsecrets import logger

SCAN_STATE_VERSION = 1

STATUS_PENDING = 'pending'
STATUS_DONE = 'done'
STATUS_FAILED = 'failed'

_READ_CHUNK_SIZE = 1024 * 1024


def new_generation_id() -> str:
    return uuid.uuid4().hex


def file_fingerprint(path: str) -> Optional[str]:
    """Content fingerprint of a file.

    Returns None when the file cannot be read; such files are never reused
    across runs and are left to the regular scan path instead.
    """
    try:
        digest = sha256()
        with open(path, 'rb') as f:
            while True:
                chunk = f.read(_READ_CHUNK_SIZE)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


class ScanFileRecord:
    """State of a single file within a generation."""

    def __init__(
        self,
        fingerprint: Optional[str] = None,
        status: str = STATUS_PENDING,
        findings: Optional[List[Dict[str, Any]]] = None,
        error: Optional[str] = None,
    ) -> None:
        self.fingerprint = fingerprint
        self.status = status
        self.findings = findings if findings is not None else []
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            'fingerprint': self.fingerprint,
            'status': self.status,
            'error': self.error,
            'findings': self.findings,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanFileRecord':
        return cls(
            fingerprint=data.get('fingerprint'),
            status=data.get('status', STATUS_PENDING),
            findings=list(data.get('findings') or []),
            error=data.get('error'),
        )


class ScanState:
    """Serializable form of one resumable generation."""

    def __init__(self, generation_id: str, workdir: str, version: int = SCAN_STATE_VERSION) -> None:
        self.version = version
        self.generation_id = generation_id
        self.workdir = workdir
        self.created_at = datetime.now().isoformat()
        self.updated_at = self.created_at
        self.completed = False
        self.manifest: List[str] = []
        self.files: Dict[str, ScanFileRecord] = {}

    @property
    def failed_files(self) -> List[str]:
        return [rel for rel in self.manifest if self.files[rel].status == STATUS_FAILED]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'version': self.version,
            'generation_id': self.generation_id,
            'workdir': self.workdir,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'completed': self.completed,
            'manifest': list(self.manifest),
            'files': {rel: record.to_dict() for rel, record in self.files.items()},
            'failed_files': self.failed_files,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanState':
        state = cls(
            generation_id=data['generation_id'],
            workdir=data['workdir'],
            version=data.get('version', SCAN_STATE_VERSION),
        )
        state.created_at = data.get('created_at', state.created_at)
        state.updated_at = data.get('updated_at', state.updated_at)
        state.completed = bool(data.get('completed', False))
        state.manifest = list(data.get('manifest') or [])

        files = data.get('files') or {}
        state.files = {rel: ScanFileRecord.from_dict(record) for rel, record in files.items()}

        if not state.manifest:
            state.manifest = list(state.files.keys())
        state.manifest = [rel for rel in state.manifest if rel in state.files]
        return state


class ScanSession:
    """Manages the lifecycle of one resumable generation on disk."""

    def __init__(self, state_path: str, workdir: str) -> None:
        self.state_path = state_path
        self.workdir = workdir
        self.resumed = False
        self.reused_files: List[str] = []
        self._abs_by_rel: Dict[str, str] = {}
        self.state = ScanState(generation_id=new_generation_id(), workdir=workdir)
        self._load()

    @property
    def generation_id(self) -> str:
        return self.state.generation_id

    @property
    def completed(self) -> bool:
        return self.state.completed

    @property
    def manifest(self) -> List[str]:
        return list(self.state.manifest)

    @property
    def failed_files(self) -> List[str]:
        return self.state.failed_files

    def _load(self) -> None:
        if not os.path.exists(self.state_path):
            return

        try:
            with open(self.state_path) as f:
                data = json.load(f)
            state = ScanState.from_dict(data)
        except Exception as e:
            logger.warning(f'Ignoring unreadable scan state at {self.state_path}: {e}')
            return

        if state.version != SCAN_STATE_VERSION:
            logger.warning(f'Ignoring scan state at {self.state_path}: unsupported version {state.version}')
            return

        if state.workdir != self.workdir:
            logger.info('Existing scan state belongs to a different target directory; starting a new generation')
            return

        self.state = state

    def begin(self, manifest_entries: List[Tuple[str, str]]) -> None:
        """Reconcile the persisted generation with the current file list.

        ``manifest_entries`` are ``(absolute_path, relative_path)`` pairs in
        scan order. Files done in a previous run are reused only when their
        content fingerprint is unchanged; failed and stale files are
        re-scheduled. Every file appears in the generation exactly once.
        """
        previous_files = self.state.files
        if self.state.completed:
            # The previous generation ran to completion: start a fresh one
            # and keep old records only as a reusable cache.
            self.state = ScanState(generation_id=new_generation_id(), workdir=self.workdir)
        else:
            # Resume the interrupted generation under the same id.
            self.resumed = len(self.state.manifest) > 0

        self.state.completed = False
        self.state.manifest = []
        self.state.files = {}
        self._abs_by_rel = {}
        self.reused_files = []

        seen = set()
        for abs_path, rel_path in manifest_entries:
            if rel_path in seen:
                continue
            seen.add(rel_path)

            fingerprint = file_fingerprint(abs_path)
            record = previous_files.get(rel_path)
            if (
                record is not None
                and record.status == STATUS_DONE
                and fingerprint is not None
                and record.fingerprint == fingerprint
            ):
                self.state.files[rel_path] = record
                self.reused_files.append(rel_path)
            else:
                self.state.files[rel_path] = ScanFileRecord(fingerprint=fingerprint)

            self.state.manifest.append(rel_path)
            self._abs_by_rel[rel_path] = abs_path

        self.persist()

    def pending_entries(self) -> List[Tuple[str, str]]:
        """``(absolute_path, relative_path)`` pairs still to be scanned."""
        return [
            (self._abs_by_rel[rel], rel)
            for rel in self.state.manifest
            if self.state.files[rel].status == STATUS_PENDING
        ]

    def record_findings(self, rel_path: str, finding_payloads: List[Dict[str, Any]]) -> None:
        record = self.state.files.get(rel_path)
        if record is None:
            logger.debug(f'Skipping findings for {rel_path}: not part of the current generation')
            return

        record.status = STATUS_DONE
        record.error = None
        record.findings = list(finding_payloads)
        self.persist()

    def record_failure(self, rel_path: str, error: str) -> None:
        record = self.state.files.get(rel_path)
        if record is None:
            logger.debug(f'Skipping failure for {rel_path}: not part of the current generation')
            return

        record.status = STATUS_FAILED
        record.error = error
        record.findings = []
        self.persist()

    def finalize(self) -> List[Tuple[str, str, List[Dict[str, Any]]]]:
        """Complete the generation and return its findings.

        Returns ``(relative_path, absolute_path, finding_payloads)`` tuples in
        manifest order. The persisted failure list is recomputed from the
        final per-file states, so it always matches the completed generation.
        """
        self.state.completed = True
        self.persist()
        return [
            (rel, self._abs_by_rel.get(rel, rel), list(self.state.files[rel].findings))
            for rel in self.state.manifest
        ]

    def persist(self) -> None:
        """Atomically write the current generation state to disk."""
        self.state.updated_at = datetime.now().isoformat()
        tmp_path = f'{self.state_path}.tmp'
        try:
            with open(tmp_path, 'w') as f:
                json.dump(self.state.to_dict(), f)
            os.replace(tmp_path, self.state_path)
        except OSError as e:
            logger.warning(f'Unable to persist scan state to {self.state_path}: {e}')
