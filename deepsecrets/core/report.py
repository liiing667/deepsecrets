import json
import os
from typing import Dict, List, Optional

from deepsecrets.core.model.finding import Finding, FindingResponse
from deepsecrets.core.utils.exceptions import ReportWriteException

REPORT_WRITE_ATTEMPTS = 2


class ScanResult:
    """A single generation of scan results.

    The merged findings and their serialized API/CLI response are bound
    together at construction time, so the report, the console output and
    the completion status always describe the very same set of findings.
    """

    findings: List[Finding]
    response: Dict[str, List[Dict]]

    def __init__(self, findings: List[Finding]) -> None:
        self.findings = findings
        self.response = FindingResponse.from_list(findings)

    def __len__(self) -> int:
        return len(self.findings)


def write_report(path: str, response: Dict[str, List[Dict]], attempts: int = REPORT_WRITE_ATTEMPTS) -> None:
    """Write the serialized scan report to `path`.

    The payload is serialized up front and written to a temporary file
    which is then atomically moved into place, so a failure never leaves
    a partially written report behind. Writing is retried up to
    `attempts` times; if every attempt fails, ReportWriteException is
    raised and no report file is produced.
    """
    try:
        payload = json.dumps(response)
    except (TypeError, ValueError) as e:
        raise ReportWriteException(f'Unable to serialize the report: {e}') from e

    last_error: Optional[Exception] = None
    for _ in range(max(1, attempts)):
        tmp_path = f'{path}.tmp'
        try:
            with open(tmp_path, 'w') as f:
                f.write(payload)
            os.replace(tmp_path, path)
            return
        except Exception as e:
            last_error = e
            _remove_file_quietly(tmp_path)

    raise ReportWriteException(f'Unable to write the report to {path}: {last_error}')


def _remove_file_quietly(path: str) -> None:
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass
