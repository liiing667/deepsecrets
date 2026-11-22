import logging
from multiprocessing import get_context
import os
from abc import abstractmethod, abstractstaticmethod
from datetime import datetime
from functools import partial
from multiprocessing.pool import Pool
from typing import Any, Callable, List, Optional, Tuple, Type
import regex as re

from dotwiz import DotWiz

from deepsecrets import PLATFORM, PROFILER_ON, logger
from deepsecrets.config import Config
from deepsecrets.core.model.finding import (
    Finding,
    FindingMerger,
    finding_from_snapshot,
    finding_to_snapshot,
)
from deepsecrets.core.model.rules.exlcuded_path import ExcludePathRule
from deepsecrets.core.rulesets.excluded_paths import ExcludedPathsBuilder
from deepsecrets.core.rulesets.false_findings import FalseFindingsBuilder
from deepsecrets.core.scan_state import ScanSession
from deepsecrets.core.utils.file_analyzer import FileAnalyzer
from deepsecrets.core.utils.fs import get_abspath


class ScanMode:
    config: Config
    filepaths: List[str]
    path_exclusion_rules: List[ExcludePathRule] = []
    file_analyzer: FileAnalyzer
    pool_engine: Type
    scan_session: Optional[ScanSession]

    def __init__(self, config: Config, pool_engine: Optional[Any] = None) -> None:
        if pool_engine is None:
            if PLATFORM == 'Darwin':
                self.pool_engine = get_context('fork').Pool
            else:
                self.pool_engine = Pool
        else:
            self.pool_engine = pool_engine

        self.scan_session = None
        self.config = config
        self.filepaths = self._get_files_list()
        self.prepare_for_scan()

    def _get_process_count_for_runner(self) -> int:
        limit = self.config.process_count

        file_count = len(self.filepaths)
        if file_count == 0:
            return 0
        return limit if file_count >= limit else file_count

    def run(self) -> List[Finding]:
        final: List[Finding] = []

        bundle = self.analyzer_bundle()
        proc_count = self._get_process_count_for_runner()
        if proc_count == 0:
            return final

        self.scan_session = self._build_scan_session()
        if self.scan_session is None:
            final = self._run_untracked(bundle=bundle, proc_count=proc_count)
        else:
            self.scan_session.begin([(path, self._relative_path(path)) for path in self.filepaths])
            final = self._run_tracked(session=self.scan_session, bundle=bundle, proc_count=proc_count)

        fin = FindingMerger(final).merge()
        fin = self.filter_false_positives(fin)
        return fin

    def _run_untracked(self, bundle: DotWiz, proc_count: int) -> List[Finding]:
        final: List[Finding] = []

        if PROFILER_ON:
            for file in self.filepaths:
                final.extend(self._per_file_analyzer(file=file, bundle=bundle))
        else:
            with self.pool_engine(processes=proc_count) as pool:
                per_file_findings: List[List[Finding]] = pool.map(
                    partial(pool_wrapper, bundle, self._per_file_analyzer),
                    self.filepaths,
                )  # type: ignore

            for file_findings in list(per_file_findings):
                if not file_findings:
                    continue
                final.extend(file_findings)

        return final

    def _run_tracked(self, session: ScanSession, bundle: DotWiz, proc_count: int) -> List[Finding]:
        """Scan the pending files of a resumable generation.

        Every worker result is persisted into the generation as soon as it
        arrives, so an interrupted run can be resumed later. The returned
        findings are assembled from the finalized generation only, which
        keeps the file list, the worker findings and this response bound to
        the same generation.
        """
        final: List[Finding] = []
        todo = session.pending_entries()

        try:
            if PROFILER_ON:
                self._scan_entries_serial(session=session, bundle=bundle, todo=todo)
            else:
                self._scan_entries_pool(session=session, bundle=bundle, todo=todo, proc_count=proc_count)
        except BaseException:
            session.persist()
            raise

        for rel_path, abs_path, payloads in session.finalize():
            for payload in payloads:
                final.append(finding_from_snapshot(path=abs_path, relative_path=rel_path, payload=payload))

        return final

    def _scan_entries_serial(
        self, session: ScanSession, bundle: DotWiz, todo: List[Tuple[str, str]]
    ) -> None:
        for abs_path, rel_path in todo:
            try:
                findings = self._per_file_analyzer(bundle=bundle, file=abs_path)
            except Exception as exc:
                session.record_failure(rel_path, f'{type(exc).__name__}: {exc}')
                continue

            session.record_findings(rel_path, [finding_to_snapshot(finding) for finding in findings])

    def _scan_entries_pool(
        self, session: ScanSession, bundle: DotWiz, todo: List[Tuple[str, str]], proc_count: int
    ) -> None:
        if len(todo) == 0:
            return

        with self.pool_engine(processes=proc_count) as pool:
            results = pool.imap_unordered(
                partial(pool_entry_guard, bundle, self._per_file_analyzer),
                todo,
            )  # type: ignore

            for rel_path, abs_path, findings, error in results:
                if error is not None or findings is None:
                    session.record_failure(rel_path, error or 'Unknown worker error')
                    continue

                session.record_findings(rel_path, [finding_to_snapshot(finding) for finding in findings])

    def _resolve_state_path(self) -> Optional[str]:
        if not getattr(self.config, 'resume_enabled', True):
            return None

        custom_path = getattr(self.config, 'resume_state_path', None)
        if custom_path:
            return get_abspath(custom_path)

        output = getattr(self.config, 'output', None)
        output_path = getattr(output, 'path', None) if output is not None else None
        if output_path:
            return f'{get_abspath(output_path)}.dsresume'

        return None

    def _build_scan_session(self) -> Optional[ScanSession]:
        state_path = self._resolve_state_path()
        if state_path is None:
            return None

        return ScanSession(state_path=state_path, workdir=self.config.workdir_path)

    def _relative_path(self, full_path: str) -> str:
        return full_path.replace(f'{self.config.workdir_path}/', '')

    def _get_files_list(self) -> List[str]:
        flist = []
        if not self.path_exclusion_rules:
            excl_paths_builder = ExcludedPathsBuilder()
            for path in self.config.global_exclusion_paths:
                excl_paths_builder.with_rules_from_file(path)

            self.path_exclusion_rules = excl_paths_builder.rules

        state_path = self._resolve_state_path()
        scan_state_paths = {state_path, f'{state_path}.tmp'} if state_path is not None else set()

        for fpath, _, files in os.walk(get_abspath(self.config.workdir_path)):
            for filename in files:
                full_path = os.path.join(fpath, filename)
                if full_path in scan_state_paths:
                    continue

                rel_path = self._relative_path(full_path)
                if not self._path_included(rel_path):
                    continue

                flist.append(full_path)

        return flist

    def _path_included(self, path: str) -> bool:
        if self.path_exclusion_rules is None or len(self.path_exclusion_rules) == 0:
            return True

        if any(excl_rule.match(path) for excl_rule in self.path_exclusion_rules):
            return False
        return True

    @abstractmethod
    def prepare_for_scan(self) -> None:
        pass

    def analyzer_bundle(self) -> DotWiz:
        return DotWiz(
            workdir=self.config.workdir_path,
            path_exclusion_rules=self.path_exclusion_rules,
            engines={}
        )

    @abstractstaticmethod
    def _per_file_analyzer(bundle, file: Any) -> List[Finding]:  # type: ignore
        pass

    def filter_false_positives(self, results: List[Finding]) -> List[Finding]:
        false_finding_rules = self.rulesets.get(FalseFindingsBuilder.ruleset_name)
        if false_finding_rules is None:
            return results
        

        final: List[Finding] = []       
        for result in results:
            good_result = True
            for false_pattern in false_finding_rules:
                if re.match(false_pattern.pattern, result.detection) is not None:
                    good_result = False
                    break
            if not good_result:
                continue

            final.append(result)

        return final


def pool_wrapper(bundle: DotWiz, runner: Callable, file: str) -> List[Finding]:  # pragma: nocover
    start_ts = datetime.now()
    result = runner(bundle, file)
    if logger.level == logging.DEBUG:
        logger.debug(
            f' ✓ [{file}] {(datetime.now() - start_ts).total_seconds()}s elapsed \t {len(result)} potential findings'
        )
    else:
        logger.info(f' ✓ [{file}] \t {len(result)} potential findings')
    return result


def pool_entry_guard(
    bundle: DotWiz, runner: Callable, entry: Tuple[str, str]
) -> Tuple[str, str, Optional[List[Finding]], Optional[str]]:
    """Run one file of a resumable generation through the worker pool.

    Per-file failures are reported back to the parent process instead of
    aborting the whole scan, so the generation can record them in its
    failure list and keep going.
    """
    abs_path, rel_path = entry
    try:
        findings = pool_wrapper(bundle, runner, abs_path)
    except Exception as exc:
        return (rel_path, abs_path, None, f'{type(exc).__name__}: {exc}')

    return (rel_path, abs_path, findings, None)
