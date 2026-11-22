import logging
import os
from typing import Any, Dict, List, Type

from dotwiz import DotWiz

from deepsecrets import PROFILER_ON, logger
from deepsecrets.core.engines.hashed_secret import HashedSecretEngine
from deepsecrets.core.engines.regex import RegexEngine
from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.modes.iscan_mode import ScanMode
from deepsecrets.core.rulesets.hashed_secrets import HashedSecretsRulesetBuilder
from deepsecrets.core.rulesets.regex import RegexRulesetBuilder
from deepsecrets.core.tokenizers.full_content import FullContentTokenizer
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.file_analyzer import FileAnalyzer


class CliScanMode(ScanMode):
    engines_enabled: Dict[Type, bool] = {}
    rulesets: Dict[str, List] = {}
    ruleset_meta: Dict[str, Dict] = {}

    def __init__(self, config, pool_engine=None) -> None:
        # These dictionaries used to be shared through the class and could
        # leak rules/engines from one scan generation into the next one.
        self.engines_enabled = {}
        self.rulesets = {}
        self.ruleset_meta = {}
        super().__init__(config=config, pool_engine=pool_engine)

    def prepare_for_scan(self) -> None:
        logger.info(f'Found {len(self.filepaths)} applicable files for the scan')
        if len(self.filepaths) == 0:
            self.engines_enabled = {}
            self.rulesets = {}
            self.ruleset_meta = {}
            return

        engines_enabled: Dict[Type, bool] = {}
        for engine in self.config.engines:
            engines_enabled[engine.name] = True

        # Load every configured ruleset into a local candidate first.  Only a
        # completely loaded rule-file set becomes visible to workers.
        rulesets: Dict[str, List] = {}
        ruleset_meta: Dict[str, Dict] = {}
        for ruleset_builder, paths in self.config.rulesets.items():
            builder = ruleset_builder()
            absolute_paths = [os.path.abspath(path) for path in paths]
            if hasattr(builder, 'with_rules_from_files'):
                builder.with_rules_from_files(absolute_paths)
            else:
                for path in absolute_paths:
                    builder.with_rules_from_file(path)
            rulesets[builder.ruleset_name] = list(builder.rules)
            ruleset_meta[builder.ruleset_name] = {
                'generation': getattr(builder, 'generation', None),
                'algorithms': set(getattr(builder, 'algorithms', set())),
                'sources': list(getattr(builder, 'sources', [])),
            }

        self.engines_enabled = engines_enabled
        self.rulesets = rulesets
        self.ruleset_meta = ruleset_meta


    def analyzer_bundle(self) -> DotWiz:
        bundle = super().analyzer_bundle()
        bundle.update(
            workdir=self.config.workdir_path,
            engines=self.engines_enabled,
            rulesets=self.rulesets,
            ruleset_meta=self.ruleset_meta,
        )
        return bundle


    @staticmethod
    def _per_file_analyzer(bundle, file: Any) -> List[Finding]:
        if logger.level == logging.DEBUG:
            logger.debug(f'Starting analysis for {file}')

        results: List[Finding] = []

        if not isinstance(file, str):
            raise Exception('Filepath as str expected')

        file = File(path=file, relative_path=file.replace(f'{bundle.workdir}/', ''))
        if file.length == 0:
            return results

        file_analyzer = FileAnalyzer(file)
        fct = FullContentTokenizer()
        lex = LexerTokenizer(deep_token_inspection=True)

        regex_engine = RegexEngine(
            ruleset=bundle.rulesets.get(RegexRulesetBuilder.ruleset_name, []),
        )

        for eng, enabled in bundle.engines.items():
            if not enabled:
                continue

            if eng == RegexEngine.name:
                file_analyzer.add_engine(regex_engine, [fct])

            if eng == HashedSecretEngine.name:
                ruleset_meta = getattr(bundle, 'ruleset_meta', {}) or {}
                hashed_meta = ruleset_meta.get(HashedSecretsRulesetBuilder.ruleset_name, {})
                hashed_secret_engine = HashedSecretEngine(
                    ruleset=bundle.rulesets.get(HashedSecretsRulesetBuilder.ruleset_name, []),
                    generation=hashed_meta.get('generation'),
                )
                file_analyzer.add_engine(hashed_secret_engine, [lex])

            if eng == SemanticEngine.name:
                semantic_engine = SemanticEngine(regex_engine)
                file_analyzer.add_engine(semantic_engine, [lex])

        try:
            results = file_analyzer.process(threaded=False)
        except Exception as e:
            logger.exception(e)

        if PROFILER_ON:
            pass

        return results
