import logging
import os
from typing import Any, Dict, List, Optional

from dotwiz import DotWiz

from deepsecrets import PROFILER_ON, logger
from deepsecrets.config import Config
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
from deepsecrets.core.utils.file_analyzer import EngineWithTokenizer, FileAnalyzer


class CliScanMode(ScanMode):
    engines_enabled: Dict[str, bool]
    rulesets: Dict[str, List]
    engine_tokenizers: List[EngineWithTokenizer]

    def __init__(self, config: Config, pool_engine: Optional[Any] = None) -> None:
        # Rulesets, engines and tokenizers are state of a single scan
        # (one generation) and must never be shared with other scans,
        # so they are initialized per instance and not on the class.
        self.engines_enabled = {}
        self.rulesets = {}
        self.engine_tokenizers = []
        super().__init__(config=config, pool_engine=pool_engine)

    def prepare_for_scan(self) -> None:
        logger.info(f'Found {len(self.filepaths)} applicable files for the scan')
        if len(self.filepaths) == 0:
            return

        for engine in self.config.engines:
            self.engines_enabled[engine.name] = True

        for ruleset_builder, paths in self.config.rulesets.items():
            builder = ruleset_builder()
            for path in paths:
                builder.with_rules_from_file(os.path.abspath(path))
            self.rulesets[builder.ruleset_name] = builder.rules

        self.engine_tokenizers = self._build_engine_tokenizers()

    def _build_engine_tokenizers(self) -> List[EngineWithTokenizer]:
        # Engine/tokenizer combinations are built exactly once per scan,
        # so every worker runs with the very same generation of rulesets,
        # engines and tokenizers. A ruleset reload or a partially failed
        # load cannot make workers diverge from each other.
        combinations: List[EngineWithTokenizer] = []

        fct = FullContentTokenizer()
        lex = LexerTokenizer(deep_token_inspection=True)

        regex_engine = RegexEngine(
            ruleset=self.rulesets.get(RegexRulesetBuilder.ruleset_name, []),
        )

        for eng, enabled in self.engines_enabled.items():
            if not enabled:
                continue

            if eng == RegexEngine.name:
                combinations.append(EngineWithTokenizer(engine=regex_engine, tokenizer=fct))

            if eng == HashedSecretEngine.name:
                hashed_secret_engine = HashedSecretEngine(
                    ruleset=self.rulesets.get(HashedSecretsRulesetBuilder.ruleset_name, [])
                )
                combinations.append(EngineWithTokenizer(engine=hashed_secret_engine, tokenizer=lex))

            if eng == SemanticEngine.name:
                semantic_engine = SemanticEngine(regex_engine)
                combinations.append(EngineWithTokenizer(engine=semantic_engine, tokenizer=lex))

        return combinations

    def analyzer_bundle(self) -> DotWiz:
        bundle = super().analyzer_bundle()
        bundle.update(
            workdir=self.config.workdir_path,
            engines=self.engines_enabled,
            rulesets=self.rulesets,
            engine_tokenizers=self.engine_tokenizers,
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
        for combination in bundle.engine_tokenizers:
            file_analyzer.add_engine(combination.engine, [combination.tokenizer])

        try:
            results = file_analyzer.process(threaded=False)
        except Exception as e:
            logger.exception(e)

        if PROFILER_ON:
            pass

        return results
