from multiprocessing import RLock
from multiprocessing.pool import Pool
from typing import Dict, List, Optional, Type

from pydantic import BaseModel

from deepsecrets import logger
from deepsecrets.core.engines.iengine import IEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding
from deepsecrets.core.model.token import Token
from deepsecrets.core.tokenizers.itokenizer import Tokenizer


class EngineWithTokenizer(BaseModel):
    engine: IEngine
    tokenizer: Tokenizer

    class Config:
        arbitrary_types_allowed = True


class FileAnalyzer:
    file: File
    engine_tokenizers: List[EngineWithTokenizer]
    tokens: Dict[Type, List[Token]]
    token_generations: Dict[Type, int]
    pool_class: Type

    def __init__(self, file: File, pool_class: Optional[Type] = None):
        if pool_class is not None:
            self.pool_class = Pool
        else:
            self.pool_class = pool_class

        self.engine_tokenizers = []
        self.file = file
        self.tokens = {}
        self.token_generations = {}
        self.tokenizers_lock = RLock()

    def add_engine(self, engine: IEngine, tokenizers: List[Tokenizer]) -> None:
        for tokenizer in tokenizers:
            self.engine_tokenizers.append(EngineWithTokenizer(engine=engine, tokenizer=tokenizer))

    def process(self, threaded: bool = False) -> List[Finding]:
        results: List[Finding] = []
        self.file.ensure_generation()

        if threaded:  # pragma: nocover
            with self.pool_class(2) as pool:
                engine_results = pool.imap(self._run_engine, self.engine_tokenizers)
                pool.close()
                pool.join()

            if engine_results is None:
                return results

            for er in engine_results:
                if not er:
                    continue
                results.extend(er)

        else:
            for et in self.engine_tokenizers:
                results.extend(self._run_engine(et))

        return results

    def _run_engine(self, et: EngineWithTokenizer) -> List[Finding]:
        results: List[Finding] = []
        processed_values: Dict[object, bool] = {}

        with self.tokenizers_lock:
            current_generation = self.file.ensure_generation()
            cached_generation = self.token_generations.get(et.tokenizer)
            if et.tokenizer not in self.tokens or cached_generation != current_generation:
                self.tokens[et.tokenizer] = et.tokenizer.tokenize(self.file)
                self.token_generations[et.tokenizer] = current_generation

        tokens: List[Token] = self.tokens[et.tokenizer]
        current_generation = self.file.generation
        tokens = [
            token
            for token in tokens
            if getattr(token, 'generation', None) in (None, current_generation)
        ]

        for token in tokens:
            processed_key = self._processing_key(token)
            is_known_content = processed_values.get(processed_key)
            if is_known_content is not None and is_known_content is False:
                continue

            processed_values[processed_key] = False

            try:
                findings: List[Finding] = et.engine.search(token)
                for finding in findings:
                    finding.map_on_file(
                        file=self.file,
                        relative_start=token.span[0],
                        generation=getattr(token, 'generation', None),
                    )
                    results.append(finding)
                    processed_values[processed_key] = True

            except Exception as e:
                logger.exception('Unable to process token')
                continue

        return results

    @staticmethod
    def _processing_key(token: Token) -> object:
        if token.semantic is None:
            return token.val_hash()

        return (
            token.val_hash(),
            token.semantic.type,
            token.semantic.name,
            token.semantic.creds_probability,
            token.generation,
        )
