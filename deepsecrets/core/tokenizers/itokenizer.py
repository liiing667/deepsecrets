from abc import abstractmethod
from collections import namedtuple
from typing import List, NamedTuple

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token


class Tokenizer:
    tokens: List[Token]
    settings: NamedTuple
    generation: int
    file: File

    def __init__(self, **kwargs) -> None:
        self.tokens = []
        self.generation = 0
        self.file = None  # type: ignore
        Settings = namedtuple('Settings', kwargs.keys())  # type: ignore
        self.settings = Settings._make(kwargs.values())  # type: ignore

    def begin_file(self, file: File) -> int:
        """
        Start a new, isolated tokenization run for ``file``.

        Tokenizers are reusable objects. Keeping tokens or semantic state from
        a previous call silently leaks variables and suppression spans into the
        next file (even when both files use the same language).
        """
        self.tokens = []
        self.file = file
        ensure_generation = getattr(file, 'ensure_generation', None)
        self.generation = (
            ensure_generation()
            if callable(ensure_generation)
            else getattr(file, 'generation', 0)
        )
        return self.generation

    @abstractmethod
    def tokenize(self, file: File) -> List[Token]:
        pass

    def __hash__(self) -> int:  # pragma: nocover
        return hash(type(self))

    def __repr__(self) -> str:  # pragma: no cover
        return self.__class__.__name__
