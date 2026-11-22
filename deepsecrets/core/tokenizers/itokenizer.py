from abc import abstractmethod
from collections import namedtuple
from typing import List, NamedTuple

from deepsecrets.core.model.file import File
from deepsecrets.core.model.token import Token


class Tokenizer:
    tokens: List[Token]
    settings: NamedTuple

    def __init__(self, **kwargs) -> None:
        self.tokens = []
        Settings = namedtuple('Settings', kwargs.keys())  # type: ignore
        self.settings = Settings._make(kwargs.values())  # type: ignore

    def __getstate__(self) -> dict:
        # 'settings' holds a dynamically created namedtuple class
        # which cannot be pickled, so it's serialized as a plain dict
        state = self.__dict__.copy()
        state['settings'] = dict(self.settings._asdict())
        return state

    def __setstate__(self, state: dict) -> None:
        settings = state.get('settings', {})
        Settings = namedtuple('Settings', settings.keys())  # type: ignore
        state['settings'] = Settings._make(settings.values())  # type: ignore
        self.__dict__.update(state)

    @abstractmethod
    def tokenize(self, file: File) -> List[Token]:
        pass

    def __hash__(self) -> int:  # pragma: nocover
        return hash(type(self))

    def __repr__(self) -> str:  # pragma: no cover
        return self.__class__.__name__
