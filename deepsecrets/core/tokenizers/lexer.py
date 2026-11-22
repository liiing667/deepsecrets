from typing import List, Optional, Sequence, Set, Type, Union

from deepsecrets import logger

from ordered_set import OrderedSet
from pygments import highlight
from pygments.formatters import RawTokenFormatter
from pygments.lexers.special import Lexer, RawTokenLexer
from pygments.token import Token as PygmentsToken

from deepsecrets.core.model.file import File
from deepsecrets.core.model.semantic import Variable
from deepsecrets.core.model.token import Semantic, SemanticType, Token
from deepsecrets.core.tokenizers.helpers.semantic.language import Language
from deepsecrets.core.tokenizers.helpers.semantic.var_detection.rules import VariableDetectionRules, VariableSuppressionRules
from deepsecrets.core.tokenizers.helpers.spot_improvements import SpotImprovements
from deepsecrets.core.tokenizers.helpers.type_stream import (
    token_to_typestream_item,
    types_to_filter_after,
    types_to_filter_before,
)
from deepsecrets.core.tokenizers.itokenizer import Tokenizer
from deepsecrets.core.utils.lexer_finder import LexerFinder

empty_tokens = ['\n', '\t', "'", "''", '"', '""']


class LexerTokenizer(Tokenizer):
    token_stream: str
    lexer: Lexer
    language: Language

    def _get_types_for_token(self, token: PygmentsToken) -> List[Type]:  # type: ignore
        types = []
        types.append(token)
        if token.parent is not None:
            if token.parent == PygmentsToken:
                return types
            deep = self._get_types_for_token(token.parent)
            types.extend(deep)
        return types

    def sanitize(self, content: str) -> Union[str, bool]:
        quotes = ["'", "''", '"', '""']

        whitespace_cleaned = content.replace(' ', '')
        if 0 <= len(whitespace_cleaned) == 0:
            return False

        # some lexers (eq. TextLexer) leave \n
        # at the end of a Token
        if len(content) > 1 and content[-1] == '\n':
            content = content[:-1]

        if content[0] == content[-1]:
            if content[0] in quotes:
                content = content[1:-1]

        if content in quotes:
            return False

        return content

    def _find_lexer_for_file(self, file: File):
        lexer = LexerFinder().find(file=file)
        if lexer is not None and lexer.name == 'Text only':
            return None
        return lexer


    def tokenize(self, file: File, post_filter=True) -> List[Token]:
        generation = self.begin_file(file)
        self.token_stream = ''
        self.lexer = None  # type: ignore
        self.language = None  # type: ignore
        # TODO: don't trust the extension, use 'file' utility ?

        self.lexer = self._find_lexer_for_file(file)
        if not self.lexer:
            return []

        try:
            self.language: Language = Language.from_text(self.lexer.filenames[0])
        except (ValueError, IndexError):
            self.language: Language = Language.from_text(file.extension)
        except Exception as e:
            logger.exception(e)

        result = highlight(file.content, self.lexer, RawTokenFormatter())
        raw_tokens = list(RawTokenLexer().get_tokens(result))
        token_improver = SpotImprovements(lang=self.language)

        current_position = 0

        for i, raw_token in enumerate(raw_tokens):
            content: str = raw_token[1]
            types: List[Type] = self._get_types_for_token(raw_token[0])
            start = current_position
            end = start + len(content)
            current_position = end

            try:
                content = self.sanitize(content)
                if not content:
                    continue

                span = file.get_span_for_string(content, between=[start - 1, end + 1])
                token = Token(file=file, content=content, span=span, generation=generation)
                token.set_type(types)

                improved_tokens = token_improver.improve_token(self.tokens, self.token_stream, token)

                self.tokens.extend(improved_tokens)
                self.add_to_token_stream(improved_tokens)
            except Exception as e:
                str(e)

        tokens_to_be_excluded = []
        if self.settings.deep_token_inspection is True:  # type: ignore
            tokens_to_be_excluded = self.deep_analyze()

        return self.final_cleanup(self.tokens, tokens_to_be_excluded) if post_filter else list(self.tokens)

    def add_to_token_stream(self, tokens: List[Token]) -> None:
        for token in tokens:
            self.token_stream += token_to_typestream_item(token=token)

    def final_cleanup(self, tokens_all: Sequence[Token], tokens_to_be_excluded: Sequence[Token]) -> List[Token]:
        if not isinstance(tokens_all, OrderedSet):
            tokens_all = OrderedSet(tokens_all)

        tokens_all = tokens_all - tokens_to_be_excluded
        final = []
        for token in tokens_all:
            if any(type in token.type for type in types_to_filter_before):  # type: ignore
                continue

            if any(type in token.type for type in types_to_filter_after):  # type: ignore
                continue

            if token.content.replace(' ', '') in empty_tokens:
                continue

            final.append(token)

        return final

    def deep_analyze(self) -> Set[Token]:
        generation = getattr(self, 'generation', None)
        if generation is None and getattr(self, 'file', None) is not None:
            generation = self.file.ensure_generation()

        current_tokens = [
            token
            for token in self.tokens
            if getattr(token, 'generation', None) in (None, generation)
        ]
        current_stream = self.token_stream
        if len(current_tokens) != len(self.tokens):
            current_stream = ''.join(token_to_typestream_item(token) for token in current_tokens)

        tokens_all = OrderedSet(current_tokens)
        if self.language is None:
            return tokens_all

        exclude_after = set()

        true_detections: List[Variable] = []
        suppression_regions: List[List[int]] = []
        
        detection_rules = VariableDetectionRules.for_language(self.language)
        suppression_rules = VariableSuppressionRules.for_language(self.language)
    
        for rule in detection_rules:
            true_detections.extend(rule.match(current_tokens, current_stream))
        
        for rule in suppression_rules:
            suppression_regions.extend(rule.match(current_tokens, current_stream))

        suppression_regions = self._collapse_suppression_regions(suppression_regions)

        for var in true_detections:
            var_generation = getattr(var, 'generation', None)
            if var_generation is not None and generation is not None and var_generation != generation:
                continue

            suppressed = self._if_suppressed(var, suppression_regions)
            if suppressed:
                exclude_after.update([var.name, var.value])
                continue

            var.value.semantic = Semantic(
                type=SemanticType.VAR,
                name=var.name.content,
                creds_probability=var.found_by.creds_probability,
                generation=var_generation,
            )
            exclude_after.add(var.name)

        return exclude_after
    
    def _if_suppressed(self, var: Variable, regions):
        var_generation = getattr(var, 'generation', None)
        for reg in regions:
            reg_generation = getattr(reg, 'generation', None)
            if (
                var_generation is not None
                and reg_generation is not None
                and var_generation != reg_generation
            ):
                continue

            if var.span[0] >= reg[0] and var.span[1] <= reg[1]:
                return True
        return False


    def get_variables(self, tokens: Optional[List[Token]] = None) -> List[Token]:
        tokens = tokens if tokens is not None else self.tokens
        vars = []
        if len(tokens) == 0:
            return []

        for token in tokens:
            if token.semantic is None:
                continue

            if token.semantic.type != SemanticType.VAR:
                continue

            vars.append(token)

        return vars

    def print_token_type_stream(self) -> None:
        print(self.token_stream)

    def _collapse_suppression_regions(self, suppression_regions):
        regions = []
        if len(suppression_regions) == 0:
            return regions
        
        for i, reg in enumerate(suppression_regions):
            if i == 0:
                regions.append(suppression_regions[0])
                continue

            previous = regions[-1]
            previous_generation = getattr(previous, 'generation', None)
            current_generation = getattr(reg, 'generation', None)
            same_generation = (
                previous_generation is None
                or current_generation is None
                or previous_generation == current_generation
            )

            if same_generation and reg[0] == previous[1]:
                regions[-1][1] = reg[1]
            else:
                regions.append(reg)
            
        return regions
            

