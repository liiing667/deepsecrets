from hashlib import sha256

from deepsecrets.core.engines.semantic import SemanticEngine
from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding, FindingMerger
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.tokenizers.lexer import LexerTokenizer
from deepsecrets.core.utils.file_analyzer import FileAnalyzer


def test_lexer_does_not_leak_state_between_files(tmp_path):
    first = File(
        path=str(tmp_path / 'first.js'),
        content='const state = { key: "firstValue", value: "firstValue" };\n',
    )
    second = File(
        path=str(tmp_path / 'second.js'),
        content='const api_key = "TESTSECRET1234";\n',
    )
    tokenizer = LexerTokenizer(deep_token_inspection=True)

    tokenizer.tokenize(first, post_filter=False)
    first_generation = first.generation
    second_tokens = tokenizer.tokenize(second, post_filter=False)

    assert second.generation != first_generation
    assert all(token.file is second for token in second_tokens)
    assert all(token.generation == second.generation for token in second_tokens)

    variables = tokenizer.get_variables(second_tokens)
    assert [(variable.content, variable.semantic.name) for variable in variables] == [
        ('TESTSECRET1234', 'api_key')
    ]

    engine = SemanticEngine(subengine=None)
    findings = []
    for token in second_tokens:
        findings.extend(engine.search(token))

    assert any(finding.detection == 'TESTSECRET1234' for finding in findings)


def test_lexer_retries_with_fresh_semantics_after_content_change(tmp_path):
    file = File(
        path=str(tmp_path / 'retry.py'),
        content='password = "OLDSECRET1234"\n',
    )
    tokenizer = LexerTokenizer(deep_token_inspection=True)

    tokenizer.tokenize(file, post_filter=False)
    first_generation = file.generation

    file.content = 'api_key = "NEWSECRET5678"\n'
    tokens = tokenizer.tokenize(file, post_filter=False)

    assert file.generation != first_generation
    assert all(token.generation == file.generation for token in tokens)
    assert [variable.content for variable in tokenizer.get_variables(tokens)] == ['NEWSECRET5678']


def test_finding_merge_respects_file_generation(tmp_path):
    path = str(tmp_path / 'same.py')
    first_file = File(path=path, content='OLD\n')
    second_file = File(path=path, content='NEW\n')
    rule = Rule(id='test')

    first = Finding(
        file=first_file,
        rules=[rule],
        detection='TESTSECRET1234',
        start_pos=0,
        end_pos=14,
    )
    second = Finding(
        file=second_file,
        rules=[rule],
        detection='TESTSECRET1234',
        start_pos=0,
        end_pos=14,
    )

    assert first != second
    assert first.get_fingerprint() == second.get_fingerprint()
    assert len(FindingMerger([first, second]).merge()) == 2


def test_reassignment_does_not_hide_a_secret_with_the_same_value(tmp_path):
    file = File(
        path=str(tmp_path / 'reassigned.py'),
        content='placeholder = "TESTSECRET1234"\npassword = "TESTSECRET1234"\n',
    )
    analyzer = FileAnalyzer(file)
    analyzer.add_engine(SemanticEngine(subengine=None), [LexerTokenizer(deep_token_inspection=True)])

    findings = analyzer.process()

    assert any(finding.detection == 'TESTSECRET1234' for finding in findings)


def test_file_analyzer_invalidates_cached_tokens_after_content_change(tmp_path):
    file = File(
        path=str(tmp_path / 'cached_retry.py'),
        content='password = "OLDSECRET1234"\n',
    )
    analyzer = FileAnalyzer(file)
    analyzer.add_engine(SemanticEngine(subengine=None), [LexerTokenizer(deep_token_inspection=True)])

    assert any(finding.detection == 'OLDSECRET1234' for finding in analyzer.process())

    file.content = 'api_key = "NEWSECRET5678"\n'
    findings = analyzer.process()

    assert any(finding.detection == 'NEWSECRET5678' for finding in findings)
    assert all(finding.detection != 'OLDSECRET1234' for finding in findings)


def test_finding_fingerprint_is_stable():
    finding = Finding(detection='TESTSECRET1234', start_pos=0, end_pos=14)
    expected = sha256(b'TESTSECRET1234').hexdigest()[23:33]

    assert finding.get_fingerprint() == expected
