from deepsecrets.core.model.file import File
from deepsecrets.core.model.finding import Finding, FindingMerger
from deepsecrets.core.model.rules.false_finding import FalseFindingRule
from deepsecrets.core.model.rules.rule import Rule
from deepsecrets.core.modes.iscan_mode import ScanMode


TEST_CONTENT = 'line1 FIRST TOKEN\nline2 TOKEN\n'
FIRST_TOKEN = (12, 17)
SECOND_TOKEN = (24, 29)


def make_file(path: str, relative_path: str) -> File:
    return File(path=path, relative_path=relative_path, content=TEST_CONTENT)


def make_finding(file: File, span=FIRST_TOKEN, rule_id: str = 'S0') -> Finding:
    return Finding(
        file=file,
        rules=[Rule(id=rule_id, name=rule_id)],
        detection=TEST_CONTENT[span[0]:span[1]],
        start_pos=span[0],
        end_pos=span[1],
    )


def test_false_finding_rule_is_scoped_to_matching_files():
    rule = FalseFindingRule(pattern='TOKEN', applicable_file_patterns=['^tests/'])
    tests_file = make_file('/work/tests/test.py', 'tests/test.py')
    production_file = make_file('/work/src/prod.py', 'src/prod.py')

    assert rule.matches_finding(make_finding(tests_file))
    assert not rule.matches_finding(make_finding(production_file))


def test_false_finding_rule_only_matches_intersecting_spans():
    rule = FalseFindingRule(pattern=r'^.*FIRST.*$')
    tests_file = make_file('/work/tests/test.py', 'tests/test.py')

    assert rule.matches_finding(make_finding(tests_file, FIRST_TOKEN))
    assert not rule.matches_finding(make_finding(tests_file, SECOND_TOKEN))


def test_false_finding_rule_is_scoped_to_matching_rules():
    rule = FalseFindingRule(pattern='TOKEN', rule_id='S0')
    production_file = make_file('/work/src/prod.py', 'src/prod.py')

    assert rule.matches_finding(make_finding(production_file, rule_id='S0'))
    assert not rule.matches_finding(make_finding(production_file, rule_id='S1'))


def test_false_finding_rule_with_only_pattern_stays_compatible():
    rule = FalseFindingRule(pattern='TOKEN')
    production_file = make_file('/work/src/prod.py', 'src/prod.py')

    assert rule.matches_finding(make_finding(production_file))


def test_finding_merge_keeps_rule_order_and_fingerprint():
    file = make_file('/work/tests/test.py', 'tests/test.py')
    first = make_finding(file, rule_id='first')
    second = make_finding(file, rule_id='second')
    second.rules.append(first.rules[0])
    third = make_finding(file, rule_id='third')

    merged = FindingMerger([first, second, third]).merge()

    assert len(merged) == 1
    assert [rule.id for rule in merged[0].rules] == ['first', 'second', 'third']
    assert merged[0].get_fingerprint() == first.get_fingerprint()


def test_false_positives_filter_preserves_finding_order():
    class Mode:
        rulesets = {'false_findings': [FalseFindingRule(pattern='TOKEN', applicable_file_patterns=['^tests/'])]}

        filter_false_positives = ScanMode.filter_false_positives

    production_file_1 = make_file('/work/src/first.py', 'src/first.py')
    tests_file = make_file('/work/tests/test.py', 'tests/test.py')
    production_file_2 = make_file('/work/src/second.py', 'src/second.py')
    findings = [
        make_finding(production_file_1),
        make_finding(tests_file),
        make_finding(production_file_2),
    ]

    filtered = Mode().filter_false_positives(findings)

    assert [finding.file.relative_path for finding in filtered] == ['src/first.py', 'src/second.py']
