from typing import Any, List, Optional, Tuple

import regex as re
from pydantic import Field, root_validator

from deepsecrets.core.model.rules.regex import RegexRuleWithoutId


class FalseFindingRule(RegexRuleWithoutId):
    rule_id: Optional[str] = Field(default=None)
    rule_ids: List[str] = Field(default=[])
    start_pos: Optional[int] = Field(default=None)
    end_pos: Optional[int] = Field(default=None)
    span: Optional[Tuple[int, int]] = Field(default=None)

    @root_validator(pre=True)
    def normalize_scope(cls, values: Any) -> Any:
        values = dict(values)

        rule_ids = values.get('rule_ids') or []
        if isinstance(rule_ids, str):
            rule_ids = [rule_ids]
        else:
            rule_ids = list(rule_ids)

        for field in ('rule_id', 'rule', 'target_rule_id', 'id'):
            value = values.get(field)
            if value is not None and value not in rule_ids:
                rule_ids.append(value)

        target_rules = values.get('rules') or values.get('target_rules') or values.get('target_rule_ids') or []
        if isinstance(target_rules, str):
            target_rules = [target_rules]
        elif isinstance(target_rules, dict):
            target_rules = [target_rules.get('id')]

        for rule in target_rules:
            rule_id = rule.get('id') if isinstance(rule, dict) else getattr(rule, 'id', rule)
            if rule_id is not None and rule_id not in rule_ids:
                rule_ids.append(rule_id)

        values['rule_ids'] = list(dict.fromkeys(rule_ids))

        if values.get('start_pos') is None:
            for field in ('start_offset', 'start'):
                if values.get(field) is not None:
                    values['start_pos'] = values[field]
                    break
        if values.get('end_pos') is None:
            for field in ('end_offset', 'end'):
                if values.get(field) is not None:
                    values['end_pos'] = values[field]
                    break

        span = values.get('span')
        if span is not None and len(span) == 2:
            if values.get('start_pos') is None:
                values['start_pos'] = span[0]
            if values.get('end_pos') is None:
                values['end_pos'] = span[1]

        return values

    def applies_to_file(self, file: Any) -> bool:
        if not self.applicable_file_patterns:
            return True
        if file is None:
            return False

        paths = {
            path
            for path in (getattr(file, 'path', None), getattr(file, 'relative_path', None))
            if path is not None
        }
        return any(pattern.search(path) is not None for pattern in self.applicable_file_patterns for path in paths)

    def matches_finding(self, finding: Any) -> bool:
        if not self.applies_to_file(finding.file):
            return False

        targets = self._target_rule_values()
        if targets and not any(rule.id in targets or rule.name in targets for rule in finding.rules):
            return False

        return any(self._intersects(span, (finding.start_pos, finding.end_pos)) for span in self._match_spans(finding))

    def _target_rule_values(self) -> set:
        return {rule_id for rule_id in self.rule_ids if rule_id is not None}

    @staticmethod
    def _intersects(first: Tuple[int, int], second: Tuple[int, int]) -> bool:
        return first[0] < second[1] and second[0] < first[1]

    def _match_spans(self, finding: Any) -> List[Tuple[int, int]]:
        if self.start_pos is not None and self.end_pos is not None:
            return [(self.start_pos, self.end_pos)]

        if self.span is not None:
            return [self.span]

        spans = self._file_match_spans(finding)
        if spans:
            return spans

        return self._detection_match_spans(finding)

    def _file_match_spans(self, finding: Any) -> List[Tuple[int, int]]:
        file = finding.file
        if file is None or not getattr(file, 'content', None):
            return []

        pattern = re.compile(self.pattern.pattern, self.pattern.flags | re.MULTILINE)
        spans: List[Tuple[int, int]] = []
        for match in pattern.finditer(file.content):
            if not self._verify(match):
                continue

            span = match.span(self.target_group)
            if span[0] >= 0 and span[1] >= 0:
                spans.append(span)

        return spans

    def _detection_match_spans(self, finding: Any) -> List[Tuple[int, int]]:
        spans: List[Tuple[int, int]] = []
        for match in self.pattern.finditer(finding.detection):
            if not self._verify(match):
                continue

            span = match.span(self.target_group)
            if span[0] < 0 or span[1] < 0:
                continue

            spans.append((finding.start_pos + span[0], finding.start_pos + span[1]))

        return spans
