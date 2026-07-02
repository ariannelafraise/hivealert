from hivesec import AuditEventHandler, AuditEvent
from typing import Any
from pathlib import Path
import re
import requests
import yaml
import json

#RULES_DIR = "/etc/hivealert/rules"
RULES_DIR = "/home/arianne/projects/hivealert/examples"

class RulesHandler(AuditEventHandler):
    def __init__(self):
        super().__init__()
        self._rules: list[dict[str, Any]] = []
        for pattern in ("*.yml", "*.yaml"):
            for path in Path(RULES_DIR).glob(pattern):
                with path.open("r") as f:
                    self._rules.append(yaml.safe_load(f))

    def _rule_match(self, rule: dict[str, Any], event: AuditEvent):
        for r in event.records:
            ok = True

            for key, value in rule["on-fields"].items():
                if not r.has_field(key):
                    ok = False
                    break

                if r.get_field_value(key) != value:
                    ok = False
                    break

            if ok:
                return True

        return False

    def matches(self, event: AuditEvent):
        for r in self._rules:
            if self._rule_match(r, event):
                return True
        return False

    def _fill_vars(self, string: str, event: AuditEvent) -> str:
        def repl(match: re.Match[str]) -> str:
            expr = match.group(1)

            record_index, field = expr.split(".", 1)

            return str(event.records[int(record_index)].get_field_value(field))

        return re.sub(r"\${([^${}]+)\}", repl, string)

    def handle(self, event: AuditEvent):
        for r in self._rules:
            if self._rule_match(r, event):
                requests.post(
                    r["webhook"]["url"],
                    json=json.loads(self._fill_vars(r["webhook"]["payload"], event)),
                    headers= json.loads(r["webhook"]["headers"]) if "headers" in r["webhook"] != None else None
                    )
