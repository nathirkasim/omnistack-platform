import codecs
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

@dataclass
class TargetLine:
    file: str
    line: int
    expect: str
    family: str
    level: str
    scenario_id: str
    rationale: str

class FixtureBuilder:
    def __init__(self, relative_path: str, eol: str = "\n", encoding: str = "utf-8", has_bom: bool = False):
        self.relative_path = relative_path
        self.lines: List[str] = []
        self.target_lines: List[TargetLine] = []
        self.eol = eol
        self.encoding = encoding
        self.has_bom = has_bom

    def add(self, line: str = "") -> "FixtureBuilder":
        self.lines.append(line)
        return self

    def add_lines(self, *lines: str) -> "FixtureBuilder":
        for l in lines:
            self.lines.append(l)
        return self

    def add_target(
        self,
        line: str,
        expect: str,
        family: str,
        level: str,
        scenario_id: str,
        rationale: str
    ) -> "FixtureBuilder":
        assert expect in ("FLAG", "NO_FLAG", "DEBATABLE"), f"Invalid expect: {expect}"
        self.lines.append(line)
        line_num = len(self.lines)
        self.target_lines.append(TargetLine(
            file=self.relative_path,
            line=line_num,
            expect=expect,
            family=family,
            level=level,
            scenario_id=scenario_id,
            rationale=rationale
        ))
        return self

    def write(self, base_dir: Path) -> List[TargetLine]:
        file_path = base_dir / self.relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        content = self.eol.join(self.lines) + self.eol
        raw_bytes = content.encode(self.encoding)
        if self.has_bom:
            raw_bytes = codecs.BOM_UTF8 + raw_bytes
        file_path.write_bytes(raw_bytes)
        return self.target_lines
