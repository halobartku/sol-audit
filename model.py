"""What every other part of the scanner shares: a finding, the rule tuple, and the little the
engine learns about a crate as a whole. Imports nothing from the rest of the scanner, so any
module may import it without creating a cycle.
"""
import re
from dataclasses import dataclass

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cwe: str
    file: str
    line: int
    snippet: str
    fix: str
    category: str = "hygiene"   # see CATEGORIES at the bottom of this file
    kind: str = "shape"         # guarded / shape / heuristic, see META

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def _ctx(lines, i, pad=1):
    return " ".join(l.strip() for l in lines[max(0, i - pad):i + pad + 1])[:220]

def _suppressed(lines, i):
    # any `// audit-ok` on this line or the one above suppresses the finding
    return "audit-ok" in lines[i] or (i > 0 and "audit-ok" in lines[i - 1])

# Each detector: (rule_id, title, severity, cwe, fix, fn(lines, relpath) -> [line_no])
def _make(rule_id, title, sev, cwe, fix, fn):
    return (rule_id, title, sev, cwe, fix, fn)

# Some classes cannot be decided inside one file. Whether `Account<'info, Vault>` needs a `has_one`
# depends on whether `Vault` carries an authority field, and in a real crate the state struct lives
# in state.rs while the accounts struct lives in instructions.rs. scan_repo does a cheap first pass
# and leaves what it learned here for the rules that need it. Single-file scans simply see less.
_ACCOUNT_STRUCT = re.compile(
    r"#\[account[^\n]*\]\s*(?:#\[[^\n]*\]\s*)*pub\s+struct\s+(\w+)\s*\{([^}]*)\}", re.S)
_AUTHORITY_PUBKEY_FIELD = re.compile(
    r"\bpub\s+(authority|owner|admin|manager|delegate|creator|update_authority)\s*:\s*Pubkey")


class ProjectIndex:
    """What a rule may know about the crate as a whole, rather than about one file."""

    def __init__(self):
        self.authority_structs = set()   # #[account] structs carrying an authority-ish Pubkey

    def add_text(self, text):
        for m in _ACCOUNT_STRUCT.finditer(text):
            if _AUTHORITY_PUBKEY_FIELD.search(m.group(2)):
                self.authority_structs.add(m.group(1))

    def clear(self):
        self.authority_structs.clear()


_PROJECT = ProjectIndex()
