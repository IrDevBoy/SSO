"""P0.5.4 — Architecture governance gates (§9.1, §9.4, Appendix E).

Four deterministic, filesystem/AST-based gates:

G-1  Document governance  — ``docs/ARCHITECTURE.md`` is the canonical
     in-repo source of truth (Appendix E: "versioned in-repo
     (``docs/ARCHITECTURE.md``)") and declares the frozen version.
G-2  Context set          — exactly the nine bounded contexts of §9.1
     (seven business contexts + org + platform_admin).
G-3  Cross-context imports — a context package must not directly import
     another context package (§9.4 seam principle: contexts interact via
     interfaces, not each other's internals).  AST-based; grep is not the
     enforcement mechanism.  This is NOT the future interface-seam
     enforcement — only the currently deterministic invariant.
G-4  ADR directory        — ADRs live under ``docs/adr/`` as markdown
     (Appendix E governance).  Numbering/index/reissue semantics are
     OQ-3 and deliberately out of scope.

The gates are pure functions of a repository root; the tests apply them
to the real repository.  They need no database, no Docker, no network,
and never mutate the repository.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

#: §9.1 — seven business contexts + two supporting subsystems (sorted for
#: deterministic failure output; "platform_admin" is the on-disk form of
#: §9.1's "platform-admin" application layer).
CANONICAL_CONTEXTS = frozenset(
    {
        "access",
        "address",
        "audit",
        "identity",
        "notification",
        "org",
        "platform_admin",
        "profile",
        "security",
    }
)

#: Directories that never contain repository ADRs (tooling artifacts).
_ADR_SCAN_IGNORES = frozenset(
    {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".freebuff", "node_modules"}
)


# ---------------------------------------------------------------------------
# Pure gate helpers (root-parameterised so proof-of-fail probes can run
# against isolated temporary trees without touching the repository).
# ---------------------------------------------------------------------------
def document_governance_errors(root: Path) -> list[str]:
    """G-1: canonical doc present, root copy gone, version + frozen status."""
    errors: list[str] = []
    canonical = root / "docs" / "ARCHITECTURE.md"
    if not canonical.is_file():
        errors.append("canonical document docs/ARCHITECTURE.md is missing")
        return errors  # nothing else can be checked without the document
    if (root / "ARCHITECTURE.md").exists():
        errors.append("root ARCHITECTURE.md still exists (canonical copy is docs/)")
    text = canonical.read_text(encoding="utf-8")
    version_row = next(
        (line for line in text.splitlines() if line.strip().startswith("| Version |")),
        None,
    )
    if version_row is None or "1.0.1" not in version_row:
        errors.append('governance marker missing/wrong: "| Version |" row must declare 1.0.1')
    if "Approved — Frozen" not in text:
        errors.append('governance marker missing: "Approved — Frozen" status')
    return errors


def context_set_errors(root: Path) -> list[str]:
    """G-2: contexts/ contains exactly the nine §9.1 context packages."""
    errors: list[str] = []
    contexts_dir = root / "contexts"
    if not contexts_dir.is_dir():
        return ["contexts/ directory is missing"]
    # Bytecode/tooling cache directories are not context packages.
    actual = sorted(
        p.name
        for p in contexts_dir.iterdir()
        if p.is_dir() and p.name != "__pycache__"
    )
    expected = sorted(CANONICAL_CONTEXTS)
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if missing:
        errors.append(f"missing context packages (§9.1): {missing}")
    if extra:
        errors.append(f"unexpected context packages (§9.1): {extra}")
    for name in sorted(set(actual) & set(expected)):
        if not (contexts_dir / name / "__init__.py").is_file():
            errors.append(f"context package {name!r} has no __init__.py package marker")
    return errors


def _context_of(file: Path, contexts_root: Path) -> str | None:
    """Context package a file belongs to (first dir component under contexts/)."""
    try:
        rel = file.relative_to(contexts_root)
    except ValueError:
        return None
    parts = rel.parts
    if len(parts) < 2:  # a file directly under contexts/ belongs to no context
        return None
    return parts[0]


def _targets_of_imports(file: Path, contexts_root: Path) -> list[str]:
    """Absolute module-path targets of every import in *file* (AST only).

    Handles both ``import a.b`` / ``import a.b as m`` and
    ``from a.b import x[, y]`` — including relative imports, resolved
    against the importing module's package.
    """
    try:
        tree = ast.parse(file.read_text(encoding="utf-8"))
    except SyntaxError:
        return []  # a syntax error is not a governance finding here
    rel = file.relative_to(contexts_root)
    pkg_parts = ["contexts", *rel.parts[:-1]]  # importing module's package
    targets: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                targets.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module:
                    targets.append(node.module)
            else:
                base = pkg_parts[: len(pkg_parts) - (node.level - 1)]
                if node.module:
                    base = base + node.module.split(".")
                if base:
                    targets.append(".".join(base))
            # ``from pkg import name`` may import a *submodule*, so each
            # alias is also a candidate target.
            if node.module or node.level:
                for alias in node.names:
                    prefix = node.module if node.level == 0 else ""
                    if node.level > 0:
                        base = pkg_parts[: len(pkg_parts) - (node.level - 1)]
                        prefix = ".".join(base + ([node.module] if node.module else []))
                    if prefix:
                        targets.append(f"{prefix}.{alias.name}")
    return targets


def cross_context_import_errors(root: Path) -> list[str]:
    """G-3: no context package imports another context package (AST).

    Recorded seam exceptions (ADR-0006 §9; §9.4 "the existence and shape of
    the seam is architecture"):
    - contexts.identity -> contexts.audit.services: the §9.4 seam operation
      ``audit.append(event) (transactional)`` — INV-08/§34.5 require the
      same-transaction append to be a direct in-process call on the audit
      context's service; the interaction is through that named seam
      operation only (AuditAppendRequest/append_audit_event), not through
      the audit context's internals.
    """
    allowed_seams = {
        "identity": ("contexts.audit.services", "contexts.audit.taxonomy"),
    }
    errors: list[str] = []
    contexts_root = root / "contexts"
    if not contexts_root.is_dir():
        return []  # G-2 owns the missing-directory case
    for file in sorted(contexts_root.rglob("*.py")):
        importer = _context_of(file, contexts_root)
        if importer is None:
            continue
        for target in _targets_of_imports(file, contexts_root):
            parts = target.split(".")
            if len(parts) >= 2 and parts[0] == "contexts" and parts[1] in CANONICAL_CONTEXTS:
                seam_ok = any(
                    target == allowed or target.startswith(allowed + ".")
                    for allowed in allowed_seams.get(importer, ())
                )
                if parts[1] != importer and not seam_ok:
                    errors.append(
                        f"cross-context import: {file.relative_to(root)} -> {target} "
                        f"(context {importer!r} must not import context {parts[1]!r}; §9.4)"
                    )
    return sorted(set(errors))


def adr_governance_errors(root: Path) -> list[str]:
    """G-4: ADRs are markdown files under the canonical docs/adr directory."""
    errors: list[str] = []
    adr_dir = root / "docs" / "adr"
    if not adr_dir.is_dir():
        return ["docs/adr/ directory is missing"]
    files = sorted(p for p in adr_dir.iterdir() if p.is_file() and not p.name.startswith("."))
    if not files:
        errors.append("docs/adr/ contains no ADR documents")
    # Hidden dotfiles (e.g. a .gitkeep placeholder) are directory markers,
    # not ADR documents, and are deliberately not judged here.
    non_md = [p.name for p in files if p.suffix != ".md"]
    if non_md:
        errors.append(f"non-markdown files in docs/adr/: {sorted(non_md)}")
    # Deterministic sibling check: the ADR naming convention (NNNN-*.md)
    # must not appear outside the canonical directory.  Tooling artifact
    # directories are ignored; anything else matching the convention is
    # reported for review.
    strays = sorted(
        str(p.relative_to(root))
        for p in root.rglob("*.md")
        if p.suffix == ".md"
        and p.parts[0] not in _ADR_SCAN_IGNORES
        and adr_dir not in p.parents
        and p.parent != root / "docs"
        and len(p.name) >= 5
        and p.name[:4].isdigit()
        and p.name[4] == "-"
    )
    if strays:
        errors.append(f"ADR-like files outside docs/adr/: {strays}")
    return errors


# ---------------------------------------------------------------------------
# The four gates applied to the real repository.
# ---------------------------------------------------------------------------
class TestArchitectureGovernance:
    """P0.5.4 gates against the actual repository tree (read-only)."""

    def test_document_governance(self):
        # G-1 — Appendix E: versioned in-repo at docs/ARCHITECTURE.md.
        errors = document_governance_errors(REPO_ROOT)
        assert not errors, "\n".join(errors)

    def test_canonical_context_set(self):
        # G-2 — §9.1: exactly the nine bounded contexts, no more, no fewer.
        errors = context_set_errors(REPO_ROOT)
        assert not errors, "\n".join(errors)

    def test_no_cross_context_imports(self):
        # G-3 — §9.4 seam principle (currently deterministic subset).
        errors = cross_context_import_errors(REPO_ROOT)
        assert not errors, "\n".join(errors)

    def test_adr_directory_governance(self):
        # G-4 — Appendix E canonical ADR directory (safe subset; OQ-3 open).
        errors = adr_governance_errors(REPO_ROOT)
        assert not errors, "\n".join(errors)
