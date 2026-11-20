"""Plasma canary files: honest impact detection (T1486).

Ransomware crews enumerate and destroy user documents. A canary is a decoy
document in a known location whose only purpose is to be touched. Plasma
does not rely on heuristic "encryption bursts" (noisy, late); it records the
exact bytes of every canary at deploy time and verifies them on every
`watch` sweep or on demand.

    deploy  -> writes decoys + root/canaries.json (path, sha256, size)
    verify  -> missing or modified canary = finding, score 10
    status  -> summary

The decoys are deliberately believable: realistic names, a random directory
under each requested location, and content that looks like the document the
name promises.  The old marker text ("PLASMA CANARY FILE") made the decoy
trivial to avoid; the manifest is the only place that records what is a
canary now.

The canary folder is excluded from normal operations: it is never read by
Plasma except by verify(), and deleting a canary is exactly the signal.
"""

from __future__ import annotations

import hashlib
import io
import json
import secrets
import time
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

from . import agentstate

MANIFEST_NAME = "canaries.json"
DEFAULT_SUBDIR = "Documents"
LEGACY_SUBDIR = "Canaries"

# Plausible document names.  Keep the extension mix: a folder containing only
# spreadsheets is as suspicious as a folder called "Canaries".
CANARY_NAMES = [
    "FY26_AP_Reconciliation.xlsx",
    "Vendor_Payments_August.csv",
    "Board_Pack_September.docx",
    "Staff_Bonus_2026.pdf",
    "Customer_Master_Extract.xlsx",
    "Service_Accounts.csv",
    "Insurance_Renewal_2026.pdf",
    "Payroll_Adjustments_Q3.docx",
]

NAME_POOL = CANARY_NAMES + [
    "Treasury_Forecast_Q4.xlsx",
    "Supplier_Onboarding_2026.csv",
    "Audit_Committee_Notes.docx",
    "Employee_Handbook_2026.pdf",
    "Direct_Debit_Mandates.csv",
    "Fixed_Asset_Register.xlsx",
]

DIR_POOL = [
    "Board_Pack_2026",
    "Finance_Archive",
    "Payroll_2026",
    "Vendor_Files",
    "Legal_2026",
    "Shared_Documents",
    "Management_Accounts",
    "Operations_2026",
]

# Kept for callers that imported the old constant.  It is no longer written
# to disk; render_content() generates a document body appropriate to the
# filename and never identifies itself as a decoy.
CANARY_BODY = "Quarterly reconciliation summary.\n"

_LEDGER_ROWS = [
    ["Date", "Reference", "Description", "Amount", "Status"],
    ["2026-08-01", "AP-10482", "Northwind Facilities — August service", "12,480.00", "Paid"],
    ["2026-08-04", "AP-10497", "Contoso Freight — route settlement", "8,215.40", "Paid"],
    ["2026-08-09", "AP-10511", "Fabrikam Supplies — consumables", "3,942.18", "Approved"],
    ["2026-08-12", "AP-10528", "Adventure Works — licence renewal", "21,600.00", "Pending"],
    ["2026-08-18", "AP-10544", "Tailspin Logistics — Q3 retainer", "15,000.00", "Paid"],
    ["2026-08-25", "AP-10571", "Wide World Imports — customs", "6,310.75", "Review"],
    ["2026-09-01", "AP-10590", "Northwind Facilities — September service", "12,480.00", "Approved"],
    ["2026-09-06", "AP-10602", "Proseware Consulting — assessment", "9,750.00", "Paid"],
]

_NARRATIVE = [
    "Quarterly reconciliation summary prepared for management review.",
    "The schedule below compares approved purchase orders with settled invoices.",
    "Variance items are marked for follow-up with the relevant cost centre.",
    "Amounts are shown in the reporting currency and exclude applicable tax.",
]


def manifest_path(root) -> Path:
    return Path(root) / MANIFEST_NAME


def default_dir(root) -> Path:
    return Path(root) / DEFAULT_SUBDIR


def legacy_dir(root) -> Path:
    return Path(root) / LEGACY_SUBDIR


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_name(name: str) -> str:
    text = str(name)
    if not text or Path(text).name != text or "/" in text or "\\" in text:
        raise ValueError(f"canary name must be a plain filename: {name!r}")
    return text


def _xlsx_bytes(rows: list[list[str]]) -> bytes:
    """A minimal but valid OOXML workbook with inline strings."""
    sheet_rows = []
    for r, row in enumerate(rows, 1):
        cells = []
        for c, value in enumerate(row):
            col = chr(ord("A") + c)
            cells.append(
                f'<c r="{col}{r}" t="inlineStr"><is><t>'
                f'{escape(str(value))}</t></is></c>'
            )
        sheet_rows.append(f'<row r="{r}">{"".join(cells)}</row>')
    sheet = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/'
        'spreadsheetml/2006/main"><sheetData>'
        + "".join(sheet_rows)
        + "</sheetData></worksheet>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/'
        'spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/'
        '2006/relationships"><sheets><sheet name="Reconciliation" '
        'sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
        'content-types"><Default Extension="rels" ContentType="application/'
        'vnd.openxmlformats-package.relationships+xml"/><Default '
        'Extension="xml" ContentType="application/xml"/><Override '
        'PartName="/xl/workbook.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType='
        '"application/vnd.openxmlformats-officedocument.spreadsheetml.'
        'worksheet+xml"/><Override PartName="/docProps/core.xml" '
        'ContentType="application/vnd.openxmlformats-package.core-'
        'properties+xml"/><Override PartName="/docProps/app.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.'
        'extended-properties+xml"/></Types>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
        '2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
        'openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://'
        'schemas.openxmlformats.org/package/2006/relationships/metadata/'
        'core-properties" Target="docProps/core.xml"/><Relationship '
        'Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/'
        '2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        '</Relationships>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
        '2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
        'openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        'Target="worksheets/sheet1.xml"/></Relationships>'
    )
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
        'package/2006/metadata/core-properties" xmlns:dc="http://purl.org/'
        'dc/elements/1.1/"><dc:title>Management reconciliation</dc:title>'
        '<dc:creator>Finance</dc:creator></cp:coreProperties>'
    )
    app = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/'
        'officeDocument/2006/extended-properties"><Application>Microsoft '
        'Excel</Application></Properties>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
    return buf.getvalue()


def _docx_bytes(paragraphs: list[str]) -> bytes:
    """A minimal but valid OOXML document."""
    body = "".join(
        f"<w:p><w:r><w:t>{escape(p)}</w:t></w:r></w:p>" for p in paragraphs
    )
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
        'wordprocessingml/2006/main"><w:body>'
        + body
        + '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/></w:sectPr>'
        '</w:body></w:document>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/'
        'content-types"><Default Extension="rels" ContentType="application/'
        'vnd.openxmlformats-package.relationships+xml"/><Default '
        'Extension="xml" ContentType="application/xml"/><Override '
        'PartName="/word/document.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/'
        'vnd.openxmlformats-package.core-properties+xml"/><Override '
        'PartName="/docProps/app.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.extended-properties+xml"/></Types>'
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
        '2006/relationships"><Relationship Id="rId1" Type="http://schemas.'
        'openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/><Relationship Id="rId2" Type="http://'
        'schemas.openxmlformats.org/package/2006/relationships/metadata/'
        'core-properties" Target="docProps/core.xml"/><Relationship '
        'Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/'
        '2006/relationships/extended-properties" Target="docProps/app.xml"/>'
        '</Relationships>'
    )
    document_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/'
        '2006/relationships"></Relationships>'
    )
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
        'package/2006/metadata/core-properties" xmlns:dc="http://purl.org/'
        'dc/elements/1.1/"><dc:title>Board pack</dc:title>'
        '<dc:creator>Executive Office</dc:creator></cp:coreProperties>'
    )
    app = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Properties xmlns="http://schemas.openxmlformats.org/'
        'officeDocument/2006/extended-properties"><Application>Microsoft '
        'Word</Application></Properties>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("word/document.xml", document)
        z.writestr("word/_rels/document.xml.rels", document_rels)
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
    return buf.getvalue()


def _pdf_bytes(lines: list[str]) -> bytes:
    """A minimal valid PDF 1.4 document with a text stream."""
    def _esc(text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    stream_lines = ["BT", "/F1 11 Tf", "50 760 Td"]
    for i, line in enumerate(lines):
        if i:
            stream_lines.append("0 -16 Td")
        stream_lines.append(f"({_esc(line)}) Tj")
    stream_lines.append("ET")
    stream = "\n".join(stream_lines).encode("latin-1", "replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
         b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"),
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n"
        + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, 1):
        offsets.append(len(out))
        out.extend(f"{i} 0 obj\n".encode())
        out.extend(obj)
        out.extend(b"\nendobj\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode())
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref}\n%%EOF\n".encode()
    )
    return bytes(out)


def render_content(name: str) -> bytes:
    """Return a plausible document body for *name*.

    The body never says "canary".  Spreadsheet and word-processing files are
    valid OOXML packages; PDFs have a real xref table.  A decoy that cannot
    be opened is almost as obvious as one that labels itself.
    """
    lower = name.lower()
    if lower.endswith(".xlsx"):
        return _xlsx_bytes(_LEDGER_ROWS)
    if lower.endswith(".docx"):
        return _docx_bytes(_NARRATIVE + [
            "Prepared by: Finance Operations",
            "Distribution: Management only",
        ])
    if lower.endswith(".pdf"):
        return _pdf_bytes(_NARRATIVE + [
            "Prepared for management review.",
        ])
    if lower.endswith(".csv"):
        rows = _LEDGER_ROWS
        return ("\n".join(",".join(row) for row in rows) + "\n").encode("utf-8")
    return ("\n".join(_NARRATIVE) + "\n").encode("utf-8")


def _random_dir_name() -> str:
    return secrets.choice(DIR_POOL)


def _random_names(count: int) -> list[str]:
    rng = secrets.SystemRandom()
    pool = list(NAME_POOL)
    rng.shuffle(pool)
    return pool[:count]


def deploy(root, extra_dirs=None, names=None, randomize: bool = True,
           subdir: str | None = None) -> dict:
    """Create canary files and record their hashes.

    Existing canaries are left untouched (their current hash is recorded,
    not overwritten).  With ``randomize`` (the default) each requested base
    directory gets a plausible subdirectory and a random subset of
    document names, so a targeted attacker cannot enumerate one fixed path.
    ``randomize=False`` preserves the old deterministic layout for tests
    and for operators who pin locations through policy.
    """
    import socket

    from . import killswitch
    if killswitch.blocked(root, host=socket.gethostname(), risk="medium"):
        return {"error": "kill switch is engaged for this host — canary "
                         "deployment is blocked", "code": "KILLSWITCH"}
    root = Path(root)
    if subdir:
        subdir = _safe_name(subdir)
    base_dirs = [default_dir(root)] + [Path(d) for d in (extra_dirs or [])]
    entries = {}
    created = 0
    used_dirs = []
    for base in base_dirs:
        directory = Path(base)
        if randomize:
            directory = directory / (subdir or _random_dir_name())
        directory.mkdir(parents=True, exist_ok=True)
        resolved_dir = str(directory.resolve())
        if resolved_dir not in used_dirs:
            used_dirs.append(resolved_dir)
        chosen = ([_safe_name(n) for n in names] if names
                  else (_random_names(len(CANARY_NAMES)) if randomize
                        else list(CANARY_NAMES)))
        for name in chosen:
            path = directory / name
            if not path.exists():
                path.write_bytes(render_content(name))
                created += 1
            key = str(path.resolve())
            if key in entries:
                continue
            entries[key] = {
                "path": str(path.resolve()),
                "name": name,
                "sha256": _sha256(path),
                "size": path.stat().st_size,
            }
    manifest = {
        "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "randomized": bool(randomize),
        "canaries": sorted(entries.values(), key=lambda e: e["path"]),
    }
    # Atomic write: a crash mid-deploy leaves files on disk but never a
    # half-written manifest; the next deploy re-hashes and records them.
    agentstate.write_json(manifest_path(root), manifest)
    return {"deployed": len(entries), "created": created,
            "manifest": str(manifest_path(root)),
            "randomized": bool(randomize),
            "dirs": used_dirs}


def verify(root) -> dict:
    """Check every canary against its recorded hash.

    A missing or modified canary is a score-10 finding: ransomware or any
    destructive process touched a file that exists only to be touched."""
    mpath = manifest_path(root)
    if not mpath.exists():
        return {"error": "no canary manifest — run: plasma canary deploy",
                "checked": 0, "intact": 0, "tripped": [], "top_score": 0}
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"error": f"canary manifest unreadable: {exc}", "checked": 0,
                "intact": 0, "tripped": [], "top_score": 0}

    checked = intact = 0
    tripped = []
    for entry in manifest.get("canaries", []):
        path = Path(entry.get("path", ""))
        checked += 1
        if path.is_symlink():
            tripped.append({"path": str(path), "reason": "symlink"})
            continue
        if not path.exists():
            tripped.append({"path": str(path), "reason": "missing"})
            continue
        if _sha256(path) != entry.get("sha256"):
            tripped.append({"path": str(path), "reason": "modified"})
            continue
        intact += 1
    return {
        "checked": checked,
        "intact": intact,
        "tripped": tripped,
        "top_score": 10 if tripped else 0,
        "verdict": "canaries tripped" if tripped else "canaries intact",
    }


def status(root) -> dict:
    mpath = manifest_path(root)
    if not mpath.exists():
        return {"deployed": False,
                "hint": "plasma canary deploy --root <root>"}
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"deployed": True, "error": f"canary manifest unreadable: {exc}",
                "manifest": str(mpath)}
    result = verify(root)
    return {"deployed": True,
            "manifest": str(mpath),
            "deployed_at": manifest.get("deployed_at"),
            "randomized": manifest.get("randomized", False),
            "canaries": len(manifest.get("canaries", [])),
            "intact": result.get("intact", 0),
            "tripped": result.get("tripped", [])}
