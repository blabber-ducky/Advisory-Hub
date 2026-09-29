"""Template rendering regressions.

Jinja autoescapes every ``{{ ... }}`` expression, including string literals
written in the template itself — so ``{{ value or '&mdash;' }}`` renders the
text ``&amp;mdash;`` and the browser shows a literal "&mdash;". Placeholders
inside expressions must be the character itself (``'—'``), never an entity.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from advisory_hub.web.inventory import templates

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "advisory_hub" / "web" / "templates"

# A quoted string literal inside a {{ ... }} or {% ... %} tag that contains
# an HTML entity (&mdash;, &nbsp;, &#8212;, ...).
_EXPR = re.compile(r"\{[{%].*?[}%]\}", re.DOTALL)
_ENTITY_LITERAL = re.compile(r"""(['"])[^'"]*&(?:[a-zA-Z]+|#\d+|#x[0-9a-fA-F]+);[^'"]*\1""")


def test_no_html_entities_inside_jinja_string_literals() -> None:
    offenders = []
    for path in sorted(TEMPLATE_DIR.glob("*.html")):
        text = path.read_text()
        for expr in _EXPR.finditer(text):
            if _ENTITY_LITERAL.search(expr.group(0)):
                line = text.count("\n", 0, expr.start()) + 1
                offenders.append(f"{path.name}:{line}: {expr.group(0)[:80]}")
    assert not offenders, "HTML entity inside a Jinja expression (autoescaped):\n" + "\n".join(
        offenders
    )


def test_empty_values_render_as_dash_not_escaped_entity() -> None:
    source = SimpleNamespace(
        id=uuid4(),
        kind=SimpleNamespace(value="CSV_DESKTOP_CENTRAL"),
        mode=SimpleNamespace(value="AGGREGATE"),
        credential_id=None,
        config=None,
        schedule_cron=None,
        last_sync_error=None,
    )
    html = templates.get_template("_inventory_detail.html").render(
        source=source, history=[], can_manage=False, snapshots=[]
    )

    assert "&amp;mdash;" not in html
    assert "<dt>Sync schedule</dt><dd>—</dd>" in html
