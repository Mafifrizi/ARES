"""AUDIT run-1 M2: untrusted finding text must be escaped before it is rendered
into a Markdown report, so a crafted title/description cannot inject headings,
links, code fences, raw HTML or table columns."""

from ares.modules.reporting.report_gen import _escape_md


def test_escapes_link_and_html_and_code_markers():
    out = _escape_md("[click](javascript:alert(1)) `code` <img src=x>")
    # Link/code/HTML structural characters are backslash-escaped, so none remain
    # unescaped to form a real link, fence or tag.
    for ch in ("`", "[", "]", "<", ">"):
        assert ch not in out.replace("\\" + ch, "")


def test_escapes_leading_heading_and_table_pipe():
    assert _escape_md("# Fake Heading").startswith("\\#")
    assert "\\|" in _escape_md("col1 | col2")


def test_single_line_collapses_newlines():
    out = _escape_md("line1\nline2\n\nline3", single_line=True)
    assert "\n" not in out
    assert out == "line1 line2 line3"


def test_plain_text_is_preserved_readably():
    # Ordinary words and spaces are untouched; only structural chars are escaped.
    assert _escape_md("Weak TLS on dc01") == "Weak TLS on dc01"
