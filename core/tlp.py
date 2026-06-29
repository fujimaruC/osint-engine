"""
core/tlp.py
TLP (Traffic Light Protocol) classification untuk report marking.
Standard NATO/FIRST untuk information sharing.
"""

TLP_LEVELS = {
    "WHITE": {
        "label": "TLP:WHITE",
        "color": "#ffffff",
        "bg": "#2a2a2a",
        "description": "Tidak ada batasan distribusi. Boleh dipublikasikan.",
        "css_class": "tlp-white",
    },
    "GREEN": {
        "label": "TLP:GREEN",
        "color": "#33cc33",
        "bg": "#0d2b0d",
        "description": "Terbatas untuk komunitas/organisasi. Jangan dipublikasikan.",
        "css_class": "tlp-green",
    },
    "AMBER": {
        "label": "TLP:AMBER",
        "color": "#ffb300",
        "bg": "#2b1f00",
        "description": "Terbatas untuk internal organisasi dan klien terkait.",
        "css_class": "tlp-amber",
    },
    "RED": {
        "label": "TLP:RED",
        "color": "#ff3333",
        "bg": "#2b0000",
        "description": "RAHASIA — Hanya untuk penerima yang ditunjuk. Jangan diteruskan.",
        "css_class": "tlp-red",
    },
}


def get_tlp_banner_html(level: str, operator: str = "", unit: str = "") -> str:
    """Generate HTML banner TLP untuk header/footer report."""
    level = level.upper()
    if level not in TLP_LEVELS:
        level = "AMBER"

    t = TLP_LEVELS[level]
    meta_parts = []
    if operator:
        meta_parts.append(f"Operator: <strong>{operator}</strong>")
    if unit:
        meta_parts.append(f"Unit: <strong>{unit}</strong>")
    meta_str = " &nbsp;|&nbsp; ".join(meta_parts) if meta_parts else ""

    return f"""
<div class="tlp-banner" style="
  background: {t['bg']};
  border: 2px solid {t['color']};
  border-radius: 6px;
  padding: 10px 20px;
  margin-bottom: 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-family: monospace;
">
  <span style="
    color: {t['color']};
    font-weight: bold;
    font-size: 15px;
    letter-spacing: 2px;
  ">{t['label']}</span>
  <span style="color: #aaa; font-size: 12px;">{t['description']}</span>
  <span style="color: #888; font-size: 11px;">{meta_str}</span>
</div>"""


def get_tlp_footer_html(level: str) -> str:
    """Footer marking untuk halaman report."""
    level = level.upper()
    if level not in TLP_LEVELS:
        level = "AMBER"
    t = TLP_LEVELS[level]
    return f"""
<div style="
  text-align: center;
  padding: 12px;
  border-top: 1px solid {t['color']}44;
  color: {t['color']};
  font-family: monospace;
  font-size: 13px;
  letter-spacing: 3px;
  font-weight: bold;
">{t['label']} — DISTRIBUSI TERBATAS</div>"""
