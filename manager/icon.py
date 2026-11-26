"""The manager's own icon (the gatehouse) in a colour picked under Settings.

Two deployments, e.g. DMZ and internal, can get different colours so their browser tabs tell
them apart. The SVG is drawn here per colour; the 180 px apple-touch-icon PNGs are made once
from it and kept in static/ as apple-touch-icon-<colour>.png."""

DEFAULT = "purple"
WOOD = ("#d49a62", "#a8692f", "#7a4519", "#4a2a10")
GOLD = ("#ffd98f", "#f4b860", "#d18f2e", "#9a6010")

# name: (label, wall gradient light→dark, outline, highlight, face, door, touch-icon background)
COLOURS = {
    "purple": ("Purple", ("#b45cd6", "#7a1aa0", "#52086d"), "#3a0550", "#efd2fb", "#24032f", GOLD, "#f1e4f7"),
    "yellow": ("Yellow", ("#ffe680", "#f2c40f", "#c29400"), "#5e4500", "#fffbe0", "#2b2100", WOOD, "#fdf6d8"),
    "orange": ("Orange", ("#ffb36b", "#f07a12", "#b85200"), "#5c2600", "#ffe8d1", "#2b1000", WOOD, "#fde9d8"),
    "red": ("Red", ("#ff7d7d", "#d12f2f", "#8f1515"), "#4d0808", "#ffe0e0", "#2b0303", GOLD, "#fbe2e2"),
    "green": ("Green", ("#7ee08f", "#2e9e47", "#1b6b2e"), "#0d3d18", "#dcf7e1", "#06210c", GOLD, "#e2f5e6"),
    "blue": ("Blue", ("#6cb8ff", "#1f6fd1", "#0f4796"), "#082a5c", "#dbeeff", "#041733", GOLD, "#e1edfb"),
}

SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <defs>
    <linearGradient id="wall" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{w0}"/>
      <stop offset=".55" stop-color="{w1}"/>
      <stop offset="1" stop-color="{w2}"/>
    </linearGradient>
    <linearGradient id="door" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{d0}"/>
      <stop offset=".55" stop-color="{d1}"/>
      <stop offset="1" stop-color="{d2}"/>
    </linearGradient>
  </defs>
  <!-- Gatehouse wall with battlements -->
  <path d="M4 59V8h9.5v6h6V8h9.5v6h6V8h9.5v6h6V8H60v51z" fill="url(#wall)" stroke="{line}" stroke-width="2.6" stroke-linejoin="round"/>
  <path d="M10 33v-9a5 5 0 0 1 3-4.6" fill="none" stroke="{hi}" stroke-width="2.6" stroke-linecap="round" opacity=".8"/>
  <!-- Gate -->
  <path d="M22 59V47a10 10 0 0 1 20 0v12z" fill="url(#door)" stroke="{line}" stroke-width="2.4" stroke-linejoin="round"/>
  <path d="M32 38v21" fill="none" stroke="{d3}" stroke-width="1.8" stroke-linecap="round" opacity=".7"/>
  <!-- Face -->
  <circle cx="25" cy="27" r="2.1" fill="{face}"/>
  <circle cx="39" cy="27" r="2.1" fill="{face}"/>
  <circle cx="25.6" cy="26.3" r=".65" fill="#fff"/>
  <circle cx="39.6" cy="26.3" r=".65" fill="#fff"/>
  <ellipse cx="21.6" cy="31" rx="2.4" ry="1.4" fill="#e76f51" opacity=".6"/>
  <ellipse cx="42.4" cy="31" rx="2.4" ry="1.4" fill="#e76f51" opacity=".6"/>
  <path d="M29 31q3 3 6 0" fill="none" stroke="{face}" stroke-width="1.8" stroke-linecap="round"/>
</svg>
"""


def valid(colour):
    return colour if colour in COLOURS else DEFAULT


def svg(colour):
    _, wall, line, hi, face, door, _ = COLOURS[valid(colour)]
    return SVG.format(w0=wall[0], w1=wall[1], w2=wall[2], d0=door[0], d1=door[1], d2=door[2], d3=door[3],
                      line=line, hi=hi, face=face)


def touch_file(colour):
    """The static file name of the 180 px home-screen icon."""
    return f"apple-touch-icon-{valid(colour)}.png"


def options():
    return [{"value": k, "label": v[0], "swatch": v[1][1]} for k, v in COLOURS.items()]
