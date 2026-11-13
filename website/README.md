# Plasma — one-page overview

A self-contained HTML5 page: no build step, no external fonts, scripts or
images. Open `index.html` directly in a browser, or serve it locally:

```bash
python3 -m http.server 8080 --directory website
# open http://localhost:8080
```

It is published with the docs at
<https://drolu.github.io/plasma/onepager.html> by the docs workflow, which
copies this file into the built site.

Features: responsive layout, dark/light theme (persisted, OS-following),
inline SVG architecture, radar and coverage diagrams, score meter, scroll
reveal with a no-JS fallback, copy buttons, and `?all=1` for static
captures (reveals every section and fills counters).

Keep it in sync with the version and numbers in the docs when a release
changes the detection or response surface.
