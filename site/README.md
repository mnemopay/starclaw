# StarClaw website

Static HTML, CSS and JavaScript. No build step, framework, analytics, cookies, or external runtime requests. Fonts are hosted locally; their SIL Open Font License notices are in `assets/fonts/`.

## Preview

```powershell
python -m http.server 4173 --bind 127.0.0.1 --directory site
```

Open `http://127.0.0.1:4173`. The pages also support static hosting and relative paths.

## Design

`DESIGN.md` records the visual system. The homepage uses original procedural canvas artwork, accessible workflow tabs, a walkthrough dialog, clipboard feedback and a mobile menu. Workflow activity is explicitly illustrative; the website does not connect to an agent runtime.

The canvas pauses off-screen and when the browser tab is hidden, uses a bounded point count, and respects reduced motion. Documentation and security content remain available without JavaScript. Installation commands remain ordinary selectable text.

## Deployment

Publish the contents of `site/` to the existing static hosting project. No server or application dependencies are required. The existing production domain is not changed by local preview.

## Content

The repository documentation is authoritative for capabilities, versions and limits. Do not add invented customers, statistics, certification claims or claims that prompt injection is prevented. Keep the alpha status and security boundaries visible.
