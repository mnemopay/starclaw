# StarClaw site

Plain static site: HTML, one CSS file, no JavaScript, no build step, no external requests.

Pages: `index.html`, `security/index.html`, `docs/index.html`, `download/index.html`. All internal links are relative, so the site works opened straight from disk and from any sub-path on a static host.

## Preview

Open `site/index.html` in a browser, or serve the folder:

```bash
npx serve site        # or: python -m http.server --directory site
```

## Deploy

Upload the contents of `site/` unchanged to any static host (GitHub Pages, Cloudflare Pages, Netlify, S3, nginx). There is nothing to configure.

## Keeping it honest

Version numbers (`2.0.0-alpha.3` on npm, `2.0.0-alpha.5` in the repo), command lists and limits are copied by hand from `README.md`, `SECURITY.md`, `CHANGELOG.md`, `package.json` and `src/cli.ts`. When those change, update the pages. Do not add statistics, testimonials, logos or certification claims that the repository cannot back up.
