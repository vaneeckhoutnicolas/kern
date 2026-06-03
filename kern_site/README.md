# kern_site

Public-facing marketing site for Kern. Single-file HTML pages, no build pipeline, deployable on any static host.

## Pages

| File | What it is |
|---|---|
| `index.html` | Landing page — hero, verticals, comparison, roadmap, Heimdall, founder, email capture |
| `whitepaper.html` | Whitepaper, rendered from `../docs/whitepaper.md` — sticky TOC sidebar, drop caps, scroll progress, print stylesheet |
| `manifesto.html` | Founder's manifesto — single column, 8 sections, dramatic typography, alternating light/dark |
| `how-it-works.html` | Mechanics, visualised — animated BFT round, gas flow, reward split, issuance curve, attestation lifecycle |
| `use-cases.html` | One animated diagram per use case (6 personas: equity, fund, real estate, public goods, energy, telco) |
| `github.html` | Source page — repo overview, quick-start terminal mockup, repo tree, docs index, contribute paths |
| `favicon.svg` / `favicon-dark.svg` / `apple-touch-icon.svg` | Site favicons (Kaun rune ᚴ, drawn as SVG paths to render identically without runic fonts) |
| `build_whitepaper.py` | Generator script — reads `../docs/whitepaper.md` and produces `whitepaper.html` |

## Design system

Shared design tokens across all pages — see the `<style>` block in any of the HTML files. Summary:

- **Display font**: Fraunces (variable serif with opsz/SOFT/WONK axes)
- **Body font**: Instrument Sans
- **Mono**: JetBrains Mono
- **Palette**: warm off-white (`#FAFAF7`), Nordic night ink (`#0E1A2B`), Skald amber accent (`#C2885E`), moss green (`#5C7553`)
- **Decoration**: runes ᚴ ᛟ ᚱ ᛁ ᛗ used as background accents and section markers

## Regenerate the whitepaper

After editing `../docs/whitepaper.md`:

```bash
python3 build_whitepaper.py
```

The script auto-generates the sidebar TOC, drop caps, § section markers, and reading time from the markdown source.

## Deploy

The site is fully static. Drop the four HTML files anywhere :

- **Netlify**: drag-and-drop the `kern_site/` folder on https://app.netlify.com/drop
- **Cloudflare Pages**: `wrangler pages deploy kern_site/`
- **GitHub Pages**: enable Pages on the `kern_site/` folder of the main branch (or copy to a `docs/` folder)
- **Vercel**: `vercel kern_site/`
- **Local test**: `cd kern_site && python3 -m http.server 8000`

## Email capture wiring

The forms currently show a local acknowledgement (`✓ Thank you. You're on the list.`). To wire them to a real provider:

1. Replace the `e.preventDefault()` JS handler at the bottom of `index.html` with a `fetch()` to your endpoint, OR
2. Replace the `<form class="capture">` tag with `<form action="https://...">` pointing at your provider's embed endpoint.

Providers known to integrate cleanly: Buttondown, ConvertKit, EmailOctopus, Mailchimp embed.

## License

Page chrome: Apache-2.0 (same as the Kern reference implementation).
Whitepaper and manifesto content: CC-BY-SA-4.0.
