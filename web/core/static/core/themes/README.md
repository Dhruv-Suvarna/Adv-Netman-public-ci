# Theme artwork drop-in locations

The ten operator-supplied UI/UX artwork assets referenced by the Phase 3
brief were **not found** in the repository or session filesystem when this
foundation was built (searched: this repo, `~/Pictures`, `~/Downloads`,
`~/Desktop`, `~/Documents`, and the Codex/Claude attachment caches — only
pasted-text attachments were present, no images). No substitute artwork was
generated or downloaded.

Drop each real asset in the matching directory below, named
`watermark.<ext>` (`svg` preferred, `png`/`webp`/`jpg`/`jpeg` also work —
`core/theme_assets.py` checks in that order). Nothing else needs to
change: `core/theme_assets.resolve_watermark_url()` looks for a matching
file at render time and the CSS fallback gradient in `tokens.css`
(`.theme-watermark--fallback`) is used automatically whenever it's absent.

| Directory | Theme / context | Suggested subject (from the Phase 3 brief) |
|---|---|---|
| `brand/` | global (all themes, header brand mark) | app identity mark |
| `minimal/` | Basic Minimal | subtle network/circuit motif |
| `dark/` | Dark Mode | restrained NOC/console motif |
| `dark_angels/core/` | Dark Angels — Core | Lion/knightly-helm-inspired watermark |
| `dark_angels/deathwing/` | Dark Angels — Deathwing | terminator-helm-style watermark |
| `dark_angels/ravenwing/` | Dark Angels — Ravenwing | Ravenwing-style watermark |
| `dark_angels/hexagrammaton/` | Dark Angels — Hexagrammaton | six-part heraldic/radial motif |
| `mechanicus/core/` | Adeptus Mechanicus — Core | cog/gear or cogitator-style mark |
| `mechanicus/forge/` | Adeptus Mechanicus — Forge | forge/industrial motif |
| `mechanicus/monitoring/` | Adeptus Mechanicus — Data/Monitoring | data/scan-line motif |

This ten-slot layout is this foundation's best-effort inference from the
Phase 3 theme/variant list (1 global + 1 + 1 + 4 + 3 = 10), not a confirmed
mapping to the operator's actual ten filenames. When the real assets
arrive, confirm which file goes in which slot (rename only if the original
name is unsafe for static serving, and document the rename) rather than
assuming this table is exactly right.

Do not resize/recompress the originals — the browser/CSS sizing rules in
`.theme-watermark` (`base.css`) handle scaling; only replace a file here if
it is later swapped for a corrected asset.
