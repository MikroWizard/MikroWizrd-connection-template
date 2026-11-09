# MikroWizard Connection Templates

Device connection templates (prompt patterns, commands, error patterns, pagination, privilege
escalation, hooks) used by [MikroWizard](https://mikrowizard.com) to talk to network devices of
every brand.

## Source and license

The templates started from the community connection templates of
[rConfig/rConfig-templates](https://github.com/rconfig/rConfig-templates) (GPL-3.0). They were
converted from YAML to JSON and have since been modified and extended by MikroWizard (prompt
handling, error patterns, privilege escalation, new brands and templates, RDP/VNC templates).

Everything in this repository is shared under the **GNU General Public License v3.0**, the
license of the original rConfig templates; see `LICENSE`.

## Contents

| Path | Description |
|------|-------------|
| `LICENSE` | GPL-3.0 (from the original rConfig repository) |
| `templates.json`, `brands.json` | The original rConfig templates converted to JSON (59 templates, 25 brands), kept unchanged for reference |
| `catalog/templates/<brand>/<os_type>.json` | Current MikroWizard templates, one file each: `key`, `revision`, `edition` (free/pro), `min_app_version`, `changelog`, `previous_hashes` / `previous_field_hashes` (maintained by the build), `content` (the template fields) |
| `catalog/brands.json` | Brands and display names |
| `dist/catalog.json`, `dist/catalog.json.sig` | Last published catalog and its signature |
| `tools/catalog_tool.py` | build / sign / verify |
| `public.b64` | MikroWizard catalog public key (Ed25519) |
| `publish.sh` | Upload a signed catalog to mikrowizard.com |

## How MikroWizard uses it

MikroWizard servers receive the templates as a **signed catalog**: from mikrowizard.com, from the
latest GitHub release of this repository as a fallback, bundled with each MikroWizard release, or
as a file imported in the Template Manager. Every catalog is signed offline with the MikroWizard
Ed25519 key (`public.b64`); servers reject anything else.

Templates an install never edited are updated with one click or automatically ("safe"). Edited
templates are offered per field ("review"), and every change can be reverted from the template
history.

## Contributing a template change

1. Edit the file under `catalog/templates/` (content only; the build bumps `revision`).
2. Add a line to `changelog` describing the change.
3. Open a pull request: CI builds the catalog and validates it: every template carries every field
   (`null` when unused), no unknown fields, and every regular expression compiles.

`display_name` is set by MikroWizard (read-only for system templates); changing it also bumps the
revision. A new template field (a new `device_templates` column) needs a MikroWizard release first:
add it to `CONTENT_FIELDS` and `FIELD_MIN_APP_VERSION` in `tools/catalog_tool.py` (and in MikroWizard),
then templates that use it must set `min_app_version` to that release.

## Release (maintainers, offline key)

```
python3 tools/catalog_tool.py build --src catalog --previous dist/catalog.json --out dist/catalog.json.new
mv dist/catalog.json.new dist/catalog.json
python3 tools/catalog_tool.py sign --key /path/to/private.pem dist/catalog.json
python3 tools/catalog_tool.py verify --pub public.b64 dist/catalog.json
gh release create catalog-<N> dist/catalog.json dist/catalog.json.sig    # GitHub fallback (must be the latest release)
WP_USER=... WP_APP_PASSWORD='...' ./publish.sh dist/catalog.json         # mikrowizard.com
```
The GitHub fallback downloads `releases/latest/download/catalog.json`, so the newest catalog release
must stay marked as **Latest**.
