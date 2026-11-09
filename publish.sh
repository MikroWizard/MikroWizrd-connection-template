#!/bin/bash
# Publish a signed catalog to mikrowizard.com (plugin "MikroWizard Template Catalog").
#   WP_USER=admin WP_APP_PASSWORD='xxxx xxxx xxxx xxxx' ./publish.sh dist/catalog.json [stable|beta]
# WP_APP_PASSWORD: Users > Profile > Application Passwords (administrator account).
set -euo pipefail
CATALOG=${1:?catalog.json}
CHANNEL=${2:-stable}
python3 tools/catalog_tool.py verify --pub public.b64 "$CATALOG"
python3 - "$CATALOG" "$CHANNEL" > /tmp/mw_publish.json <<'PY'
import json, sys
print(json.dumps({"catalog": open(sys.argv[1], encoding="utf-8").read(),
                  "signature": open(sys.argv[1] + ".sig").read().strip(), "channel": sys.argv[2]}))
PY
curl -sS -u "${WP_USER:?}:${WP_APP_PASSWORD:?}" -H 'Content-Type: application/json' \
     --data-binary @/tmp/mw_publish.json https://mikrowizard.com/wp-json/mikrowizard/v1/templates_publish
echo
rm -f /tmp/mw_publish.json
