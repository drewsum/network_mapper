"""Refresh the OUI snapshot bundled in the package from the IEEE registries.

Run from the repo root: `cd backend && uv run python ../scripts/update_oui_bundle.py`.
The running collector refreshes its DB copy on its own; this only updates the offline
fallback that ships in the image.
"""

from netmap import oui

entries = oui.download()
oui.write_bundle(entries.items())
print(f"wrote {len(entries)} prefixes to {oui.BUNDLE}")
