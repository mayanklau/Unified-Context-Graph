#!/usr/bin/env python3
"""Write the API's OpenAPI description to a file, without starting a server or a database.

python scripts/export_openapi.py docs/openapi.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/openapi.json")
    from secgraph.api.app import create_app
    from secgraph.config import Settings

    settings = Settings(_env_file=None, database_url="sqlite://", log_level="ERROR")  # type: ignore[call-arg]
    schema = create_app(settings).openapi()
    target.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{target}: {len(schema['paths'])} paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
