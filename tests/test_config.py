from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hids.config import load_config


class ConfigTests(unittest.TestCase):
    def test_load_config_merges_known_network_file_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            known_ips = temp_path / "known_ips.txt"
            known_ips.write_text("# comment\n203.0.113.10\n198.51.100.0/24\n", encoding="utf-8")

            config_path = temp_path / "config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "rules": {
                            "known_networks": ["8.8.8.8/32"],
                            "known_network_files": ["known_ips.txt"],
                        }
                    }
                ),
                encoding="utf-8",
            )

            config = load_config(config_path)

            self.assertIn("8.8.8.8/32", config.rules.known_networks)
            self.assertIn("203.0.113.10", config.rules.known_networks)
            self.assertIn("198.51.100.0/24", config.rules.known_networks)


if __name__ == "__main__":
    unittest.main()
