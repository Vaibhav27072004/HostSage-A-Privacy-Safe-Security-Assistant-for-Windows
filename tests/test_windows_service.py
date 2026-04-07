from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from hids.windows_service import _is_path_within_roots, _status_label, validate_service_installation_environment

try:
    import win32service
except ImportError:  # pragma: no cover
    win32service = None


class WindowsServiceTests(unittest.TestCase):
    def test_is_path_within_roots_detects_nested_path(self) -> None:
        path = Path("C:/Projects/HIDS/hids/__init__.py")
        roots = [Path("C:/Projects/HIDS"), Path("C:/Other")]
        self.assertTrue(_is_path_within_roots(path, roots))

    @unittest.skipUnless(win32service is not None, "pywin32 not installed")
    def test_status_label_maps_running_state(self) -> None:
        self.assertEqual(_status_label(win32service.SERVICE_RUNNING), "running")

    def test_validate_environment_requires_installed_package(self) -> None:
        with mock.patch("hids.windows_service._require_service_support"), mock.patch(
            "hids.windows_service._is_path_within_roots",
            return_value=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "pip install"):
                validate_service_installation_environment()


if __name__ == "__main__":
    unittest.main()
