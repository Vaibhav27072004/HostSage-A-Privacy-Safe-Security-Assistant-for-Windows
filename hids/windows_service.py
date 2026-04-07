from __future__ import annotations

import site
import sys
from pathlib import Path

from hids.runtime import load_monitoring_runtime

DEFAULT_SERVICE_NAME = "HostSage"
DEFAULT_SERVICE_DISPLAY_NAME = "HostSage: A Privacy-Safe Security Assistant for Windows"
DEFAULT_SERVICE_DESCRIPTION = "HostSage service for process-aware monitoring, explainable alerts, and privacy-safe reporting."

SERVICE_CONFIG_OPTION = "ConfigPath"

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:  # pragma: no cover
    servicemanager = None
    win32event = None
    win32service = None
    win32serviceutil = None


def service_support_available() -> bool:
    return (
        sys.platform == "win32"
        and servicemanager is not None
        and win32event is not None
        and win32service is not None
        and win32serviceutil is not None
    )


def _require_service_support() -> None:
    if sys.platform != "win32":
        raise RuntimeError("Windows Service support is only available on Windows.")
    if not service_support_available():
        raise RuntimeError(
            "pywin32 is required for Windows Service support. Install dependencies with 'pip install -r requirements.txt'."
        )


def _site_package_roots() -> list[Path]:
    paths = []
    for value in [*site.getsitepackages(), site.getusersitepackages()]:
        if value:
            paths.append(Path(value).resolve())
    return paths


def _is_path_within_roots(path: Path, roots: list[Path]) -> bool:
    resolved = path.resolve()
    return any(resolved.is_relative_to(root) for root in roots)


def validate_service_installation_environment() -> None:
    _require_service_support()

    import hids

    package_path = Path(hids.__file__).resolve()
    if _is_path_within_roots(package_path, _site_package_roots()):
        return

    raise RuntimeError(
        "Install the project into your Python environment before installing the Windows Service. "
        "Run 'pip install .' from the project root so pythonservice.exe can import the 'hids' package at boot."
    )


def _startup_type_from_name(startup: str) -> int:
    _require_service_support()
    startup_map = {
        "auto": win32service.SERVICE_AUTO_START,
        "manual": win32service.SERVICE_DEMAND_START,
        "disabled": win32service.SERVICE_DISABLED,
    }
    return startup_map[startup]


def _status_label(status_code: int) -> str:
    labels = {
        getattr(win32service, "SERVICE_STOPPED", -1): "stopped",
        getattr(win32service, "SERVICE_START_PENDING", -1): "start_pending",
        getattr(win32service, "SERVICE_STOP_PENDING", -1): "stop_pending",
        getattr(win32service, "SERVICE_RUNNING", -1): "running",
        getattr(win32service, "SERVICE_CONTINUE_PENDING", -1): "continue_pending",
        getattr(win32service, "SERVICE_PAUSE_PENDING", -1): "pause_pending",
        getattr(win32service, "SERVICE_PAUSED", -1): "paused",
    }
    return labels.get(status_code, f"unknown({status_code})")


def install_windows_service(
    *,
    config_path: Path,
    startup: str = "auto",
    start_immediately: bool = False,
) -> str:
    validate_service_installation_environment()

    resolved_config = config_path.resolve()
    if not resolved_config.exists():
        raise FileNotFoundError(f"Configuration file not found: {resolved_config}")
    load_monitoring_runtime(resolved_config)

    win32serviceutil.InstallService(
        pythonClassString="hids.windows_service.HostSageWindowsService",
        serviceName=DEFAULT_SERVICE_NAME,
        displayName=DEFAULT_SERVICE_DISPLAY_NAME,
        startType=_startup_type_from_name(startup),
        description=DEFAULT_SERVICE_DESCRIPTION,
    )
    win32serviceutil.SetServiceCustomOption(DEFAULT_SERVICE_NAME, SERVICE_CONFIG_OPTION, str(resolved_config))

    if start_immediately:
        win32serviceutil.StartService(DEFAULT_SERVICE_NAME)
        return f"Installed and started Windows Service '{DEFAULT_SERVICE_NAME}' using config {resolved_config}."

    return f"Installed Windows Service '{DEFAULT_SERVICE_NAME}' using config {resolved_config}."


def remove_windows_service() -> str:
    _require_service_support()
    win32serviceutil.RemoveService(DEFAULT_SERVICE_NAME)
    return f"Removed Windows Service '{DEFAULT_SERVICE_NAME}'."


def start_windows_service() -> str:
    _require_service_support()
    win32serviceutil.StartService(DEFAULT_SERVICE_NAME)
    return f"Started Windows Service '{DEFAULT_SERVICE_NAME}'."


def stop_windows_service() -> str:
    _require_service_support()
    win32serviceutil.StopService(DEFAULT_SERVICE_NAME)
    return f"Stopped Windows Service '{DEFAULT_SERVICE_NAME}'."


def get_windows_service_status() -> str:
    _require_service_support()
    status = win32serviceutil.QueryServiceStatus(DEFAULT_SERVICE_NAME)
    return _status_label(status[1])


def get_windows_service_config_path(service_name: str = DEFAULT_SERVICE_NAME) -> Path:
    _require_service_support()
    value = win32serviceutil.GetServiceCustomOption(service_name, SERVICE_CONFIG_OPTION)
    if not value:
        raise RuntimeError(
            f"No config path is stored for Windows Service '{service_name}'. Reinstall the service with --service-install."
        )
    return Path(str(value)).resolve()


class HostSageWindowsService(win32serviceutil.ServiceFramework if win32serviceutil is not None else object):
    _svc_name_ = DEFAULT_SERVICE_NAME
    _svc_display_name_ = DEFAULT_SERVICE_DISPLAY_NAME
    _svc_description_ = DEFAULT_SERVICE_DESCRIPTION

    def __init__(self, args):
        if win32serviceutil is None or win32event is None:  # pragma: no cover
            raise RuntimeError("pywin32 is not available.")

        super().__init__(args)
        self._service_name = args[0] if args else self._svc_name_
        self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._stop_requested = False

    def SvcStop(self):  # pragma: no cover
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop_requested = True
        win32event.SetEvent(self._stop_event)

    def SvcDoRun(self):  # pragma: no cover
        servicemanager.LogInfoMsg(f"{self._service_name} starting.")
        config_path = get_windows_service_config_path(self._service_name)
        config, service = load_monitoring_runtime(config_path)

        if config.api.enabled:
            servicemanager.LogInfoMsg(
                f"{self._service_name} is running in service mode. API serving is skipped; monitoring continues normally."
            )

        while not self._stop_requested:
            try:
                service.run_scan()
            except Exception as exc:
                servicemanager.LogErrorMsg(f"{self._service_name} scan failed: {exc}")

            wait_result = win32event.WaitForSingleObject(
                self._stop_event,
                max(1, config.runtime.interval_seconds) * 1000,
            )
            if wait_result == win32event.WAIT_OBJECT_0:
                break

        servicemanager.LogInfoMsg(f"{self._service_name} stopped.")


# Backward-compatible alias for older local installs that referenced the previous class name.
RealTimeHIDSWindowsService = HostSageWindowsService
