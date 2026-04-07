from __future__ import annotations

from pathlib import Path

from hids.collector import ConnectionCollector
from hids.config import HIDSConfig, load_config
from hids.detector import Detector
from hids.intel import ThreatIntelClient
from hids.logger import JsonAlertLogger
from hids.service import HIDSService
from hids.state import DetectionState


def build_monitoring_service(config: HIDSConfig) -> HIDSService:
    collector = ConnectionCollector()
    intel_client = ThreatIntelClient(config.threat_intel)
    detector = Detector(config.rules, intel_client)
    export_logger = JsonAlertLogger(
        config.runtime.export_path,
        config.runtime.scan_log_path,
        config.runtime.database_path,
    )
    detection_state = DetectionState.load(
        Path(config.runtime.state_path) if config.runtime.state_path else None,
        max_history=config.runtime.state_history_size,
    )
    return HIDSService(
        collector=collector,
        detector=detector,
        export_logger=export_logger,
        detection_state=detection_state,
        state_path=Path(config.runtime.state_path) if config.runtime.state_path else None,
        history_limit=config.runtime.history_limit,
    )


def load_monitoring_runtime(config_path: Path) -> tuple[HIDSConfig, HIDSService]:
    config = load_config(config_path)
    service = build_monitoring_service(config)
    return config, service
