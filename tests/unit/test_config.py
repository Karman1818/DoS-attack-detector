"""Unit tests for DetectionConfig validation."""

import pytest

from dos_detector.config import DetectionConfig


@pytest.mark.unit
def test_default_config_is_valid() -> None:
    config = DetectionConfig()
    config.validate()
    assert config.window_size_seconds == 1.0
    assert config.syn_flood_pps_threshold == 100.0


@pytest.mark.unit
def test_invalid_window_size_raises_value_error() -> None:
    config = DetectionConfig(window_size_seconds=0.0)
    with pytest.raises(ValueError, match="window_size_seconds must be positive"):
        config.validate()


@pytest.mark.unit
def test_invalid_syn_threshold_raises_value_error() -> None:
    config = DetectionConfig(syn_flood_pps_threshold=-5.0)
    with pytest.raises(ValueError, match="syn_flood_pps_threshold must be positive"):
        config.validate()
