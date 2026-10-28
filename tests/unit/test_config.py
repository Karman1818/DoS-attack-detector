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


@pytest.mark.unit
def test_invalid_detector_mode_raises_value_error() -> None:
    config = DetectionConfig(detector_mode="invalid_engine")
    with pytest.raises(ValueError, match="detector_mode must be one of"):
        config.validate()


@pytest.mark.unit
def test_invalid_ml_contamination_raises_value_error() -> None:
    config_zero = DetectionConfig(ml_contamination=0.0)
    with pytest.raises(ValueError, match="ml_contamination must be between"):
        config_zero.validate()

    config_high = DetectionConfig(ml_contamination=0.6)
    with pytest.raises(ValueError, match="ml_contamination must be between"):
        config_high.validate()
