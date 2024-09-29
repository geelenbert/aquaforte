"""Custom types for Aquaforte."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.loader import Integration

    from .api import AquaforteApiClient
    from .coordinator import AquaforteDataUpdateCoordinator


type IntegrationAquaforteConfigEntry = ConfigEntry[IntegrationAquaforteData]


@dataclass
class IntegrationAquaforteData:
    """Data for the Aquaforte integration."""

    client: AquaforteApiClient
    coordinator: AquaforteDataUpdateCoordinator
    integration: Integration
