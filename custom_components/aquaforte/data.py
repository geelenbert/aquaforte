<<<<<<< HEAD
"""Custom types for Aquaforte."""
=======
"""Custom types for integration_blueprint."""
>>>>>>> 734b058 (Initial rebranding to Aquaforte)

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry
    from homeassistant.loader import Integration

<<<<<<< HEAD
    from .api import IntegrationAquaforteApiClient
    from .coordinator import AquaforteDataUpdateCoordinator


type IntegrationAquaforteConfigEntry = ConfigEntry[IntegrationAquaforteData]


@dataclass
class IntegrationAquaforteData:
    """Data for the Aquaforte integration."""

    client: IntegrationAquaforteApiClient
    coordinator: AquaforteDataUpdateCoordinator
=======
    from .api import IntegrationBlueprintApiClient
    from .coordinator import BlueprintDataUpdateCoordinator


type IntegrationBlueprintConfigEntry = ConfigEntry[IntegrationBlueprintData]


@dataclass
class IntegrationBlueprintData:
    """Data for the Blueprint integration."""

    client: IntegrationBlueprintApiClient
    coordinator: BlueprintDataUpdateCoordinator
>>>>>>> 734b058 (Initial rebranding to Aquaforte)
    integration: Integration
