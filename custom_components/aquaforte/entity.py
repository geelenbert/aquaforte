"""Aquaforte Entity Definitions."""

from homeassistant.helpers.entity import Entity, EntityDescription
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.helpers.device_registry import DeviceInfo
from .api import AquaforteApiClient
from .const import DOMAIN


class AquaforteEntity(Entity):
    """Base class for all Aquaforte entities."""

    def __init__(self, client: AquaforteApiClient, description: EntityDescription = None) -> None:
        """Initialize the base entity."""
        self._client = client
        self.entity_description = description
        self._attr_name = f"Aquaforte {self._client.device_id} {description.name}" if description else f"Aquaforte {self._client.device_id}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, self._client.device_id)},
            name=f"Aquaforte {self._client.device_id}",
            manufacturer="Aquaforte",
            model="Water Pump",
            sw_version=self._client.firmware_version
        )

    @property
    def unique_id(self) -> str:
        """Return the unique ID for this entity."""
        if self.entity_description:
            return f"{self._client.device_id}_{self.entity_description.key}"
        return self._client.device_id

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        return self._attr_device_info

    @property
    def available(self) -> bool:
        """Return if the entity is available."""
        return self._client.connected

    async def async_update(self) -> None:
        """Fetch data from the device."""
        await self._client.async_get_status()
