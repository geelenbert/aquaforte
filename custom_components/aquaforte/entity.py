"""Aquaforte Entity Definitions."""

from homeassistant.helpers.entity import Entity
from homeassistant.helpers import device_registry as dr

from .const import DOMAIN


class AquaforteEntity(Entity):
    """Base class for all Aquaforte entities."""

    def __init__(self, client, entry, description=None):
        """Initialize the AquaForte entity."""
        self._client = client
        self._entry = entry
        self._attr_name = description.name
        self._attr_key = description.key
        self._attr_unique_id = f"{self._client._device_id}_{self._attr_key}"

    @property
    def device_info(self):
        """Return device information for this entity to link it to the device."""
        return {
            "identifiers": {(DOMAIN, self._client._device_id)},
            "name": f"Aquaforte Pump",
            "manufacturer": "AquaForte",
            "model": "Water Pump",
            "model_id": self._client._product_key,
            "sw_version": self._client._firmware_version,
            "connections": {(dr.CONNECTION_NETWORK_MAC, self._client._mac)},
            "serial_number": self._client._device_id
        }

    @property
    def unique_id(self) -> str:
        """Return the unique ID for this entity."""
        return self._attr_unique_id

    @property
    def available(self) -> bool:
        """Return if the entity is available."""
        return self._client._connected

    async def async_update(self) -> None:
        """Fetch data from the device."""
        #await self._client.async_get_status()
