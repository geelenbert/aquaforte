"""Number platform for Aquaforte."""

from homeassistant.components.number import NumberEntity
from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte number entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities([AquaforteNumber(client, entry, "Speed Control", "speed", 30, 100)])


class AquaforteNumber(NumberEntity):
    """Representation of an Aquaforte number entity."""

    def __init__(self, client, entry, name, control_key, min_value, max_value):
        """Initialize the number entity."""
        self._client = client
        self._attr_name = name
        self._control_key = control_key
        self._attr_min_value = min_value
        self._attr_max_value = max_value
        self._attr_value = min_value
        self._attr_unique_id = f"{self._client._device_id}_{self._control_key}"

    @property
    def unique_id(self) -> str:
        """Return the unique ID for this entity."""
        return self._attr_unique_id

    async def async_set_value(self, value: float) -> None:
        """Set the value."""
        await self._client.async_set_speed(self._control_key, value)
        self._attr_value = value
        self.async_write_ha_state()
