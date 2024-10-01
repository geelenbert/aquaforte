"""Number platform for Aquaforte."""

from homeassistant.components.number import NumberEntity, NumberEntityDescription
from .const import DOMAIN
from .entity import AquaforteEntity


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte number entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities([AquaforteNumber(client, entry, NumberEntityDescription(key="motor_speed", name="Motor Speed", min_value=30, max_value=100, step=1, unit_of_measurement="%", icon="mdi:engine"))])


class AquaforteNumber(AquaforteEntity, NumberEntity):
    """Representation of an Aquaforte number entity."""

    def __init__(self, client, entry, description):
        """Initialize the number entity."""
        super().__init__(client, entry, description)

        # Apply EntityDescription properties
        self._attr_min_value = description.min_value
        self._attr_max_value = description.max_value
        self._attr_step = description.step
        self._attr_unit_of_measurement = description.unit_of_measurement
        self._attr_icon = description.icon


    async def async_set_value(self, value: float) -> None:
        """Set the value."""
        #await self._client.async_set_speed(self._control_key, value)
        self._attr_value = value
        self.async_write_ha_state()
