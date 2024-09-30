"""Binary sensor platform for Aquaforte."""

from homeassistant.components.binary_sensor import BinarySensorEntity
from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte binary sensor entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities([
        AquaforteBinarySensor(client, entry, "Fault Overcurrent", "fault_overcurrent"),
        AquaforteBinarySensor(client, entry, "Fault Overvoltage", "fault_overvoltage"),
        AquaforteBinarySensor(client, entry, "High Temperature", "fault_high_temp"),
        AquaforteBinarySensor(client, entry, "Fault Undervoltage", "fault_undervoltage"),
        AquaforteBinarySensor(client, entry, "Fault Locked Rotor", "fault_locked_rotor"),
        AquaforteBinarySensor(client, entry, "No Load", "fault_no_load"),
        AquaforteBinarySensor(client, entry, "Serial Port Connection Fault", "fault_uart"),
    ])


class AquaforteBinarySensor(BinarySensorEntity):
    """Representation of an Aquaforte binary sensor."""

    def __init__(self, client, entry, name, sensor_key):
        """Initialize the binary sensor."""
        self._client = client
        self._attr_name = name
        self._sensor_key = sensor_key
        self._attr_is_on = False

    @property
    def unique_id(self) -> str:
        """Return the unique ID for this entity."""
        return f"{self._client.device_id}_{self.entity_description.key}"

    @property
    def is_on(self) -> bool:
        """Return the state of the sensor."""
        return self._attr_is_on

    async def async_update(self):
        """Update the sensor state."""
        self._attr_is_on = await self._client.async_get_fault(self._sensor_key)
        self.async_write_ha_state()
