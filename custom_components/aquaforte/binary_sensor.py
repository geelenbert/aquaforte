"""Binary sensor platform for Aquaforte."""

from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorEntityDescription

from .const import DOMAIN
from .entity import AquaforteEntity



async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte binary sensor entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities(
        [
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_overcurrent", name="Fault Overcurrent", device_class="problem", )),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_overvoltage", name="Fault Overvoltage", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_high_temp", name="High Temperature", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_undervoltage", name="Fault Undervoltage", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_locked_rotor", name="Fault Locked Rotor", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_no_load", name="No Load", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_uart", name="Serial Port Connection Fault", device_class="problem")),
        ]
    )


class AquaforteBinarySensor(AquaforteEntity, BinarySensorEntity):
    """Representation of an Aquaforte binary sensor."""

    def __init__(self, client, entry, description):
        """Initialize the binary sensor."""
        super().__init__(client, entry, description)

        # Apply EntityDescription properties
        self._attr_device_class = description.device_class
        #self._attr_icon = description.icon

        self._attr_is_on = False

    @property
    def is_on(self) -> bool:
        """Return the state of the sensor."""
        return self._attr_is_on

    async def async_update(self):
        """Update the sensor state."""
        #self._attr_is_on = await self._client.async_get_fault(self._sensor_key)
        self.async_write_ha_state()
