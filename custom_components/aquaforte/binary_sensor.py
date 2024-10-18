"""Binary sensor platform for Aquaforte."""

from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorEntityDescription

from .const import DOMAIN
from .entity import AquaforteEntity

import logging
_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte binary sensor entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]

    # Create switch entities
    binairy_sensors = [
            # Map the key of the switch to the same key as the endpoint on the aquaforte device
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_overcurrent", name="Fault Overcurrent", device_class="problem", )),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_overvoltage", name="Fault Overvoltage", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_high_temp", name="High Temperature", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_undervoltage", name="Fault Undervoltage", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_locked_rotor", name="Fault Locked Rotor", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_no_load", name="No Load", device_class="problem")),
            AquaforteBinarySensor(client, entry, BinarySensorEntityDescription(key="fault_uart", name="Serial Port Connection Fault", device_class="problem")),
    ]

    # Register the switches in Home Assistant
    async_add_entities(binairy_sensors)

    # Register entities in the EntityManager using their keys
    for binairy_sensor in binairy_sensors:
        client.entity_manager.register_entity(binairy_sensor._attr_key, binairy_sensors)


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

    # async def async_update(self):
    #     """Update the sensor state."""
    #     #self._attr_is_on = await self._client.async_get_fault(self._sensor_key)
    #     self.async_write_ha_state()

    def update_state(self, state: bool):
        """Update the binary sensor state externally from the EntityManager."""
        self._attr_is_on = state
        self.async_write_ha_state()