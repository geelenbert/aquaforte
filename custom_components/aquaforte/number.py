"""Number platform for Aquaforte."""

from homeassistant.components.number import NumberEntity, NumberEntityDescription
from .const import DOMAIN
from .entity import AquaforteEntity

import logging
_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte number entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]

    # Create number entities
    numbers = [
        AquaforteNumber(client, entry, NumberEntityDescription(
            key="speed", name="Motor Speed", native_min_value=30, native_max_value=100, native_step=1, native_unit_of_measurement="%", icon="mdi:gauge")),
    ]

    # Register the number entities in Home Assistant
    async_add_entities(numbers)

    # Register entities in the EntityManager using their keys
    for number in numbers:
        client.entity_manager.register_entity(number._attr_key, number)


class AquaforteNumber(AquaforteEntity, NumberEntity):
    """Representation of an Aquaforte number entity."""

    def __init__(self, client, entry, description: NumberEntityDescription):
        """Initialize the number entity."""
        super().__init__(client, entry, description)

        # Apply EntityDescription properties using native_* attributes
        self._attr_native_min_value = description.native_min_value
        self._attr_native_max_value = description.native_max_value
        self._attr_native_step = description.native_step
        self._attr_native_unit_of_measurement = description.native_unit_of_measurement
        self._attr_icon = description.icon
        self._attr_native_value = 0.0  # Default to 0.0 if unknown

    async def async_added_to_hass(self):
        """Called when entity is added to Home Assistant."""
        _LOGGER.debug(f"Entity {self._attr_key} added to Home Assistant with initial value {self._attr_native_value}")
        self.async_write_ha_state()

    async def async_set_native_value(self, value: float) -> None:
        """Set the value via Home Assistant."""
        _LOGGER.debug(f"Sending control request for {self._attr_key} to set value {value}")
        await self._client.entity_manager.control_device(self._attr_key, int(value))  # Send control command to device
        # No immediate update to _attr_native_value; we wait for the device to report back

    def update_state(self, value: float):
        """Update the number state when the device reports back."""
        _LOGGER.debug(f"Updating {self._attr_key} state to {value} from device")
        self._attr_native_value = float(value)  # Ensure it's a float
        self.async_write_ha_state()  # Now update the Home Assistant state
