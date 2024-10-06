"""Switch platform for Aquaforte."""

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN
from .entity import AquaforteEntity


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte switch entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    # Create switch entities
    switches = [
            # Map the key of the switch to the same key as the endpoint on the aquaforte device
            AquaforteSwitch(client, entry, SwitchEntityDescription(key="SwitchON", name="Power", icon="mdi:power")),
            AquaforteSwitch(client, entry, SwitchEntityDescription(key="FeedSwitch", name="Pause", icon="mdi:pause")),
            AquaforteSwitch(client, entry, SwitchEntityDescription(key="TimerON", name="Timer", icon="mdi:timer")),
    ]

    # Register the switches in Home Assistant
    async_add_entities(switches)

    # Register entities in the EntityManager using their keys
    for switch in switches:
        client.entity_manager.register_entity(switch._attr_key, switch)


class AquaforteSwitch(AquaforteEntity, SwitchEntity):
    """Representation of an Aquaforte switch."""

    def __init__(self, client, entry, description):
        """Initialize the switch."""
        super().__init__(client, entry, description)

        # Apply EntityDescription properties
        self._attr_icon = description.icon

        # Set default state
        self._is_on = False

    @property
    def is_on(self) -> bool:
        """Return the switch state."""
        return self._is_on

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        await self._client.entity_manager.control_device(self._attr_key, "on")

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        await self._client.entity_manager.control_device(self._attr_key, "off")

    def update_state(self, state: bool):
        """Update the switch state externally from the EntityManager."""
        self._is_on = state
        self.async_write_ha_state()
