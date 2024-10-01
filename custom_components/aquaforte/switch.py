"""Switch platform for Aquaforte."""

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN
from .entity import AquaforteEntity


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte switch entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities(
        [
            AquaforteSwitch(client, entry, SwitchEntityDescription(key="power", name="Power", icon="mdi:power")),
            AquaforteSwitch(client, entry, SwitchEntityDescription(key="pause", name="Pause", icon="mdi:pause")),
        ]
    )

class AquaforteSwitch(AquaforteEntity, SwitchEntity):
    """Representation of an Aquaforte switch."""

    def __init__(self, client, entry, description):
        """Initialize the switch."""
        super().__init__(client, entry, description)

        # Apply EntityDescription properties
        self._attr_icon = description.icon

        self._is_on = False

    @property
    def is_on(self) -> bool:
        """Return the switch state."""
        return self._is_on

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        #await self._client.async_turn_on(self.entity_description.key)
        self._is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        #await self._client.async_turn_off(self.entity_description.key)
        self._is_on = False
        self.async_write_ha_state()
