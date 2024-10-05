"""Select platform for Aquaforte."""

from homeassistant.components.select import SelectEntity, SelectEntityDescription
from .const import DOMAIN
from .entity import AquaforteEntity

async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte select entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities([
        AquaforteSelect(client, entry, SelectEntityDescription(key="operation_mode", name="Operation Mode", options=["Shutdown", "Automatic", "Feed"], icon="mdi:cog"))
    ])


class AquaforteSelect(AquaforteEntity, SelectEntity):
    """Representation of an Aquaforte select entity."""

    def __init__(self, client, entry, description):
        """Initialize the select entity."""
        super().__init__(client, entry, description)

        # Apply EntityDescription properties
        self._attr_options = description.options
        self._attr_icon = description.icon

        self._attr_current_option = description.options[0]

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        await self._client.control_device(self._attr_key, option)


    def update_state(self, option: str):
        """Update the select state externally from the EntityManager."""
        self._attr_current_option = option
        self.async_write_ha_state()