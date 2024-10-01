"""Select platform for Aquaforte."""

from homeassistant.components.select import SelectEntity
from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte select entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities([
        AquaforteSelect(client, entry, "Operation Mode", "operation_mode", ["Shutdown", "Automatic", "Feed"])
    ])


class AquaforteSelect(SelectEntity):
    """Representation of an Aquaforte select entity."""

    def __init__(self, client, entry, name, select_key, options):
        """Initialize the select entity."""
        self._client = client
        self._attr_name = name
        self._select_key = select_key
        self._attr_options = options
        self._attr_current_option = options[0]
        self._attr_unique_id = f"{self._client._device_id}_{self._select_key}"

    @property
    def unique_id(self) -> str:
        """Return the unique ID for this entity."""
        return self._attr_unique_id

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        await self._client.async_set_mode(self._select_key, option)
        self._attr_current_option = option
        self.async_write_ha_state()
