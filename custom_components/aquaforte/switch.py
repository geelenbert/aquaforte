"""Switch platform for Aquaforte."""

from homeassistant.components.switch import SwitchEntity, SwitchEntityDescription
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):
    """Set up Aquaforte switch entities from a config entry."""
    client = hass.data[DOMAIN][entry.entry_id]["client"]

    async_add_entities(
        [
            AquaforteSwitch(client, entry, SwitchEntityDescription(key="power", name="Power Switch")),
            AquaforteSwitch(client, entry, SwitchEntityDescription(key="pause", name="Pause Switch")),
        ]
    )


class AquaforteSwitch(SwitchEntity):
    """Representation of an Aquaforte switch."""

    def __init__(self, client, entry, entity_description):
        """Initialize the switch."""
        self._client = client
        self._attr_name = f"AquaForte {entity_description.name}"
        self.entity_description = entity_description
        self._is_on = False
        self._entry = entry
        self._attr_unique_id = f"{self._client._device_id}_{self.entity_description.key}"

    @property
    def unique_id(self) -> str:
        """Return the unique ID for this entity."""
        return self._attr_unique_id

    @property
    def is_on(self) -> bool:
        """Return the switch state."""
        return self._is_on

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information to tie this entity to a device."""
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.data["device_id"])},
            name=f"AquaForte {self._entry.data['device_id']}",
            manufacturer="AquaForte",
            model="Water Pump",
            sw_version=self._entry.data.get("firmware_version"),
        )

    async def async_turn_on(self, **kwargs):
        """Turn the switch on."""
        await self._client.async_turn_on(self.entity_description.key)
        self._is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        """Turn the switch off."""
        await self._client.async_turn_off(self.entity_description.key)
        self._is_on = False
        self.async_write_ha_state()
