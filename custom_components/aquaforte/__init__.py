"""Aquaforte integration initialization."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AquaforteApiClient
from .const import DOMAIN, LOGGER

PLATFORMS = ["binary_sensor", "number", "select", "switch"]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Aquaforte integration from YAML or config entries."""
    LOGGER.debug("Aquaforte: async_setup called")
    return True


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up AquaForte integration from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    client = AquaforteApiClient(discovery_data = config_entry.data)
    await client.async_connect_device()

    # Store the device_id:
    client._device_id =  config_entry.data["device_id"]

    # Store client for this entry
    hass.data[DOMAIN][config_entry.entry_id] = {
        "client": client,
    }

    # Register the device
    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=config_entry.entry_id,
        identifiers={(DOMAIN, config_entry.data["device_id"])},
        manufacturer="AquaForte",
        model="Water Pump",
        name=f"AquaForte {config_entry.data['device_id']}",
        sw_version=config_entry.data.get("firmware_version"),
    )

    # Forward setup to the platforms
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Unload an AquaForte config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(config_entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(config_entry.entry_id)

    return unload_ok
