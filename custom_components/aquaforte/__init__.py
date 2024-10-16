"""Aquaforte integration initialization."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AquaforteApiClient
from .const import DOMAIN, LOGGER

PLATFORMS = ["binary_sensor", "number", "switch"]

async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Aquaforte integration from YAML or config entries."""
    LOGGER.debug("Aquaforte: async_setup called")
    return True

async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up Aquaforte from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Use the discovery data from the initial configuration, and don't allow updates
    discovery_data = config_entry.data

    # Create a new client instance
    client = AquaforteApiClient(discovery_data=discovery_data, hass=hass)
    await client.async_initialize()
    await client.async_connect_device()

    # Store the client in hass.data using the config entry ID
    hass.data[DOMAIN][config_entry.entry_id] = {"client": client}

    # Forward setup to platforms (e.g., binary_sensor, switch)
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    # Perform an initial status request
    await client.request_status()

    return True

async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Unload an AquaForte config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(config_entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(config_entry.entry_id)

    return unload_ok

async def async_update_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> None:
    """Update the AquaForte config entry."""
    # Unload the entry and reload it with updated data (e.g., IP address)
    await hass.config_entries.async_reload(config_entry.entry_id)
