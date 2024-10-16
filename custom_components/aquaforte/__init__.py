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

<<<<<<< HEAD
async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    # Create a new client instance for each config entry
    client = AquaforteApiClient(discovery_data=config_entry.data, hass=hass)
    await client.async_initialize()
    await client.async_connect_device()

    # Store the client in hass.data using entry ID
    hass.data[DOMAIN][config_entry.entry_id] = {"client": client}

    # Forward setup to platforms
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    return True


=======
>>>>>>> eea7c5d (Support for Multiple Devices)
async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    # Create a new client instance for each config entry
    client = AquaforteApiClient(discovery_data=config_entry.data, hass=hass)
    await client.async_initialize()
    await client.async_connect_device()

    # Store the client in hass.data using entry ID
    hass.data[DOMAIN][config_entry.entry_id] = {"client": client}

    # Forward setup to platforms
    await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

    # Do an initial status request
    await client.request_status()

    return True


async def async_unload_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Unload an AquaForte config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(config_entry, PLATFORMS)

    if unload_ok:
        hass.data[DOMAIN].pop(config_entry.entry_id)

    return unload_ok
