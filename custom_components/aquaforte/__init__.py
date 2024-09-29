"""Aquaforte integration initialization."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AquaforteApiClient
from .const import DOMAIN, LOGGER

PLATFORMS = ["switch", "sensor", "number", "binary_sensor"]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Aquaforte integration from YAML or config entries."""
    LOGGER.debug("Aquaforte: async_setup called")
    session = async_get_clientsession(hass)
    client = AquaforteApiClient(session)

    # Start auto-discovery at startup
    hass.async_create_task(async_discover_devices(hass, client))

    return True


# async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
#     """Set up Aquaforte from a config entry."""
#     LOGGER.debug("Aquaforte: async_setup_entry called")
#     hass.data.setdefault(DOMAIN, {})

#     session = async_get_clientsession(hass)
#     client = AquaforteApiClient(session)

#     # Store client and device ID in hass.data
#     hass.data[DOMAIN][entry.entry_id] = {"client": client, "device_id": entry.data["device_id"]}

#     # Start device discovery
#     hass.async_create_task(async_discover_devices(hass, client))

#     # Forward setup to supported platforms
#     hass.config_entries.async_setup_platforms(entry, PLATFORMS)
#     return True


async def async_setup_entry(hass, config_entry):
    """Set up AquaForte integration from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    client = AquaforteApiClient(async_get_clientsession(hass))
    await client.async_connect_device(config_entry.data["ip"])

    # Store client for future use
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

    # Forward setup to the switch platform
    hass.async_create_task(
        hass.config_entries.async_forward_entry_setup(config_entry, "switch")
    )

    return True


async def async_discover_devices(hass: HomeAssistant, client: AquaforteApiClient):
    """Discover Aquaforte devices and prompt the config flow."""
    discovered_devices = await client.async_discover_devices()

    if discovered_devices:
        for device in discovered_devices:
            unique_id = device["device_id"]
            existing_entry = await hass.config_entries.async_entries(DOMAIN)

            if not any(entry.unique_id == unique_id for entry in existing_entry):
                # Create a new config flow entry for each discovered device
                hass.config_entries.flow.async_init(
                    DOMAIN,
                    context={"source": "discovery"},
                    data=device
                )
                LOGGER.info(f"Discovered Aquaforte device: {device}")
    else:
        LOGGER.info("No Aquaforte devices discovered")
