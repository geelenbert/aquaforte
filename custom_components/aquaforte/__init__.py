"""Aquaforte integration initialization."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AquaforteApiClient, AquaforteDiscoveryClient
from homeassistant.exceptions import ConfigEntryNotReady
from .const import DOMAIN, LOGGER

PLATFORMS = ["binary_sensor", "number", "switch"]

# async def async_setup(hass: HomeAssistant, config: dict) -> bool:
#     """Set up the Aquaforte integration from YAML or config entries."""
#     LOGGER.debug("Aquaforte: async_setup called")

#     # Perform device discovery
#     session = async_get_clientsession(hass)
#     client = AquaforteDiscoveryClient(session)
#     discovered_devices = await client.async_discover_devices()

#     # Get all configured devices (entries)
#     configured_entries = hass.config_entries.async_entries(DOMAIN)

#     # Match discovered devices with configured entries
#     for entry in configured_entries:
#         configured_device_id = entry.data.get("device_id")

#         # Find the matching discovered device by device_id
#         matching_device = next(
#             (dev for dev in discovered_devices if dev["device_id"] == configured_device_id),
#             None
#         )

#         if matching_device:
#             # Check if the IP has changed and update if necessary
#             if entry.data["ip"] != matching_device["ip"]:
#                 LOGGER.info(f"Updating IP for {configured_device_id}: {matching_device['ip']}")

#                 # Update the entry with the new IP
#                 hass.config_entries.async_update_entry(
#                     entry,
#                     data={**entry.data, "ip": matching_device["ip"]}
#                 )

#     return True


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up a single Aquaforte device from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Extract the configured device data
    configured_device_id = config_entry.data["device_id"]
    configured_ip = config_entry.data["ip"]

    # Perform a general device discovery (no IP provided)
    session = async_get_clientsession(hass)
    discovery_client = AquaforteDiscoveryClient(session)

    try:
        LOGGER.debug("Performing general discovery")
        discovered_devices = await discovery_client.async_discover_devices()

        # Look for a device that matches the configured device ID
        matching_device = next(
            (dev for dev in discovered_devices if dev["device_id"] == configured_device_id),
            None
        )

        if matching_device:
            # If we found a matching device, update its IP and other properties if needed
            LOGGER.info(f"Device {configured_device_id} found during general discovery. Updating stored data.")
            updated_data = {
                "ip": matching_device["ip"],
                "firmware_version": matching_device["firmware_version"],
                "mac": matching_device["mac"],
                "wifi_version": matching_device["wifi_version"],
                "api_server": matching_device["api_server"],
                "mcu_attributes": matching_device["mcu_attributes"],
            }

            # Update the config entry with the new data
            hass.config_entries.async_update_entry(config_entry, data={**config_entry.data, **updated_data})

        else:
            # If no matching device is found, attempt discovery at the configured IP
            LOGGER.warning(f"No matching device found during general discovery. Attempting targeted discovery for IP {configured_ip}")
            targeted_discovery = await discovery_client.async_discover_devices(target_ip=configured_ip)

            # Ensure that the device ID matches
            if targeted_discovery and targeted_discovery[0]["device_id"] == configured_device_id:
                LOGGER.info(f"Device {configured_device_id} found at {configured_ip}.")
            else:
                LOGGER.error(f"Device with ID {configured_device_id} not found or device ID mismatch during discovery.")
                raise ConfigEntryNotReady(f"Device with ID {configured_device_id} not found or device ID mismatch.")

    except Exception as e:
        LOGGER.error(f"Error setting up device: {e}")
        raise ConfigEntryNotReady from e

    # Create a new client instance with the updated device data
    client = AquaforteApiClient(discovery_data=config_entry.data, hass=hass)
    await client.async_initialize()
    await client.async_connect_device()

    # Store the client in hass.data using entry ID
    hass.data[DOMAIN][config_entry.entry_id] = {"client": client}

    # Forward setup to platforms
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
