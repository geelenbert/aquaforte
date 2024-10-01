"""Config flow for Aquaforte."""

from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries, data_entry_flow
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AquaforteDiscoveryClient, AquaforteApiClient
from .const import DOMAIN, LOGGER

class AquaforteFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Aquaforte."""
    VERSION = 1

    def __init__(self):
        self._discovered_devices = []

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        errors = {}

        if user_input is not None:
            # Validate if IP is provided or start discovery
            self._discovered_devices = await self._discover_devices(user_input.get("ip_address"))

            if self._discovered_devices:
                return await self.async_step_select_device()

            errors["base"] = "no_devices_found"

        # Display the form for IP address input
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Optional("ip_address"): str
                }
            ),
            errors=errors,
            description_placeholders={"info": "Enter IP or leave blank to auto-discover"}
        )

    async def async_step_select_device(self, user_input=None):
        """Step to select the discovered device."""
        if user_input is not None:
            device_id = user_input["device_id"]
            device = next(dev for dev in self._discovered_devices if dev["device_id"] == device_id)
            return self.async_create_entry(title=device_id, data=device)
        #     return self.async_create_entry(
        #         title=device_info["device_id"],
        #         data=device_info
        # )

        return self.async_show_form(
            step_id="select_device",
            data_schema=vol.Schema(
                {
                    vol.Required("device_id"): vol.In(
                        {device["device_id"]: f"{device['device_id']} ({device['ip']})" for device in self._discovered_devices}
                    )
                }
            )
        )

    async def _discover_devices(self, ip_address=None):
        """Perform the device discovery."""
        LOGGER.debug("Starting discovery")
        session = async_get_clientsession(self.hass)
        client = AquaforteDiscoveryClient(session)

        if ip_address:
            devices = await client.async_discover_devices(target_ip=ip_address)
        else:
            devices = await client.async_discover_devices()

        return devices
