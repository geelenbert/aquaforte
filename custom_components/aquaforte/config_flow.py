"""Config flow for Aquaforte."""

from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback

from .api import AquaforteDiscoveryClient
from .const import DOMAIN

import logging
_LOGGER = logging.getLogger(__name__)

class AquaforteFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Config flow for Aquaforte."""
    VERSION = 1

    def __init__(self):
        self._discovered_devices = []
        self._selected_device = None

    async def async_step_user(self, user_input=None):
        """Handle the initial step where we ask for IP or perform auto discovery."""
        errors = {}

        if user_input is not None:
            # Validate if IP is provided or start discovery
            self._discovered_devices = await self._discover_devices(user_input.get("ip_address"))

            if self._discovered_devices:
                return await self.async_step_select_device()

            errors["base"] = "no_devices_found"

        # Display the form for IP address input or auto-discovery
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Optional("ip_address"): str  # Optional IP entry for direct discovery
                }
            ),
            errors=errors,
            description_placeholders={"info": "Enter IP or leave blank to auto-discover devices."}
        )

    async def async_step_select_device(self, user_input=None):
        """Handle the step where the user selects a discovered device."""
        if user_input is not None:
            device_id = user_input["device_id"]
            # Check if the device is already configured to prevent duplicates
            if await self._is_device_already_configured(device_id):
                return self.async_abort(reason="device_already_configured")

            # Store the selected device and move to the next step
            self._selected_device = next(
                (dev for dev in self._discovered_devices if dev["device_id"] == device_id), None
            )
            return await self.async_step_set_device_name()

        # Provide a list of discovered devices to the user
        return self.async_show_form(
            step_id="select_device",
            data_schema=vol.Schema(
                {
                    vol.Required("device_id"): vol.In(
                        {device["device_id"]: f"{device['device_id']} ({device['ip']})" for device in self._discovered_devices}
                    )
                }
            ),
            description_placeholders={"info": "Select the device you want to configure."}
        )

    async def async_step_set_device_name(self, user_input=None):
        """Handle the step where the user sets the device name."""
        if user_input is not None:
            # Create the device entry with the provided name
            return self.async_create_entry(
                title=user_input.get("device_name", "Water Pump"),
                data={
                    **self._selected_device,
                    "device_name": user_input.get("device_name", "Water Pump"),
                }
            )

        # Show the form to enter the device name, defaulting to "Water Pump"
        return self.async_show_form(
            step_id="set_device_name",
            data_schema=vol.Schema(
                {
                    vol.Optional("device_name", default="Water Pump"): str,
                }
            ),
            description_placeholders={"info": "Enter a name for the device."}
        )

    async def _discover_devices(self, ip_address=None):
        """Perform the device discovery."""
        LOGGER.debug("Starting discovery")
        client = AquaforteDiscoveryClient()

        devices = await client.async_discover_devices(target_ip=ip_address)

        return devices

    async def _is_device_already_configured(self, device_id: str) -> bool:
        """Check if the device is already configured based on the device ID."""
        for entry in self._async_current_entries():
            if entry.data.get("device_id") == device_id:
                return True
        return False