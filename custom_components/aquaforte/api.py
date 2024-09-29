"""AquaForte API Client."""

from __future__ import annotations

import socket
import struct
import asyncio
import logging
from typing import Any, Optional

import aiohttp

AQUAFORTE_UDP_PORT = 12414
AQUAFORTE_TCP_PORT = 12416
DISCOVERY_TIMEOUT = 5  # Timeout for device discovery
RECONNECT_DELAY = 10  # Delay before attempting to reconnect
_LOGGER = logging.getLogger(__name__)


class AquaforteApiClientError(Exception):
    """Exception to indicate a general API error."""


class AquaforteApiClientCommunicationError(AquaforteApiClientError):
    """Exception to indicate a communication error."""


class AquaforteApiClientAuthenticationError(AquaforteApiClientError):
    """Exception to indicate an authentication error."""


class AquaforteApiClient:
    """AquaForte API Client."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        """Initialize the API client."""
        self._session = session
        self._discovered_devices = []
        self._ip_address = None
        self._reader = None
        self._writer = None
        self._connected = False
        _LOGGER.debug("AquaforteApiClient initialized")

    async def async_discover_devices(self, target_ip: Optional[str] = None) -> list[dict]:
        """Discover AquaForte devices on the network or at a specific IP."""
        self._discovered_devices.clear()
        _LOGGER.debug("Starting device discovery...")

        # Set up UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(DISCOVERY_TIMEOUT)

        # Send discovery message
        DISCOVERY_MESSAGE = b'\x00\x00\x00\x03\x03\x00\x00\x03'
        try:
            if target_ip:
                # Direct transmission to the specified IP address
                _LOGGER.debug(f"Sending direct discovery message to {target_ip} on port {AQUAFORTE_UDP_PORT}")
                sock.bind(("", AQUAFORTE_UDP_PORT))  # Bind to the same source port
                sock.sendto(DISCOVERY_MESSAGE, (target_ip, AQUAFORTE_UDP_PORT))
            else:
                # Broadcast discovery as previous
                _LOGGER.debug(f"Sending broadcast discovery message to port {AQUAFORTE_UDP_PORT}")
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(DISCOVERY_MESSAGE, ('<broadcast>', AQUAFORTE_UDP_PORT))

            # Listen for responses
            while True:
                data, addr = sock.recvfrom(1024)
                _LOGGER.debug(f"Received data from {addr}: {data.hex()}")
                self._parse_response(data, addr)
        except socket.timeout:
            _LOGGER.debug("Discovery timeout reached. No more devices found.")
        except Exception as e:
            _LOGGER.error(f"Error during discovery: {e}")
        finally:
            sock.close()
            _LOGGER.debug("UDP socket closed after discovery")

        return self._discovered_devices

    async def async_connect_device(self, device_ip: str) -> bool:
        """Connect to a specific AquaForte device over TCP."""
        _LOGGER.debug(f"Connecting to device at {device_ip}...")
        try:
            self._reader, self._writer = await asyncio.open_connection(device_ip, AQUAFORTE_TCP_PORT)
            self._ip_address = device_ip
            self._connected = True
            _LOGGER.info(f"Connected to AquaForte device at {device_ip}")
            return True
        except (asyncio.TimeoutError, OSError) as e:
            _LOGGER.error(f"Error connecting to device: {e}")
            return False

    async def async_disconnect(self) -> None:
        """Disconnect from the AquaForte device."""
        if self._writer:
            _LOGGER.debug("Disconnecting from AquaForte device...")
            self._writer.close()
            await self._writer.wait_closed()
            self._connected = False
            _LOGGER.info("Disconnected from AquaForte device")

    def _parse_response(self, message: bytes, remote: tuple) -> None:
        """Parse the full response message to handle different packet types."""
        offset = 0
        try:
            prefix, offset = read_uint32_be(message, offset)
            if prefix != 0x00000003:
                _LOGGER.debug(f"Ignore data package because invalid prefix: {message.hex()}")
                return
        except Exception as err:
            _LOGGER.debug(f"Ignore data package because short prefix: {message.hex()}")
            return

        try:
            data_length, offset = read_varint(message, offset)
        except Exception:
            _LOGGER.debug(f"Ignore data package because invalid length: {message.hex()}")
            return

        try:
            flag, offset = read_int8(message, offset)
        except Exception:
            _LOGGER.debug(f"Error parsing flag from data: {message.hex()}")
            return

        try:
            message_type, offset = read_int16_be(message, offset)
        except Exception:
            _LOGGER.debug(f"Error parsing message type from data: {message.hex()}")
            return

        if message_type == 0x04:  # DISCOVERY_RESPONSE (as per your original code)
            _LOGGER.debug(f'DISCOVERY_RESPONSE from {remote}')
            self._handle_reply_broadcast(remote, message, offset)
        else:
            _LOGGER.debug(f'Ignore message due to invalid message type {message_type}: {message.hex()}')

    def _handle_reply_broadcast(self, remote: tuple, message: bytes, offset: int) -> None:
        """Handle the parsed discovery response to extract device details."""
        _LOGGER.debug(f'Parsing discovered device: {remote[0]}:{remote[1]} - {message.hex()}')

        try:
            device_id_len, offset = read_int16_be(message, offset)
            device_id, offset = read_string(message, offset, length=device_id_len)

            mac_len, offset = read_int16_be(message, offset)
            mac, offset = read_bytes(message, offset, length=mac_len)

            wifi_ver_len, offset = read_int16_be(message, offset)
            wifi_ver, offset = read_bytes(message, offset, length=wifi_ver_len)

            prod_key_len, offset = read_int16_be(message, offset)
            prod_key, offset = read_string(message, offset, length=prod_key_len)

            mcu_attr, offset = read_bytes(message, offset, length=8)

            api_server, offset = read_string(message, offset)

            firmware, offset = read_string(message, offset)

            result = {
                'ip': remote[0],
                'device_id': device_id,
                'mac': mac.hex(),
                'wifi_version': wifi_ver.decode('ascii'),
                'product_key': prod_key,
                'mcu_attributes': mcu_attr.hex(),
                'api_server': api_server,
                'firmware_version': firmware
            }
            self._discovered_devices.append(result)
            _LOGGER.debug(f'Discovered device: {result}')
        except Exception as e:
            _LOGGER.error(f"Error parsing discovery response: {e}")


# Utility functions
def read_uint32_be(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from('>I', data, offset)[0], offset + 4


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, offset


def read_string(data: bytes, offset: int, length: Optional[int] = None) -> tuple[str, int]:
    if length is not None:
        string = data[offset:offset + length].decode('ascii')
        return string, offset + length
    else:
        end = offset
        while end < len(data) and data[end] != 0:
            end += 1
        string = data[offset:end].decode('ascii')
        return string, end + 1  # Skip the null terminator


def read_bytes(data: bytes, offset: int, length: int) -> tuple[bytes, int]:
    return data[offset:offset + length], offset + length


def read_int8(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from('>b', data, offset)[0], offset + 1


def read_int16_be(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from('>h', data, offset)[0], offset + 2
