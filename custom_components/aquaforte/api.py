"""AquaForte API Client."""

from __future__ import annotations

import socket
import struct
import asyncio
import logging
from typing import Any, Optional
from enum import Enum

import aiohttp

AQUAFORTE_UDP_PORT = 12414
AQUAFORTE_TCP_PORT = 12416
DISCOVERY_TIMEOUT = 5  # Timeout for device discovery
PING_INTERVAL = 5  # Interval to send ping messages
RESPONSE_TIMEOUT = 5  # Timeout waiting for response
RECONNECT_DELAY = 10  # Delay before attempting to reconnect

_LOGGER = logging.getLogger(__name__)


class AquaforteApiClientError(Exception):
    """Exception to indicate a general API error."""


class AquaforteApiClientCommunicationError(AquaforteApiClientError):
    """Exception to indicate a communication error."""


class AquaforteApiClientAuthenticationError(AquaforteApiClientError):
    """Exception to indicate an authentication error."""

class PacketType(Enum):
    DISCOVERY_REQUEST = 0x03
    DISCOVERY_RESPONSE = 0x04
    PASSCODE_REQUEST = 0x06
    PASSCODE_RESPONSE = 0x07
    LOGIN_REQUEST = 0x08
    LOGIN_RESPONSE = 0x09
    WIFI_INFO_REQUEST = 0x13
    WIFI_INFO_RESPONSE = 0x14
    PING_PONG_REQUEST = 0x15
    PING_PONG_RESPONSE = 0x16
    DATA_TRANSMIT_REQUEST = 0x90
    DATA_TRANSMIT_RESPONSE = 0x91
    DATA_CONTROL_REQUEST = 0x93
    DATA_CONTROL_RESPONSE = 0x94

class AquaforteDiscoveryClient:
    """AquaForte Discovery Client."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        """Initialize the Discovery client."""
        self._session = session
        self._discovered_devices = []
        _LOGGER.debug("AquaforteDiscoveryClient initialized")

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
                _LOGGER.debug(f"Sending direct discovery message to {target_ip} on port {AQUAFORTE_UDP_PORT}")
                sock.bind(("", AQUAFORTE_UDP_PORT))  # Bind to the same source port
                sock.sendto(DISCOVERY_MESSAGE, (target_ip, AQUAFORTE_UDP_PORT))
            else:
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

    def _parse_response(self, message: bytes, remote: tuple) -> None:
        """Parse the discovery response message."""
        offset = 0
        try:
            prefix, offset = read_uint32_be(message, offset)
            if prefix != 0x00000003:
                _LOGGER.debug(f"Ignore data package because invalid prefix: {message.hex()}")
                return
        except Exception:
            _LOGGER.debug(f"Ignore data package because short prefix: {message.hex()}")
            return

        try:
            data_length, offset = read_varint(message, offset)
            flag, offset = read_int8(message, offset)
            message_type, offset = read_int16_be(message, offset)
        except Exception:
            _LOGGER.debug(f"Error parsing message from data: {message.hex()}")
            return

        if message_type == PacketType.DISCOVERY_RESPONSE:  # DISCOVERY_RESPONSE
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


class AquaforteApiClient:
    """AquaForte API Client for communication with a specific device."""

    def __init__(self, discovery_data: dict) -> None:
        """Initialize the API client with device information."""
        self._ip_address = discovery_data.get('ip')
        self._device_id = discovery_data.get('device_id')
        self._firmware_version = discovery_data.get('firmware_version')

        self._passcode = None

        self._reader = None
        self._writer = None
        self._connected = False
        self._logged_in = False
        self._ping_task = None
        self._listener_task = None
        self._reconnect_task = None

        self._missed_ping_count = 0
        self._allowed_missed_pings = 3
        self._expected_response_events = {}

        # Map of packet types to handler functions
        self._packet_handlers = {
            PacketType.PING_PONG_RESPONSE: self._handle_ping_response,
            PacketType.DATA_TRANSMIT_RESPONSE: self._handle_data_transmit_response,
            PacketType.DATA_CONTROL_RESPONSE: self._handle_data_control_response,
            PacketType.PASSCODE_RESPONSE: self._handle_passcode_response,
            PacketType.LOGIN_RESPONSE: self._handle_login_response,
            PacketType.WIFI_INFO_RESPONSE: self._handle_wifi_info_response,
        }
        _LOGGER.debug(f"AquaforteApiClient initialized for device: {self._device_id}")

    async def async_connect_device(self) -> bool:
        """Initial connection to the device."""
        if await self._connect_and_authenticate():
            return True
        else:
            # Handle failed initial connection
            if not self._reconnect_task:
                self._reconnect_task = asyncio.create_task(self._reconnect_loop())
            return False

    async def _connect_and_authenticate(self) -> bool:
        """Handle the full connection and authentication process."""
        _LOGGER.debug(f"Attempting full connection process for {self._ip_address}...")

        try:
            # Open connection
            self._reader, self._writer = await asyncio.open_connection(self._ip_address, AQUAFORTE_TCP_PORT)
            self._connected = True
            _LOGGER.info(f"Connected to AquaForte device at {self._ip_address}")

            # Start listener task
            self._listener_task = asyncio.create_task(self._listen())

            # Retrieve passcode if necessary
            if self._passcode is None:
                await self.get_passcode()

            # Perform login
            await self.login()

            # Start ping task if login is successful
            if not self._ping_task or self._ping_task.cancelled():
                self._ping_task = asyncio.create_task(self._ping_task_loop())

            return True

        except (asyncio.TimeoutError, OSError, AquaforteApiClientAuthenticationError) as e:
            _LOGGER.error(f"Error during connection process ({self._ip_address}): {e}")
            await self.async_disconnect()  # Ensure we disconnect in case of error
            return False


    async def async_disconnect(self) -> None:
        """Disconnect from the AquaForte device."""
        if self._writer:
            _LOGGER.debug(f"Disconnecting from AquaForte device ({self._ip_address})...")
            self._writer.close()
            await self._writer.wait_closed()
            self._connected = False
            _LOGGER.info(f"Disconnected from AquaForte device ({self._ip_address})")

            # Cancel ongoing tasks
            if self._ping_task:
                self._ping_task.cancel()
            if self._listener_task:
                self._listener_task.cancel()

            # Start reconnect attempts
            if not self._reconnect_task:
                self._reconnect_task = asyncio.create_task(self._reconnect_loop())

    async def _reconnect_loop(self) -> None:
        """Attempt to reconnect to the AquaForte device if disconnected."""
        _LOGGER.info(f"Starting reconnect loop for {self._ip_address}...")
        while not self._connected:
            try:
                _LOGGER.info(f"Reconnecting to AquaForte device at {self._ip_address}...")
                await asyncio.sleep(RECONNECT_DELAY)

                if await self._connect_and_authenticate():
                    _LOGGER.info(f"Successfully reconnected to AquaForte device at {self._ip_address}")
                    return  # Exit loop once reconnection is successful

            except Exception as e:
                _LOGGER.error(f"Reconnection attempt failed ({self._ip_address}): {e}")

            await asyncio.sleep(RECONNECT_DELAY)

    async def _ping_task_loop(self) -> None:
        """Ping the device every PING_INTERVAL seconds."""
        while self._connected:
            try:
                await asyncio.sleep(PING_INTERVAL)
                _LOGGER.debug(f"Sending ping ({self._ip_address})...")
                message = self.build_message(PacketType.PING_PONG_REQUEST)
                if not await self.transmit_and_wait_for_response(message, PacketType.PING_PONG_RESPONSE):
                    self._missed_ping_count += 1
                    _LOGGER.error(f"Ping response timeout ({self._ip_address}). Missed ping count: {self._missed_ping_count}")

                    if self._missed_ping_count > self._allowed_missed_pings:
                        _LOGGER.error(f"Exceeded allowed missed ping responses. Disconnecting ({self._ip_address})...")
                        await self.async_disconnect()
                        break  # Exit loop to stop the task
                else:
                    self._missed_ping_count = 0
            except asyncio.CancelledError:
                _LOGGER.debug(f"Ping task cancelled ({self._ip_address}).")
                break

    async def _listen(self) -> None:
        """Continuously listen for incoming data from the device."""
        _LOGGER.debug(f"Starting listener task ({self._ip_address})...")
        while self._connected:
            try:
                data = await self._reader.read(1024)
                if not data:
                    raise ConnectionError(f"No data received ({self._ip_address}). Connection might be closed.")
                await self._handle_data(data)
            except (asyncio.CancelledError, ConnectionError):
                _LOGGER.warning(f"Listener task terminated or connection lost ({self._ip_address}).")
                await self.async_disconnect()
                break
            except Exception as e:
                _LOGGER.error(f"Error while listening for data ({self._ip_address}): {e}")

    async def _handle_data(self, message: bytes) -> None:
        """Decode and handle incoming data packets."""
        offset = 0
        try:
            prefix, offset = read_uint32_be(message, offset)
            if prefix != 0x00000003:
                _LOGGER.debug(f"Ignore data package because invalid prefix ({self._ip_address}): {message.hex()}")
                return

            data_length, offset = read_varint(message, offset)
            flag, offset = read_int8(message, offset)
            message_type_value, offset = read_int16_be(message, offset)

            try:
                message_type = PacketType(message_type_value)
            except ValueError:
                _LOGGER.warning(f"Received unknown message type ({self._ip_address}): {message_type_value}")
                return

            data = message[offset:offset + data_length] if data_length else None
            handler = self._packet_handlers.get(message_type)
            if handler:
                await handler(data)
            else:
                _LOGGER.debug(f"Unhandled message type {message_type.name} ({self._ip_address}): {message.hex()}")

        except Exception as err:
            _LOGGER.error(f"Error processing data packet ({self._ip_address}): {err}")

    async def transmit_and_wait_for_response(self, message, expected_response_type: PacketType, timeout=None) -> bool:
        """Send a message and wait for a specific response type."""
        if timeout is None:
            timeout = RESPONSE_TIMEOUT

        event = asyncio.Event()
        self._expected_response_events[expected_response_type] = event

        self._writer.write(message)
        await self._writer.drain()

        try:
            await asyncio.wait_for(event.wait(), timeout)
        except asyncio.TimeoutError:
            _LOGGER.error(f"Timeout waiting for response ({self._ip_address}): {expected_response_type}")
            await self.async_disconnect()  # Disconnect on timeout
            return False
        return True

    def build_message(self, command: PacketType, data=None) -> bytes:
        """Build a message to send to the device."""
        prefix = b'\x00\x00\x00\x03'
        flag = b'\x00'
        command_bytes = struct.pack('>H', command.value)
        data = data or b''
        length = len(flag) + len(command_bytes) + len(data)
        length_bytes = struct.pack('>B', length)

        return prefix + length_bytes + flag + command_bytes + data

    async def get_passcode(self) -> bool:
        """Send the get passcode request to the device."""
        _LOGGER.debug(f"Sending passcode request ({self._ip_address})...")
        message = self.build_message(PacketType.PASSCODE_REQUEST)
        if not await self.transmit_and_wait_for_response(message, PacketType.PASSCODE_RESPONSE):
            _LOGGER.error(f"Retrieving passcode failed ({self._ip_address}).")
            return False
        _LOGGER.info(f"Retrieved passcode ({self._ip_address}).")
        return True


    async def login(self) -> bool:
        """Send the login request to the device."""
        _LOGGER.debug(f"Sending login request ({self._ip_address})...")

        length_bytes = struct.pack('>H', len(self._passcode))
        data = length_bytes + bytes(self._passcode, 'utf-8')
        message = self.build_message(PacketType.LOGIN_REQUEST, data=data)

        # Wait for the login response or timeout
        if not await self.transmit_and_wait_for_response(message, PacketType.LOGIN_RESPONSE):
            _LOGGER.error(f"Login failed ({self._ip_address}).")
            raise AquaforteApiClientAuthenticationError(f"Login failed ({self._ip_address}).")  # Raise an error to handle it in connect
        return True


    # Handler functions for specific packet types
    async def _handle_ping_response(self, data: Optional[bytes]):
        _LOGGER.debug(f"Received ping response ({self._ip_address}).")
        if PacketType.PING_PONG_RESPONSE in self._expected_response_events:
            self._expected_response_events[PacketType.PING_PONG_RESPONSE].set()

    async def _handle_data_transmit_response(self, data: Optional[bytes]):
        _LOGGER.info(f"Data Transmit Response received ({self._ip_address}): {data.hex() if data else f'No data ({self._ip_address})'}")

    async def _handle_data_control_response(self, data: Optional[bytes]):
        _LOGGER.info(f"Data Control Response received ({self._ip_address}): {data.hex() if data else f'No data ({self._ip_address})'}")

    async def _handle_login_response(self, data: Optional[bytes]):
        """Handle the login response and check if login was successful."""
        if data is None or len(data) < 1:
            _LOGGER.error(f"Invalid login response: no data received ({self._ip_address}).")
            return

        # The last byte should indicate success (00) or failure (01)
        login_status = data[-1]

        if login_status == 0x00:
            self._logged_in = True
            _LOGGER.info("Login successful.")
            if PacketType.LOGIN_RESPONSE in self._expected_response_events:
                self._expected_response_events[PacketType.LOGIN_RESPONSE].set()
        else:
            self._logged_in = False
            _LOGGER.error("Login failed ({self._ip_address}).")
            if PacketType.LOGIN_RESPONSE in self._expected_response_events:
                self._expected_response_events[PacketType.LOGIN_RESPONSE].set()
            raise AquaforteApiClientAuthenticationError(f"Login failed ({self._ip_address}).")

    async def _handle_passcode_response(self, data: Optional[bytes]):
        _LOGGER.info(f"Passcode Response received ({self._ip_address}).")

        try:
            # Ensure data is not None or empty
            if data is None or len(data) < 2:
                raise AquaforteApiClientAuthenticationError("Invalid passcode response: No data or insufficient length.")

            offset = 0
            # Read the passcode length
            pass_len, offset = read_int16_be(data, offset)

            # Ensure passcode length is valid
            if pass_len < 1:
                raise AquaforteApiClientAuthenticationError("Invalid passcode response: Passcode length is less than 1.")

            # Extract the passcode
            self._passcode = data[offset: offset + pass_len].decode("utf-8")

            # Log the received passcode
            _LOGGER.debug(f"Received passcode: {self._passcode}")

            # Set the response event if it's expected
            if PacketType.PASSCODE_RESPONSE in self._expected_response_events:
                self._expected_response_events[PacketType.PASSCODE_RESPONSE].set()

        except (UnicodeDecodeError, struct.error) as e:
            _LOGGER.error(f"Error decoding passcode ({self._ip_address}): {e}")
            raise AquaforteApiClientAuthenticationError(f"Invalid passcode format ({self._ip_address}): {e}")

        except AquaforteApiClientAuthenticationError as auth_error:
            _LOGGER.error(auth_error)
            raise auth_error

    async def _handle_wifi_info_response(self, data: Optional[bytes]):
        _LOGGER.info(f"WiFi Info Response received ({self._ip_address}): {data.hex() if data else f'No data ({self._ip_address})'}")


# Utility functions remain the same
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
        return string, end + 1

def read_bytes(data: bytes, offset: int, length: int) -> tuple[bytes, int]:
    return data[offset:offset + length], offset + length

def read_int8(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from('>b', data, offset)[0], offset + 1

def read_int16_be(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from('>h', data, offset)[0], offset + 2
