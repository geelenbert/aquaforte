"""AquaForte API Client."""

from __future__ import annotations

import socket
import struct
import asyncio
import logging
from typing import Any, Optional
from enum import Enum
from pathlib import Path

import requests
import aiofiles
import aiohttp
import json
import os

AQUAFORTE_UDP_PORT = 12414
AQUAFORTE_TCP_PORT = 12416
DISCOVERY_TIMEOUT = 5  # Timeout for device discovery
PING_INTERVAL = 5  # Interval to send ping messages
RESPONSE_TIMEOUT = 5  # Timeout waiting for response
RECONNECT_DELAY = 10  # Delay before attempting to reconnect

AQUAFORTE_MODELS_API_URL = "http://site.gizwits.com/v2/datapoint"

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


import os
import requests
import json

class DeviceDataMap:
    """Class to represent the data structure and manage updates from the AquaForte device."""

    def __init__(self, name, packet_version, protocol_type, product_key, endpoints):
        self.name = name
        self.packet_version = packet_version
        self.protocol_type = protocol_type
        self.product_key = product_key
        self.endpoints = endpoints

    @property
    def endpoint_size(self):
        """Calculate the total size of all endpoints in bytes."""
        max_offset = 0
        for endpoint in self.endpoints.values():
            if 'byte_offset' in endpoint and 'length' in endpoint and 'unit' in endpoint:
                if endpoint['unit'] == 'byte':
                    end_offset = endpoint['byte_offset'] + endpoint['length']
                elif endpoint['unit'] == 'bit':
                    end_offset = endpoint['byte_offset'] + 1
                else:
                    raise ValueError(f"Endpoint unit type undefined: {endpoint['unit']} ")

                if end_offset > max_offset:
                    max_offset = end_offset
        return max_offset

    @classmethod
    async def load_device_data(cls, product_key):
        """Simplified device data loader: tries local first, then cloud."""
        if not product_key:
            _LOGGER.error("Product Key is empty. Cannot load device data.")
            return None

        # Get the current directory where api.py is located
        base_path = os.path.dirname(__file__)

        # Construct the file path for the local JSON in the 'models' directory relative to api.py
        models_path = os.path.join(base_path, 'modelsAAA', f"{product_key}.json")

        # Try to load from local file first
        if os.path.exists(models_path):
            _LOGGER.info(f"Loading device data from local file: {models_path}")
            try:
                async with aiofiles.open(models_path, 'r') as file:
                    data = await file.read()
                    json_data = json.loads(data)
                return cls.load_format_from_dict(json_data)
            except Exception as e:
                _LOGGER.error(f"Error loading JSON from file: {e}")
                return None
        else:
            # If local file not found, attempt to fetch from the cloud
            _LOGGER.warning(f"Local file not found: {models_path}. Trying to fetch from cloud.")
            remote_url = f"{AQUAFORTE_MODELS_API_URL}?product_key={product_key}"
            _LOGGER.warning(f"Fetching remote configuration for {product_key} from: {remote_url}")

            # Use aiohttp for asynchronous non-blocking requests
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                try:
                    async with session.get(remote_url) as response:
                        if response.status == 200:
                            _LOGGER.info(f"Remote configuration fetched for product key: {product_key}")
                            remote_data = await response.json()
                            return cls.load_format_from_dict(remote_data)
                        else:
                            _LOGGER.error(f"Failed to fetch remote JSON. Status code: {response.status}")
                except aiohttp.ClientError as e:
                    _LOGGER.error(f"Error fetching remote JSON: {e}")
                except asyncio.TimeoutError:
                    _LOGGER.error(f"Timeout occurred when fetching remote JSON for {product_key}")

        return None

    @classmethod
    def load_format_from_dict(cls, data):
        """Load device format from a dictionary."""
        _LOGGER.debug(f"Loading device data from dictionary for product key: {data.get('product_key')}")
        name = data['name']
        packet_version = data['packetVersion']
        protocol_type = data['protocolType']
        product_key = data['product_key']
        endpoints = {}

        for entity in data['entities']:
            for attr in entity['attrs']:
                endpoint_name = attr['name']
                endpoint_data = {
                    'display_name': attr['display_name'],
                    'data_type': attr['data_type'],
                    'byte_offset': attr['position']['byte_offset'],
                    'unit': attr['position']['unit'],
                    'length': attr['position']['len'],
                    'bit_offset': attr['position'].get('bit_offset', 0),
                    'type': attr['type'],
                    'id': attr['id'],
                    'desc': attr['desc']
                }
                if 'enum' in attr:
                    endpoint_data['enum'] = attr['enum']

                # Initialize value field based on data type
                if attr['data_type'] == 'bool':
                    endpoint_data['value'] = None
                elif attr['data_type'] == 'uint8':
                    endpoint_data['value'] = None
                elif attr['data_type'] == 'binary':
                    endpoint_data['value'] = bytearray(attr['position']['len'])
                elif attr['data_type'] == 'enum':
                    endpoint_data['value'] = attr['enum'][0] if 'enum' in attr else None

                endpoints[endpoint_name] = endpoint_data

        return cls(name, packet_version, protocol_type, product_key, endpoints)


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
        self._product_key = discovery_data.get('product_key')
        self._mac = discovery_data.get('firmware_version')
        self._firmware_version = discovery_data.get('firmware_version')


        self._passcode = None
        self._reader = None
        self._writer = None
        self._connected = False
        self._authenticated = False
        self._ping_task = None
        self._listener_task = None
        self._reconnect_task = None

        self._missed_ping_count = 0
        self._allowed_missed_pings = 3
        self._expected_response_events = {}

        self._data_map = None

        # Map of packet types to handler functions
        self._packet_handlers = {
            PacketType.PING_PONG_RESPONSE: self._handle_ping_response,
            PacketType.DATA_TRANSMIT_RESPONSE: self._handle_data_transmit_response,
            PacketType.DATA_CONTROL_REQUEST: self._handle_data_control_request,
            PacketType.DATA_CONTROL_RESPONSE: self._handle_data_control_response,
            PacketType.PASSCODE_RESPONSE: self._handle_passcode_response,
            PacketType.LOGIN_RESPONSE: self._handle_login_response,
            PacketType.WIFI_INFO_RESPONSE: self._handle_wifi_info_response,
        }
        _LOGGER.debug(f"AquaforteApiClient initialized for device: {self._device_id}")

    async def _setup_datamap(self):
        """Set up the AquaForte device datamap."""
        _LOGGER.info(f"Setting up AquaForte device with product key: {self._product_key}")

        # Attempt to load device data
        self._data_map = await DeviceDataMap.load_device_data(product_key=self._product_key)

        # If loading the device data map fails, abort setup
        if not self._data_map:
            _LOGGER.error(f"Failed to load device data for product key: {self._product_key}. Aborting setup.")
            raise Exception(f"Device setup failed: Unable to load device data for product key {self._product_key}")

        _LOGGER.info(f"Device setup completed successfully for product key: {self._product_key}")

    async def async_connect_device(self) -> bool:
        """Attempt to connect to the device."""
        try:
            # Step 1: Get the datamap if not loaded
            if not self._data_map:
                await self._setup_datamap()

            # Step 1: Connect
            await self._connect()

            # Step 2: Start the listener
            self._listener_task = asyncio.create_task(self._listen())

            # Step 3: Authenticate (retrieve passcode and login)
            await self._authenticate()

            # Step 4: Start ping task if authentication successful
            self._ping_task = asyncio.create_task(self._ping_task_loop())

            return True
        except (asyncio.TimeoutError, OSError, AquaforteApiClientAuthenticationError) as e:
            _LOGGER.error(f"Error connecting to device ({self._ip_address}): {e}")
            # Start reconnect attempts if connection fails
            if not self._reconnect_task:
                self._reconnect_task = asyncio.create_task(self._reconnect_loop())
            return False

    async def _connect(self) -> None:
        """Handle the connection process to the device."""
        _LOGGER.info(f"Connecting to AquaForte device at {self._ip_address}...")
        try:
            self._reader, self._writer = await asyncio.open_connection(self._ip_address, AQUAFORTE_TCP_PORT)
            self._connected = True
            _LOGGER.info(f"Connected to AquaForte device at {self._ip_address}")
        except Exception as e:
            self._connected = False
            raise e

    async def _authenticate(self) -> None:
        """Authenticate with the device (retrieve passcode and login)."""
        try:
            # Step 1: Retrieve passcode
            await self.get_passcode()

            # Step 2: Perform login
            await self.login()

            self._authenticated = True
            _LOGGER.info(f"Authentication successful for {self._ip_address}")
        except AquaforteApiClientAuthenticationError as e:
            self._authenticated = False
            _LOGGER.error(f"Authentication failed for {self._ip_address}: {e}")
            raise e

    async def async_disconnect(self) -> None:
        """Disconnect from the AquaForte device."""
        _LOGGER.debug(f"Disconnecting from AquaForte device ({self._ip_address})...")

        # Ensure all tasks are canceled cleanly
        if self._ping_task:
            _LOGGER.debug(f"Cancelling ping task ({self._ip_address})...")
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                _LOGGER.debug(f"Ping task cancelled ({self._ip_address}).")

        if self._listener_task:
            _LOGGER.debug(f"Cancelling listener task ({self._ip_address})...")
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                _LOGGER.debug(f"Listener task cancelled ({self._ip_address}).")

        # Close connection if writer exists
        if self._writer:
            _LOGGER.debug(f"Closing writer for device ({self._ip_address})...")
            self._writer.close()
            await self._writer.wait_closed()

        self._connected = False
        _LOGGER.info(f"Disconnected from AquaForte device ({self._ip_address})")

        # Trigger reconnect after cleaning up
        if not self._reconnect_task:
            _LOGGER.info(f"Starting reconnect process for device ({self._ip_address})...")
            self._reconnect_task = asyncio.create_task(self._reconnect_loop())


    async def _reconnect_loop(self) -> None:
        """Reconnect to the device after disconnection."""
        _LOGGER.info(f"Starting reconnect loop for device ({self._ip_address})...")
        while not self._connected:
            try:
                _LOGGER.info(f"Attempting to reconnect to device ({self._ip_address})...")
                await asyncio.sleep(RECONNECT_DELAY)  # Sleep before attempting reconnection
                if await self.async_connect_device():
                    _LOGGER.info(f"Successfully reconnected to device ({self._ip_address})")
                    return  # Exit the loop once reconnected
            except Exception as e:
                _LOGGER.error(f"Reconnection attempt failed for device ({self._ip_address}): {e}")
            # Sleep again before the next retry
            await asyncio.sleep(RECONNECT_DELAY)

    # Ping task loop
    async def _ping_task_loop(self) -> None:
        """Ping the device every PING_INTERVAL seconds."""
        try:
            while self._connected:
                await asyncio.sleep(PING_INTERVAL)
                _LOGGER.debug(f"Sending ping ({self._ip_address})...")
                message = self.build_message(PacketType.PING_PONG_REQUEST)

                # Wait for ping response, but don't disconnect immediately if it times out
                if not await self.transmit_and_wait_for_response(message, PacketType.PING_PONG_RESPONSE, is_ping=True):
                    self._missed_ping_count += 1
                    _LOGGER.error(f"Ping response timeout ({self._ip_address}). Missed ping count: {self._missed_ping_count}")

                    # Only disconnect if missed ping count exceeds the allowed number
                    if self._missed_ping_count > self._allowed_missed_pings:
                        _LOGGER.error(f"Exceeded allowed missed ping responses. Disconnecting ({self._ip_address})...")
                        await self.async_disconnect()
                        break  # Stop the ping task loop
                else:
                    self._missed_ping_count = 0  # Reset the counter on successful ping
        except asyncio.CancelledError:
            _LOGGER.debug(f"Ping task cancelled ({self._ip_address}).")
        except Exception as e:
            _LOGGER.error(f"Error in ping task ({self._ip_address}): {e}")

    async def _listen(self) -> None:
        """Continuously listen for incoming data from the device."""
        _LOGGER.debug(f"Starting listener task ({self._ip_address})...")
        try:
            while self._connected:
                data = await self._reader.read(1024)
                if not data:
                    raise ConnectionError(f"No data received ({self._ip_address}). Connection might be closed by the remote host.")

                await self._handle_data(data)
        except (asyncio.CancelledError, ConnectionError) as e:
            _LOGGER.warning(f"Listener task terminated or connection lost ({self._ip_address}): {e}")
            await self.async_disconnect()  # Clean up on disconnection
        except Exception as e:
            _LOGGER.error(f"Error while listening for data ({self._ip_address}): {e}")
        finally:
            _LOGGER.debug(f"Listener task finished for ({self._ip_address})")

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

    async def transmit_and_wait_for_response(self, message, expected_response_type: PacketType, is_ping=False) -> bool:
        """Send a message and wait for a specific response type."""
        if is_ping:
            timeout = PING_INTERVAL  # Use the ping interval for timeouts
        else:
            timeout = RESPONSE_TIMEOUT  # Default response timeout

        event = asyncio.Event()
        self._expected_response_events[expected_response_type] = event

        self._writer.write(message)
        await self._writer.drain()

        try:
            await asyncio.wait_for(event.wait(), timeout)
        except asyncio.TimeoutError:
            _LOGGER.error(f"Timeout waiting for {'ping ' if is_ping else ''}response ({self._ip_address}): {expected_response_type}")
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

    # Authentication Steps
    async def get_passcode(self) -> bool:
        """Send the get passcode request to the device."""
        _LOGGER.debug(f"Sending passcode request ({self._ip_address})...")
        message = self.build_message(PacketType.PASSCODE_REQUEST)
        if not await self.transmit_and_wait_for_response(message, PacketType.PASSCODE_RESPONSE):
            _LOGGER.error(f"Retrieving passcode failed ({self._ip_address}).")
            raise AquaforteApiClientAuthenticationError(f"Failed to retrieve passcode from {self._ip_address}")

        _LOGGER.info(f"Passcode retrieved successfully from {self._ip_address}.")
        return True

    async def login(self) -> bool:
        """Send the login request to the device."""
        _LOGGER.debug(f"Sending login request ({self._ip_address})...")

        length_bytes = struct.pack('>H', len(self._passcode))
        data = length_bytes + bytes(self._passcode, 'utf-8')
        message = self.build_message(PacketType.LOGIN_REQUEST, data=data)

        if not await self.transmit_and_wait_for_response(message, PacketType.LOGIN_RESPONSE):
            _LOGGER.error(f"Login failed ({self._ip_address}).")
            raise AquaforteApiClientAuthenticationError(f"Login failed for device {self._ip_address}")

        _LOGGER.info(f"Login successful for {self._ip_address}")
        return True

    # Handler functions for specific packet types
    async def _handle_ping_response(self, data: Optional[bytes]):
        """Handle ping response packets."""
        _LOGGER.debug(f"Received ping response ({self._ip_address}).")
        if PacketType.PING_PONG_RESPONSE in self._expected_response_events:
            self._expected_response_events[PacketType.PING_PONG_RESPONSE].set()

    async def _handle_data_transmit_response(self, data: Optional[bytes]):
        """Handle data transmission response packets."""
        _LOGGER.info(f"Data Transmit Response received ({self._ip_address}): {data.hex() if data else f'No data ({self._ip_address})'}")
        if PacketType.DATA_TRANSMIT_RESPONSE in self._expected_response_events:
            self._expected_response_events[PacketType.DATA_TRANSMIT_RESPONSE].set()

    async def _handle_data_control_response(self, data: Optional[bytes]):
        """Handle data control response packets."""
        _LOGGER.info(f"Data Control Response received ({self._ip_address}): {data.hex() if data else f'No data ({self._ip_address})'}")
        if PacketType.DATA_CONTROL_RESPONSE in self._expected_response_events:
            self._expected_response_events[PacketType.DATA_CONTROL_RESPONSE].set()

    async def _handle_data_control_request(self, data: Optional[bytes]):
        """Handle data control request packets."""
        # This packet type is initiated from the device, wehn something has changed
        _LOGGER.info(f"Data Control Request received ({self._ip_address}): {data.hex() if data else f'No data ({self._ip_address})'}")
        if PacketType.DATA_CONTROL_RESPONSE in self._expected_response_events:
            self._expected_response_events[PacketType.DATA_CONTROL_RESPONSE].set()

    async def _handle_login_response(self, data: Optional[bytes]):
        """Handle the login response and check if login was successful."""
        if data is None or len(data) < 1:
            _LOGGER.error(f"Invalid login response: no data received ({self._ip_address}).")
            return

        # The last byte should indicate success (00) or failure (01)
        login_status = data[-1]

        if login_status == 0x00:
            self._authenticated = True
            _LOGGER.info(f"Login successful for device {self._ip_address}.")
            if PacketType.LOGIN_RESPONSE in self._expected_response_events:
                self._expected_response_events[PacketType.LOGIN_RESPONSE].set()
        else:
            self._authenticated = False
            _LOGGER.error(f"Login failed for device {self._ip_address}.")
            if PacketType.LOGIN_RESPONSE in self._expected_response_events:
                self._expected_response_events[PacketType.LOGIN_RESPONSE].set()
            raise AquaforteApiClientAuthenticationError(f"Login failed for device {self._ip_address}.")

    async def _handle_passcode_response(self, data: Optional[bytes]):
        """Handle passcode response packets."""
        _LOGGER.info(f"Passcode Response received ({self._ip_address}).")

        try:
            # Ensure data is not None or empty
            if data is None or len(data) < 2:
                raise AquaforteApiClientAuthenticationError(f"Invalid passcode response: No data or insufficient length ({self._ip_address}).")

            offset = 0
            # Read the passcode length
            pass_len, offset = read_int16_be(data, offset)

            # Ensure passcode length is valid
            if pass_len < 1:
                raise AquaforteApiClientAuthenticationError(f"Invalid passcode response: Passcode length is less than 1 ({self._ip_address}).")

            # Extract the passcode
            self._passcode = data[offset: offset + pass_len].decode("utf-8")

            # Log the received passcode
            _LOGGER.debug(f"Received passcode: {self._passcode} for device {self._ip_address}")

            # Set the response event if it's expected
            if PacketType.PASSCODE_RESPONSE in self._expected_response_events:
                self._expected_response_events[PacketType.PASSCODE_RESPONSE].set()

        except (UnicodeDecodeError, struct.error) as e:
            _LOGGER.error(f"Error decoding passcode for device {self._ip_address}: {e}")
            raise AquaforteApiClientAuthenticationError(f"Invalid passcode format for device {self._ip_address}: {e}")

        except AquaforteApiClientAuthenticationError as auth_error:
            _LOGGER.error(auth_error)
            raise auth_error

    async def _handle_wifi_info_response(self, data: Optional[bytes]):
        """Handle WiFi information response packets."""
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
