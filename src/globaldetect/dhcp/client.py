"""
DHCP client implementation for network troubleshooting.

Provides DHCP operations with detailed verbose output for debugging:
- DHCP server issues
- Relay agent (Option 82) problems
- PXE boot configuration issues

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import random
import socket
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Any, Callable

# DHCP Constants
DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
DHCP_MAGIC_COOKIE = bytes([99, 130, 83, 99])  # 0x63825363

# Hardware types
HTYPE_ETHERNET = 1

# DHCP Operation codes
BOOTREQUEST = 1
BOOTREPLY = 2


class DHCPMessageType(IntEnum):
    """DHCP message types (Option 53)."""
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


class DHCPOption(IntEnum):
    """Common DHCP options."""
    PAD = 0
    SUBNET_MASK = 1
    TIME_OFFSET = 2
    ROUTER = 3
    TIME_SERVER = 4
    NAME_SERVER = 5
    DNS_SERVER = 6
    LOG_SERVER = 7
    HOSTNAME = 12
    DOMAIN_NAME = 15
    BROADCAST_ADDRESS = 28
    NTP_SERVER = 42
    VENDOR_SPECIFIC = 43
    REQUESTED_IP = 50
    LEASE_TIME = 51
    MESSAGE_TYPE = 53
    SERVER_ID = 54
    PARAMETER_REQUEST = 55
    MESSAGE = 56
    MAX_MESSAGE_SIZE = 57
    RENEWAL_TIME = 58
    REBINDING_TIME = 59
    VENDOR_CLASS_ID = 60
    CLIENT_ID = 61
    TFTP_SERVER_NAME = 66
    BOOTFILE_NAME = 67
    RELAY_AGENT_INFO = 82  # Option 82 - Relay Agent Information
    CLIENT_FQDN = 81
    # PXE Options
    PXE_CLIENT_ARCH = 93
    PXE_CLIENT_NDI = 94
    PXE_CLIENT_UUID = 97
    # End
    END = 255


# Option 82 Sub-options
class RelayAgentSubOption(IntEnum):
    """Relay Agent Information sub-options (Option 82)."""
    CIRCUIT_ID = 1
    REMOTE_ID = 2
    DOCSIS_DEVICE_CLASS = 4
    LINK_SELECTION = 5
    SUBSCRIBER_ID = 6
    RADIUS_ATTRIBUTES = 7
    AUTHENTICATION = 8
    VENDOR_SPECIFIC = 9
    RELAY_AGENT_FLAGS = 10
    SERVER_ID_OVERRIDE = 11


@dataclass
class DHCPConfig:
    """DHCP client configuration."""
    interface: str | None = None
    mac_address: str | None = None  # Override MAC (for testing)
    hostname: str | None = None
    client_id: bytes | None = None

    # Timeouts
    discover_timeout: float = 5.0
    request_timeout: float = 5.0
    max_retries: int = 3

    # Options to request
    requested_options: list[int] = field(default_factory=lambda: [
        DHCPOption.SUBNET_MASK,
        DHCPOption.ROUTER,
        DHCPOption.DNS_SERVER,
        DHCPOption.DOMAIN_NAME,
        DHCPOption.BROADCAST_ADDRESS,
        DHCPOption.NTP_SERVER,
        DHCPOption.LEASE_TIME,
        DHCPOption.RENEWAL_TIME,
        DHCPOption.REBINDING_TIME,
        DHCPOption.TFTP_SERVER_NAME,
        DHCPOption.BOOTFILE_NAME,
    ])

    # Vendor class identifier (for PXE)
    vendor_class_id: str | None = None  # e.g., "PXEClient:Arch:00000:UNDI:002001"

    # PXE options
    pxe_client_arch: int | None = None  # 0=x86 BIOS, 7=x64 UEFI, 9=EFI x86
    pxe_uuid: bytes | None = None


@dataclass
class DHCPLease:
    """Represents a DHCP lease."""
    ip_address: str | None = None
    subnet_mask: str | None = None
    gateway: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    domain_name: str | None = None
    broadcast_address: str | None = None
    ntp_servers: list[str] = field(default_factory=list)

    # Lease timing
    lease_time: int | None = None  # seconds
    renewal_time: int | None = None  # T1
    rebinding_time: int | None = None  # T2

    # Server info
    server_id: str | None = None
    server_hostname: str | None = None

    # PXE/Boot info
    tftp_server: str | None = None
    bootfile: str | None = None
    next_server: str | None = None  # siaddr from DHCP packet

    # Relay agent info (Option 82)
    relay_agent_circuit_id: bytes | None = None
    relay_agent_remote_id: bytes | None = None
    relay_agent_info_raw: bytes | None = None

    # Timestamps
    obtained_at: datetime | None = None
    expires_at: datetime | None = None

    # Transaction
    transaction_id: int | None = None
    client_mac: str | None = None

    # All options received
    all_options: dict[int, bytes] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "subnet_mask": self.subnet_mask,
            "gateway": self.gateway,
            "dns_servers": self.dns_servers,
            "domain_name": self.domain_name,
            "broadcast_address": self.broadcast_address,
            "ntp_servers": self.ntp_servers,
            "lease_time": self.lease_time,
            "renewal_time": self.renewal_time,
            "rebinding_time": self.rebinding_time,
            "server_id": self.server_id,
            "tftp_server": self.tftp_server,
            "bootfile": self.bootfile,
            "next_server": self.next_server,
            "relay_agent_circuit_id": self.relay_agent_circuit_id.hex() if self.relay_agent_circuit_id else None,
            "relay_agent_remote_id": self.relay_agent_remote_id.hex() if self.relay_agent_remote_id else None,
            "obtained_at": self.obtained_at.isoformat() if self.obtained_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "transaction_id": self.transaction_id,
            "client_mac": self.client_mac,
        }


class DHCPClient:
    """
    DHCP client for network troubleshooting.

    Provides verbose output for debugging DHCP issues, relay agent
    problems, and PXE boot configurations.

    Usage:
        client = DHCPClient(verbose=True)
        lease = client.discover_and_request(interface="eth0")
        print(f"Got IP: {lease.ip_address}")

        # Release
        client.release(lease)
    """

    def __init__(
        self,
        config: DHCPConfig | None = None,
        verbose: bool = False,
        log_callback: Callable[[str, str], None] | None = None,
    ):
        """
        Initialize DHCP client.

        Args:
            config: Client configuration
            verbose: Enable verbose debug output
            log_callback: Optional callback for log messages (level, message)
        """
        self.config = config or DHCPConfig()
        self.verbose = verbose
        self.log_callback = log_callback
        self._socket: socket.socket | None = None

    def _log(self, level: str, message: str):
        """Log a message."""
        if self.log_callback:
            self.log_callback(level, message)
        elif self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] [{level.upper():5}] {message}")

    def _log_debug(self, message: str):
        if self.verbose:
            self._log("debug", message)

    def _log_info(self, message: str):
        self._log("info", message)

    def _log_warn(self, message: str):
        self._log("warn", message)

    def _log_error(self, message: str):
        self._log("error", message)

    def _get_mac_address(self, interface: str | None = None) -> bytes:
        """Get MAC address for interface."""
        if self.config.mac_address:
            # Parse provided MAC
            mac = self.config.mac_address.replace(":", "").replace("-", "")
            return bytes.fromhex(mac)

        # Try to get from interface
        interface = interface or self.config.interface

        if interface:
            try:
                import fcntl
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                info = fcntl.ioctl(
                    sock.fileno(),
                    0x8927,  # SIOCGIFHWADDR
                    struct.pack('256s', interface.encode()[:15])
                )
                return info[18:24]
            except Exception as e:
                self._log_debug(f"Could not get MAC from interface: {e}")

        # Generate random MAC for testing (locally administered)
        mac = bytes([0x02, random.randint(0, 255), random.randint(0, 255),
                     random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)])
        self._log_warn(f"Using random MAC address: {self._format_mac(mac)}")
        return mac

    def _format_mac(self, mac: bytes) -> str:
        """Format MAC address as string."""
        return ":".join(f"{b:02x}" for b in mac)

    def _format_ip(self, ip_bytes: bytes) -> str:
        """Format IP address bytes as string."""
        return ".".join(str(b) for b in ip_bytes)

    def _parse_ip(self, ip_str: str) -> bytes:
        """Parse IP string to bytes."""
        return bytes(int(x) for x in ip_str.split("."))

    def _create_socket(self, interface: str | None = None) -> socket.socket:
        """Create UDP socket for DHCP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Bind to specific interface if provided
        if interface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, 25, interface.encode())  # SO_BINDTODEVICE
                self._log_debug(f"Bound to interface: {interface}")
            except OSError as e:
                self._log_warn(f"Could not bind to interface {interface}: {e}")

        sock.bind(('0.0.0.0', DHCP_CLIENT_PORT))
        return sock

    def _build_dhcp_packet(
        self,
        message_type: DHCPMessageType,
        mac: bytes,
        transaction_id: int,
        ciaddr: bytes = b'\x00\x00\x00\x00',
        requested_ip: str | None = None,
        server_id: str | None = None,
    ) -> bytes:
        """Build a DHCP packet."""
        self._log_debug(f"Building DHCP {message_type.name} packet")

        # DHCP Header
        op = BOOTREQUEST
        htype = HTYPE_ETHERNET
        hlen = 6
        hops = 0
        xid = transaction_id
        secs = 0
        flags = 0x8000  # Broadcast flag

        # Pad MAC to 16 bytes
        chaddr = mac + b'\x00' * 10

        # Server hostname (64 bytes) and boot filename (128 bytes) - unused
        sname = b'\x00' * 64
        bfile = b'\x00' * 128

        # Build header (236 bytes before options)
        packet = struct.pack(
            '>BBBBIHH4s4s4s4s16s64s128s',
            op, htype, hlen, hops,
            xid, secs, flags,
            ciaddr,  # ciaddr
            b'\x00\x00\x00\x00',  # yiaddr
            b'\x00\x00\x00\x00',  # siaddr
            b'\x00\x00\x00\x00',  # giaddr
            chaddr,
            sname,
            bfile,
        )

        # Magic cookie
        packet += DHCP_MAGIC_COOKIE

        # Options
        # Message type (required)
        packet += bytes([DHCPOption.MESSAGE_TYPE, 1, message_type])

        # Client identifier
        if self.config.client_id:
            packet += bytes([DHCPOption.CLIENT_ID, len(self.config.client_id)])
            packet += self.config.client_id
        else:
            # Default: hardware type + MAC
            client_id = bytes([HTYPE_ETHERNET]) + mac
            packet += bytes([DHCPOption.CLIENT_ID, len(client_id)])
            packet += client_id

        # Hostname
        if self.config.hostname:
            hostname = self.config.hostname.encode()
            packet += bytes([DHCPOption.HOSTNAME, len(hostname)])
            packet += hostname

        # Requested IP (for REQUEST)
        if requested_ip:
            ip_bytes = self._parse_ip(requested_ip)
            packet += bytes([DHCPOption.REQUESTED_IP, 4])
            packet += ip_bytes
            self._log_debug(f"  Requesting IP: {requested_ip}")

        # Server identifier (for REQUEST/RELEASE)
        if server_id:
            server_bytes = self._parse_ip(server_id)
            packet += bytes([DHCPOption.SERVER_ID, 4])
            packet += server_bytes
            self._log_debug(f"  Server ID: {server_id}")

        # Parameter request list
        if self.config.requested_options:
            packet += bytes([DHCPOption.PARAMETER_REQUEST, len(self.config.requested_options)])
            packet += bytes(self.config.requested_options)

        # Vendor class ID (for PXE)
        if self.config.vendor_class_id:
            vci = self.config.vendor_class_id.encode()
            packet += bytes([DHCPOption.VENDOR_CLASS_ID, len(vci)])
            packet += vci
            self._log_debug(f"  Vendor Class ID: {self.config.vendor_class_id}")

        # PXE client architecture
        if self.config.pxe_client_arch is not None:
            packet += bytes([DHCPOption.PXE_CLIENT_ARCH, 2])
            packet += struct.pack('>H', self.config.pxe_client_arch)
            arch_names = {0: "x86 BIOS", 7: "x64 UEFI", 9: "x86 UEFI"}
            arch_name = arch_names.get(self.config.pxe_client_arch, "Unknown")
            self._log_debug(f"  PXE Client Arch: {self.config.pxe_client_arch} ({arch_name})")

        # PXE UUID
        if self.config.pxe_uuid:
            packet += bytes([DHCPOption.PXE_CLIENT_UUID, 17])
            packet += bytes([0])  # Type
            packet += self.config.pxe_uuid

        # Max message size
        packet += bytes([DHCPOption.MAX_MESSAGE_SIZE, 2])
        packet += struct.pack('>H', 1500)

        # End option
        packet += bytes([DHCPOption.END])

        # Pad to minimum size
        if len(packet) < 300:
            packet += b'\x00' * (300 - len(packet))

        return packet

    def _parse_dhcp_packet(self, data: bytes, mac: bytes, xid: int) -> DHCPLease | None:
        """Parse a DHCP response packet."""
        if len(data) < 240:
            self._log_debug(f"Packet too short: {len(data)} bytes")
            return None

        # Parse header
        op, htype, hlen, hops = struct.unpack('>BBBB', data[0:4])
        rx_xid = struct.unpack('>I', data[4:8])[0]
        secs, flags = struct.unpack('>HH', data[8:12])
        ciaddr = data[12:16]
        yiaddr = data[16:20]
        siaddr = data[20:24]
        giaddr = data[24:28]
        chaddr = data[28:44]

        self._log_debug(f"Received DHCP packet:")
        self._log_debug(f"  Operation: {'REPLY' if op == BOOTREPLY else 'REQUEST'}")
        self._log_debug(f"  Transaction ID: 0x{rx_xid:08x}")
        self._log_debug(f"  Your IP (yiaddr): {self._format_ip(yiaddr)}")
        self._log_debug(f"  Server IP (siaddr): {self._format_ip(siaddr)}")
        self._log_debug(f"  Gateway IP (giaddr): {self._format_ip(giaddr)}")

        # Verify transaction ID
        if rx_xid != xid:
            self._log_debug(f"Transaction ID mismatch: expected 0x{xid:08x}, got 0x{rx_xid:08x}")
            return None

        # Verify it's a reply
        if op != BOOTREPLY:
            self._log_debug("Not a BOOTREPLY")
            return None

        # Verify magic cookie
        if data[236:240] != DHCP_MAGIC_COOKIE:
            self._log_debug("Invalid magic cookie")
            return None

        # Parse options
        lease = DHCPLease(
            transaction_id=rx_xid,
            client_mac=self._format_mac(mac),
            obtained_at=datetime.now(),
        )

        # Set yiaddr as offered IP
        if yiaddr != b'\x00\x00\x00\x00':
            lease.ip_address = self._format_ip(yiaddr)

        # siaddr is next-server for PXE
        if siaddr != b'\x00\x00\x00\x00':
            lease.next_server = self._format_ip(siaddr)
            self._log_debug(f"  Next Server (siaddr): {lease.next_server}")

        # Parse options
        options_data = data[240:]
        i = 0
        message_type = None

        self._log_debug("  Options:")

        while i < len(options_data):
            option = options_data[i]

            if option == DHCPOption.PAD:
                i += 1
                continue

            if option == DHCPOption.END:
                break

            if i + 1 >= len(options_data):
                break

            length = options_data[i + 1]
            if i + 2 + length > len(options_data):
                break

            value = options_data[i + 2:i + 2 + length]
            lease.all_options[option] = value

            # Parse known options
            option_name = DHCPOption(option).name if option in DHCPOption._value2member_map_ else f"Unknown({option})"

            if option == DHCPOption.MESSAGE_TYPE and length == 1:
                message_type = DHCPMessageType(value[0])
                self._log_debug(f"    [{option:3}] {option_name}: {message_type.name}")

            elif option == DHCPOption.SUBNET_MASK and length == 4:
                lease.subnet_mask = self._format_ip(value)
                self._log_debug(f"    [{option:3}] {option_name}: {lease.subnet_mask}")

            elif option == DHCPOption.ROUTER and length >= 4:
                lease.gateway = self._format_ip(value[0:4])
                self._log_debug(f"    [{option:3}] {option_name}: {lease.gateway}")

            elif option == DHCPOption.DNS_SERVER:
                for j in range(0, length, 4):
                    if j + 4 <= length:
                        dns = self._format_ip(value[j:j + 4])
                        lease.dns_servers.append(dns)
                self._log_debug(f"    [{option:3}] {option_name}: {', '.join(lease.dns_servers)}")

            elif option == DHCPOption.DOMAIN_NAME:
                lease.domain_name = value.decode('utf-8', errors='ignore').rstrip('\x00')
                self._log_debug(f"    [{option:3}] {option_name}: {lease.domain_name}")

            elif option == DHCPOption.BROADCAST_ADDRESS and length == 4:
                lease.broadcast_address = self._format_ip(value)
                self._log_debug(f"    [{option:3}] {option_name}: {lease.broadcast_address}")

            elif option == DHCPOption.NTP_SERVER:
                for j in range(0, length, 4):
                    if j + 4 <= length:
                        ntp = self._format_ip(value[j:j + 4])
                        lease.ntp_servers.append(ntp)
                self._log_debug(f"    [{option:3}] {option_name}: {', '.join(lease.ntp_servers)}")

            elif option == DHCPOption.LEASE_TIME and length == 4:
                lease.lease_time = struct.unpack('>I', value)[0]
                self._log_debug(f"    [{option:3}] {option_name}: {lease.lease_time}s ({lease.lease_time // 3600}h)")

            elif option == DHCPOption.RENEWAL_TIME and length == 4:
                lease.renewal_time = struct.unpack('>I', value)[0]
                self._log_debug(f"    [{option:3}] {option_name}: {lease.renewal_time}s (T1)")

            elif option == DHCPOption.REBINDING_TIME and length == 4:
                lease.rebinding_time = struct.unpack('>I', value)[0]
                self._log_debug(f"    [{option:3}] {option_name}: {lease.rebinding_time}s (T2)")

            elif option == DHCPOption.SERVER_ID and length == 4:
                lease.server_id = self._format_ip(value)
                self._log_debug(f"    [{option:3}] {option_name}: {lease.server_id}")

            elif option == DHCPOption.TFTP_SERVER_NAME:
                lease.tftp_server = value.decode('utf-8', errors='ignore').rstrip('\x00')
                self._log_debug(f"    [{option:3}] {option_name}: {lease.tftp_server}")

            elif option == DHCPOption.BOOTFILE_NAME:
                lease.bootfile = value.decode('utf-8', errors='ignore').rstrip('\x00')
                self._log_debug(f"    [{option:3}] {option_name}: {lease.bootfile}")

            elif option == DHCPOption.RELAY_AGENT_INFO:
                self._log_debug(f"    [{option:3}] {option_name}: (Option 82 - Relay Agent Info)")
                lease.relay_agent_info_raw = value
                self._parse_relay_agent_info(value, lease)

            elif option == DHCPOption.MESSAGE:
                msg = value.decode('utf-8', errors='ignore').rstrip('\x00')
                self._log_debug(f"    [{option:3}] {option_name}: {msg}")

            elif option == DHCPOption.VENDOR_SPECIFIC:
                self._log_debug(f"    [{option:3}] {option_name}: {value.hex()}")

            elif option == DHCPOption.PXE_CLIENT_ARCH:
                arch = struct.unpack('>H', value)[0] if length >= 2 else 0
                arch_names = {0: "x86 BIOS", 7: "x64 UEFI", 9: "x86 UEFI"}
                self._log_debug(f"    [{option:3}] {option_name}: {arch} ({arch_names.get(arch, 'Unknown')})")

            else:
                # Unknown option - show hex
                hex_value = value.hex() if len(value) <= 16 else value[:16].hex() + "..."
                self._log_debug(f"    [{option:3}] {option_name}: {hex_value}")

            i += 2 + length

        # Calculate expiration
        if lease.lease_time and lease.obtained_at:
            lease.expires_at = lease.obtained_at + timedelta(seconds=lease.lease_time)

        return lease if message_type else None

    def _parse_relay_agent_info(self, data: bytes, lease: DHCPLease):
        """Parse Option 82 (Relay Agent Information) sub-options."""
        i = 0
        while i < len(data):
            if i + 1 >= len(data):
                break

            sub_option = data[i]
            sub_length = data[i + 1]

            if i + 2 + sub_length > len(data):
                break

            sub_value = data[i + 2:i + 2 + sub_length]

            sub_option_name = (
                RelayAgentSubOption(sub_option).name
                if sub_option in RelayAgentSubOption._value2member_map_
                else f"Unknown({sub_option})"
            )

            if sub_option == RelayAgentSubOption.CIRCUIT_ID:
                lease.relay_agent_circuit_id = sub_value
                # Try to decode as ASCII if printable
                try:
                    decoded = sub_value.decode('ascii')
                    if decoded.isprintable():
                        self._log_debug(f"      Sub-option {sub_option}: {sub_option_name} = {decoded}")
                    else:
                        self._log_debug(f"      Sub-option {sub_option}: {sub_option_name} = {sub_value.hex()}")
                except:
                    self._log_debug(f"      Sub-option {sub_option}: {sub_option_name} = {sub_value.hex()}")

            elif sub_option == RelayAgentSubOption.REMOTE_ID:
                lease.relay_agent_remote_id = sub_value
                self._log_debug(f"      Sub-option {sub_option}: {sub_option_name} = {sub_value.hex()}")

            else:
                self._log_debug(f"      Sub-option {sub_option}: {sub_option_name} = {sub_value.hex()}")

            i += 2 + sub_length

    def discover(self, interface: str | None = None) -> DHCPLease | None:
        """
        Send DHCPDISCOVER and wait for DHCPOFFER.

        Args:
            interface: Network interface to use

        Returns:
            DHCPLease with offer details, or None if no offer received
        """
        interface = interface or self.config.interface
        mac = self._get_mac_address(interface)
        xid = random.randint(0, 0xFFFFFFFF)

        self._log_info(f"=== DHCP DISCOVER ===")
        self._log_info(f"Interface: {interface or 'default'}")
        self._log_info(f"Client MAC: {self._format_mac(mac)}")
        self._log_info(f"Transaction ID: 0x{xid:08x}")

        packet = self._build_dhcp_packet(DHCPMessageType.DISCOVER, mac, xid)

        self._log_debug(f"Packet size: {len(packet)} bytes")
        self._log_info("Sending DHCPDISCOVER broadcast...")

        try:
            sock = self._create_socket(interface)
            sock.settimeout(self.config.discover_timeout)

            # Send to broadcast
            sock.sendto(packet, ('255.255.255.255', DHCP_SERVER_PORT))
            self._log_debug("Packet sent, waiting for DHCPOFFER...")

            # Wait for response
            start_time = time.time()
            while time.time() - start_time < self.config.discover_timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    self._log_debug(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")

                    lease = self._parse_dhcp_packet(data, mac, xid)
                    if lease:
                        msg_type = lease.all_options.get(DHCPOption.MESSAGE_TYPE)
                        if msg_type and msg_type[0] == DHCPMessageType.OFFER:
                            self._log_info(f"=== DHCP OFFER RECEIVED ===")
                            self._log_info(f"Offered IP: {lease.ip_address}")
                            self._log_info(f"Server ID: {lease.server_id}")
                            return lease

                except socket.timeout:
                    break

            self._log_warn("No DHCPOFFER received (timeout)")
            return None

        except PermissionError:
            self._log_error("Permission denied - run as root or with CAP_NET_RAW")
            raise
        finally:
            if 'sock' in locals():
                sock.close()

    def request(
        self,
        offer: DHCPLease,
        interface: str | None = None,
    ) -> DHCPLease | None:
        """
        Send DHCPREQUEST for an offer and wait for DHCPACK.

        Args:
            offer: DHCPLease from discover()
            interface: Network interface to use

        Returns:
            DHCPLease with confirmed lease, or None if NAK received
        """
        interface = interface or self.config.interface
        mac = bytes.fromhex(offer.client_mac.replace(":", ""))
        xid = offer.transaction_id or random.randint(0, 0xFFFFFFFF)

        self._log_info(f"=== DHCP REQUEST ===")
        self._log_info(f"Requesting IP: {offer.ip_address}")
        self._log_info(f"Server ID: {offer.server_id}")
        self._log_info(f"Transaction ID: 0x{xid:08x}")

        packet = self._build_dhcp_packet(
            DHCPMessageType.REQUEST,
            mac,
            xid,
            requested_ip=offer.ip_address,
            server_id=offer.server_id,
        )

        self._log_info("Sending DHCPREQUEST...")

        try:
            sock = self._create_socket(interface)
            sock.settimeout(self.config.request_timeout)

            sock.sendto(packet, ('255.255.255.255', DHCP_SERVER_PORT))
            self._log_debug("Packet sent, waiting for DHCPACK/NAK...")

            start_time = time.time()
            while time.time() - start_time < self.config.request_timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    self._log_debug(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")

                    lease = self._parse_dhcp_packet(data, mac, xid)
                    if lease:
                        msg_type = lease.all_options.get(DHCPOption.MESSAGE_TYPE)
                        if msg_type:
                            if msg_type[0] == DHCPMessageType.ACK:
                                self._log_info(f"=== DHCP ACK RECEIVED ===")
                                self._log_info(f"Assigned IP: {lease.ip_address}")
                                self._log_info(f"Subnet Mask: {lease.subnet_mask}")
                                self._log_info(f"Gateway: {lease.gateway}")
                                self._log_info(f"DNS: {', '.join(lease.dns_servers)}")
                                self._log_info(f"Lease Time: {lease.lease_time}s")
                                if lease.tftp_server or lease.bootfile:
                                    self._log_info(f"TFTP Server: {lease.tftp_server or lease.next_server}")
                                    self._log_info(f"Boot File: {lease.bootfile}")
                                return lease

                            elif msg_type[0] == DHCPMessageType.NAK:
                                self._log_error("=== DHCP NAK RECEIVED ===")
                                msg = lease.all_options.get(DHCPOption.MESSAGE)
                                if msg:
                                    self._log_error(f"Server message: {msg.decode('utf-8', errors='ignore')}")
                                return None

                except socket.timeout:
                    break

            self._log_warn("No DHCPACK received (timeout)")
            return None

        finally:
            if 'sock' in locals():
                sock.close()

    def discover_and_request(
        self,
        interface: str | None = None,
    ) -> DHCPLease | None:
        """
        Complete DHCP DORA process (Discover-Offer-Request-Ack).

        Args:
            interface: Network interface to use

        Returns:
            DHCPLease with confirmed lease, or None if failed
        """
        self._log_info("=" * 50)
        self._log_info("Starting DHCP DORA process")
        self._log_info("=" * 50)

        for attempt in range(self.config.max_retries):
            if attempt > 0:
                self._log_info(f"Retry {attempt + 1}/{self.config.max_retries}")
                time.sleep(1)

            offer = self.discover(interface)
            if not offer:
                continue

            lease = self.request(offer, interface)
            if lease:
                self._log_info("=" * 50)
                self._log_info("DHCP lease obtained successfully")
                self._log_info("=" * 50)
                return lease

        self._log_error("Failed to obtain DHCP lease after all retries")
        return None

    def release(
        self,
        lease: DHCPLease,
        interface: str | None = None,
    ) -> bool:
        """
        Release a DHCP lease.

        Args:
            lease: The lease to release
            interface: Network interface to use

        Returns:
            True if release was sent (no response expected)
        """
        interface = interface or self.config.interface
        mac = bytes.fromhex(lease.client_mac.replace(":", ""))
        xid = random.randint(0, 0xFFFFFFFF)
        ciaddr = self._parse_ip(lease.ip_address)

        self._log_info(f"=== DHCP RELEASE ===")
        self._log_info(f"Releasing IP: {lease.ip_address}")
        self._log_info(f"Server ID: {lease.server_id}")

        packet = self._build_dhcp_packet(
            DHCPMessageType.RELEASE,
            mac,
            xid,
            ciaddr=ciaddr,
            server_id=lease.server_id,
        )

        try:
            sock = self._create_socket(interface)

            # Send unicast to server
            server_ip = lease.server_id or '255.255.255.255'
            sock.sendto(packet, (server_ip, DHCP_SERVER_PORT))

            self._log_info(f"DHCPRELEASE sent to {server_ip}")
            self._log_info("Lease released (no response expected)")
            return True

        except Exception as e:
            self._log_error(f"Failed to release lease: {e}")
            return False
        finally:
            if 'sock' in locals():
                sock.close()

    def inform(
        self,
        ip_address: str,
        interface: str | None = None,
    ) -> DHCPLease | None:
        """
        Send DHCPINFORM to get configuration without requesting an IP.

        Useful for getting options (DNS, NTP, PXE, etc.) when you
        already have an IP address.

        Args:
            ip_address: Your current IP address
            interface: Network interface to use

        Returns:
            DHCPLease with configuration options, or None if no response
        """
        interface = interface or self.config.interface
        mac = self._get_mac_address(interface)
        xid = random.randint(0, 0xFFFFFFFF)
        ciaddr = self._parse_ip(ip_address)

        self._log_info(f"=== DHCP INFORM ===")
        self._log_info(f"Client IP: {ip_address}")
        self._log_info(f"Client MAC: {self._format_mac(mac)}")

        packet = self._build_dhcp_packet(
            DHCPMessageType.INFORM,
            mac,
            xid,
            ciaddr=ciaddr,
        )

        try:
            sock = self._create_socket(interface)
            sock.settimeout(self.config.request_timeout)

            sock.sendto(packet, ('255.255.255.255', DHCP_SERVER_PORT))
            self._log_info("DHCPINFORM sent, waiting for DHCPACK...")

            start_time = time.time()
            while time.time() - start_time < self.config.request_timeout:
                try:
                    data, addr = sock.recvfrom(4096)
                    self._log_debug(f"Received {len(data)} bytes from {addr[0]}:{addr[1]}")

                    lease = self._parse_dhcp_packet(data, mac, xid)
                    if lease:
                        msg_type = lease.all_options.get(DHCPOption.MESSAGE_TYPE)
                        if msg_type and msg_type[0] == DHCPMessageType.ACK:
                            self._log_info("=== DHCPACK RECEIVED ===")
                            return lease

                except socket.timeout:
                    break

            self._log_warn("No DHCPACK received (timeout)")
            return None

        finally:
            if 'sock' in locals():
                sock.close()
