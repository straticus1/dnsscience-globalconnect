"""
Netcat core implementation with TLS encryption support.

Provides netcat-like functionality with:
- TCP/UDP connections
- TLS encryption (auto, yes, no)
- Listen mode (server)
- Connect mode (client)
- File transfer
- Verbose debugging

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import os
import select
import socket
import ssl
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, BinaryIO, Callable


class EncryptionMode(str, Enum):
    """TLS encryption mode."""
    YES = "yes"      # Force TLS
    NO = "no"        # No encryption
    AUTO = "auto"    # Try TLS, fall back to plain


class Protocol(str, Enum):
    """Network protocol."""
    TCP = "tcp"
    UDP = "udp"


@dataclass
class NetcatConfig:
    """Configuration for netcat operations."""
    # Connection
    host: str = "localhost"
    port: int = 0
    protocol: Protocol = Protocol.TCP

    # Encryption
    encryption: EncryptionMode = EncryptionMode.AUTO
    ssl_cert: str | None = None  # Path to certificate file
    ssl_key: str | None = None   # Path to key file
    ssl_ca: str | None = None    # Path to CA bundle
    ssl_verify: bool = True      # Verify server certificate
    ssl_hostname: str | None = None  # Override hostname for SNI

    # Timeouts
    connect_timeout: float = 10.0
    read_timeout: float | None = None  # None = blocking
    idle_timeout: float | None = None  # Close after idle period

    # Behavior
    listen: bool = False         # Listen mode (server)
    keep_open: bool = False      # Keep listening after client disconnects
    zero_io: bool = False        # Zero-I/O mode (port scan)
    execute: str | None = None   # Execute command on connect (DANGEROUS)
    source_host: str | None = None  # Source address to bind
    source_port: int | None = None  # Source port to bind

    # Logging
    verbose: bool = False
    hex_dump: bool = False       # Show hex dump of data
    log_callback: Callable[[str, str], None] | None = None


class NetcatClient:
    """
    Netcat client for outbound connections.

    Usage:
        config = NetcatConfig(host="example.com", port=443, encryption=EncryptionMode.YES)
        client = NetcatClient(config)
        await client.connect()
        await client.send(b"GET / HTTP/1.0\\r\\n\\r\\n")
        response = await client.recv()
        await client.close()
    """

    def __init__(self, config: NetcatConfig):
        self.config = config
        self._socket: socket.socket | None = None
        self._ssl_socket: ssl.SSLSocket | None = None
        self._connected = False

    def _log(self, level: str, message: str):
        """Log a message."""
        if self.config.log_callback:
            self.config.log_callback(level, message)
        elif self.config.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] [{level.upper():5}] {message}", file=sys.stderr)

    def _hex_dump(self, data: bytes, prefix: str = ""):
        """Print hex dump of data."""
        if not self.config.hex_dump:
            return

        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            print(f"{prefix}{i:08x}  {hex_part:<48}  {ascii_part}", file=sys.stderr)

    async def connect(self) -> bool:
        """
        Connect to remote host.

        Returns:
            True if connected successfully
        """
        try:
            self._log("info", f"Connecting to {self.config.host}:{self.config.port}")

            # Create socket
            if self.config.protocol == Protocol.TCP:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self._socket.settimeout(self.config.connect_timeout)

            # Bind source if specified
            if self.config.source_host or self.config.source_port:
                source = (
                    self.config.source_host or "0.0.0.0",
                    self.config.source_port or 0
                )
                self._socket.bind(source)
                self._log("debug", f"Bound to {source[0]}:{source[1]}")

            # Connect
            self._socket.connect((self.config.host, self.config.port))
            self._log("info", f"Connected to {self.config.host}:{self.config.port}")

            # Handle TLS
            if self.config.protocol == Protocol.TCP:
                if self.config.encryption == EncryptionMode.YES:
                    await self._wrap_ssl()
                elif self.config.encryption == EncryptionMode.AUTO:
                    # Try TLS on common secure ports
                    secure_ports = {443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 8443}
                    if self.config.port in secure_ports:
                        try:
                            await self._wrap_ssl()
                        except ssl.SSLError as e:
                            self._log("warn", f"TLS failed, using plain: {e}")

            # Set read timeout
            if self.config.read_timeout:
                self._socket.settimeout(self.config.read_timeout)
            else:
                self._socket.settimeout(None)

            self._connected = True
            return True

        except socket.timeout:
            self._log("error", "Connection timed out")
            return False
        except ConnectionRefusedError:
            self._log("error", "Connection refused")
            return False
        except Exception as e:
            self._log("error", f"Connection failed: {e}")
            return False

    async def _wrap_ssl(self):
        """Wrap socket with SSL/TLS."""
        self._log("debug", "Initiating TLS handshake")

        context = ssl.create_default_context()

        if not self.config.ssl_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self._log("warn", "TLS certificate verification disabled")

        if self.config.ssl_ca:
            context.load_verify_locations(self.config.ssl_ca)

        if self.config.ssl_cert:
            context.load_cert_chain(
                self.config.ssl_cert,
                keyfile=self.config.ssl_key
            )

        hostname = self.config.ssl_hostname or self.config.host

        self._ssl_socket = context.wrap_socket(
            self._socket,
            server_hostname=hostname
        )

        # Log TLS info
        cipher = self._ssl_socket.cipher()
        version = self._ssl_socket.version()
        self._log("info", f"TLS established: {version}, {cipher[0]}")

        try:
            cert = self._ssl_socket.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert.get("subject", []))
                cn = subject.get("commonName", "Unknown")
                self._log("debug", f"Server certificate CN: {cn}")
        except Exception:
            pass

    async def send(self, data: bytes) -> int:
        """
        Send data to remote host.

        Args:
            data: Data to send

        Returns:
            Number of bytes sent
        """
        if not self._connected:
            raise RuntimeError("Not connected")

        sock = self._ssl_socket or self._socket

        self._log("debug", f"Sending {len(data)} bytes")
        self._hex_dump(data, ">>> ")

        if self.config.protocol == Protocol.UDP:
            return sock.sendto(data, (self.config.host, self.config.port))
        else:
            return sock.send(data)

    async def recv(self, size: int = 8192) -> bytes:
        """
        Receive data from remote host.

        Args:
            size: Maximum bytes to receive

        Returns:
            Received data (empty if connection closed)
        """
        if not self._connected:
            raise RuntimeError("Not connected")

        sock = self._ssl_socket or self._socket

        try:
            if self.config.protocol == Protocol.UDP:
                data, addr = sock.recvfrom(size)
            else:
                data = sock.recv(size)

            if data:
                self._log("debug", f"Received {len(data)} bytes")
                self._hex_dump(data, "<<< ")

            return data

        except socket.timeout:
            return b""

    async def close(self):
        """Close the connection."""
        self._connected = False

        if self._ssl_socket:
            try:
                self._ssl_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self._ssl_socket.close()
            self._ssl_socket = None

        if self._socket:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self._socket.close()
            self._socket = None

        self._log("info", "Connection closed")

    @property
    def connected(self) -> bool:
        return self._connected


class NetcatServer:
    """
    Netcat server for inbound connections.

    Usage:
        config = NetcatConfig(port=8080, listen=True)
        server = NetcatServer(config)
        await server.start()
        # Handle connections...
        await server.stop()
    """

    def __init__(self, config: NetcatConfig):
        self.config = config
        self._socket: socket.socket | None = None
        self._ssl_context: ssl.SSLContext | None = None
        self._running = False
        self._clients: list[socket.socket] = []

    def _log(self, level: str, message: str):
        """Log a message."""
        if self.config.log_callback:
            self.config.log_callback(level, message)
        elif self.config.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"[{timestamp}] [{level.upper():5}] {message}", file=sys.stderr)

    async def start(self) -> bool:
        """
        Start listening for connections.

        Returns:
            True if server started successfully
        """
        try:
            bind_host = self.config.source_host or "0.0.0.0"

            # Create socket
            if self.config.protocol == Protocol.TCP:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self._socket.bind((bind_host, self.config.port))

            if self.config.protocol == Protocol.TCP:
                self._socket.listen(5)

            # Setup TLS if needed
            if self.config.encryption == EncryptionMode.YES:
                if not self.config.ssl_cert:
                    self._log("error", "TLS requires certificate (--ssl-cert)")
                    return False

                self._ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                self._ssl_context.load_cert_chain(
                    self.config.ssl_cert,
                    keyfile=self.config.ssl_key
                )
                self._log("info", "TLS enabled")

            actual_port = self._socket.getsockname()[1]
            self._log("info", f"Listening on {bind_host}:{actual_port} ({self.config.protocol.value})")

            self._running = True
            return True

        except PermissionError:
            self._log("error", f"Permission denied for port {self.config.port}")
            return False
        except OSError as e:
            self._log("error", f"Failed to bind: {e}")
            return False

    async def accept(self) -> tuple[socket.socket, tuple[str, int]] | None:
        """
        Accept a client connection (TCP only).

        Returns:
            Tuple of (client_socket, (host, port)) or None
        """
        if not self._running or self.config.protocol != Protocol.TCP:
            return None

        try:
            self._socket.settimeout(1.0)
            client, addr = self._socket.accept()

            self._log("info", f"Connection from {addr[0]}:{addr[1]}")

            # Wrap with TLS if configured
            if self._ssl_context:
                self._log("debug", "Starting TLS handshake")
                client = self._ssl_context.wrap_socket(client, server_side=True)
                self._log("debug", f"TLS established: {client.version()}")

            self._clients.append(client)
            return client, addr

        except socket.timeout:
            return None
        except ssl.SSLError as e:
            self._log("error", f"TLS handshake failed: {e}")
            return None

    async def stop(self):
        """Stop the server."""
        self._running = False

        # Close all client connections
        for client in self._clients:
            try:
                client.close()
            except Exception:
                pass
        self._clients.clear()

        if self._socket:
            self._socket.close()
            self._socket = None

        self._log("info", "Server stopped")

    @property
    def running(self) -> bool:
        return self._running


async def port_scan(
    host: str,
    ports: list[int],
    timeout: float = 2.0,
    verbose: bool = False,
) -> dict[int, str]:
    """
    Scan ports on a host.

    Args:
        host: Target host
        ports: List of ports to scan
        timeout: Connection timeout per port
        verbose: Show scan progress

    Returns:
        Dict mapping open ports to service banners (if received)
    """
    results = {}

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            if result == 0:
                # Port is open
                banner = ""
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass

                results[port] = banner
                if verbose:
                    print(f"  {port}/tcp open {banner[:50] if banner else ''}")

            sock.close()

        except Exception as e:
            if verbose:
                print(f"  {port}/tcp error: {e}")

    return results
