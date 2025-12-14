"""
CLI for netcat operations.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import asyncio
import os
import select
import sys
import threading

import click
from rich.console import Console
from rich.table import Table

from globaldetect.netcat.core import (
    NetcatClient,
    NetcatConfig,
    NetcatServer,
    EncryptionMode,
    Protocol,
    port_scan,
)

console = Console()


@click.group()
def nc():
    """Netcat - network utility for connections and port scanning.

    A versatile networking tool for:
    - TCP/UDP connections with optional TLS encryption
    - Listen mode (server)
    - Port scanning
    - Data transfer

    \b
    Examples:
        # Connect to a server
        globaldetect nc connect example.com 80

        # Connect with TLS
        globaldetect nc connect example.com 443 --tls yes

        # Listen on a port
        globaldetect nc listen 8080

        # Port scan
        globaldetect nc scan example.com 1-1000
    """
    pass


@nc.command()
@click.argument("host")
@click.argument("port", type=int)
@click.option("--tls", "-e", type=click.Choice(["yes", "no", "auto"]), default="auto",
              help="TLS encryption mode")
@click.option("--udp", "-u", is_flag=True, help="Use UDP instead of TCP")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--hex", "-x", is_flag=True, help="Show hex dump of data")
@click.option("--timeout", "-w", type=float, default=10.0, help="Connection timeout")
@click.option("--source", "-s", help="Source address to bind")
@click.option("--source-port", "-p", type=int, help="Source port to bind")
@click.option("--ssl-cert", help="Client certificate file")
@click.option("--ssl-key", help="Client key file")
@click.option("--ssl-ca", help="CA certificate bundle")
@click.option("--no-verify", is_flag=True, help="Don't verify server certificate")
@click.option("--zero", "-z", is_flag=True, help="Zero-I/O mode (just test connection)")
def connect(
    host: str,
    port: int,
    tls: str,
    udp: bool,
    verbose: bool,
    hex: bool,
    timeout: float,
    source: str | None,
    source_port: int | None,
    ssl_cert: str | None,
    ssl_key: str | None,
    ssl_ca: str | None,
    no_verify: bool,
    zero: bool,
):
    """Connect to a remote host.

    \b
    Examples:
        # Simple connection
        globaldetect nc connect example.com 80

        # HTTPS connection
        globaldetect nc connect example.com 443 --tls yes

        # Test connection only
        globaldetect nc connect example.com 22 -z

        # With verbose output
        globaldetect nc connect example.com 443 --tls yes -v
    """
    config = NetcatConfig(
        host=host,
        port=port,
        protocol=Protocol.UDP if udp else Protocol.TCP,
        encryption=EncryptionMode(tls),
        connect_timeout=timeout,
        verbose=verbose,
        hex_dump=hex,
        source_host=source,
        source_port=source_port,
        ssl_cert=ssl_cert,
        ssl_key=ssl_key,
        ssl_ca=ssl_ca,
        ssl_verify=not no_verify,
        zero_io=zero,
    )

    client = NetcatClient(config)

    async def run():
        if not await client.connect():
            return 1

        if zero:
            console.print(f"[green]Connection to {host}:{port} succeeded[/green]")
            await client.close()
            return 0

        # Interactive mode - relay stdin/stdout
        console.print(f"[dim]Connected to {host}:{port}. Type to send, Ctrl+C to exit.[/dim]",
                      file=sys.stderr)

        try:
            await relay_io(client)
        except KeyboardInterrupt:
            pass
        finally:
            await client.close()

        return 0

    sys.exit(asyncio.run(run()))


async def relay_io(client: NetcatClient):
    """Relay data between stdin/stdout and network connection."""
    loop = asyncio.get_event_loop()

    # Reader task
    async def read_network():
        while client.connected:
            try:
                data = await client.recv(8192)
                if not data:
                    break
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            except Exception:
                break

    # Writer task
    async def write_network():
        while client.connected:
            try:
                # Read from stdin in a thread
                data = await loop.run_in_executor(
                    None,
                    lambda: sys.stdin.buffer.read(1) if select.select([sys.stdin], [], [], 0.1)[0] else None
                )
                if data:
                    await client.send(data)
            except Exception:
                break

    # Run both tasks
    await asyncio.gather(
        read_network(),
        write_network(),
        return_exceptions=True
    )


@nc.command()
@click.argument("port", type=int)
@click.option("--tls", "-e", type=click.Choice(["yes", "no"]), default="no",
              help="TLS encryption mode")
@click.option("--udp", "-u", is_flag=True, help="Use UDP instead of TCP")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--hex", "-x", is_flag=True, help="Show hex dump of data")
@click.option("--keep-open", "-k", is_flag=True, help="Keep listening after client disconnects")
@click.option("--bind", "-s", default="0.0.0.0", help="Address to bind to")
@click.option("--ssl-cert", help="Server certificate file (required for TLS)")
@click.option("--ssl-key", help="Server key file")
def listen(
    port: int,
    tls: str,
    udp: bool,
    verbose: bool,
    hex: bool,
    keep_open: bool,
    bind: str,
    ssl_cert: str | None,
    ssl_key: str | None,
):
    """Listen for incoming connections.

    \b
    Examples:
        # Listen on port 8080
        globaldetect nc listen 8080

        # Listen with TLS
        globaldetect nc listen 8443 --tls yes --ssl-cert cert.pem --ssl-key key.pem

        # Keep listening after disconnect
        globaldetect nc listen 8080 -k
    """
    config = NetcatConfig(
        port=port,
        protocol=Protocol.UDP if udp else Protocol.TCP,
        encryption=EncryptionMode(tls),
        verbose=verbose,
        hex_dump=hex,
        keep_open=keep_open,
        source_host=bind,
        ssl_cert=ssl_cert,
        ssl_key=ssl_key,
        listen=True,
    )

    server = NetcatServer(config)

    async def run():
        if not await server.start():
            return 1

        console.print(f"[dim]Listening on {bind}:{port}. Ctrl+C to exit.[/dim]",
                      file=sys.stderr)

        try:
            while server.running:
                result = await server.accept()
                if result:
                    client_sock, addr = result
                    console.print(f"[green]Connection from {addr[0]}:{addr[1]}[/green]",
                                  file=sys.stderr)

                    # Handle client
                    await handle_client(client_sock, config)

                    if not keep_open:
                        break

        except KeyboardInterrupt:
            pass
        finally:
            await server.stop()

        return 0

    sys.exit(asyncio.run(run()))


async def handle_client(sock, config: NetcatConfig):
    """Handle a client connection."""
    loop = asyncio.get_event_loop()

    try:
        while True:
            # Read from client
            readable, _, _ = select.select([sock], [], [], 0.1)
            if readable:
                data = sock.recv(8192)
                if not data:
                    break
                if config.hex_dump:
                    for i in range(0, len(data), 16):
                        chunk = data[i:i + 16]
                        hex_part = " ".join(f"{b:02x}" for b in chunk)
                        print(f"<<< {i:08x}  {hex_part}", file=sys.stderr)
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()

            # Read from stdin
            stdin_readable, _, _ = select.select([sys.stdin], [], [], 0.1)
            if stdin_readable:
                data = sys.stdin.buffer.read(1)
                if data:
                    sock.send(data)

    except Exception as e:
        if config.verbose:
            console.print(f"[red]Error: {e}[/red]", file=sys.stderr)
    finally:
        sock.close()


@nc.command()
@click.argument("host")
@click.argument("ports")
@click.option("--timeout", "-w", type=float, default=2.0, help="Timeout per port")
@click.option("--verbose", "-v", is_flag=True, help="Show all ports (not just open)")
@click.option("--json-output", "json_out", is_flag=True, help="Output as JSON")
def scan(host: str, ports: str, timeout: float, verbose: bool, json_out: bool):
    """Scan ports on a host.

    PORTS can be:
    - Single port: 80
    - Range: 1-1000
    - List: 22,80,443
    - Common: common (top 100 ports)

    \b
    Examples:
        # Scan common ports
        globaldetect nc scan example.com common

        # Scan port range
        globaldetect nc scan example.com 1-1000

        # Scan specific ports
        globaldetect nc scan example.com 22,80,443,8080
    """
    import json

    # Parse ports
    port_list = []

    if ports.lower() == "common":
        # Top 100 common ports
        port_list = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888,
            20, 69, 79, 88, 106, 113, 119, 123, 137, 138, 161, 162, 177, 179,
            199, 389, 427, 443, 444, 445, 465, 500, 512, 513, 514, 515, 520,
            548, 554, 587, 631, 646, 873, 902, 990, 992, 993, 994, 995, 1025,
            1026, 1027, 1028, 1029, 1080, 1433, 1521, 1720, 1723, 2000, 2049,
            2082, 2083, 2086, 2087, 2095, 2096, 2222, 3128, 3306, 3389, 4443,
            5000, 5060, 5432, 5900, 5901, 6000, 6001, 6379, 8000, 8008, 8080,
            8081, 8443, 8888, 9000, 9090, 9200, 10000, 27017, 28017
        ]
    elif "-" in ports:
        # Range
        start, end = ports.split("-")
        port_list = list(range(int(start), int(end) + 1))
    elif "," in ports:
        # List
        port_list = [int(p.strip()) for p in ports.split(",")]
    else:
        # Single
        port_list = [int(ports)]

    if not json_out:
        console.print(f"[dim]Scanning {host} ({len(port_list)} ports)...[/dim]")

    results = asyncio.run(asyncio.to_thread(
        lambda: port_scan_sync(host, port_list, timeout, verbose and not json_out)
    ))

    if json_out:
        import json
        click.echo(json.dumps({
            "host": host,
            "open_ports": results
        }, indent=2))
        return

    if not results:
        console.print("[yellow]No open ports found[/yellow]")
        return

    table = Table(title=f"Open Ports on {host}")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Protocol")
    table.add_column("Service")
    table.add_column("Banner")

    # Common port services
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
        993: "imaps", 995: "pop3s", 3306: "mysql", 3389: "rdp",
        5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
        8443: "https-alt", 27017: "mongodb"
    }

    for port, banner in sorted(results.items()):
        service = services.get(port, "")
        table.add_row(
            str(port),
            "tcp",
            service,
            (banner[:50] + "...") if len(banner) > 50 else banner
        )

    console.print(table)
    console.print(f"\n[dim]{len(results)} open port(s) found[/dim]")


def port_scan_sync(host: str, ports: list[int], timeout: float, verbose: bool) -> dict[int, str]:
    """Synchronous port scan wrapper."""
    import socket
    results = {}

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))

            if result == 0:
                banner = ""
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass

                results[port] = banner
                if verbose:
                    console.print(f"  [green]{port}/tcp open[/green] {banner[:50] if banner else ''}")
            elif verbose:
                pass  # Don't show closed ports unless very verbose

            sock.close()

        except Exception as e:
            if verbose:
                console.print(f"  [red]{port}/tcp error: {e}[/red]")

    return results


if __name__ == "__main__":
    nc()
