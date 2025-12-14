"""
HTTP Swiss-Army Knife CLI commands.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import sys
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
import xml.etree.ElementTree as ET

from globaldetect.http.client import (
    HTTPClient,
    HTTPRequest,
    parse_headers,
    format_json,
    format_xml,
)


@click.group()
def http():
    """HTTP endpoint testing swiss-army knife."""
    pass


@http.command("request")
@click.argument("url")
@click.option("-X", "--method", default="GET", help="HTTP method (GET, POST, PUT, DELETE, etc.)")
@click.option("-H", "--header", multiple=True, help="Headers in 'Name: Value' format")
@click.option("-d", "--data", help="Request body data")
@click.option("--json", "json_data", help="JSON request body")
@click.option("-p", "--param", multiple=True, help="Query params in 'name=value' format")
@click.option("-u", "--user", help="Basic auth in 'username:password' format")
@click.option("--bearer", help="Bearer token for Authorization header")
@click.option("--api-key", nargs=2, help="API key as 'header-name key-value'")
@click.option("-t", "--timeout", default=30.0, help="Request timeout in seconds")
@click.option("-L", "--follow/--no-follow", default=True, help="Follow redirects")
@click.option("-k", "--insecure", is_flag=True, help="Disable SSL verification")
@click.option("-v", "--verbose", is_flag=True, help="Show request details")
@click.option("-o", "--output", help="Save response body to file")
@click.option("--raw", is_flag=True, help="Show raw response without formatting")
def request_cmd(url: str, method: str, header: tuple, data: str | None, json_data: str | None,
                param: tuple, user: str | None, bearer: str | None, api_key: tuple | None,
                timeout: float, follow: bool, insecure: bool, verbose: bool,
                output: str | None, raw: bool):
    """Make an HTTP request to a URL.

    Supports JSON and XML response parsing, custom headers, authentication,
    and response validation.

    Examples:
        globaldetect http request https://api.example.com/users
        globaldetect http request https://api.example.com/users -X POST --json '{"name": "test"}'
        globaldetect http request https://api.example.com/data -H "X-API-Key: abc123"
        globaldetect http request https://api.example.com/auth -u "user:pass"
        globaldetect http request https://api.example.com/v1 --bearer "token123"
    """
    console = Console()

    # Parse headers
    headers = parse_headers(list(header))

    # Parse params
    params = {}
    for p in param:
        if "=" in p:
            name, value = p.split("=", 1)
            params[name] = value

    # Parse auth
    auth = None
    if user and ":" in user:
        auth = tuple(user.split(":", 1))

    # Parse API key
    api_key_tuple = None
    if api_key:
        api_key_tuple = (api_key[0], api_key[1])

    # Parse JSON body
    json_body = None
    if json_data:
        try:
            json_body = json.loads(json_data)
        except json.JSONDecodeError as e:
            console.print(f"[red]Error:[/red] Invalid JSON: {e}")
            raise SystemExit(1)

    # Build request
    req = HTTPRequest(
        url=url,
        method=method.upper(),
        headers=headers,
        params=params,
        body=data,
        json_body=json_body,
        timeout=timeout,
        follow_redirects=follow,
        verify_ssl=not insecure,
        auth=auth,
        bearer_token=bearer,
        api_key=api_key_tuple,
    )

    # Show request details if verbose
    if verbose:
        console.print(f"\n[cyan]Request:[/cyan]")
        console.print(f"  {method.upper()} {url}")
        for h_name, h_value in headers.items():
            console.print(f"  [dim]{h_name}:[/dim] {h_value}")
        if params:
            console.print(f"  [dim]Params:[/dim] {params}")
        if data:
            console.print(f"  [dim]Body:[/dim] {data[:100]}...")
        if json_body:
            console.print(f"  [dim]JSON:[/dim] {json.dumps(json_body)[:100]}...")
        console.print()

    # Make request
    client = HTTPClient(timeout=timeout, verify_ssl=not insecure)

    try:
        result = client.request(req)
    finally:
        client.close()

    if not result.success:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    resp = result.response

    # Show redirect chain
    if result.redirect_chain:
        console.print("[yellow]Redirect chain:[/yellow]")
        for i, redirect_url in enumerate(result.redirect_chain):
            console.print(f"  {i+1}. {redirect_url}")
        console.print(f"  → {url}")
        console.print()

    # Status line
    if resp.is_success:
        status_color = "green"
    elif resp.is_redirect:
        status_color = "yellow"
    elif resp.is_client_error:
        status_color = "red"
    else:
        status_color = "red bold"

    console.print(f"[{status_color}]{resp.status_code} {resp.status_text}[/{status_color}] ({resp.elapsed_ms:.0f}ms)")

    # Headers
    if verbose:
        console.print("\n[cyan]Response Headers:[/cyan]")
        for h_name, h_value in resp.headers.items():
            console.print(f"  [dim]{h_name}:[/dim] {h_value}")

    # Body
    if resp.body:
        console.print()

        if output:
            # Save to file
            with open(output, "wb") as f:
                f.write(resp.body_bytes)
            console.print(f"[green]Response saved to {output}[/green]")
        elif raw:
            # Raw output
            console.print(resp.body)
        elif resp.json_data is not None:
            # Pretty-print JSON
            formatted = format_json(resp.json_data)
            syntax = Syntax(formatted, "json", theme="monokai", line_numbers=False)
            console.print(syntax)
        elif resp.xml_data is not None:
            # Pretty-print XML
            formatted = format_xml(resp.xml_data)
            syntax = Syntax(formatted, "xml", theme="monokai", line_numbers=False)
            console.print(syntax)
        else:
            # Plain text (truncate if long)
            body = resp.body
            if len(body) > 2000 and not verbose:
                console.print(body[:2000])
                console.print(f"\n[dim]... ({len(body) - 2000} more bytes)[/dim]")
            else:
                console.print(body)

    # Summary
    console.print(f"\n[dim]Content-Type: {resp.content_type or 'N/A'} | "
                  f"Size: {resp.content_length:,} bytes[/dim]")


@http.command("get")
@click.argument("url")
@click.option("-H", "--header", multiple=True, help="Headers in 'Name: Value' format")
@click.option("-p", "--param", multiple=True, help="Query params in 'name=value' format")
@click.option("--bearer", help="Bearer token")
@click.option("-v", "--verbose", is_flag=True, help="Show details")
@click.pass_context
def get_cmd(ctx, url: str, header: tuple, param: tuple, bearer: str | None, verbose: bool):
    """Make a GET request (shortcut).

    Examples:
        globaldetect http get https://api.example.com/users
        globaldetect http get https://api.example.com/data?format=json -v
    """
    ctx.invoke(request_cmd, url=url, method="GET", header=header, param=param,
               bearer=bearer, verbose=verbose, data=None, json_data=None,
               user=None, api_key=None, timeout=30.0, follow=True,
               insecure=False, output=None, raw=False)


@http.command("post")
@click.argument("url")
@click.option("-H", "--header", multiple=True, help="Headers")
@click.option("-d", "--data", help="Request body")
@click.option("--json", "json_data", help="JSON body")
@click.option("--bearer", help="Bearer token")
@click.option("-v", "--verbose", is_flag=True, help="Show details")
@click.pass_context
def post_cmd(ctx, url: str, header: tuple, data: str | None, json_data: str | None,
             bearer: str | None, verbose: bool):
    """Make a POST request (shortcut).

    Examples:
        globaldetect http post https://api.example.com/users --json '{"name": "test"}'
        globaldetect http post https://api.example.com/form -d "name=test&value=123"
    """
    ctx.invoke(request_cmd, url=url, method="POST", header=header, data=data,
               json_data=json_data, bearer=bearer, verbose=verbose, param=(),
               user=None, api_key=None, timeout=30.0, follow=True,
               insecure=False, output=None, raw=False)


@http.command("validate")
@click.argument("url")
@click.option("-X", "--method", default="GET", help="HTTP method")
@click.option("-H", "--header", multiple=True, help="Headers")
@click.option("--json", "json_data", help="JSON body")
@click.option("--status", type=int, help="Expected status code")
@click.option("--content-type", help="Expected content type")
@click.option("--json-path", help="JSON path to check (e.g., 'data.items[0].id')")
@click.option("--json-value", help="Expected value at JSON path")
@click.option("--xpath", help="XPath to check in XML response")
@click.option("--xpath-value", help="Expected value at XPath")
@click.option("--contains", help="String that body must contain")
@click.option("--regex", help="Regex pattern that body must match")
@click.option("--header-exists", help="Header that must exist")
def validate_cmd(url: str, method: str, header: tuple, json_data: str | None,
                 status: int | None, content_type: str | None,
                 json_path: str | None, json_value: str | None,
                 xpath: str | None, xpath_value: str | None,
                 contains: str | None, regex: str | None,
                 header_exists: str | None):
    """Validate an HTTP endpoint response.

    Run validations against the response and report pass/fail.

    Examples:
        globaldetect http validate https://api.example.com/health --status 200
        globaldetect http validate https://api.example.com/users --json-path "data[0].id"
        globaldetect http validate https://api.example.com/status --contains "OK"
    """
    console = Console()

    headers = parse_headers(list(header))
    json_body = None
    if json_data:
        try:
            json_body = json.loads(json_data)
        except json.JSONDecodeError as e:
            console.print(f"[red]Error:[/red] Invalid JSON: {e}")
            raise SystemExit(1)

    req = HTTPRequest(
        url=url,
        method=method.upper(),
        headers=headers,
        json_body=json_body,
    )

    client = HTTPClient()
    try:
        result = client.request(req)

        if not result.success:
            console.print(f"[red]Request failed:[/red] {result.error}")
            raise SystemExit(1)

        # Run validations
        result = client.validate_response(
            result,
            expected_status=status,
            expected_content_type=content_type,
            json_path=json_path,
            json_value=json_value,
            xml_xpath=xpath,
            xml_value=xpath_value,
            body_contains=contains,
            body_regex=regex,
            header_exists=header_exists,
        )
    finally:
        client.close()

    # Display results
    console.print(f"\n[cyan]Validation Results for {url}[/cyan]\n")

    table = Table(box=None)
    table.add_column("Check", style="cyan")
    table.add_column("Expected", style="white")
    table.add_column("Actual", style="white")
    table.add_column("Result", style="white")

    all_passed = True
    for v in result.validations:
        check = v.get("check", "unknown")
        expected = str(v.get("expected", v.get("path", v.get("pattern", v.get("header", "-")))))
        actual = str(v.get("actual", "-"))
        passed = v.get("passed", False)

        if passed:
            result_str = "[green]PASS[/green]"
        else:
            result_str = "[red]FAIL[/red]"
            all_passed = False

        table.add_row(check, expected[:40], actual[:40], result_str)

    console.print(table)

    if all_passed:
        console.print("\n[green]All validations passed![/green]")
    else:
        console.print("\n[red]Some validations failed[/red]")
        raise SystemExit(1)


@http.command("bench")
@click.argument("url")
@click.option("-n", "--requests", default=10, help="Number of requests")
@click.option("-c", "--concurrent", default=1, help="Concurrent requests")
@click.option("-X", "--method", default="GET", help="HTTP method")
@click.option("-H", "--header", multiple=True, help="Headers")
@click.option("--json", "json_data", help="JSON body")
def bench_cmd(url: str, requests: int, concurrent: int, method: str,
              header: tuple, json_data: str | None):
    """Simple HTTP benchmark/load test.

    Examples:
        globaldetect http bench https://api.example.com/health -n 100
        globaldetect http bench https://api.example.com/api -n 50 -c 5
    """
    console = Console()
    import time
    import statistics
    from concurrent.futures import ThreadPoolExecutor, as_completed

    headers = parse_headers(list(header))
    json_body = None
    if json_data:
        try:
            json_body = json.loads(json_data)
        except json.JSONDecodeError as e:
            console.print(f"[red]Error:[/red] Invalid JSON: {e}")
            raise SystemExit(1)

    console.print(f"\n[cyan]Benchmarking {url}[/cyan]")
    console.print(f"  Requests: {requests}, Concurrency: {concurrent}\n")

    times = []
    errors = 0
    status_codes = {}

    def make_request():
        client = HTTPClient()
        try:
            req = HTTPRequest(
                url=url,
                method=method.upper(),
                headers=headers,
                json_body=json_body,
            )
            result = client.request(req)
            return result
        finally:
            client.close()

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=concurrent) as executor:
        futures = [executor.submit(make_request) for _ in range(requests)]

        for future in as_completed(futures):
            result = future.result()
            if result.success:
                times.append(result.response.elapsed_ms)
                code = result.response.status_code
                status_codes[code] = status_codes.get(code, 0) + 1
            else:
                errors += 1

    total_time = time.time() - start_time

    # Calculate stats
    if times:
        avg_time = statistics.mean(times)
        min_time = min(times)
        max_time = max(times)
        p50 = statistics.median(times)
        p95 = sorted(times)[int(len(times) * 0.95)] if len(times) >= 20 else max_time
        p99 = sorted(times)[int(len(times) * 0.99)] if len(times) >= 100 else max_time
    else:
        avg_time = min_time = max_time = p50 = p95 = p99 = 0

    rps = requests / total_time if total_time > 0 else 0

    # Display results
    console.print(Panel(
        f"[cyan]Total Time:[/cyan] {total_time:.2f}s\n"
        f"[cyan]Requests/sec:[/cyan] {rps:.2f}\n"
        f"[cyan]Successful:[/cyan] {len(times)}\n"
        f"[cyan]Failed:[/cyan] {errors}",
        title="Summary",
    ))

    if times:
        console.print(Panel(
            f"[cyan]Min:[/cyan] {min_time:.2f}ms\n"
            f"[cyan]Max:[/cyan] {max_time:.2f}ms\n"
            f"[cyan]Avg:[/cyan] {avg_time:.2f}ms\n"
            f"[cyan]P50:[/cyan] {p50:.2f}ms\n"
            f"[cyan]P95:[/cyan] {p95:.2f}ms\n"
            f"[cyan]P99:[/cyan] {p99:.2f}ms",
            title="Latency",
        ))

    if status_codes:
        status_str = ", ".join(f"{code}: {count}" for code, count in sorted(status_codes.items()))
        console.print(f"\n[cyan]Status codes:[/cyan] {status_str}")


@http.command("headers")
@click.argument("url")
@click.option("-v", "--verbose", is_flag=True, help="Show all headers")
def headers_cmd(url: str, verbose: bool):
    """Show response headers for a URL.

    Examples:
        globaldetect http headers https://www.google.com
        globaldetect http headers https://api.example.com -v
    """
    console = Console()

    client = HTTPClient()
    try:
        result = client.head(url)
        if not result.success:
            # Fall back to GET if HEAD not supported
            result = client.get(url)
    finally:
        client.close()

    if not result.success:
        console.print(f"[red]Error:[/red] {result.error}")
        raise SystemExit(1)

    resp = result.response

    console.print(f"\n[cyan]Headers for {url}[/cyan]\n")

    # Security-relevant headers
    security_headers = {
        "strict-transport-security": "HSTS",
        "content-security-policy": "CSP",
        "x-content-type-options": "X-Content-Type-Options",
        "x-frame-options": "X-Frame-Options",
        "x-xss-protection": "X-XSS-Protection",
        "referrer-policy": "Referrer-Policy",
        "permissions-policy": "Permissions-Policy",
    }

    table = Table(box=None)
    table.add_column("Header", style="cyan")
    table.add_column("Value", style="white")

    for header_name, header_value in sorted(resp.headers.items()):
        header_lower = header_name.lower()

        # Highlight security headers
        if header_lower in security_headers:
            display_name = f"[green]{header_name}[/green]"
        else:
            display_name = header_name

        # Truncate long values unless verbose
        if len(header_value) > 80 and not verbose:
            display_value = header_value[:77] + "..."
        else:
            display_value = header_value

        table.add_row(display_name, display_value)

    console.print(table)

    # Check for missing security headers
    missing = []
    for header_lower, display_name in security_headers.items():
        if header_lower not in [h.lower() for h in resp.headers.keys()]:
            missing.append(display_name)

    if missing:
        console.print(f"\n[yellow]Missing security headers:[/yellow] {', '.join(missing)}")
