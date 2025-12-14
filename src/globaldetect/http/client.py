"""
HTTP client for endpoint testing.

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import time
import ssl
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlencode
import xml.etree.ElementTree as ET

import httpx


@dataclass
class HTTPRequest:
    """HTTP request configuration."""
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    json_body: dict | list | None = None
    timeout: float = 30.0
    follow_redirects: bool = True
    verify_ssl: bool = True
    auth: tuple[str, str] | None = None  # (username, password)
    bearer_token: str | None = None
    api_key: tuple[str, str] | None = None  # (header_name, key_value)


@dataclass
class HTTPResponse:
    """HTTP response details."""
    status_code: int
    status_text: str
    headers: dict[str, str]
    body: str
    body_bytes: bytes
    elapsed_ms: float
    content_type: str | None = None
    content_length: int = 0

    # Parsed content
    json_data: dict | list | None = None
    xml_data: ET.Element | None = None

    # SSL/TLS info
    ssl_version: str | None = None
    ssl_cipher: str | None = None
    ssl_cert_subject: str | None = None
    ssl_cert_issuer: str | None = None
    ssl_cert_expires: str | None = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600

    @property
    def is_json(self) -> bool:
        ct = self.content_type or ""
        return "json" in ct.lower()

    @property
    def is_xml(self) -> bool:
        ct = self.content_type or ""
        return "xml" in ct.lower()


@dataclass
class HTTPResult:
    """Result of an HTTP request."""
    success: bool = False
    request: HTTPRequest | None = None
    response: HTTPResponse | None = None
    error: str | None = None
    redirect_chain: list[str] = field(default_factory=list)

    # Validation results
    validations: list[dict[str, Any]] = field(default_factory=list)


class HTTPClient:
    """HTTP client for testing endpoints."""

    def __init__(self, timeout: float = 30.0, verify_ssl: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                verify=self.verify_ssl,
                follow_redirects=False,  # We handle redirects manually
            )
        return self._client

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            self._client.close()

    def request(self, req: HTTPRequest) -> HTTPResult:
        """Make an HTTP request."""
        result = HTTPResult(request=req)
        redirect_chain = []

        try:
            # Build headers
            headers = dict(req.headers)

            # Add auth headers
            if req.bearer_token:
                headers["Authorization"] = f"Bearer {req.bearer_token}"
            if req.api_key:
                headers[req.api_key[0]] = req.api_key[1]

            # Determine body
            content = None
            if req.json_body is not None:
                content = json.dumps(req.json_body)
                if "Content-Type" not in headers:
                    headers["Content-Type"] = "application/json"
            elif req.body is not None:
                content = req.body

            # Build URL with params
            url = req.url
            if req.params:
                separator = "&" if "?" in url else "?"
                url = url + separator + urlencode(req.params)

            # Make request
            client = self._get_client()
            start_time = time.time()

            # Handle auth
            auth = None
            if req.auth:
                auth = httpx.BasicAuth(req.auth[0], req.auth[1])

            # Follow redirects manually to track chain
            current_url = url
            final_response = None
            max_redirects = 10

            for _ in range(max_redirects + 1):
                response = client.request(
                    method=req.method,
                    url=current_url,
                    headers=headers,
                    content=content,
                    auth=auth,
                )

                if response.is_redirect and req.follow_redirects:
                    redirect_chain.append(current_url)
                    location = response.headers.get("location")
                    if location:
                        # Handle relative redirects
                        if location.startswith("/"):
                            parsed = urlparse(current_url)
                            current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                        else:
                            current_url = location
                        continue

                final_response = response
                break

            elapsed_ms = (time.time() - start_time) * 1000

            if final_response is None:
                result.error = "Too many redirects"
                return result

            # Build response object
            http_response = HTTPResponse(
                status_code=final_response.status_code,
                status_text=final_response.reason_phrase,
                headers=dict(final_response.headers),
                body=final_response.text,
                body_bytes=final_response.content,
                elapsed_ms=elapsed_ms,
                content_type=final_response.headers.get("content-type"),
                content_length=len(final_response.content),
            )

            # Parse JSON if applicable
            if http_response.is_json:
                try:
                    http_response.json_data = final_response.json()
                except Exception:
                    pass

            # Parse XML if applicable
            if http_response.is_xml:
                try:
                    http_response.xml_data = ET.fromstring(final_response.content)
                except Exception:
                    pass

            result.response = http_response
            result.redirect_chain = redirect_chain
            result.success = True

        except httpx.ConnectError as e:
            result.error = f"Connection failed: {e}"
        except httpx.TimeoutException:
            result.error = f"Request timed out after {req.timeout}s"
        except httpx.SSLError as e:
            result.error = f"SSL error: {e}"
        except Exception as e:
            result.error = str(e)

        return result

    def get(self, url: str, **kwargs) -> HTTPResult:
        """Make a GET request."""
        req = HTTPRequest(url=url, method="GET", **kwargs)
        return self.request(req)

    def post(self, url: str, **kwargs) -> HTTPResult:
        """Make a POST request."""
        req = HTTPRequest(url=url, method="POST", **kwargs)
        return self.request(req)

    def put(self, url: str, **kwargs) -> HTTPResult:
        """Make a PUT request."""
        req = HTTPRequest(url=url, method="PUT", **kwargs)
        return self.request(req)

    def patch(self, url: str, **kwargs) -> HTTPResult:
        """Make a PATCH request."""
        req = HTTPRequest(url=url, method="PATCH", **kwargs)
        return self.request(req)

    def delete(self, url: str, **kwargs) -> HTTPResult:
        """Make a DELETE request."""
        req = HTTPRequest(url=url, method="DELETE", **kwargs)
        return self.request(req)

    def head(self, url: str, **kwargs) -> HTTPResult:
        """Make a HEAD request."""
        req = HTTPRequest(url=url, method="HEAD", **kwargs)
        return self.request(req)

    def options(self, url: str, **kwargs) -> HTTPResult:
        """Make an OPTIONS request."""
        req = HTTPRequest(url=url, method="OPTIONS", **kwargs)
        return self.request(req)

    def validate_response(
        self,
        result: HTTPResult,
        expected_status: int | list[int] | None = None,
        expected_content_type: str | None = None,
        json_path: str | None = None,
        json_value: Any = None,
        xml_xpath: str | None = None,
        xml_value: str | None = None,
        body_contains: str | None = None,
        body_regex: str | None = None,
        header_exists: str | None = None,
        header_value: tuple[str, str] | None = None,
    ) -> HTTPResult:
        """Validate response against expectations."""
        if not result.response:
            return result

        resp = result.response

        # Status code validation
        if expected_status is not None:
            if isinstance(expected_status, int):
                expected_status = [expected_status]

            passed = resp.status_code in expected_status
            result.validations.append({
                "check": "status_code",
                "expected": expected_status,
                "actual": resp.status_code,
                "passed": passed,
            })

        # Content-Type validation
        if expected_content_type is not None:
            actual_ct = resp.content_type or ""
            passed = expected_content_type.lower() in actual_ct.lower()
            result.validations.append({
                "check": "content_type",
                "expected": expected_content_type,
                "actual": actual_ct,
                "passed": passed,
            })

        # JSON path validation
        if json_path is not None and resp.json_data is not None:
            actual_value = self._get_json_path(resp.json_data, json_path)
            if json_value is not None:
                passed = actual_value == json_value
            else:
                passed = actual_value is not None

            result.validations.append({
                "check": "json_path",
                "path": json_path,
                "expected": json_value,
                "actual": actual_value,
                "passed": passed,
            })

        # XML XPath validation
        if xml_xpath is not None and resp.xml_data is not None:
            try:
                elements = resp.xml_data.findall(xml_xpath)
                if elements:
                    actual_value = elements[0].text
                else:
                    actual_value = None

                if xml_value is not None:
                    passed = actual_value == xml_value
                else:
                    passed = actual_value is not None

                result.validations.append({
                    "check": "xml_xpath",
                    "path": xml_xpath,
                    "expected": xml_value,
                    "actual": actual_value,
                    "passed": passed,
                })
            except Exception as e:
                result.validations.append({
                    "check": "xml_xpath",
                    "path": xml_xpath,
                    "error": str(e),
                    "passed": False,
                })

        # Body contains validation
        if body_contains is not None:
            passed = body_contains in resp.body
            result.validations.append({
                "check": "body_contains",
                "expected": body_contains,
                "passed": passed,
            })

        # Body regex validation
        if body_regex is not None:
            passed = bool(re.search(body_regex, resp.body))
            result.validations.append({
                "check": "body_regex",
                "pattern": body_regex,
                "passed": passed,
            })

        # Header exists validation
        if header_exists is not None:
            passed = header_exists.lower() in [h.lower() for h in resp.headers.keys()]
            result.validations.append({
                "check": "header_exists",
                "header": header_exists,
                "passed": passed,
            })

        # Header value validation
        if header_value is not None:
            header_name, expected_val = header_value
            actual_val = resp.headers.get(header_name, "")
            passed = expected_val in actual_val
            result.validations.append({
                "check": "header_value",
                "header": header_name,
                "expected": expected_val,
                "actual": actual_val,
                "passed": passed,
            })

        return result

    def _get_json_path(self, data: Any, path: str) -> Any:
        """Get value from JSON data using dot notation path."""
        # Support paths like "data.items[0].name" or "results.count"
        parts = re.split(r'\.|\[|\]', path)
        parts = [p for p in parts if p]

        current = data
        for part in parts:
            if current is None:
                return None

            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx] if idx < len(current) else None
                except ValueError:
                    return None
            else:
                return None

        return current


def parse_headers(header_strings: list[str]) -> dict[str, str]:
    """Parse header strings in 'Name: Value' format."""
    headers = {}
    for h in header_strings:
        if ":" in h:
            name, value = h.split(":", 1)
            headers[name.strip()] = value.strip()
    return headers


def format_json(data: Any, indent: int = 2) -> str:
    """Format JSON data for display."""
    return json.dumps(data, indent=indent, default=str)


def format_xml(element: ET.Element, indent: int = 2) -> str:
    """Format XML element for display."""
    ET.indent(element, space=" " * indent)
    return ET.tostring(element, encoding="unicode")
