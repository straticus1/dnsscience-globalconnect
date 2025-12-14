"""
HTTP Swiss-Army Knife module.

Provides comprehensive HTTP endpoint testing with support for:
- JSON and XML response parsing
- Custom headers and authentication
- Request body handling
- Response validation
- Performance testing

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

from globaldetect.http.client import (
    HTTPClient,
    HTTPRequest,
    HTTPResponse,
    HTTPResult,
)

__all__ = [
    "HTTPClient",
    "HTTPRequest",
    "HTTPResponse",
    "HTTPResult",
]
