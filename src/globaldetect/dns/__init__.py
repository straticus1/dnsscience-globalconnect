"""
DNS Utilities Module

Provides utilities for DNS lookups, propagation checking,
and zone analysis.
"""

from globaldetect.dns.core import (
    DNSResolver,
    lookup,
    lookup_all,
    reverse_lookup,
    check_propagation,
    get_nameservers,
    get_mx_records,
    get_txt_records,
    trace_delegation,
)

__all__ = [
    "DNSResolver",
    "lookup",
    "lookup_all",
    "reverse_lookup",
    "check_propagation",
    "get_nameservers",
    "get_mx_records",
    "get_txt_records",
    "trace_delegation",
]
