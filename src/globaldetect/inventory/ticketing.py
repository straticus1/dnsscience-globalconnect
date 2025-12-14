"""
Ticketing system integrations for inventory management.

Supports:
- JIRA (Atlassian)
- ServiceNow
- BMC Remedy
- After Dark Systems Ticket System

Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.
All rights reserved.
"""

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urljoin

import httpx


class TicketingSystem(str, Enum):
    """Supported ticketing systems."""
    JIRA = "jira"
    SERVICENOW = "servicenow"
    REMEDY = "remedy"
    ADS = "ads"  # After Dark Systems
    CUSTOM = "custom"


class TicketPriority(str, Enum):
    """Standard ticket priorities."""
    CRITICAL = "critical"  # P1
    HIGH = "high"  # P2
    MEDIUM = "medium"  # P3
    LOW = "low"  # P4


class TicketStatus(str, Enum):
    """Standard ticket statuses."""
    NEW = "new"
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING = "pending"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass
class Ticket:
    """Ticket representation."""
    id: str | None = None
    key: str | None = None  # e.g., "INC0001234" or "INFRA-123"
    url: str | None = None  # Direct link to ticket
    title: str | None = None
    description: str | None = None
    priority: TicketPriority = TicketPriority.MEDIUM
    status: TicketStatus = TicketStatus.NEW
    assignee: str | None = None
    reporter: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    resolved_at: datetime | None = None
    system_hostname: str | None = None  # Related system
    system_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "url": self.url,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "status": self.status.value,
            "assignee": self.assignee,
            "reporter": self.reporter,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "system_hostname": self.system_hostname,
            "system_id": self.system_id,
        }


@dataclass
class TicketingConfig:
    """Configuration for a ticketing system."""
    system: TicketingSystem = TicketingSystem.CUSTOM
    base_url: str = ""
    api_key: str | None = None
    username: str | None = None
    password: str | None = None
    oauth_token: str | None = None

    # System-specific settings
    project_key: str | None = None  # JIRA project key
    instance: str | None = None  # ServiceNow instance name
    form_name: str | None = None  # Remedy form name

    # Custom templates
    ticket_url_template: str | None = None  # e.g., "{base_url}/browse/{key}"
    create_url_template: str | None = None  # URL to create new ticket

    # Defaults
    default_assignee_group: str | None = None
    default_category: str | None = None
    default_priority: TicketPriority = TicketPriority.MEDIUM

    # Mappings (system field names to standard names)
    field_mappings: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TicketingConfig":
        return cls(
            system=TicketingSystem(data.get("system", "custom")),
            base_url=data.get("base_url", ""),
            api_key=data.get("api_key"),
            username=data.get("username"),
            password=data.get("password"),
            oauth_token=data.get("oauth_token"),
            project_key=data.get("project_key"),
            instance=data.get("instance"),
            form_name=data.get("form_name"),
            ticket_url_template=data.get("ticket_url_template"),
            create_url_template=data.get("create_url_template"),
            default_assignee_group=data.get("default_assignee_group"),
            default_category=data.get("default_category"),
            default_priority=TicketPriority(data.get("default_priority", "medium")),
            field_mappings=data.get("field_mappings", {}),
        )

    @classmethod
    def from_env(cls, prefix: str = "TICKETING") -> "TicketingConfig":
        """Load config from environment variables."""
        system = os.environ.get(f"{prefix}_SYSTEM", "custom")
        return cls(
            system=TicketingSystem(system),
            base_url=os.environ.get(f"{prefix}_URL", ""),
            api_key=os.environ.get(f"{prefix}_API_KEY"),
            username=os.environ.get(f"{prefix}_USERNAME"),
            password=os.environ.get(f"{prefix}_PASSWORD"),
            oauth_token=os.environ.get(f"{prefix}_OAUTH_TOKEN"),
            project_key=os.environ.get(f"{prefix}_PROJECT_KEY"),
            instance=os.environ.get(f"{prefix}_INSTANCE"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "system": self.system.value,
            "base_url": self.base_url,
            "api_key": "***" if self.api_key else None,
            "username": self.username,
            "password": "***" if self.password else None,
            "project_key": self.project_key,
            "instance": self.instance,
            "form_name": self.form_name,
            "ticket_url_template": self.ticket_url_template,
            "create_url_template": self.create_url_template,
            "default_assignee_group": self.default_assignee_group,
            "default_category": self.default_category,
            "default_priority": self.default_priority.value,
        }


class TicketingClient(ABC):
    """Abstract ticketing client interface."""

    def __init__(self, config: TicketingConfig):
        self.config = config

    @abstractmethod
    async def get_ticket(self, ticket_id: str) -> Ticket | None:
        """Get ticket by ID or key."""
        pass

    @abstractmethod
    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: TicketPriority = TicketPriority.MEDIUM,
        assignee: str | None = None,
        system_hostname: str | None = None,
        **kwargs,
    ) -> Ticket | None:
        """Create a new ticket."""
        pass

    @abstractmethod
    async def update_ticket(
        self,
        ticket_id: str,
        status: TicketStatus | None = None,
        assignee: str | None = None,
        comment: str | None = None,
        **kwargs,
    ) -> Ticket | None:
        """Update an existing ticket."""
        pass

    @abstractmethod
    async def search_tickets(
        self,
        system_hostname: str | None = None,
        status: TicketStatus | None = None,
        assignee: str | None = None,
        limit: int = 50,
    ) -> list[Ticket]:
        """Search for tickets."""
        pass

    def get_ticket_url(self, ticket_key: str) -> str:
        """Get URL to view a ticket."""
        if self.config.ticket_url_template:
            return self.config.ticket_url_template.format(
                base_url=self.config.base_url.rstrip("/"),
                key=ticket_key,
            )
        return f"{self.config.base_url.rstrip('/')}/ticket/{ticket_key}"

    def get_create_url(self, system_hostname: str | None = None) -> str:
        """Get URL to create a new ticket."""
        if self.config.create_url_template:
            return self.config.create_url_template.format(
                base_url=self.config.base_url.rstrip("/"),
                hostname=system_hostname or "",
            )
        return f"{self.config.base_url.rstrip('/')}/create"


class JiraClient(TicketingClient):
    """JIRA ticketing client."""

    async def get_ticket(self, ticket_id: str) -> Ticket | None:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/rest/api/2/issue/{ticket_id}"

                resp = await client.get(url, headers=headers, timeout=30.0)
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_jira_issue(data)
                return None
            except Exception:
                return None

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: TicketPriority = TicketPriority.MEDIUM,
        assignee: str | None = None,
        system_hostname: str | None = None,
        **kwargs,
    ) -> Ticket | None:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/rest/api/2/issue"

                # Map priority
                jira_priority = self._map_priority(priority)

                payload = {
                    "fields": {
                        "project": {"key": self.config.project_key},
                        "summary": title,
                        "description": description,
                        "issuetype": {"name": kwargs.get("issue_type", "Task")},
                        "priority": {"name": jira_priority},
                    }
                }

                if assignee:
                    payload["fields"]["assignee"] = {"name": assignee}

                # Add system hostname as label
                if system_hostname:
                    payload["fields"]["labels"] = [f"system:{system_hostname}"]

                resp = await client.post(
                    url, headers=headers, json=payload, timeout=30.0
                )
                if resp.status_code == 201:
                    data = resp.json()
                    return Ticket(
                        id=data["id"],
                        key=data["key"],
                        url=self.get_ticket_url(data["key"]),
                        title=title,
                        priority=priority,
                        status=TicketStatus.NEW,
                        system_hostname=system_hostname,
                    )
                return None
            except Exception:
                return None

    async def update_ticket(
        self,
        ticket_id: str,
        status: TicketStatus | None = None,
        assignee: str | None = None,
        comment: str | None = None,
        **kwargs,
    ) -> Ticket | None:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()

                # Add comment if provided
                if comment:
                    comment_url = f"{self.config.base_url}/rest/api/2/issue/{ticket_id}/comment"
                    await client.post(
                        comment_url,
                        headers=headers,
                        json={"body": comment},
                        timeout=30.0,
                    )

                # Update assignee if provided
                if assignee:
                    update_url = f"{self.config.base_url}/rest/api/2/issue/{ticket_id}"
                    await client.put(
                        update_url,
                        headers=headers,
                        json={"fields": {"assignee": {"name": assignee}}},
                        timeout=30.0,
                    )

                # Transition status if provided
                if status:
                    transition_id = self._get_transition_id(status)
                    if transition_id:
                        transition_url = f"{self.config.base_url}/rest/api/2/issue/{ticket_id}/transitions"
                        await client.post(
                            transition_url,
                            headers=headers,
                            json={"transition": {"id": transition_id}},
                            timeout=30.0,
                        )

                # Return updated ticket
                return await self.get_ticket(ticket_id)
            except Exception:
                return None

    async def search_tickets(
        self,
        system_hostname: str | None = None,
        status: TicketStatus | None = None,
        assignee: str | None = None,
        limit: int = 50,
    ) -> list[Ticket]:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/rest/api/2/search"

                # Build JQL query
                jql_parts = [f"project = {self.config.project_key}"]
                if system_hostname:
                    jql_parts.append(f'labels = "system:{system_hostname}"')
                if status:
                    jql_parts.append(f'status = "{self._map_status(status)}"')
                if assignee:
                    jql_parts.append(f'assignee = "{assignee}"')

                jql = " AND ".join(jql_parts)

                resp = await client.get(
                    url,
                    headers=headers,
                    params={"jql": jql, "maxResults": limit},
                    timeout=30.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [self._parse_jira_issue(issue) for issue in data.get("issues", [])]
                return []
            except Exception:
                return []

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.oauth_token:
            headers["Authorization"] = f"Bearer {self.config.oauth_token}"
        elif self.config.api_key:
            import base64
            auth = base64.b64encode(
                f"{self.config.username}:{self.config.api_key}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {auth}"
        return headers

    def _parse_jira_issue(self, data: dict) -> Ticket:
        fields = data.get("fields", {})
        return Ticket(
            id=data.get("id"),
            key=data.get("key"),
            url=self.get_ticket_url(data.get("key", "")),
            title=fields.get("summary"),
            description=fields.get("description"),
            priority=self._parse_priority(fields.get("priority", {}).get("name", "")),
            status=self._parse_status(fields.get("status", {}).get("name", "")),
            assignee=fields.get("assignee", {}).get("displayName") if fields.get("assignee") else None,
            reporter=fields.get("reporter", {}).get("displayName") if fields.get("reporter") else None,
            created_at=datetime.fromisoformat(fields["created"].replace("Z", "+00:00")) if fields.get("created") else None,
            updated_at=datetime.fromisoformat(fields["updated"].replace("Z", "+00:00")) if fields.get("updated") else None,
        )

    def _map_priority(self, priority: TicketPriority) -> str:
        mapping = {
            TicketPriority.CRITICAL: "Highest",
            TicketPriority.HIGH: "High",
            TicketPriority.MEDIUM: "Medium",
            TicketPriority.LOW: "Low",
        }
        return mapping.get(priority, "Medium")

    def _parse_priority(self, jira_priority: str) -> TicketPriority:
        mapping = {
            "highest": TicketPriority.CRITICAL,
            "high": TicketPriority.HIGH,
            "medium": TicketPriority.MEDIUM,
            "low": TicketPriority.LOW,
            "lowest": TicketPriority.LOW,
        }
        return mapping.get(jira_priority.lower(), TicketPriority.MEDIUM)

    def _map_status(self, status: TicketStatus) -> str:
        mapping = {
            TicketStatus.NEW: "To Do",
            TicketStatus.OPEN: "Open",
            TicketStatus.IN_PROGRESS: "In Progress",
            TicketStatus.PENDING: "Pending",
            TicketStatus.RESOLVED: "Done",
            TicketStatus.CLOSED: "Closed",
        }
        return mapping.get(status, "Open")

    def _parse_status(self, jira_status: str) -> TicketStatus:
        status_lower = jira_status.lower()
        if "done" in status_lower or "resolved" in status_lower:
            return TicketStatus.RESOLVED
        if "closed" in status_lower:
            return TicketStatus.CLOSED
        if "progress" in status_lower:
            return TicketStatus.IN_PROGRESS
        if "pending" in status_lower or "waiting" in status_lower:
            return TicketStatus.PENDING
        if "open" in status_lower:
            return TicketStatus.OPEN
        return TicketStatus.NEW

    def _get_transition_id(self, status: TicketStatus) -> str | None:
        # These are common JIRA transition IDs - may need customization
        mapping = {
            TicketStatus.IN_PROGRESS: "21",
            TicketStatus.RESOLVED: "31",
            TicketStatus.CLOSED: "41",
        }
        return mapping.get(status)

    def get_ticket_url(self, ticket_key: str) -> str:
        return f"{self.config.base_url.rstrip('/')}/browse/{ticket_key}"

    def get_create_url(self, system_hostname: str | None = None) -> str:
        url = f"{self.config.base_url.rstrip('/')}/secure/CreateIssue.jspa"
        if self.config.project_key:
            url += f"?pid={self.config.project_key}"
        return url


class ServiceNowClient(TicketingClient):
    """ServiceNow ticketing client."""

    async def get_ticket(self, ticket_id: str) -> Ticket | None:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                # Try incident table first
                url = f"{self.config.base_url}/api/now/table/incident"

                resp = await client.get(
                    url,
                    headers=headers,
                    params={"sysparm_query": f"number={ticket_id}", "sysparm_limit": 1},
                    timeout=30.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results = data.get("result", [])
                    if results:
                        return self._parse_incident(results[0])
                return None
            except Exception:
                return None

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: TicketPriority = TicketPriority.MEDIUM,
        assignee: str | None = None,
        system_hostname: str | None = None,
        **kwargs,
    ) -> Ticket | None:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/api/now/table/incident"

                payload = {
                    "short_description": title,
                    "description": description,
                    "impact": self._map_priority_to_impact(priority),
                    "urgency": self._map_priority_to_urgency(priority),
                }

                if assignee:
                    payload["assigned_to"] = assignee
                if self.config.default_assignee_group:
                    payload["assignment_group"] = self.config.default_assignee_group
                if self.config.default_category:
                    payload["category"] = self.config.default_category
                if system_hostname:
                    payload["cmdb_ci"] = system_hostname

                resp = await client.post(
                    url, headers=headers, json=payload, timeout=30.0
                )
                if resp.status_code == 201:
                    data = resp.json()
                    result = data.get("result", {})
                    return Ticket(
                        id=result.get("sys_id"),
                        key=result.get("number"),
                        url=self.get_ticket_url(result.get("number", "")),
                        title=title,
                        priority=priority,
                        status=TicketStatus.NEW,
                        system_hostname=system_hostname,
                    )
                return None
            except Exception:
                return None

    async def update_ticket(
        self,
        ticket_id: str,
        status: TicketStatus | None = None,
        assignee: str | None = None,
        comment: str | None = None,
        **kwargs,
    ) -> Ticket | None:
        # Get sys_id first
        ticket = await self.get_ticket(ticket_id)
        if not ticket or not ticket.id:
            return None

        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/api/now/table/incident/{ticket.id}"

                payload = {}
                if status:
                    payload["state"] = self._map_status_to_state(status)
                if assignee:
                    payload["assigned_to"] = assignee
                if comment:
                    payload["work_notes"] = comment

                if payload:
                    await client.patch(
                        url, headers=headers, json=payload, timeout=30.0
                    )

                return await self.get_ticket(ticket_id)
            except Exception:
                return None

    async def search_tickets(
        self,
        system_hostname: str | None = None,
        status: TicketStatus | None = None,
        assignee: str | None = None,
        limit: int = 50,
    ) -> list[Ticket]:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/api/now/table/incident"

                # Build query
                query_parts = []
                if system_hostname:
                    query_parts.append(f"cmdb_ci.name={system_hostname}")
                if status:
                    query_parts.append(f"state={self._map_status_to_state(status)}")
                if assignee:
                    query_parts.append(f"assigned_to={assignee}")

                query = "^".join(query_parts) if query_parts else ""

                resp = await client.get(
                    url,
                    headers=headers,
                    params={"sysparm_query": query, "sysparm_limit": limit},
                    timeout=30.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [self._parse_incident(inc) for inc in data.get("result", [])]
                return []
            except Exception:
                return []

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.config.oauth_token:
            headers["Authorization"] = f"Bearer {self.config.oauth_token}"
        elif self.config.username and self.config.password:
            import base64
            auth = base64.b64encode(
                f"{self.config.username}:{self.config.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {auth}"
        return headers

    def _parse_incident(self, data: dict) -> Ticket:
        return Ticket(
            id=data.get("sys_id"),
            key=data.get("number"),
            url=self.get_ticket_url(data.get("number", "")),
            title=data.get("short_description"),
            description=data.get("description"),
            priority=self._parse_priority(data.get("priority", "3")),
            status=self._parse_state(data.get("state", "1")),
            assignee=data.get("assigned_to", {}).get("display_value") if isinstance(data.get("assigned_to"), dict) else data.get("assigned_to"),
            created_at=datetime.fromisoformat(data["sys_created_on"]) if data.get("sys_created_on") else None,
            updated_at=datetime.fromisoformat(data["sys_updated_on"]) if data.get("sys_updated_on") else None,
        )

    def _map_priority_to_impact(self, priority: TicketPriority) -> str:
        mapping = {
            TicketPriority.CRITICAL: "1",
            TicketPriority.HIGH: "2",
            TicketPriority.MEDIUM: "2",
            TicketPriority.LOW: "3",
        }
        return mapping.get(priority, "2")

    def _map_priority_to_urgency(self, priority: TicketPriority) -> str:
        mapping = {
            TicketPriority.CRITICAL: "1",
            TicketPriority.HIGH: "2",
            TicketPriority.MEDIUM: "2",
            TicketPriority.LOW: "3",
        }
        return mapping.get(priority, "2")

    def _parse_priority(self, snow_priority: str) -> TicketPriority:
        mapping = {"1": TicketPriority.CRITICAL, "2": TicketPriority.HIGH, "3": TicketPriority.MEDIUM, "4": TicketPriority.LOW, "5": TicketPriority.LOW}
        return mapping.get(snow_priority, TicketPriority.MEDIUM)

    def _map_status_to_state(self, status: TicketStatus) -> str:
        mapping = {
            TicketStatus.NEW: "1",
            TicketStatus.OPEN: "2",
            TicketStatus.IN_PROGRESS: "2",
            TicketStatus.PENDING: "3",
            TicketStatus.RESOLVED: "6",
            TicketStatus.CLOSED: "7",
        }
        return mapping.get(status, "1")

    def _parse_state(self, state: str) -> TicketStatus:
        mapping = {"1": TicketStatus.NEW, "2": TicketStatus.IN_PROGRESS, "3": TicketStatus.PENDING, "6": TicketStatus.RESOLVED, "7": TicketStatus.CLOSED}
        return mapping.get(state, TicketStatus.NEW)

    def get_ticket_url(self, ticket_key: str) -> str:
        return f"{self.config.base_url.rstrip('/')}/nav_to.do?uri=incident.do?sysparm_query=number={ticket_key}"


class ADSClient(TicketingClient):
    """After Dark Systems ticket system client."""

    async def get_ticket(self, ticket_id: str) -> Ticket | None:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/api/v1/tickets/{ticket_id}"

                resp = await client.get(url, headers=headers, timeout=30.0)
                if resp.status_code == 200:
                    data = resp.json()
                    return self._parse_ticket(data)
                return None
            except Exception:
                return None

    async def create_ticket(
        self,
        title: str,
        description: str,
        priority: TicketPriority = TicketPriority.MEDIUM,
        assignee: str | None = None,
        system_hostname: str | None = None,
        **kwargs,
    ) -> Ticket | None:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/api/v1/tickets"

                payload = {
                    "title": title,
                    "description": description,
                    "priority": priority.value,
                    "assignee": assignee,
                    "system_hostname": system_hostname,
                    "category": self.config.default_category,
                    "assignment_group": self.config.default_assignee_group,
                }
                payload.update(kwargs)

                resp = await client.post(
                    url, headers=headers, json=payload, timeout=30.0
                )
                if resp.status_code == 201:
                    data = resp.json()
                    return self._parse_ticket(data)
                return None
            except Exception:
                return None

    async def update_ticket(
        self,
        ticket_id: str,
        status: TicketStatus | None = None,
        assignee: str | None = None,
        comment: str | None = None,
        **kwargs,
    ) -> Ticket | None:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/api/v1/tickets/{ticket_id}"

                payload = {}
                if status:
                    payload["status"] = status.value
                if assignee:
                    payload["assignee"] = assignee
                payload.update(kwargs)

                if payload:
                    await client.patch(
                        url, headers=headers, json=payload, timeout=30.0
                    )

                # Add comment if provided
                if comment:
                    comment_url = f"{self.config.base_url}/api/v1/tickets/{ticket_id}/comments"
                    await client.post(
                        comment_url,
                        headers=headers,
                        json={"body": comment},
                        timeout=30.0,
                    )

                return await self.get_ticket(ticket_id)
            except Exception:
                return None

    async def search_tickets(
        self,
        system_hostname: str | None = None,
        status: TicketStatus | None = None,
        assignee: str | None = None,
        limit: int = 50,
    ) -> list[Ticket]:
        async with httpx.AsyncClient() as client:
            try:
                headers = self._get_headers()
                url = f"{self.config.base_url}/api/v1/tickets"

                params = {"limit": limit}
                if system_hostname:
                    params["system_hostname"] = system_hostname
                if status:
                    params["status"] = status.value
                if assignee:
                    params["assignee"] = assignee

                resp = await client.get(url, headers=headers, params=params, timeout=30.0)
                if resp.status_code == 200:
                    data = resp.json()
                    return [self._parse_ticket(t) for t in data.get("tickets", [])]
                return []
            except Exception:
                return []

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def _parse_ticket(self, data: dict) -> Ticket:
        return Ticket(
            id=data.get("id"),
            key=data.get("key", data.get("id")),
            url=self.get_ticket_url(data.get("key", data.get("id", ""))),
            title=data.get("title"),
            description=data.get("description"),
            priority=TicketPriority(data.get("priority", "medium")),
            status=TicketStatus(data.get("status", "new")),
            assignee=data.get("assignee"),
            reporter=data.get("reporter"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else None,
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else None,
            resolved_at=datetime.fromisoformat(data["resolved_at"]) if data.get("resolved_at") else None,
            system_hostname=data.get("system_hostname"),
        )

    def get_ticket_url(self, ticket_key: str) -> str:
        return f"{self.config.base_url.rstrip('/')}/tickets/{ticket_key}"

    def get_create_url(self, system_hostname: str | None = None) -> str:
        url = f"{self.config.base_url.rstrip('/')}/tickets/new"
        if system_hostname:
            url += f"?system={system_hostname}"
        return url


def get_ticketing_client(config: TicketingConfig) -> TicketingClient:
    """Factory function to get appropriate ticketing client."""
    clients = {
        TicketingSystem.JIRA: JiraClient,
        TicketingSystem.SERVICENOW: ServiceNowClient,
        TicketingSystem.ADS: ADSClient,
    }

    client_class = clients.get(config.system)
    if client_class:
        return client_class(config)

    # Return ADS client as default/custom handler
    return ADSClient(config)
