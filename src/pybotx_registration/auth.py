from __future__ import annotations

import ipaddress

from starlette.requests import Request

from pybotx_registration.domain import RegistrationAuthenticationError


class AllowlistedPeerAuthenticator:
    """Private-network profile for a directly connected, non-public ingress.

    Do not use this behind a reverse proxy unless the ASGI server has been
    configured to trust and sanitize forwarded client-address headers.
    mTLS is the preferred production profile when the caller can be outside one
    tightly controlled network zone.
    """

    def __init__(self, allowed_networks: frozenset[str]) -> None:
        if not allowed_networks:
            raise ValueError("at least one source network is required")
        self._networks = tuple(
            ipaddress.ip_network(network, strict=False)
            for network in allowed_networks
        )

    async def authenticate(self, request: Request) -> str:
        if request.client is None:
            raise RegistrationAuthenticationError("client address is unavailable")
        try:
            client_ip = ipaddress.ip_address(request.client.host)
        except ValueError as exc:
            raise RegistrationAuthenticationError("client address is invalid") from exc
        if not any(client_ip in network for network in self._networks):
            raise RegistrationAuthenticationError("client network is not trusted")
        return f"network:{client_ip.compressed}"
