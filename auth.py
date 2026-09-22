"""OAuth 2.1 authorization server that bridges MCP sessions to JDE logins.

- JDE Orchestrator's ``tokenrequest`` endpoint only accepts a raw username and
password (no OAuth/SAML/Kerberos grant of its own)

- Orchestrator tokens are bound to the machine/network origin that requested them,
so the token has to be minted by this server itself, not by the connecting client.

- This module makes the MCP server its own authorization server: `/authorize`
redirects to a login page served on this same origin, the submitted
credentials are forwarded to JDE exactly once (should not be logged, persisted,
nor exposed as an MCP tool argument).

- The resulting JDE token is attached to an MCP session token handed back to the
client.

- Session tokens expire with the JDE token they wrap (~hourly) instead of being
silently refreshed.

- The TTLs, retry limit, and JDE environment name are read from the process
environment (see `.env.example`) rather than hardcoded, so they can be
retuned without a code change.
"""

from __future__ import annotations

import html
import os
import secrets
import time

import httpx2 as httpx
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

from fastmcp.server.auth import AccessToken, OAuthProvider

_TOKEN_NBYTES = 32
"""`secrets.token_urlsafe()` byte count for every random id this module mints
(pending-login ids, authorization codes, access tokens). 32 random bytes is
256 bits of entropy: comfortably past the >=160-bit minimum RFC 6749 section
10.10 recommends for OAuth codes/tokens, and it's Python's own documented
default nbytes for security tokens."""


class _JdeAuthError(Exception):
    """JDE rejected the submitted credentials."""


class _JdeUnavailableError(Exception):
    """JDE's orchestrator could not be reached or returned something unexpected."""


class _PendingLogin:
    """An in-flight `/authorize` request waiting on the user to submit the login form.

    Attributes:
        params: The original OAuth authorization request (redirect_uri, PKCE
            challenge, requested scopes, state) to resume once login succeeds.
        client_id: The OAuth client that started this authorization request.
        created_at: `time.time()` when this pending login was created; used
            to evict it once older than the configured pending-login TTL.
        attempts: Number of failed login submissions so far, capped at the
            configured max-attempts value.
    """

    __slots__ = ("params", "client_id", "created_at", "attempts")

    def __init__(self, params: AuthorizationParams, client_id: str) -> None:
        """Record a freshly-received authorization request as a pending login.

        Args:
            params: The validated OAuth authorization request to resume after login.
            client_id: The OAuth client that started this authorization request.
        """
        self.params = params
        self.client_id = client_id
        self.created_at = time.time()
        self.attempts = 0


class JdeOAuthProvider(OAuthProvider):
    """Authorization server whose login page bridges to JDE's `tokenrequest`.

    Attributes:
        _orch_token_url: Base URL of JDE orchestrator's token endpoint
            (`ORCH_TOKEN_URL`); `/tokenrequest` is appended when calling it.
        _orch_environment: JDE environment name (e.g. `JDV920`) sent with
            every `tokenrequest` call (`ORCH_ENVIRONMENT`). Not a secret.
        _auth_code_ttl_seconds: How long a minted authorization code stays
            redeemable (`AUTH_CODE_TTL_SECONDS`).
        _pending_login_ttl_seconds: How long an unsubmitted login form stays
            valid before `_evict_expired_pending_logins` removes it
            (`PENDING_LOGIN_TTL_SECONDS`).
        _jde_token_ttl_seconds: TTL given to the MCP session token this
            server issues, standing in for JDE's own unreported token expiry
            (`JDE_TOKEN_TTL_SECONDS`).
        _max_login_attempts: Failed login attempts allowed per pending login
            before it's torn down (`MAX_LOGIN_ATTEMPTS_PER_PENDING`).
        _clients: OAuth clients registered via dynamic client registration,
            keyed by client_id.
        _pending_logins: In-flight `/authorize` requests awaiting a submitted
            login form, keyed by a random pending-login id.
        _auth_codes: Minted, not-yet-redeemed authorization codes, keyed by
            the code string.
        _code_jde_tokens: `(jde_token, username)` pairs waiting to be attached
            to an access token once their authorization code is redeemed,
            keyed by the same code string as `_auth_codes`.
        _access_tokens: Issued MCP session tokens, keyed by the token string.
    """

    def __init__(self, *, base_url: str, orch_token_url: str) -> None:
        """Configure the authorization server and load its tunables from the environment.

        Args:
            base_url: Public HTTPS URL this server is reachable at; used to
                build the `/authorize`, `/token`, and `/login` URLs.
            orch_token_url: Base URL of JDE orchestrator's token endpoint
                (everything before `/tokenrequest`).
        """
        super().__init__(
            base_url=base_url,
            client_registration_options=ClientRegistrationOptions(enabled=True),
        )
        self._orch_token_url = orch_token_url.rstrip("/")
        self._orch_environment = os.environ["ORCH_ENVIRONMENT"]
        self._auth_code_ttl_seconds = int(os.environ["AUTH_CODE_TTL_SECONDS"])
        self._pending_login_ttl_seconds = int(os.environ["PENDING_LOGIN_TTL_SECONDS"])
        self._jde_token_ttl_seconds = int(os.environ["JDE_TOKEN_TTL_SECONDS"])
        self._max_login_attempts = int(os.environ["MAX_LOGIN_ATTEMPTS_PER_PENDING"])

        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending_logins: dict[str, _PendingLogin] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._code_jde_tokens: dict[str, tuple[str, str]] = {}
        self._access_tokens: dict[str, AccessToken] = {}

    # --- Dynamic client registration (OAuth 2.0) ----------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Look up a previously-registered OAuth client by id.

        Args:
            client_id: The client id to look up.

        Returns:
            The registered client, or None if no client with that id exists.
        """
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a new OAuth client via dynamic client registration.

        Args:
            client_info: The client metadata submitted to `/register`.

        Raises:
            ValueError: If the submitted metadata has no client_id.
        """
        if client_info.client_id is None:
            raise ValueError("client_id is required for client registration")
        self._clients[client_info.client_id] = client_info

    # --- /authorize: hand off to our own login page ---

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Start a login instead of redirecting to a third-party IdP.

        Stashes the authorization request as a pending login and returns our
        own `/login` URL, so the SDK's `/authorize` handler redirects the
        browser here instead of to an external identity provider.

        Args:
            client: The OAuth client requesting authorization.
            params: The validated authorization request (redirect_uri, PKCE
                challenge, requested scopes, state) to resume after login.

        Returns:
            The `/login` URL to redirect the browser to.

        Raises:
            AuthorizeError: If the client has no client_id.
        """
        if client.client_id is None:
            raise AuthorizeError(
                error="invalid_request", error_description="Client ID is required"
            )
        pending_id = secrets.token_urlsafe(_TOKEN_NBYTES)
        self._pending_logins[pending_id] = _PendingLogin(params, client.client_id)
        assert self.base_url is not None
        return f"{str(self.base_url).rstrip('/')}/login?pending_id={pending_id}"

    # --- The login page itself: our only custom route ----------------------

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """Return the standard OAuth routes plus this provider's `/login` route.

        Args:
            mcp_path: The path the MCP endpoint is mounted at (e.g. `/mcp`),
                forwarded to the base implementation for resource-metadata URLs.

        Returns:
            All routes this authorization server needs, including `/login`.
        """
        routes = super().get_routes(mcp_path)
        routes.append(Route("/login", endpoint=self._handle_login, methods=["GET", "POST"]))
        return routes

    async def _handle_login(self, request: Request) -> Response:
        """Serve the login form (GET) or validate a submission (POST).

        A GET renders the form for the `pending_id` in the query string. A
        POST reads `pending_id`/`username`/`password`, calls JDE's
        `tokenrequest` once, and on success redirects back to the OAuth
        client with a freshly-minted authorization code; on failure it
        re-renders the form with a generic error.

        Args:
            request: The incoming `/login` request.

        Returns:
            An HTML form response, or (on successful login) a redirect back
            to the OAuth client's `redirect_uri`.
        """
        self._evict_expired_pending_logins()

        if request.method == "GET":
            pending_id = request.query_params.get("pending_id", "")
            return HTMLResponse(_render_login_page(pending_id))

        form = await request.form()
        pending_id = str(form.get("pending_id", ""))
        pending = self._pending_logins.get(pending_id)
        if pending is None:
            return HTMLResponse(
                _render_login_page(
                    "",
                    error="Login session expired. Close this tab and reconnect from your MCP client.",
                ),
                status_code=400,
            )

        if pending.attempts >= self._max_login_attempts:
            del self._pending_logins[pending_id]
            return HTMLResponse(
                _render_login_page(
                    "",
                    error="Too many failed attempts. Close this tab and reconnect from your MCP client.",
                ),
                status_code=400,
            )

        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))

        try:
            jde_token = await _mint_jde_token(
                self._orch_token_url, self._orch_environment, username, password
            )
        except _JdeAuthError:
            pending.attempts += 1
            return HTMLResponse(
                _render_login_page(pending_id, error="Incorrect JDE username or password."),
                status_code=401,
            )
        except _JdeUnavailableError:
            return HTMLResponse(
                _render_login_page(
                    pending_id, error="JDE orchestrator is unreachable right now. Try again shortly."
                ),
                status_code=502,
            )

        del self._pending_logins[pending_id]

        code_value = secrets.token_urlsafe(_TOKEN_NBYTES)
        self._auth_codes[code_value] = AuthorizationCode(
            code=code_value,
            client_id=pending.client_id,
            redirect_uri=pending.params.redirect_uri,
            redirect_uri_provided_explicitly=pending.params.redirect_uri_provided_explicitly,
            scopes=pending.params.scopes or [],
            expires_at=time.time() + self._auth_code_ttl_seconds,
            code_challenge=pending.params.code_challenge,
            subject=username,
        )
        self._code_jde_tokens[code_value] = (jde_token, username)

        return RedirectResponse(
            url=construct_redirect_uri(
                str(pending.params.redirect_uri), code=code_value, state=pending.params.state
            ),
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )

    def _evict_expired_pending_logins(self) -> None:
        """Drop pending logins older than `_pending_login_ttl_seconds`."""
        now = time.time()
        expired = [
            pending_id
            for pending_id, pending in self._pending_logins.items()
            if now - pending.created_at > self._pending_login_ttl_seconds
        ]
        for pending_id in expired:
            del self._pending_logins[pending_id]

    # --- Authorization code -> MCP session token ----------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Look up a minted authorization code, if it's still valid for this client.

        Args:
            client: The OAuth client redeeming the code.
            authorization_code: The code string to look up.

        Returns:
            The `AuthorizationCode`, or None if it doesn't exist, belongs to
            a different client, or has expired (expired entries are evicted).
        """
        code = self._auth_codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        if code.expires_at < time.time():
            self._auth_codes.pop(authorization_code, None)
            self._code_jde_tokens.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(
        self, _client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Redeem a one-time authorization code for an MCP session token.

        Args:
            _client: The OAuth client redeeming the code; already validated
                by `load_authorization_code`, so unused here.
            authorization_code: The code to redeem, as returned by
                `load_authorization_code`.

        Returns:
            An OAuth token response carrying the new MCP session token. No
            refresh token is included — see `exchange_refresh_token`.

        Raises:
            TokenError: If the code has already been redeemed or is unknown.
        """
        self._auth_codes.pop(authorization_code.code, None)
        jde_token_entry = self._code_jde_tokens.pop(authorization_code.code, None)
        if jde_token_entry is None:
            raise TokenError("invalid_grant", "Authorization code not found or already used.")
        jde_token, username = jde_token_entry

        access_token_value = secrets.token_urlsafe(_TOKEN_NBYTES)
        expires_at = int(time.time() + self._jde_token_ttl_seconds)
        self._access_tokens[access_token_value] = AccessToken(
            token=access_token_value,
            client_id=authorization_code.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
            subject=username,
            claims={"jde_token": jde_token},
        )
        return OAuthToken(
            access_token=access_token_value,
            token_type="Bearer",
            expires_in=self._jde_token_ttl_seconds,
            scope=" ".join(authorization_code.scopes),
        )

    # --- No refresh tokens: an expired session means logging in again ------

    async def load_refresh_token(
        self, _client: OAuthClientInformationFull, _refresh_token: str
    ) -> RefreshToken | None:
        """Always report no refresh token: this server never issues any.

        Args:
            _client: Unused; required by the base protocol's signature.
            _refresh_token: Unused; required by the base protocol's signature.

        Returns:
            None, always.
        """
        return None

    async def exchange_refresh_token(
        self,
        _client: OAuthClientInformationFull,
        _refresh_token: RefreshToken,
        _scopes: list[str],
    ) -> OAuthToken:
        """Always reject: this server never issues refresh tokens.

        An expired MCP session token means logging in again through
        `/login`, not a silent refresh — see the module docstring for why.

        Args:
            _client: Unused; required by the base protocol's signature.
            _refresh_token: Unused; required by the base protocol's signature.
            _scopes: Unused; required by the base protocol's signature.

        Raises:
            TokenError: Always; `unsupported_grant_type`.
        """
        raise TokenError(
            "unsupported_grant_type",
            "This server does not issue refresh tokens; reconnect to log in again.",
        )

    # --- Access token verification -------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Verify an MCP session token; called on every authenticated request.

        Args:
            token: The bearer token presented by the MCP client.

        Returns:
            The `AccessToken` (carrying the JDE token in
            `claims["jde_token"]`), or None if the token is unknown or has
            expired (expired entries are evicted).
        """
        access_token = self._access_tokens.get(token)
        if access_token is None:
            return None
        if access_token.expires_at is not None and access_token.expires_at <= time.time():
            del self._access_tokens[token]
            return None
        return access_token

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoke an MCP session token, if it exists.

        Args:
            token: The access token to revoke (refresh tokens are a no-op
                since none are ever issued).
        """
        self._access_tokens.pop(token.token, None)


async def _mint_jde_token(
    orch_token_url: str, environment: str, username: str, password: str
) -> str:
    """Exchange a JDE username and password for an orchestrator token.

    The only function in this codebase that handles a raw password: it lives
    in this function's local scope for the one HTTP call it takes to reach
    JDE, and is never logged, stored, or echoed back to the caller.

    Args:
        orch_token_url: Base URL of JDE orchestrator's token endpoint
            (`/tokenrequest` is appended).
        environment: JDE environment name (e.g. `JDV920`) to authenticate
            against. Not a secret.
        username: The JDE username submitted on the login form.
        password: The JDE password submitted on the login form.

    Returns:
        The minted orchestrator token string.

    Raises:
        _JdeAuthError: JDE rejected the username/password.
        _JdeUnavailableError: JDE couldn't be reached, or its response didn't
            look like a successful `tokenrequest` response.
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{orch_token_url}/tokenrequest",
                headers={"Content-Type": "application/json"},
                json={
                    "username": username,
                    "password": password,
                    "environment": environment,
                },
            )
    except httpx.HTTPError as exc:
        raise _JdeUnavailableError(str(exc)) from exc

    if response.status_code == 403:
        raise _JdeAuthError("Authorization failed")
    if response.status_code != 200:
        raise _JdeUnavailableError(f"Unexpected HTTP {response.status_code}")

    token = response.json().get("token")
    if not token:
        raise _JdeUnavailableError("Orchestrator response did not include a token")
    return token


def _render_login_page(pending_id: str, error: str | None = None) -> str:
    """Render the login form as a standalone HTML page.

    Args:
        pending_id: The pending-login id to round-trip through the form's
            hidden field; empty string if there's none to preserve.
        error: An optional error message to display above the form (already
            HTML-escaped by this function; pass plain text).

    Returns:
        A complete HTML document string.
    """
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>mrad-mcp-test-server login</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 24rem; margin: 4rem auto; padding: 0 1rem; }}
  label {{ display: block; margin-top: 1rem; }}
  input {{ width: 100%; padding: 0.4rem; box-sizing: border-box; margin-top: 0.25rem; }}
  button {{ margin-top: 1.5rem; padding: 0.5rem 1rem; }}
  .error {{ color: #b00020; }}
</style>
</head>
<body>
  <h1>Sign in with your JDE credentials</h1>
  <p>This grants the MCP server a session to look up data on your behalf.</p>
  {error_html}
  <form method="post" action="/login">
    <input type="hidden" name="pending_id" value="{html.escape(pending_id)}">
    <label>Username<input type="text" name="username" autocomplete="username" required autofocus></label>
    <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>"""
