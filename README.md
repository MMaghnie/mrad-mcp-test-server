# mrad-mcp-test-server

A minimal remote MCP server (FastMCP, streamable HTTP) used to verify that
employees can connect to a self-hosted MCP server from Claude Desktop.

## Requirements

- Python 3.12+
- [`uv`](https://docs.astral.sh/uv/) for dependency management

## Run locally

```bash
uv sync
uv run python server.py
```

## Deploying on a new VM

These steps assume Ubuntu with nginx already installed, and DNS control over
whatever domain/subdomain you're pointing at the VM.

### 1. Get the code onto the VM and install dependencies

```bash
sudo mkdir -p /opt/mrad-mcp-test-server
sudo chown $USER:$USER /opt/mrad-mcp-test-server
git clone <this-repo-url> /opt/mrad-mcp-test-server
cd /opt/mrad-mcp-test-server
curl -LsSf https://astral.sh/uv/install.sh | sh   # if uv isn't installed yet
uv sync --frozen
```

### 2. Create a dedicated service user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcpserver
sudo chown -R mcpserver:mcpserver /opt/mrad-mcp-test-server
```

### 3. Install the systemd service

```bash
sudo cp deploy/mcp-server.service /etc/systemd/system/mcp-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-server
sudo systemctl status mcp-server
```

The service binds to `127.0.0.1:8000` only — it's never exposed directly to
the network. nginx is the only public entry point.

### 4. Get a TLS certificate

Point your DNS record at the VM's (VPN/private) IP, then issue a cert. If
your DNS provider isn't reachable from the VM directly (e.g. it's an
internal-only host), use a DNS-01 challenge so certbot never needs inbound
access:

```bash
sudo apt install certbot python3-certbot-dns-<your-provider-plugin>
sudo certbot certonly --dns-<your-provider-plugin> -d <your-domain>
```

Substitute the plugin for whatever DNS provider hosts your domain
(`dns-google`, `dns-cloudflare`, `dns-route53`, etc.). Without a supported
plugin, use `certbot certonly --manual --preferred-challenges dns` and add
the TXT record it prints by hand.

### 5. Configure nginx

```bash
sudo cp deploy/nginx-mcp-server.conf /etc/nginx/sites-available/mcp-server
sudo ln -s /etc/nginx/sites-available/mcp-server /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 6. Firewall

Only allow 443 (and 22) from your VPN subnet — the server should not be
reachable from the open internet:

```bash
sudo ufw allow from <vpn-subnet> to any port 443 proto tcp
sudo ufw allow from <vpn-subnet> to any port 22 proto tcp
sudo ufw enable
```

## Customizing the tools

Edit `server.py` — each `@mcp.tool` function becomes an MCP tool, with the
docstring as its description and type hints driving the input schema. Keep
docstrings terse; they're sent to Claude verbatim on every connection.
