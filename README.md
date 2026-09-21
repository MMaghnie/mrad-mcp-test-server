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

Notes about these steps:
1. We use `/opt/` to store the mcp server as a non-distro package software on the VM
1. `chown $USER:$USER` is meant to transfer ownership *temporarily* from sudo to the regular user, so the next couple of commands work properly. 
1. The `--frozen` after `uv sync` is important to stay here, because installing the project on the VM should not automatically update the `uv.lock` file in case of inconsistencies. Those, if they show up, should be resolved by the user in a dev env, not on this test env. 

```bash
sudo mkdir -p /opt/mrad-mcp-test-server
sudo chown $USER:$USER /opt/mrad-mcp-test-server
git clone <this-repo-url> /opt/mrad-mcp-test-server
cd /opt/mrad-mcp-test-server
curl -LsSf https://astral.sh/uv/install.sh | sh   # if uv isn't installed yet
uv sync --frozen
cp .env.example .env
```

Then add your environment secrets to `.env`

### 2. Create a dedicated service user

For better separation of concerns, a dedicated `mcpserver` user is created to run this service.

This user has only one job: running the mcp server. 

It doesn't have a `home` dir or other privileges like a regular user.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin mcpserver
sudo chown -R mcpserver:mcpserver /opt/mrad-mcp-test-server
```

### 3. Install the systemd service

Since the first line below copies the `mcp-server.service` file from this repo to the VM's unit directory, any edits to this file in this repo would necessitate that the steps in this section to be repeated, so that the VM's copy of the file and its processes have the newest version too.

```bash
sudo cp deploy/mcp-server.service /etc/systemd/system/mcp-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-server
sudo systemctl status mcp-server
```

The service binds to `127.0.0.1:8000` only. It's never exposed directly to
the network. nginx is the only public entry point.

### 4. Get a TLS certificate

Point your DNS record at the VM's private IP. The VM itself isn't reachable
from the internet (it sits behind the company firewall), so Let's Encrypt
can't validate ownership by connecting to it directly. Use a DNS-01
challenge instead — it only needs the VM to reach *out* to Cloudflare's API,
not the other way around:

```bash
sudo apt install certbot python3-certbot-dns-cloudflare
```

Create a credentials file with a Cloudflare API token scoped to
`Zone:DNS:Edit` for this domain's zone:

```bash
sudo mkdir -p /etc/letsencrypt
printf 'dns_cloudflare_api_token = <your-api-token>\n' | sudo tee /etc/letsencrypt/cloudflare.ini
sudo chmod 600 /etc/letsencrypt/cloudflare.ini
```

```bash
sudo certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --cert-name mrad-services.com \
  -d '*.mrad-services.com'
```

The Cloudflare token is scoped to `*.mrad-services.com`, so we request a
single wildcard cert (covers `mcpserver.mrad-services.com` and any future
subdomain) rather than one cert per subdomain. `--cert-name` pins the
lineage directory to `/etc/letsencrypt/live/mrad-services.com/` — without
it, certbot still drops the wildcard's leading `*.` to name the lineage, but
being explicit keeps this predictable across renewals and matches what
`nginx-mcp-server.conf` expects.

This also enables certbot's automatic renewal timer, which reuses this
credentials file — no manual steps needed going forward, as long as the file
stays in place and the token stays valid.

### 5. Configure nginx

```bash
sudo cp deploy/nginx-mcp-server.conf /etc/nginx/sites-available/mcp-server
sudo ln -s /etc/nginx/sites-available/mcp-server /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 6. Firewall

The company firewall is what keeps the VM off the open internet, so `ufw`
here just needs to open the ports this service actually uses:

```bash
sudo ufw allow 443/tcp
sudo ufw allow 22/tcp
sudo ufw enable
```

### 7. Connecting a client

IT forwards external port `555` to this VM's `443` (NAT, not a direct
listener change — nginx still listens on 443 as configured above). So the
MCP endpoint clients (e.g. Claude Desktop) actually connect to is:

```
https://mcpserver.mrad-services.com:555/mcp
```

## Updating the deployment

Some extra steps for security has been taken in this repo, so just `cd <to this repo>` and `git pull` wont work directly.

`mcpserver` has no home directory, no git credentials, and no `uv`
installation, so it can't pull or rebuild anything itself. 

This keeps updates a manual, human-mediated step rather than something a
compromised remote or leaked credential could trigger unattended. 

To ship a change to a VM that's already set up, reuse the same ownership handoff from
steps 1-2:

```bash
cd /opt/mrad-mcp-test-server
sudo chown -R $USER:$USER .
git pull
uv sync --frozen   # only needed if pyproject.toml or uv.lock changed
sudo chown -R mcpserver:mcpserver .
sudo systemctl restart mcp-server
sudo systemctl status mcp-server
```

Reclaim ownership under your own account so `git`/`uv` have your credentials
and `PATH` available, pull and rebuild, then hand ownership back to
`mcpserver` *before* restarting, so the service starts up owning its own
files again.

## Customizing the tools

Edit `server.py`: each `@mcp.tool` function becomes an MCP tool, with the
docstring as its description and type hints driving the input schema. Keep
docstrings terse; they're sent to Claude verbatim on every connection.
