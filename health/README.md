# Health endpoint bind address

The health endpoint listens on `127.0.0.1:9999` by default. Set
`HEALTH_HOST` to another address when it must accept connections from
outside the host, and set `HEALTH_PORT` to change the port. For example:

```sh
HEALTH_HOST=0.0.0.0 HEALTH_PORT=9999 python3 health/health_endpoint.py
```

The Docker Compose service sets `HEALTH_HOST=0.0.0.0` so Docker can reach
the endpoint inside its container. Its published port is bound to the host's
`127.0.0.1` address. The systemd deployment uses the loopback default,
which works with the local Cloudflare tunnel.
