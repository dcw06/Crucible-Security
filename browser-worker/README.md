# Crucible Browser Worker

This separately operated execution boundary runs authorized, non-destructive
web tests with Playwright and axe-core. It accepts declarative plans only; it
does not execute model-generated JavaScript.

## Production boundary

Deploy the worker independently from Crucible and place it behind HTTPS.
Production infrastructure must provide:

- an egress firewall or proxy restricted to authorized target hosts;
- an ephemeral container or VM for every job;
- no host filesystem or application-credential mounts;
- a non-root runtime, read-only root filesystem, and CPU, memory, PID, disk,
  response-size, and execution-time limits;
- job-scoped credentials for future authenticated tests;
- destruction of the execution environment after every job.

Playwright route interception is defense in depth, not a substitute for
infrastructure-level egress isolation.

## Configuration

```text
BROWSER_SANDBOX_TOKEN=<at least 32 characters>
BROWSER_SANDBOX_ATTESTATION_SECRET=<at least 32 characters>
WEB_ALLOWED_HOSTS=staging.example.com
WEB_EGRESS_PROXY_URL=http://egress-gateway.internal:8080
REQUIRE_WEB_EGRESS_GATEWAY=true
```

Use matching values in Crucible, set `BROWSER_SANDBOX_URL` to the worker's
public HTTPS endpoint, and set `WEB_DYNAMIC_MODE=remote`.

The egress gateway must resolve and pin public destination addresses while
preserving the original hostname for TLS verification. Setting
`REQUIRE_WEB_EGRESS_GATEWAY=true` makes the worker refuse to start without it;
the proxy URL alone is not an attestation that the gateway is correctly built.

```bash
npm ci
npm test
docker build -t crucible-browser-worker .
```

Do not target production by default. The dashboard requires a per-scan
authorization confirmation, while ownership and staging policy must also be
enforced operationally.
