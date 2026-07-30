# Crucible desktop inspection worker

This service is the isolated native-package trust boundary. Crucible sends one
immutable artifact with its SHA-256 digest, a fresh request nonce, and a pinned
policy digest. The worker rejects replayed nonces and signs bounded normalized
evidence with HMAC-SHA256. The client verifies the artifact, nonce, platform,
policy, tool versions, isolation profile, and evidence digest before accepting
the result. Policy `crucible-native-static-v2` also binds the artifact type and
its complete required-check set, so abbreviated coverage cannot be reported as
complete.

Deploy one worker profile per operating system:

- **Windows VM/container:** `DESKTOP_WORKER_PLATFORM=Windows`, PowerShell and
  Windows Installer APIs available.
- **macOS ephemeral VM:** `DESKTOP_WORKER_PLATFORM=macOS`, with `hdiutil`,
  `pkgutil`, `codesign`, `spctl`, `stapler`, and `otool`.
- **Linux container/VM:** build `Dockerfile.linux`; it includes `dpkg-deb`,
  `rpm`, `readelf`, and `unsquashfs`.

The service must sit behind HTTPS. Its runtime must enforce the isolation
claims carried in the signed response: no network, non-root execution, no host
filesystem, read-only artifact after admission, CPU/memory/PID/disk limits, an
ephemeral filesystem, and a hard request timeout. The worker reports incomplete
coverage unless every required structural and provenance check for that format
completed.

The launcher must create a short-lived, read-only JSON receipt containing
`launcher_id`, `sandbox_id`, `platform`, `issued_at`, `expires_at`, the exact
isolation object from `worker.py`, and concrete `resource_limits` for
`cpu_count`, `memory_mib`, `disk_mib`, `processes`, and `timeout_seconds`.
It also binds `max_jobs: 1`, a unique `worker_instance_id`, and the one-time
worker public key.
It signs the canonical receipt fields with an Ed25519 private key that is never
available to the worker. The worker receives only the read-only public key,
validates the signature and expiry, performs its own non-root and
read-only-artifact checks, and binds the receipt digest and runtime checks into
every result attestation. `DESKTOP_ISOLATION_ATTESTED=true` is no longer
accepted.

Required environment variables:

```text
DESKTOP_WORKER_PLATFORM=Linux
DESKTOP_WORKER_TOKEN=<at least 32 characters>
DESKTOP_ISOLATION_RECEIPT_PATH=/run/secrets/isolation-receipt.json
DESKTOP_LAUNCHER_PUBLIC_KEY_PATH=/run/secrets/launcher-public-key.pem
DESKTOP_WORKER_PRIVATE_KEY_PATH=/run/secrets/one-time-worker-key.pem
PORT=8080
```

The launcher receipt must bind the Base64 raw public half of the one-time
worker key and a unique `worker_instance_id`. Crucible is configured with the
same launcher public key for the target platform. It independently verifies
the launcher signature, then verifies every job result with the receipt-bound
worker public key. The API bearer token authorizes submission only and is not
a result-signing credential. The one-time private-key file must live on a
worker-private ephemeral filesystem: startup loads it into the parent attestor
and deletes it before any native inspection child is created. Inspection
children receive neither that key nor submission/receipt environment variables.
After its first successful response, the worker shuts down. Crucible rejects a
second result from the same worker instance within the scanner process.

Never expose the worker directly to untrusted clients. Replay state is
process-local; production deployments must route a nonce consistently for its
one-hour retention window or replace the in-memory store with shared atomic
storage.
