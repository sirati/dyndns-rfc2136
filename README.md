# dyndns-rfc2136

`dyndns-rfc2136` accepts a small DynDNS-compatible HTTPS request and replaces one
A or AAAA RRset through an authenticated RFC 2136 update. It is intended for
routers that can call a custom update URL but cannot speak RFC 2136.

The service terminates HTTPS itself with Rustls. It obtains and renews its
certificate through ACME TLS-ALPN-01, so the public listener only needs TCP 443.
Its HTTP and TSIG credentials are loaded from a separate runtime file and never
need to enter the Nix store.

## Request

Configure a custom update URL like this:

```
https://dyndns.example.org/nic/update?hostname=<domain>&myip=<ipaddr>&username=<username>&password=<pass>
```

HTTP Basic authentication is also accepted. If Basic and query credentials are
both present, they must match. The service accepts only `GET /nic/update`, an
exact configured hostname, and an IPv4 or IPv6 address. Each configured username
can update only its assigned hostname. No record type or owner is accepted from
the caller.

## Configuration

Run the package with exactly two file arguments:

```
dyndns-rfc2136 --config /etc/dyndns-rfc2136/config.toml \
  --secrets /run/secrets/dyndns-rfc2136.toml
```

See [`examples/config.toml`](examples/config.toml) for public settings and
[`examples/secrets.toml`](examples/secrets.toml) for runtime secrets. The secret
file must be an absolute regular file outside `/nix/store`, must not be a
symlink, and must have no group or other permissions.

`acme_directory` accepts `production`, `staging`, or an explicit directory URL.
`acme_ca_certificate` may point to a PEM CA certificate for a private ACME test
server such as Pebble. The cache directory is mandatory, outside `/nix/store`,
and forced to mode `0700`; persist it so ACME account and certificate state
survive restarts.

Unauthenticated traffic is limited independently by peer IP. Authenticated
global and per-host limits are applied only after the credential and owner are
authorized. `max_connections` bounds TLS handshakes and HTTP requests together.

The authoritative server should grant the TSIG key update permission only for
the configured A and AAAA owners. That server-side ACL remains the final bound
if this service is compromised.

## Nix

The flake follows the same `flake-parts` and `buildRustPackage` layout used by
Pumpkin. It exports `packages.default`, `packages.dyndns-rfc2136`,
`checks.default`, a development shell, and `nixfmt-tree` as its formatter.

```console
nix build
nix flake check
```
