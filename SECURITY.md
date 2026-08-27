# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately—do not open a public GitHub issue.
Use this repository's
[private vulnerability reporting form](https://github.com/DelineaXPM/tss-sdk-go/security/advisories/new),
the **Report issue** link in Delinea's
[Responsible Disclosure](https://trust.delinea.com/) portal, or your usual
Delinea support channel.

## Supply chain

tss-sdk-go has exactly one direct Go module dependency:
[`github.com/DelineaXPM/delinea-common`](https://github.com/DelineaXPM/delinea-common).
That module imports only the Go standard library. CI verifies downloaded module
content, requires tidy module files, rejects replacements during release, and
requires the resolved graph to contain only tss-sdk-go and delinea-common.

The Go toolchain, standard library, and pinned common module are the complete
build and runtime dependency surface. CI runs a version-pinned
[`govulncheck`](https://go.dev/doc/security/vuln/) on every pull request and push
to `main`, using the minimum Go version declared in `go.mod`. It also runs
`staticcheck`, `gosec`, `go vet`, race-enabled tests, and `actionlint`.

## Supported toolchain and version floor

The `go` directive in `go.mod` (currently `go 1.26.6`) is the minimum supported
toolchain. A patch-level floor makes the standard-library security baseline
explicit and auditable. When an upstream Go security release fixes a reachable
standard-library vulnerability, advance this floor to the fixed release and
ship it through the normal review and CI process.

## Release provenance

tss-sdk-go is distributed as tagged Go module source, not as a prebuilt artifact.
Stable tags are created only after cross-platform CI and live Secret Server and
Platform tests pass. GitHub releases contain generated notes and GitHub's source
snapshots only. Tags are intended to be immutable after publication. The project
does not currently publish a separate SBOM, signature, or provenance attestation
for module tags. See `RELEASING.md` for the maintainer procedure.
