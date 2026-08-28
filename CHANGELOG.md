# Changelog

## v3.1.0 (unreleased)

This release replaces the SDK's bespoke authentication and transport engine with
the public stable `github.com/DelineaXPM/delinea-common/api` v1.0.0 engine while
retaining the v3 typed Secret Server API.

### Security

- Reject remote plaintext HTTP unless `AllowInsecureHTTP` is explicitly enabled.
- Validate cloud tenant labels, Delinea region TLDs, base-URL structure, and
  supplied bearer-token syntax before sending credentials.
- Validate Platform-discovered vault origins and require explicit trust for
  nonstandard on-premises hosts.
- Keep TLS policy scoped to each `Server`, snapshot mutable TLS configuration,
  refuse unsafe redirects, and keep credentials and secret response bodies out
  of diagnostics.
- Move bearer-token caching out of environment variables and delegate bounded,
  concurrency-safe grant caching and stale-token recovery to `delinea-common`.
- Bound response bodies, attachment fan-out, request bodies, request targets,
  search results, retries, and operation duration.

### Added

- Context variants for every network operation.
- `HTTPError` and `PartialWriteError` for structured failure handling.
- `Server.CloseIdleConnections` for promptly releasing an initialized server's
  underlying idle HTTP connections.
- `CACertPEM`, `AllowedVaultHosts`, retry controls, `MaxResponseBytes`,
  `MaxRequestBytes`, `MaxAttachmentDownloads`, and `MaxSearchResults`.

### Behavior changes

- Go 1.26.6 is required by the delegated engine.
- `New` is offline and snapshots configuration; the first operation lazily probes
  username/password targets. A supplied token remains a Secret Server token.
- A reused token is refreshed and a safe read replayed on 401 or Secret Server's
  exact expired-token 403 response. Unrelated 403 authorization failures are not
  replayed, and mutations are never replayed.
- Platform vault routes expire after five minutes and fail closed if refresh fails.
- Mutating requests are never automatically replayed, including across HTTP
  redirects.
- Context-free operations use a 60-second total deadline by default.
- Searches paginate rather than silently stopping at 30 results and fail when
  `MaxSearchResults` would be exceeded.
- `UserCredential` JSON output redacts password and token values and is no longer
  a persistence or round-trip format.
- Create and update can return a partial `*Secret` with `PartialWriteError` after
  the initial server write succeeds; callers must not blindly retry creation.
- Direct secret and template reads reject mismatched response IDs before any
  attachment or write follow-up; path reads, delete inputs, and generated-password
  template field IDs must be positive.
- `SecretTemplate.GetField` returns a pointer to the matching field in the
  template, so edits through it now update that template instead of a loop copy.

### Release requirements

The manually dispatched release workflow requires the requested stable v3 version
to match this unreleased changelog entry; rejects prerelease, pseudo-version, or
pre-v1 `delinea-common` dependencies, module replacements, and unreviewed
transitive modules; reruns the complete offline and required live batteries;
confirms `main` has not moved; and only then creates an annotated tag and
source-only GitHub release whose body begins with the reviewed customer-facing
content above and continues with GitHub's generated change notes.
