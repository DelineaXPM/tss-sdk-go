# Releasing

Releases are tagged Go module source. The project does not attach binaries or
other build artifacts to GitHub releases.

1. Complete and review the first `vX.Y.Z (unreleased)` changelog section. The
   workflow requires the requested version to match that heading; update the
   heading on `main` after publication according to the maintainers' changelog
   convention.
2. Merge all intended changes to `main` and wait for its CI and CodeQL runs to
   pass.
3. In GitHub Actions, run **Verify and publish release** from `main` with the exact
   stable version declared by the changelog, such as `v3.1.0`.
4. Confirm that the workflow passes its complete cross-platform CI and serialized
   live Secret Server and Platform gates. It then verifies that `main` has not
   moved, creates an annotated tag for the tested commit, and publishes generated
   change notes after the reviewed, customer-facing changelog content, without
   attached assets.
5. Verify the tag from a clean module cache before announcing the release.

The workflow rejects prerelease syntax, a version that does not match the pending
changelog entry, an existing GitHub release, a version not newer than the latest
stable v3 tag, module replacements, and a non-stable `delinea-common` dependency.

If tag creation succeeded but GitHub release creation did not, rerun the same
version while `main` still identifies the tagged commit. The workflow reruns every
gate, verifies the existing tag exactly, and completes publication without moving
it.

Matching `v*` tags can be created only with a deploy key held by the `release`
environment. A separate rule blocks every actor, including that deploy key, from
updating or deleting a release tag after creation. Do not add another write-enabled
deploy key without revisiting the tag-creation rule: GitHub rulesets grant their
deploy-key bypass by actor type, not by an individual key.
