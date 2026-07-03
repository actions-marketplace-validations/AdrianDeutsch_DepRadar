# ADR 0028 — Standalone binaries (distribution without the .NET SDK)

- Status: Accepted
- Date: 2026-07-03
- Deciders: Architecture

## Context

`dotnet tool install` presumes a .NET SDK — which the npm/PyPI/Cargo/Go audience, the
whole point of the multi-ecosystem work, typically does not have. The CLI needed a
distribution channel with zero prerequisites.

## Decision

- **Self-contained single-file, NOT Native AOT.** The hand-rolled mediator registers
  handlers by assembly scanning and the DI graph is built by reflection; AOT/trimming
  would demand annotations and source generators across every layer for a size win
  that does not matter for a CI tool. The binary alone, in an empty directory, runs a
  full registry scan (verified).
- **A csproj flag, not CLI properties.** `-p:AssemblyName=depradar` on the command line
  applies to every project in the restore graph (ambiguous-name failure), so the
  standalone shape is gated behind `-p:StandaloneBinary=true` inside the CLI's csproj
  (sets AssemblyName/SelfContained/PublishSingleFile/compression, disables PackAsTool).
- **Five RIDs per release** (linux-x64/arm64, osx-x64/arm64, win-x64), packed as
  tar.gz/zip containing only the binary, plus a `SHA256SUMS.txt`, all covered by the
  same keyless provenance attestation as the nupkg.
- **Unversioned asset names** (`depradar-osx-arm64.tar.gz`) — deliberately, so
  `releases/latest/download/…` URLs in docs and scripts never go stale.
- **The publish workflow now owns the release:** it creates the GitHub release for the
  tag (if none exists) and uploads the binaries; release notes are edited afterwards
  without re-uploading assets.

- **Single-file compression is OFF** (~86 MB instead of ~38 MB). End-user
  verification of the first compressed binaries caught an intermittent
  `AccessViolationException` inside System.Text.Json's type-metadata initialization
  when the analyzer's eight concurrent advisory lookups hit the first JSON
  serialization together (SIGABRT; reproduced 5/5 on go/cargo scans, 10/10 stable
  uncompressed). A working 86 MB binary beats a crashing 38 MB one.

## Consequences

- Install for a non-.NET developer is one curl: no SDK, no account, no key.
- ~430 MB of release assets per version (5 × ~86 MB, uncompressed) — irrelevant on GitHub releases.
- PDB/XML files land next to the publish output but are NOT shipped; the archives
  contain exactly one file.
- Verified locally on osx-arm64: the published binary scanned PyPI end-to-end with the
  correct exit codes, straight from an empty directory.
