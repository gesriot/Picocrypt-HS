# Important
These rules apply to every task in this project unless explicitly overridden.
Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

## Rule 1 — Think Before Coding
State assumptions explicitly. If uncertain, ask rather than guess.
Present multiple interpretations when ambiguity exists.
Push back when a simpler approach exists.
Stop when confused. Name what's unclear.

## Rule 2 — Simplicity First
Minimum code that solves the problem. Nothing speculative.
No features beyond what was asked. No abstractions for single-use code.
Test: would a senior engineer say this is overcomplicated? If yes, simplify.

## Rule 3 — Surgical Changes
Touch only what you must. Clean up only your own mess.
Don't "improve" adjacent code, comments, or formatting.
Don't refactor what isn't broken. Match existing style.

## Rule 4 — Goal-Driven Execution
Define success criteria. Loop until verified.
Don't follow steps. Define success and iterate.
Strong success criteria let you loop independently.

## Rule 5 — Use the model only for judgment calls
Use me for: classification, drafting, summarization, extraction.
Do NOT use me for: routing, retries, deterministic transforms.
If code can answer, code answers.

## Rule 6 — Token budgets are not advisory
If approaching budget, summarize and start fresh.
Try using subagents.
Surface the breach. Do not silently overrun.

## Rule 7 — Surface conflicts, don't average them
If two patterns contradict, pick one (more recent / more tested).
Explain why. Flag the other for cleanup.
Don't blend conflicting patterns.

## Rule 8 — Read before you write
Before adding code, read exports, immediate callers, shared utilities.
"Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.

## Rule 9 — Tests verify intent, not just behavior
Tests must encode WHY behavior matters, not just WHAT it does.
A test that can't fail when business logic changes is wrong.

## Rule 10 — Checkpoint after every significant step
Summarize what was done, what's verified, what's left.
Don't continue from a state you can't describe back.
If you lose track, stop and restate.

## Rule 11 — Match the codebase's conventions, even if you disagree
Conformance > taste inside the codebase.
If you genuinely think a convention is harmful, surface it. Don't fork silently.

## Rule 12 — Fail loud
"Completed" is wrong if anything was skipped silently.
"Tests pass" is wrong if any were skipped.
Default to surfacing uncertainty, not hiding it.

# Repository Context
Picocrypt NG is a security-sensitive file encryption app. Treat correctness,
compatibility, privacy, and release integrity as first-class requirements.
Always say "Picocrypt NG" or "Picocrypt-NG" when referring to this project.

## Sources Of Truth
- `README.md`: user-facing product, platform, and feature description.
- `ARCHITECTURE.md`: package map, crypto data flow, audit-critical areas.
- `API.md`: internal API contracts for maintainers.
- `Internals.md`: cryptographic and volume-format details.
- `CLI.md`: command-line behavior and flags.
- `src/README.md`: desktop/CLI source build and Go test notes.
- `android/README.md`: native Android architecture, gomobile, signing, release notes.
- `VERSION`: root release version; keep lockstep with cmd/app/header constants,
  `src/FyneApp.toml`, packaging metadata, and release workflows.
- `Changelog.md`, `SIGNING.md`, `fastlane/`: release-facing metadata.

## Repository Map
- `src/`: main Go module. Honor `src/go.mod` for the required Go version and deps.
- `src/cmd/picocrypt/`: desktop GUI + CLI entry point.
- `src/cmd/wasm/`: browser/WASM entry point.
- `src/mobile/`: gomobile bindings used by the Android app.
- `src/internal/app/`: operation state and progress reporting.
- `src/internal/cli/`: Cobra CLI implementation.
- `src/internal/ui/`: Fyne desktop UI.
- `src/internal/wasm/`: browser bridge behavior and WASM feature limits.
- `src/internal/fileops/`: zip, split, recombine, unpack, path handling.
- `src/internal/encoding/`: Reed-Solomon and padding.
- `src/internal/diskspace/`, `src/internal/distmeta/`, `src/internal/docs/`,
  `src/internal/workflowpolicy/`: platform, release, embedded-doc, and CI policy support.
- `android/`: native Android app using Kotlin/Compose + gomobile AAR.
- `dist/`: tracked packaging metadata for Windows, macOS, Linux, Snap, Flatpak, MIME.
- `.github/workflows/`: release and PR validation workflows.

## Audit-Critical Code
These packages directly affect encrypted volume semantics:
- `src/internal/crypto/`
- `src/internal/header/`
- `src/internal/keyfile/`
- `src/internal/volume/`

For changes there, read immediate callers and relevant docs first. Preserve v1/v2
compatibility, golden vectors, deniability semantics, keyfile behavior, Reed-Solomon
behavior, and verify-first behavior. Use crypto-secure randomness, constant-time
MAC comparison, explicit sensitive-memory zeroing, and existing cleanup patterns.
Never rely on AI confidence for a cryptographic decision.

## Platform And Feature Notes
- Desktop GUI uses Fyne; CLI-only builds use the `cli` tag.
- Web/WASM is an in-memory bridge (`src/cmd/wasm/`, `src/internal/wasm/`)
  with its own feature contract and a 1 GiB input guard. Check code and tests
  before assuming parity or limits; file/folder/streaming/splitting need bridge
  changes. Account for JS/runtime copy limits when discussing zeroing.
- Android is a native app under `android/`; rebuild the gomobile AAR after Go bridge
  changes. Passwords cross Kotlin to Go as bytes, but Go operation internals may use
  strings as documented.
- Comments stored in volumes are plaintext header data; never describe them as
  secret. Current v2 header auth covers comments, but verify version/format nuance
  before making authentication claims.
- Deniability changes are high risk: random-looking output, comment behavior, manual
  naming, and mode interactions are part of the user-visible contract.
- File associations and packaging metadata are release behavior, not cosmetic files.

## Common Commands
Run commands from `src/` unless noted.
- Fast Go suite: `go test ./...`
- Golden compatibility: `go test -run 'TestGoldenDecryption|TestGoldenCompressedDecryption|TestGoldenWrongPassword|TestGoldenV1WrongPassword' ./internal/volume`
- CLI package: `go test ./internal/cli`
- Opt-in CLI integration: `PICOCRYPT_RUN_CLI_INTEGRATION=1 go test ./internal/cli`
- Race-sensitive Go work: `go test -race ./...`
- Desktop build: `CGO_ENABLED=1 go build -ldflags="-s -w" -o Picocrypt-NG ./cmd/picocrypt`
- CLI-only build: `CGO_ENABLED=1 go build -tags cli -ldflags="-s -w" -o Picocrypt-NG-cli ./cmd/picocrypt`
- Android gomobile AAR from `android/`: `./build-gomobile.sh`
- Android app from `android/`: `./build-app`

## Change Discipline
- Make surgical changes. Do not refactor crypto, UI, Android, or packaging while
  solving an unrelated issue.
- When docs disagree with executable config, prefer executable config and surface
  the conflict.
- For release/version work, check `VERSION`, `src/cmd/picocrypt/main.go`,
  `src/internal/app/state.go`, `src/internal/header/format.go`,
  `src/internal/distmeta`, packaging metadata, changelog, and workflows together.
- For dependency or library/API questions, use Context7 docs first as required above.
- Keep generated/local artifacts out of commits: build outputs, gomobile AARs unless
  explicitly intended, local signing material, IDE files, and AI-agent state.
- If a validation command cannot run, say exactly which command was skipped and why.
