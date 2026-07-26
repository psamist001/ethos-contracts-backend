# SBT Contract

`contracts/sbt` implements soulbound tokens (SBTs): non-transferable, admin-issued
badges bound to a Stellar address. It has no `transfer` function — the only way a
token's holder ever changes is a successful recovery. On top of the core
mint/holder model it implements four features tracked as issues #48-#51.

## Core Model

- `initialize(env, admin)` — sets the issuer authority.
- `mint_sbt(env, owner, metadata) -> u64` — admin-only issuance, returns `sbt_id`.
- `get_holder`, `get_metadata`, `get_schema_version` — read accessors.

## #48 — Identity Linkage (`link_sbt_to_identity`)

SBT ownership is pseudonymous by default. Optional linking associates a token
with a real-world identity for use cases like KYC, without putting identity
data or proofs on-chain.

**Privacy guarantee**: the contract never stores raw identity data or the
proof used to establish it — only two hashes:

1. An attestor (a registered KYC/identity oracle) verifies an individual
   off-chain and calls `register_identity_attestation(env, attestor,
   identity_hash, proof)`. The contract stores `sha256(proof)` keyed by
   `(identity_hash, sha256(proof))` — a commitment, not the proof itself.
2. The SBT owner later reveals the same `proof` to
   `link_sbt_to_identity(env, sbt_id, identity_hash, proof)`. The contract
   re-hashes it and checks it matches a commitment from a *currently
   trusted* attestor, then stores only `identity_hash` against the SBT.

This means: the contract can attest "this SBT is linked to an identity a
trusted attestor vouched for," while `identity_hash` reveals nothing about
the underlying identity on its own (it's presumed to be a salted hash the
individual controls), and the proof/PII never touch chain state at all.

`unlink_sbt_identity`, `is_identity_linked`, and `get_linked_identity_hash`
round out the lifecycle. Revoking an attestor (`remove_attestor`) does not
delete existing links, but blocks new links from being redeemed against that
attestor's outstanding commitments — mirroring `zk_verifier`'s oracle
revocation semantics.

## #49 — Holder Verification Cache (`verify_holder_cached`)

`get_holder` is already a single storage read, but callers that check the
same SBT's holder repeatedly in a short window can go through
`verify_holder_cached(env, sbt_id, claimed_holder)` instead.

**Strategy**: each cache entry stores `(holder, cached_at, expires_at)` with
a fixed TTL (`HOLDER_CACHE_TTL_SECONDS`, 300s). A hit returns the cached
holder comparison directly; a miss re-reads the canonical record and
repopulates the entry. The cache is invalidated automatically whenever a
holder actually changes (i.e. on successful recovery) and can be evicted
manually via the admin-only `invalidate_holder_cache`.

**Benchmarking**: every lookup increments a global hit/miss counter.
`get_cache_stats` returns the raw counters and `cache_hit_rate_bps` derives
a basis-points hit rate from them, so hit-rate can be measured on-chain over
time rather than only in an isolated benchmark run.

## #50 — Metadata Schema Versioning (`migrate_sbt_metadata`)

Each SBT carries a `schema_version`. `CURRENT_SCHEMA_VERSION` is the ceiling
new mints are issued at; existing SBTs stay on their version until migrated.

**Strategy**: migrations are pure, single-step functions of
`(from_version, metadata)` defined in `apply_schema_migration`. Migrating to
a target more than one version ahead replays each intermediate step in
order (v1 -> v2 -> v3, not a direct v1 -> v3 jump), so every version's
transform only ever needs to know about the version immediately before it.
`migrate_sbt_metadata(env, sbt_id, new_schema_version) -> bool` returns
`false` (rather than panicking) for a no-op or invalid target — at or below
the current version, or beyond `CURRENT_SCHEMA_VERSION` — and `true` once
applied. Adding a new schema version is a matter of bumping
`CURRENT_SCHEMA_VERSION` and adding one new `match` arm.

## #51 — Recovery Code System

Lost SBTs (lost keys, lost devices) can't otherwise be recovered since
there's no transfer function.

- `generate_sbt_recovery_codes(env, sbt_id) -> Vec<BytesN<32>>` — owner-only,
  generates a fresh batch of one-time codes and returns the plaintext values
  once. Only `sha256(code)` is persisted; regenerating replaces (and thus
  invalidates) any previously issued, unused codes.
- `recover_sbt_with_recovery_code(env, sbt_id, recovery_code, new_holder) ->
  bool` — hashes the submitted code, checks it against the stored, unused
  hashes, and on a match reassigns the SBT's holder to `new_holder` and
  evicts the holder cache. `new_holder` is an explicit parameter (a
  deliberate departure from the issue's suggested signature): Soroban has no
  implicit caller identity, so the address regaining control must be passed
  and must authorize the call itself, since by definition the original
  owner can no longer sign.
- **Attempt tracking & rate limiting**: every call — success or failure —
  counts against a per-SBT limit of `RECOVERY_MAX_ATTEMPTS` (5) attempts per
  `RECOVERY_ATTEMPT_WINDOW_SECONDS` (1 hour). Exceeding it panics with
  `RecoveryRateLimited` rather than silently failing, so brute-forcing a
  code is bounded.

**Known limitation**: recovery codes are generated with `env.prng()`, which
the Soroban SDK documents as unsuitable for secrets in low-risk-tolerance
applications. This is acceptable for the current scope but should be
revisited (e.g. an off-chain-generated, on-chain-committed scheme) before
using this contract to guard high-value identities.

## Error Codes

| Code | Name | Description |
|------|------|--------------|
| 1 | AlreadyInitialized | Contract already initialized |
| 2 | NotInitialized | Contract not yet initialized |
| 3 | NotAttestor | Caller is not a registered identity attestor |
| 4 | SbtNotFound | No SBT exists with the given id |
| 5 | EmptyMetadata | Metadata bytes were empty |
| 6 | MetadataTooLarge | Metadata exceeds `MAX_METADATA_SIZE` |
| 7 | EmptyProof | Proof bytes were empty |
| 8 | ProofTooLarge | Proof exceeds `MAX_IDENTITY_PROOF_SIZE` |
| 9 | IdentityAlreadyLinked | SBT already has a linked identity |
| 10 | NoIdentityLinked | SBT has no linked identity to unlink |
| 11 | AttestationNotFound | No matching, currently-trusted attestation |
| 12 | InvalidSchemaTransition | Not a valid forward migration target |
| 13 | NoRecoveryCodes | No unused recovery codes exist for this SBT |
| 14 | RecoveryRateLimited | Too many recovery attempts in the current window |
