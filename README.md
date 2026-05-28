# CordisChat pq-chat — Tauri client

A desktop client for the post-quantum encrypted group-chat relay.
Reuses the same cryptographic stack as the server (ML-KEM-768 for key
encapsulation, ML-DSA-65 for signatures, AES-256-GCM for symmetric).
The relay is a dumb fan-out — it never sees plaintext or group keys.

## Build & run

You need:

- **Rust** (stable, 1.77+) — `rustup` will fetch it.
- **Tauri 2 prerequisites** for your OS — see
  <https://tauri.app/start/prerequisites/>. On Linux that's WebKitGTK
  and a few build tools; on macOS the Xcode CLI tools; on Windows
  the WebView2 runtime + MSVC build tools.
- The **`tauri` CLI**:

  ```bash
  cargo install tauri-cli --version "^2.0" --locked
  ```

Then, from this directory:

```bash
# Dev (hot-reloads the Rust core; the static HTML/CSS/JS is served as-is)
cargo tauri dev

# Production bundle (.app / .msi / .deb / .AppImage depending on host)
cargo tauri build
```

**Make sure the relay server is running** on `ws://127.0.0.1:8080`
before launching the client (or change the relay URL on the onboarding
screen).

## Running the relay

A minimal in-memory relay lives in [`relay/`](relay/). It's a "dumb
fan-out" — it stores public keys + ciphertext, tracks channel
membership and epochs, and forwards frames, but never sees a private
key, group key, or plaintext.

```bash
# In a separate terminal, from the repo root:
cd relay
cargo run                 # listens on ws://127.0.0.1:8080

# Or bind a different address:
cargo run 0.0.0.0:9000    # (set the same URL on the client's onboarding screen)
```

Leave it running, then start the client.

### Persistence

The relay persists its **user table** (so `user_id`s stay stable and
clients don't have to re-register) to a JSON file, reloading it on
startup. The file defaults to `relay-db.json` in the working directory;
override the location with `PQ_CHAT_RELAY_DB`:

```bash
PQ_CHAT_RELAY_DB=/var/lib/pq-chat/relay-db.json cargo run 0.0.0.0:8080
```

**Channels are intentionally *not* persisted.** Group keys are
session-only and live only in client memory, so a freshly-started relay
holds no key. If it revived old servers, anyone rejoining would be stuck
"waiting for key" with no member able to rekey. So a relay restart keeps
your identity but starts with no servers — you create fresh ones (where
the creator holds the key and distribution works normally).

Delete the file to also reset the user table to empty; clients then
detect their `user_id` is unknown on next login and silently re-register
with the same keypairs.

To smoke-test the relay on its own (no GUI), with the relay running:

```bash
cargo run --example smoke   # drives register → auth → create → … over a real WS
```

> **Note:** this relay is for local development and integration
> testing. It accepts the auth challenge response without verifying the
> Dilithium signature; a production relay would verify it against the
> registered signing key.

## Running two clients (multi-member testing)

Each client persists its identity to one app-data location, so two
instances would both load the *same* identity. To run several clients
under distinct identities — e.g. to watch a key get re-distributed on a
membership change — point each at its own data dir with
`PQ_CHAT_DATA_DIR`:

```bash
# Terminal 1 — default identity ("David")
cargo tauri dev

# Terminal 2 — a fresh, separate identity ("Alice")
PQ_CHAT_DATA_DIR=/tmp/pqchat-alice cargo tauri dev
```

The second instance has no identity in its dir, so it shows onboarding
and registers as a new user on the relay. Both connect to the same
relay and can join the same server.

## What it does

- First launch shows an onboarding card asking for a display name and
  the relay URL. The client generates a fresh ML-KEM-768 keypair and an
  ML-DSA-65 signing key locally, then registers the *public* keys with
  the relay. The relay assigns a `user_id` and the client persists the
  whole bundle to the OS app-data dir.
- Subsequent launches load that identity, reconnect, and authenticate
  by signing a server-issued challenge with the Dilithium key.
- **Create a server** — generates a fresh 32-byte group key locally;
  you're the sole member at epoch 0.
- **Discover & join** — the relay lists known servers; joining bumps
  the epoch and an existing member rewraps a new group key for you
  using your registered Kyber public key.
- **Send a message** — AES-GCM with the current group key, then
  signed (over `server_id || epoch_le || nonce || ciphertext`) with
  your Dilithium key, then handed to the relay for fan-out.
- **Member joins / leaves** — bump the epoch and trigger a rekey.

## Design choices worth flagging

### Deterministic rekey election

When a member joins or leaves, multiple existing clients see the same
event simultaneously. If they all generated and distributed a fresh
group key in parallel, you'd get conflicting keys for the new epoch.

So the client uses a deterministic election: **the lowest-UUID member
of the new epoch's member set (excluding the joiner, who has no prior
key) is the one who rewraps**. Everyone else just waits for the
`KeyMaterial` frame.

This is a session-local convention, not a protocol-level rule — the
relay doesn't enforce it. But it's stable as long as all clients
agree on the heuristic.

### Group keys are session-only

Group keys live in memory and are wiped on disconnect. This is **a
feature**: forward secrecy across restarts. The cost is that history
fetched after a reconnect renders as sealed envelopes until someone
re-distributes the current key (which happens automatically on the
next membership change).

### Identity is persisted unencrypted

The Kyber and Dilithium *secret* keys live in plain JSON in the OS
app-data dir. For real deployment you'd want one of:

- a passphrase + Argon2id-derived AES-GCM wrap around the private keys
- OS keychain integration (Keychain / DPAPI / libsecret via the
  `keyring` crate)

The hook for this is in `identity.rs::save` / `::load` — both
operations are single-call, so it's a localised change.

### Server re-registration on "unknown user"

The backend keeps its user table in memory (`DashMap`), so a relay
restart wipes everyone's `user_id`. The client detects the
`unknown user` error from `AuthBegin` and re-registers with the
*same* keypairs — you get a new `user_id` but cryptographic identity
stays stable.

## Architecture

```
src-tauri/src/
├── main.rs        — bin shim
├── lib.rs         — Tauri Builder, command registration
├── protocol.rs    — ClientMessage / ServerMessage (mirrors server)
├── crypto.rs      — Kyber wrap/unwrap, Dilithium sign/verify, AES-GCM
├── identity.rs    — load/save keypairs in app-data dir
├── state.rs       — in-memory channel views, member cache, group keys
├── client.rs      — WS transport, reader loop, RPC dispatch, rekey logic
└── commands.rs    — #[tauri::command] wrappers callable from JS

src/
├── index.html     — onboarding + 3-pane chat shell + modals
├── styles.css     — design tokens, layout, animations
└── main.js        — state, Tauri invoke/listen, rendering
```

The Rust side does **everything** that touches a private key. The JS
side never sees a Kyber secret or a group key — it gets either
plaintext strings (`new_message` events) or `sealed` status flags.

## Known limitations

- Group keys aren't persisted across restarts (intentional, see above).
- Past sealed messages stay sealed in the UI even if a key arrives
  later — the JS side doesn't keep raw ciphertext, so it can't retry
  decryption. A "retry decryption" command on the Rust side would be
  straightforward to add.
- Channel membership is tracked client-side per session — on relaunch
  you start with an empty server strip and need to re-discover. The
  relay persists `members` in its `Channel` struct, so a "what
  channels am I in" command on the server would close this gap.
- AES-GCM nonces are random 12-byte values. With a single key, the
  birthday bound on collision is ~2^32 messages — safely far beyond
  any realistic per-epoch volume, but worth noting if you ever raise
  the rekey period.

## Icons

`src-tauri/icons/` is empty in this repo — Tauri's `build` step will
complain about a missing `icon.png`. Drop a 512×512 PNG in there
named `icon.png` (or run `cargo tauri icon path/to/source.png` to
generate the full set). For `cargo tauri dev` it's optional.
