# eD2K UDP Source Reask & Queue-Slot Persistence — Design Sketch

**Status:** Proposed · post-parity · **out of RC2 scope**
**Area:** ed2k download/upload client (`emulebb-ed2k`)
**Audience:** anyone implementing client↔client UDP reask in emulebb-rust
**Backlog item:** [`FEAT-001`](../active/items/FEAT-001.md)

---

## 1. Background: what UDP reask is in eMule/eMuleBB

In eMule, when you want a file from a remote client you don't get served
immediately — you take a **position in that client's upload queue** and wait
(often for hours). Holding a TCP connection open to every client you are queued
on for hours does not scale: a downloader can be queued on hundreds of sources
at once. So eMule **disconnects** and keeps each queue position alive by
periodically **reasking**:

- **Primary path — UDP.** The downloader sends a tiny UDP `OP_REASKFILEPING`
  to the source. The source replies `OP_REASKACK` with the downloader's *current
  queue position*, or `OP_QUEUEFULL` / `OP_FILENOTFOUND`. No TCP socket is held;
  one datagram each way refreshes the slot.
- **Fallback path — TCP.** When UDP is unavailable (no source UDP port, we're
  firewalled, proxy in use, or the source is LowID without a reachable buddy),
  the downloader instead reconnects over TCP and re-sends `OP_SETREQFILEID`.

This reask cadence is the backbone of eMule's queue economy. The relevant
constants in `srchybrid/opcodes.h` (current `emulebb-main`):

| Constant | Value | Meaning |
|---|---|---|
| `FILEREASKTIME` | 29 min | nominal reask interval per source (×2 for NoNeededParts sources) |
| `MIN_REQUESTTIME` | 10 min | minimum spacing between reasks to one source |
| `UDPMAXQUEUETIME` | 20 s | uploader-side: how long a *just-asked* slot is held warm |

### 1.1 Opcodes (all under `OP_EMULEPROT` 0xC5, on the client UDP socket)

| Opcode | Value | Direction | Meaning |
|---|---|---|---|
| `OP_REASKFILEPING` | `0x90` | downloader → source | "still here, what's my rank for this file?" |
| `OP_REASKACK` | `0x91` | source → downloader | `[partstatus?] + queue position (u16)` |
| `OP_FILENOTFOUND` | `0x92` | source → downloader | source no longer has the file (→ drop source) |
| `OP_QUEUEFULL` | `0x93` | source → downloader | queue full / not findable; treated as rank 0, stay TCP |
| `OP_REASKCALLBACKUDP` | `0x94` | downloader → **buddy** | LowID reask relayed via the source's KAD buddy |
| `OP_DIRECTCALLBACKREQ` | `0x95` | downloader → source | direct callback request (firewalled-peer connect) |
| `OP_PORTTEST` | `0xFE` | — | already handled in rust |

> **Note:** `0x90`–`0x95` collide numerically with server-global opcodes
> (`OP_GLOBSEARCHREQ3` 0x90 …) and eMule-TCP opcodes (`OP_REQUESTPREVIEW` 0x90,
> `OP_MULTIPACKET` 0x92). They are disambiguated entirely by **socket + protocol
> byte**: these are `OP_EMULEPROT` packets on the *client UDP* socket. Any new
> rust client-UDP dispatcher must key on that context, exactly as the eD2K-TCP
> and server-UDP dispatchers already do.

### 1.2 Exact wire format (from `emulebb-main`)

`OP_REASKFILEPING` request body (`CUpDownClient::UDPReaskForDownload`,
`DownloadClient.cpp`):

```text
hash16            file MD4 (16 bytes)
if udp_version > 3:
    partstatus    (u16 count + bitfield) if we hold a partfile, else u16 0
if udp_version > 2:
    u16           our reported complete-source count for this file
```

`OP_REASKACK` reply body (`ClientUDPSocket.cpp`, OP_REASKFILEPING handler):

```text
if peer udp_version > 3:
    partstatus    uploader's part status for the file (or u16 0 if complete file)
u16               our queue position on the uploader (GetWaitingPosition)
```

`OP_QUEUEFULL`, `OP_FILENOTFOUND`: **empty body** (opcode only).

LowID variant `OP_REASKCALLBACKUDP` request body prepends the buddy id:

```text
hash16            buddy KAD id (GetBuddyID)
hash16            file MD4
... same optional partstatus + complete-count tail as REASKFILEPING ...
```

### 1.3 Sender-side rules eMule enforces (worth mirroring)

From `UDPReaskForDownload`:

- Send UDP reask **only if** the source advertised a UDP port *and* a non-zero
  `udp_version`, we have a local UDP port, we are **not** firewalled, there is
  **no** live TCP socket to that source, and no proxy is configured.
- Back off UDP for a source once its failure ratio is bad: `total > 3 &&
  failed/total > 0.3` → stop UDP-reasking it (fall back to TCP).
- A `pending` flag (`m_bUDPPending`) guards one outstanding reask per source;
  unsolicited `OP_REASKACK`/`OP_QUEUEFULL`/`OP_FILENOTFOUND` (pending == false)
  are dropped. This is a basic anti-spoof / correlation gate.

Receiver-side (when **we** are the uploader answering a reask): only answer if
the sender is a *known waiting client* located by `(ip, udp_port)`; if we can't
locate them, deliberately **stay silent** to force a TCP connection (prevents
UDP-port-mapping confusion). If queue is near full, answer `OP_QUEUEFULL`.

### 1.4 Obfuscation

UDP reask packets honour eMule UDP protocol obfuscation: they are sent encrypted
when the peer `ShouldReceiveCryptUDPPackets()` (keyed on the peer user hash),
plain otherwise. This is the **client-to-client userhash key path** of
`CEncryptedDatagramSocket::EncryptSendClient`/`DecryptReceivedClient` —
`MD5(userHash16 || ip4 || MAGICVALUE_UDP || randomKeyPart2)` with **no RC4 drop**
(`bSkipDiscard=true`). It is genuinely distinct from the keys the rust client
already had: `kad-net/obfuscation` uses Kad NodeID / ReceiverVerifyKey, and
`ed2k_server/obfuscation` uses the server base key — neither derives the
client userhash key. So a dedicated primitive was the correct call, **now built**
as `crates/emulebb-ed2k/src/ed2k_client_udp_obfuscation.rs`
(`obfuscate_client_udp` / `deobfuscate_client_udp`, faithful 8-byte crypt header,
reserved-marker pass-through) plus `classify_inbound_client_udp`, the
`DecryptReceivedClient` first-byte key-try triage (plaintext vs eD2k-client-first
vs Kad-first). The Kad NodeID/RecvKey paths remain `emulebb-kad-net`'s concern.

---

## 2. Current state in emulebb-rust

emulebb-rust (and its upstream `p2p-overlord-agents`, from which the eD2K stack
was copied verbatim) inherited **none** of the client↔client UDP *transport*:
there is still no client UDP socket and `ed2k_tcp/` has no reask dispatcher.
Provenance is upstream — an inherited gap, not a rust regression. The **pure,
transport-free foundation is now built** (see §2.1); what remains is the gated
transport wiring.

Instead, the rust downloader uses a **held-TCP queued** model
(`crates/emulebb-ed2k/src/ed2k_tcp/download/session.rs`):

- It opens a TCP session per source and, if queued, **keeps the socket open**,
  reading `OP_QUEUERANK` / `OP_QUEUERANKING` updates inline. A short
  `QUEUE_RANK_GRACE = 20s` read deadline is extended each time a rank arrives; if
  no rank lands within the grace, the source is dropped as
  `AcceptedButIncomplete`.
- The application-level retry loop
  (`crates/emulebb-core/src/lib.rs`, `*_direct_download*`) only reschedules
  sources when **all** sources are loopback (`retry_deadline = Some(now+360s)`
  gated on `sources.iter().all(|s| s.ip.is_loopback())`). That branch exists for
  the local lab harness; for real swarm sources `retry_deadline = None`, so once
  the active set drains the download returns with no further reask.

### Consequences

| Role | Stock eMule | emulebb-rust today |
|---|---|---|
| As downloader | Disconnects, refreshes each queue slot via UDP every ~29 min for hours | Holds TCP while queued; loses the slot ~20 s after the last rank or on TCP drop; no re-reask for non-loopback sources |
| As uploader | Answers remote `OP_REASKFILEPING` so queued peers keep position cheaply | No client UDP socket → remote eMule queued on us **cannot** UDP-reask; must TCP-reconnect, costing both sides a socket |

Interoperability is preserved (everything degrades to TCP, which stock supports),
but **long-duration queue persistence — the core of eMule's "wait in queue"
behaviour — is effectively absent for real sources.** On a busy swarm where
uploaders won't hold idle TCP sockets open to queued downloaders, the rust client
struggles to climb queues.

### 2.1 Foundation implemented (2026-06-14)

The Phase-1 pieces that are **pure** (no socket, no integration decision) are
built, committed and unit-tested, so the gated transport wiring (§4) is the only
thing that remains:

| Piece | Module | Covers |
|---|---|---|
| Reask codec | `ed2k_client_udp/codec.rs` | encode/decode `OP_REASKFILEPING`/`OP_REASKACK` + partstatus bitfield, exact `udp_version` tail gating (§1.2); plus the Phase-2 `OP_REASKCALLBACKUDP` LowID buddy codec (buddy_id + ping tail) |
| Reask policy | `ed2k_client_udp/state.rs` | `reask_interval` (FILEREASKTIME ×2 NNP ≥ MIN_REQUESTTIME), `udp_reask_eligible`, failure-ratio TCP fallback (§1.3) |
| Pending registry | `ed2k_client_udp/registry.rs` | `(ip,udp_port)` anti-spoof correlation gate (R3) |
| Source state + reaction | `ed2k_client_udp/state.rs` | `ReaskSource` (QueuedDetached) transitions + downloader `apply_reask_reply` reaction table (§4.4) |
| Uploader reciprocity | `ed2k_client_udp/reciprocity.rs` | `answer_inbound_reask` decision: Ack/FileNotFound/QueueFull/Silent (§4.5, R5) |
| Client UDP obfuscation | `ed2k_client_udp_obfuscation.rs` | userhash-key encrypt/decrypt (§1.4) + `classify_inbound_client_udp` first-byte key-try triage |

**Still gated — do not land blind (operator design call + live validation):** the
inbound reask arrives on the **shared Kad UDP socket** (rust advertises
`kad_udp_port` as its eD2k UDP port, hello `ET_UDPPORT`). The remaining wiring is
(1) the §4.3 transport recv loop + demux in `emulebb-kad-net` (now that the
classifier and obfuscation exist), (2) the §4.2 per-transfer ticker in the
download runtime, (3) §4.5 uploader reciprocity, and (4) live validation. The
open **design decision** is shared Kad UDP port (eMule-faithful, touches working
Kad) vs a separate eD2k client UDP port (safer, diverges). The pure foundation
above is agnostic to that decision.

---

## 3. The problem, stated independently of eMule

Given a long-running download with sources that queue us rather than serve
immediately:

- **R1 — Cheap slot keepalive.** Maintain queue position on many sources for
  hours without holding a TCP socket per queued source.
- **R2 — Survive TCP teardown.** Losing the queued TCP connection (the normal
  case — uploaders reclaim idle sockets) must **not** lose the queue position.
- **R3 — Detect dead/stale sources.** Learn promptly when a source no longer has
  the file (`OP_FILENOTFOUND`) or is full (`OP_QUEUEFULL`) and react (drop /
  deprioritise) rather than waiting blindly.
- **R4 — Correct fallback.** When UDP is not usable (firewalled self, no source
  UDP port, LowID, proxy), fall back to TCP reask deterministically.
- **R5 — Reciprocity.** As an uploader, answer well-formed reasks from peers we
  are actually queuing, so stock peers can keep their slot on us cheaply.
- **R6 — Fit the per-transfer-task model.** emulebb-rust downloads are
  independent per-transfer tasks with **no shared scheduler**
  (see [`source-management-and-a4af.md`](./source-management-and-a4af.md) and
  the download-model decision). Reask must live inside the per-transfer / per-
  source state machine, not become a new global scheduler.

---

## 4. Proposed model

### 4.1 Promote a queued source to a *detached* reask state

Today a queued source is a live `download/session` future blocking on a socket.
Introduce a third source state between "connected" and "gone":

```text
SourceConn:
  Connecting   -> tcp connect + hello + SETREQFILEID
  Active       -> downloading (slot granted)
  QueuedDetached {                 // NEW: no socket held
      udp_port, udp_version, user_hash, should_crypt,
      last_rank, last_reask, next_reask, pending: bool,
      udp_total, udp_failed,       // failure-ratio backoff (§1.3)
      fallback_tcp_only: bool,     // set when UDP disqualified
  }
  Dead         -> FNF / exhausted
```

When a source queues us (we receive `OP_QUEUERANK`/`OP_QUEUERANKING` and are not
granted a slot), and the source is **UDP-eligible** (§1.3), the per-source task
**closes the TCP socket** and transitions to `QueuedDetached`. This directly
buys R1/R2: there is no socket to lose.

If the source is **not** UDP-eligible, keep today's held-TCP behaviour but bound
it, and schedule a TCP reconnect-reask on the `FILEREASKTIME` cadence (R4).

### 4.2 A per-transfer reask ticker, not a global scheduler (R6)

Each download transfer already owns a task. Give that task a single
`tokio::time::interval` (or a min-heap of `next_reask` deadlines over *its own*
detached sources). On each tick it reasks the sources whose `next_reask` is due:

```text
for src in self.detached_sources.due(now):
    if src.fallback_tcp_only || !udp_usable(self, src):
        spawn tcp_reconnect_reask(src)         // SETREQFILEID over fresh TCP
    else:
        send_udp_reask(src); src.pending = true
    src.next_reask = now + reask_interval(src) // FILEREASKTIME, ×2 if NNP, ≥ MIN_REQUESTTIME
```

No cross-transfer coordination is introduced — each transfer reasks its own
sources. This honours the "independent per-transfer tasks, no shared scheduler"
decision. (A4AF-style cross-file dedup is a *separate*, already-parked design;
the two compose but neither requires the other.)

### 4.3 One shared client UDP socket, fanned in by correlation key

UDP is connectionless, so a single bound UDP socket (the existing local eD2K UDP
port) serves all transfers. Add an `ed2k_tcp` sibling module, e.g.
`ed2k_client_udp/`, that:

1. Owns the recv loop on the client UDP port, de-obfuscates, and dispatches
   `OP_EMULEPROT` reask opcodes.
2. Routes replies back to the waiting transfer/source by correlation key
   `(peer_ip, peer_udp_port)` — mirroring eMule's `GetDownloadClientByIP_UDP`.
   A small `HashMap<(Ipv4Addr,u16), SourceHandle>` registry, populated when a
   source enters `QueuedDetached` with `pending = true`, is enough.
3. Enforces the **pending gate** (R3 anti-spoof): drop `OP_REASKACK` /
   `OP_QUEUEFULL` / `OP_FILENOTFOUND` for which no `pending` reask is outstanding.

This is the one structural addition. It is shared *transport*, not a shared
*scheduler* — it carries datagrams; the per-transfer tasks still own all policy.

### 4.4 Reaction table (downloader side)

| Received | Action |
|---|---|
| `OP_REASKACK` | parse optional partstatus + `u16` rank; update `last_rank`; clear `pending`; set `next_reask` |
| `OP_QUEUEFULL` | treat as rank 0, mark `remote_queue_full`, clear `pending`, keep source, retry next cadence |
| `OP_FILENOTFOUND` | mark source dead for this file; remove from transfer's source set (R3) |
| reask timeout (no reply) | `udp_failed++`; if `udp_total>3 && failed/total>0.3` set `fallback_tcp_only`; retry via TCP |

### 4.5 Reciprocity — answer inbound reasks (R5)

The new client-UDP recv loop also handles **inbound** `OP_REASKFILEPING` when we
are an uploader. Reuse the upload-queue state already in
`ed2k_tcp/listener/session/upload_queue.rs`:

- Locate the sender among our waiting clients by `(ip, udp_port)`.
- Known & file matches → reply `OP_REASKACK` with `GetWaitingPosition`-equivalent
  rank (+ partstatus if peer `udp_version > 3`).
- Unknown sender → **stay silent** (force TCP), exactly as stock, unless queue is
  near-full → `OP_QUEUEFULL`.
- File not shared → `OP_FILENOTFOUND`.

### 4.6 Concrete integration point (shared-Kad-port decision taken)

The operator chose the **shared Kad UDP port** (eMule-faithful; peers reask to the
advertised `ET_UDPPORT == kad_udp_port`). The pure framing layer is built
(`ed2k_client_udp/{codec,dispatch,outbound}` + `ed2k_client_udp_obfuscation`).
What remains is the wiring, and the safe hook is precise:

- **Inbound hook = the Kad-decode-failure branch** of
  `emulebb-kad-net/src/rpc/receive_loop.rs` (`KadPacket::decode(&plain)` `Err`,
  ~L34-77). A reask datagram lands there (Kad's `decrypt` is non-destructive on a
  non-Kad key, and the raw `data` is still in scope). Calling
  `parse_inbound_reask_datagram(&data, from_ipv4, our_user_hash, our_udp_version)`
  there is **purely additive**: it only inspects packets Kad already rejected, so
  it cannot change Kad behaviour for any packet Kad decodes. On `Some(msg)`,
  handle + `continue`; on `None`, fall through to today's decode-failed logging.
- **Three plumbing needs** (the boundary architecture, the part to land behind
  live validation):
  1. **eD2k user hash** into kad-net — kad-net knows the Kad `NodeId`, not the
     eD2k user hash the reask key needs. Inject it (config/handle), don't derive.
  2. **Foreign-datagram handler** — kad-net must hand a non-Kad datagram up to an
     ed2k/core-registered callback (kad-net must not depend on core). An
     `Option<Arc<dyn Fn(&[u8], SocketAddr) + Send + Sync>>` on `RpcManager` inner,
     `None` by default (= exactly today's behaviour), invoked in the hook above.
  3. **Send-handle** — replies (reciprocity) and the per-transfer ticker
     (outbound `build_*_datagram`) send via the *same* shared socket, so the
     handler/ticker needs a clone of kad-net's `Transport` (or a thin
     `send_raw(addr, bytes)` handle).
- **Ticker** (§4.2) lives in the core download runtime, owns the
  `ReaskPendingRegistry` + per-source `ReaskSource`s, calls the outbound builders,
  and feeds replies (routed by `(ip,udp_port)`) into `apply_reask_reply`.
- **Validation gate:** land the above incrementally and prove it on the wire
  (Rust↔Rust accelerated cadence, then a gentle Rust↔stock witness) before
  trusting it — do not enable by default until validated.

---

## 5. What we deliberately keep, and what we drop

- **Keep** the existing held-TCP queued read as the **non-UDP fallback** only
  (firewalled self, no peer UDP port, proxy). Do not delete it; bound it.
- **Drop** "held-TCP is the primary queued strategy." For UDP-eligible sources
  the socket is released and the slot is kept by datagram.
- **Do not** build a global reask scheduler. Per-transfer tickers + one shared
  UDP transport (R6).
- **Defer** LowID/buddy reask (`OP_REASKCALLBACKUDP` 0x94) and
  `OP_DIRECTCALLBACKREQ` 0x95 to a second phase — they depend on KAD buddy state
  and firewalled-peer callback, which is a heavier, separable slice. Phase 1 is
  HighID UDP reask + TCP fallback + reciprocity.

---

## 6. Protocol & parity caveats

- **Wire-faithful or omitted, never half-spoken.** If implemented, packet bytes,
  the optional partstatus/complete-count tails, the `udp_version` gating, and the
  obfuscation choice must match stock exactly (§1.2). Until then this stays a
  documented omission (`policy/rust-client-omissions.toml`), since
  half-implemented reask that mis-frames is worse than honest TCP-only fallback.
- **IPv4-only**, consistent with the rest of the rust client.
- **Advertised capability already implies it.** The rust hello advertises
  `udp_version = 4` (`ed2k_tcp/hello.rs`). Peers may therefore *expect* us to
  answer UDP reask. That makes the reciprocity half (R5) the more
  parity-sensitive gap: we currently advertise UDP support we don't honour.
  Either implement it or drop the advertised `udp_version` while omitted.

---

## 7. Scope & sequencing

- **Out of RC2 scope** (RC2 is verification + release-blocking fixes only;
  emulebb-rust is out of ship scope). Capture and stage; do not build under the
  freeze.
- **Phase 0 (now):** record the omission in
  `policy/rust-client-omissions.toml` (id e.g. `udp-source-reask`) so the wire
  surface is honestly described. Reconcile the advertised `udp_version`.
- **Phase 1 — foundation + framing DONE (2026-06-14, §2.1):** reask codec,
  policy, pending gate, source state, both reaction tables (downloader
  `apply_reask_reply` + uploader `answer_inbound_reask`), client-UDP obfuscation +
  inbound classifier, and the bidirectional datagram framing
  (`parse_inbound_reask_datagram` / `build_*_datagram`) are built and unit-tested.
  The shared-Kad-port design call is **taken** (§4.6). **Remaining (gated on live
  validation):** the receive_loop.rs inbound hook + the three plumbing needs
  (user hash, foreign-datagram callback, send-handle) + the per-transfer ticker.
- **Phase 2:** LowID buddy reask (`OP_REASKCALLBACKUDP` — **codec done**, buddy-
  relay transport pending) and `OP_DIRECTCALLBACKREQ`.
- New code lands as new modules within the per-module size budget
  (`policy/rust-client.toml`); no big-refactor of the legacy-shaped `.rs` files.

---

## 8. Validation

- **Unit:** encode/decode round-trips for each opcode body incl. the
  `udp_version > 2` / `> 3` tail variants; pending-gate drop of unsolicited
  replies; failure-ratio backoff threshold; reask-interval math
  (`FILEREASKTIME`, `×2` NNP, `≥ MIN_REQUESTTIME`).
- **Rust↔Rust:** two rust clients, one queues the other, downloader releases TCP
  and keeps position purely via UDP reask across an accelerated cadence.
- **Rust↔aMule / Rust↔eMuleBB:** short-path witness that a stock client accepts
  our `OP_REASKFILEPING` and that we answer a stock client's reask with a correct
  rank. Gentle, widely-spaced, single-pass live runs only — confirm before any
  live-wire run (live-wire policy).
- **Tracing:** packet_trace labels for the new opcodes added to
  `ed2k_tcp/dump.rs`'s sibling so the harness can assert the exchange.

---

## 9. Summary

eMule keeps queue positions alive for hours by **disconnecting and UDP-reasking**
each source on a ~29-minute cadence; emulebb-rust inherited a held-TCP model from
`p2p-overlord-agents` that has no client UDP socket and no reask, so real-swarm
queue slots are lost on TCP teardown and we silently fail to answer reasks we
advertise support for. The fix is a single shared **client UDP transport** plus a
**per-transfer reask ticker** (no global scheduler, honouring the per-transfer
download model), implementing HighID `OP_REASKFILEPING`/`OP_REASKACK`/
`OP_QUEUEFULL`/`OP_FILENOTFOUND` on both downloader and uploader sides with
exact stock framing and obfuscation, TCP reask as the bounded fallback, and LowID
buddy reask deferred to a later phase. Until built, record it as a wire omission
and reconcile the advertised `udp_version`.
