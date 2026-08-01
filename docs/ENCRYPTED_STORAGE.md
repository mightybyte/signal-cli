# Encrypted Secret Storage (Master-Key Provider Seam)

**Status:** Draft — awaiting design review
**Upstream context:** [AsamK/signal-cli#1707](https://github.com/AsamK/signal-cli/issues/1707)
**Maintainer guidance (AsamK, 2025-02-27):**
> "If this gets implemented, I'd probably go the same route as Signal-Desktop.
> I.e. store one master key in the keyring and use that to encrypt all other
> sensitive data in signal-cli."

This document follows that route with one deviation: the master key is supplied
**through a generic in-RAM channel** (file descriptor 3) rather than read from
the OS keyring directly. The OS-keyring path is left as a trivial later
addition behind the same seam.

---

## 1. Goals

- **Secrets never written to disk in cleartext.** Today the account JSON file
  (`<number>`) and the SQLite database (`<number>.d/account.db`) hold private
  keys, server password, prekeys, and session ratchet state — all in cleartext.
  After this change, both files are ciphertext at rest.
- **Generic, transport-agnostic seam.** The storage layer asks an interface for
  the 32-byte master key and encrypts/decrypts with it. How the key arrives is
  an implementation detail of the provider. A future contributor adding OS-
  keyring support implements one method and touches nothing else.
- **Zero behavior change for existing users.** When no provider is configured,
  signal-cli runs exactly as today (cleartext files, same formats, same
  performance). Encryption is opt-in.

## 2. Non-goals

- **No OS-keyring integration in this work.** A `KeyringMasterKeyProvider`
  stub with a TODO referencing #1707 is left as the documented extension point.
- **No in-memory-only storage.** Files remain on disk; only their content is
  encrypted. This preserves the existing `FileLock`-based single-writer
  semantics and crash-recovery properties.
- **No changes to the JSON-RPC protocol, daemon mode, dbus, or any command
  surface beyond the one new CLI flag.**

## 3. Background: what is secret today

Two on-disk artifacts hold all of signal-cli's cryptographic material:

### 3.1 The account JSON file (`<number>`)

Written by `SignalAccount.save()` as a single JSON blob. Confirmed live
contents (storage version 10):

| Field | Secret? |
|---|---|
| `password` | Yes — Signal server auth credential |
| `aciAccountData.identityPrivateKey` | Yes — long-term Curve25519 identity private key |
| `pniAccountData.identityPrivateKey` | Yes — PNI identity private key |
| `profileKey` | Yes — 32-byte profile decryption key |
| `pinMasterKey` / `storageKey` / `accountEntropyPool` | Yes (when present) |
| `mediaRootBackupKey` | Yes (when present) |
| `usernameLinkEntropy` | Sensitive (when present) |
| prekey id metadata, registration id, number, uuid, deviceId | Not secret |

Read/written via `SignalAccount.openFileChannel` (`RandomAccessFile` +
`FileChannel` + `FileLock`) — **file:** `lib/src/main/java/org/asamk/signal/manager/storage/SignalAccount.java`.

### 3.2 The SQLite database (`<number>.d/account.db`)

Opened by `AccountDatabase.init(File)` → `Database.getHikariDataSource`. Schema
confirmed by inspection of a live install:

| Table | Rows (sample) | Secret? |
|---|---:|---|
| `pre_key` | 199 | **Yes — one-time Curve25519 private keys** |
| `signed_pre_key` | 2 | **Yes — signed Curve25519 private keys + signatures** |
| `kyber_pre_key` | 201 | **Yes — post-quantum Kyber secret keys (4824-byte blobs)** |
| `session` | 2 | **Yes — symmetric ratchet state; decrypts future messages** |
| `sender_key` / `sender_key_shared` | 0+ | **Yes (group ratchet keys, when present)** |
| `identity` | 3 | Public peer identity keys + trust (not secret, but trust-level tampering → MITM) |
| `recipient` / `group_v1` / `group_v2` / `cdsi` / `key_value` / `sticker` | — | PII / metadata, not crypto secrets |

The DB is mutated constantly (prekeys rotate, sessions advance per message),
whereas the JSON blob changes only on a handful of lifecycle events. Both
must be encrypted to satisfy the "no cleartext secrets at rest" goal —
protecting only the JSON file leaves ~400 private keys + session ratchets
exposed.

**File:** `lib/src/main/java/org/asamk/signal/manager/storage/AccountDatabase.java`,
`lib/src/main/java/org/asamk/signal/manager/storage/Database.java` (JDBC URL at
`Database.java:98`: `jdbc:sqlite:<file>?foreign_keys=ON&journal_mode=wal`,
driver `org.xerial:sqlite-jdbc:3.53.2.1`).

---

## 4. Design

### 4.1 The seam: `MasterKeyProvider`

New file: `lib/src/main/java/org/asamk/signal/manager/storage/MasterKeyProvider.java`

```java
package org.asamk.signal.manager.storage;

import java.io.IOException;

/**
 * Source of the 32-byte AES-GCM master key used to encrypt the on-disk account
 * data. Implementations decide how the key is delivered (RAM channel, OS
 * keyring, HSM, ...); the storage layer is agnostic to the transport.
 *
 * Returning {@code null} selects cleartext storage (the historical behavior).
 */
public interface MasterKeyProvider {
    int KEY_LEN = 32;

    /**
     * @return the 32-byte master key, or {@code null} to disable encryption.
     * @throws IOException if the key could not be obtained (caller should abort).
     */
    byte[] getMasterKey() throws IOException;
}
```

The storage layer calls this **once at startup** (the key is not re-read per
access), caches the result, and uses it to wrap every file I/O site. The
interface is deliberately minimal so that adding the OS-keyring path later is
a one-method implementation, not a redesign.

### 4.2 Stock implementations

#### `NullMasterKeyProvider` (default)
Returns `null`. Today's cleartext behavior, bit-for-bit. Selected when no
`--master-key-fd` flag is passed. This is what every existing user gets, so
there is zero migration burden and no risk to the installed base.

#### `MemoryChannelMasterKeyProvider` (the one Seal uses)
New file: `lib/src/main/java/org/asamk/signal/manager/storage/MemoryChannelMasterKeyProvider.java`

```java
package org.asamk.signal.manager.manager.storage;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

public final class MemoryChannelMasterKeyProvider implements MasterKeyProvider {
    private final int fd;

    public MemoryChannelMasterKeyProvider(int fd) { this.fd = fd; }

    @Override
    public byte[] getMasterKey() throws IOException {
        // FileDescriptor.in is fd 0; construct an InputStream over fd `fd`.
        var fdObj = sun.misc.SharedSecrets.getJavaIOFileDescriptorAccess()
                       .newFileDescriptor(fd);
        try (InputStream in = new FileInputStream(fdObj)) {
            byte[] key = in.readNBytes(KEY_LEN);
            if (key.length != KEY_LEN)
                throw new IOException("master-key fd " + fd + " short read: "
                                      + key.length + " bytes");
            return key;
        }
    }
}
```

Reads exactly 32 bytes from the supplied file descriptor at startup, then
closes it. The key exists transiently in the kernel pipe buffer (RAM) and
then in signal-cli's heap. It is never read from disk, never placed in
`ps`/`environ`, never serialized.

Selected by the new CLI flag `--master-key-fd <N>` (see §4.5).

#### `KeyringMasterKeyProvider` (stub — explicitly out of scope here)
New file: `lib/src/main/java/org/asamk/signal/manager/storage/KeyringMasterKeyProvider.java`

```java
// TODO(#1707): implement by calling the platform keyring
// (macOS Security.framework / libsecret on Linux / Windows Credential Manager).
// Return the 32 bytes from that source. The storage layer requires no other
// change. Selected by --master-key-provider=keyring.
public final class KeyringMasterKeyProvider implements MasterKeyProvider {
    @Override
    public byte[] getMasterKey() throws IOException {
        throw new UnsupportedOperationException("keyring provider not yet implemented (see #1707)");
    }
}
```

This stub exists to document the extension point and keep the CLI flag
namespace coherent. It is not wired in this phase.

### 4.3 Encrypting the JSON blob

`SignalAccount` is the sole reader/writer of the `<number>` account file. The
change is localized to its file I/O:

- Replace `openFileChannel(File, boolean)` with a method that, after opening
  the channel, checks whether the file begins with the encryption magic
  header (see §6). If it does, the provider's key is required; the entire
  file content is the AES-GCM ciphertext + nonce + tag. Decrypt into the
  in-memory `ByteArrayInputStream` that `load(...)` already consumes today
  (`jsonProcessor.readTree(Channels.newInputStream(fileChannel))` becomes
  `jsonProcessor.readTree(decryptedInputStream)`).
- `save()` already serializes to a `ByteArrayOutputStream` before writing
  (existing code: *"Write to memory first to prevent corrupting the file in
  case of serialization errors"*). Add an AES-GCM encrypt step on that byte
  array before `input.transferTo(Channels.newOutputStream(fileChannel))`.
- The `FileLock` semantics are unchanged — the lock is on the ciphertext
  file, same as today; encryption is transparent to the locking logic.

The cipher layer is a small helper, not a per-call abstraction:

New file: `lib/src/main/java/org/asamk/signal/manager/storage/AesGcm.java`

```java
// AES-GCM (12-byte nonce, 16-byte tag).
// encrypt(plaintext, key) -> magic || nonce || ciphertext || tag
// decrypt(magic||nonce||ciphertext||tag, key) -> plaintext
// Both throw on tampering (GCM integrity check fails).
static byte[] encrypt(byte[] plaintext, byte[] key);
static byte[] decrypt(byte[] blob, byte[] key) throws IntegrityException;
static boolean isEncrypted(byte[] blob); // magic-header check
```

BouncyCastle is already a dependency (`libs.bouncycastle`); use its `GCMBlockCipher`.

### 4.4 Encrypting the SQLite database (SQLCipher)

The DB is the larger surface because it is mutated on every message. SQLCipher
is the drop-in encrypted-SQLite solution: same C API, transparent page-level
encryption, automatic encryption of `-wal`/`-shm` sidecar files. Hikari and
the `org.xerial:sqlite-jdbc` connection plumbing remain — only the JDBC URL
and the driver artifact change.

Changes to `Database.getHikariDataSource` (`Database.java:92`):

```java
private static HikariDataSource getHikariDataSource(
    String databaseFile, MasterKeyProvider provider
) throws SQLException, IOException {
    byte[] key = provider.getMasterKey();

    var sqliteConfig = new SQLiteConfig();
    sqliteConfig.setBusyTimeout(60_000);
    sqliteConfig.setTransactionMode(SQLiteConfig.TransactionMode.IMMEDIATE);

    HikariConfig config = new HikariConfig();
    if (key != null) {
        // SQLCipher: key supplied via PRAGMA on first connection.
        config.setJdbcUrl("jdbc:sqlite:" + databaseFile
                           + "?foreign_keys=ON&journal_mode=wal");
        // hex key avoids quoting issues; SQLCipher accepts PRAGMA key = "x'..'"
        var hexKey = toHex(key);
        sqliteConfig.setProperty("key", "x'" + hexKey + "'");
    } else {
        config.setJdbcUrl("jdbc:sqlite:" + databaseFile
                           + "?foreign_keys=ON&journal_mode=wal");
    }
    config.setDataSourceProperties(sqliteConfig.toProperties());
    // ... (pool sizing unchanged)
    return new HikariDataSource(config);
}
```

**Build dependency (spike required):** `org.xerial:sqlite-jdbc` is **not**
built with SQLCipher; a SQLCipher-compatible JDBC driver must replace it.
Candidate artifacts to evaluate in implementation (list, not endorsement):
- `net.zetetic:sqlcipher-android` — Android only, **not** usable here.
- A SQLCipher-native build of `sqlite-jdbc` (community forks exist; verify
  active maintenance and JVM-native artifact availability).
- The Xerial driver's documented SQLCipher compatibility via a swapped native
  library.

Resolving this dependency is the first implementation task; the design's
storage-layer surface is identical regardless of which artifact is chosen.
The constraint is: the driver must accept `PRAGMA key = "x'...'";` and
encrypt the file, `-wal`, and `-shm`. If no maintained JVM SQLCipher driver is
found, the fallback is to encrypt the whole `account.db` file with AES-GCM
on startup-to-tmpfile / shutdown-reencrypt (transient cleartext file in a
`0600` Seal-private dir during the run); this is strictly worse than SQLCipher
(cleartext window while running) and should only be taken if the driver spike
fails. Record the decision in the implementation PR.

### 4.5 CLI flag

In `src/main/java/org/asamk/signal/Main.java` (or the arg-parsing layer
above the command dispatch), add a top-level named argument:

```
--master-key-fd <N>    Read a 32-byte AES-GCM master key from file descriptor
                      <N> at startup and use it to encrypt the on-disk account
                      data. The fd is read once and closed immediately.
                      Mutually exclusive with --master-key-provider.
                      Absent => cleartext storage (default).
```

Plumbing: when set, `Main` constructs a `MemoryChannelMasterKeyProvider(N)`
and passes it down through `SignalAccountFiles` → `AccountsStore` /
`loadAccount` → `SignalAccount.load(...)` and `AccountDatabase.init(...)`.
The provider threads through as a single new constructor parameter at each
of those two call sites; nothing downstream (`ManagerImpl`,
`RegistrationManagerImpl`, `ProvisioningManagerImpl`, JSON-RPC) takes it or
needs to change.

### 4.6 File-level change map

| File | Change |
|---|---|
| `lib/.../storage/MasterKeyProvider.java` | **New** — the interface. |
| `lib/.../storage/NullMasterKeyProvider.java` | **New** — returns `null`. |
| `lib/.../storage/MemoryChannelMasterKeyProvider.java` | **New** — reads fd. |
| `lib/.../storage/KeyringMasterKeyProvider.java` | **New stub** — TODO #1707. |
| `lib/.../storage/AesGcm.java` | **New** — encrypt/decrypt helpers. |
| `lib/.../storage/SignalAccount.java` | `openFileChannel` / `load` / `save` gain AES-GCM wrap/unwrap; `load(...)` / `create(...)` / `createLinkedAccount(...)` take `MasterKeyProvider`. |
| `lib/.../storage/Database.java` | `getHikariDataSource` takes provider; SQLCipher URL+PRAGMA when key non-null. |
| `lib/.../storage/AccountDatabase.java` | `init(File)` → `init(File, MasterKeyProvider)`. |
| `lib/.../manager/SignalAccountFiles.java` | Constructor + `loadAccount` thread the provider through to `SignalAccount` / `AccountDatabase`. The `File`-based default builds a `NullMasterKeyProvider`. |
| `src/main/java/org/asamk/signal/Main.java` | Parse `--master-key-fd`; construct the provider; pass to `SignalAccountFiles`. |
| `gradle/libs.versions.toml` + `lib/build.gradle.kts` | Add the SQLCipher-compatible JDBC driver (TBD by spike). |
| `man/signal-cli.1.adoc` | Document `--master-key-fd`. |

No changes to: `ManagerImpl`, `RegistrationManagerImpl`,
`ProvisioningManagerImpl`, any `commands/*`, any `jsonrpc/*`, `dbus/*`.

---

## 5. Threat model

| Threat | Before | After |
|---|---|---|
| Disk read by attacker with file access (offline disk image, stolen laptop, backup tape) | All secrets cleartext | **Ciphertext only; key not on disk.** Attacker gets nothing. |
| `ps` / `/proc/<pid>/environ` snooping by same-user process | N/A (no secrets in process args/env today) | **No regression.** Key arrives via fd, not `environ`; not visible in `ps`. |
| Same-user process reading signal-cli's heap (e.g. `gdb attach`) | All secrets in heap | All secrets in heap. **No change** — in-memory protection is out of scope; use OS process isolation. |
| Process crash / SIGKILL during run | Files on disk are consistent (cleartext) | Files on disk are consistent (ciphertext). SQLCipher's WAL semantics are unchanged; no extra crash window. |
| Attacker compromises the key-delivery channel | N/A | **Key in transit over a pipe from the parent.** A same-user process that can read the parent's pipe can capture the key. Mitigation: the pipe is created by the parent (Seal) and inherited only by this child; same threat surface as any inherited fd. |
| Attacker tampers with ciphertext on disk | N/A | **AES-GCM integrity check fails → signal-cli refuses to load.** (JSON blob: explicit tag check. DB: SQLCipher's own per-page HMAC.) Tampering is detected, not silently corrupted. |

**What this design does NOT protect against:** a fully-compromised host where
the attacker runs code as the signal-cli user. No at-rest encryption helps
there; that requires process isolation / HSM, which is out of scope.

## 6. On-disk format & migration

### 6.1 JSON blob

Encrypted file layout (prefix + ciphertext):

```
[ 8 bytes magic: "SIGACCT1" ]   // "Signal Account v1, encrypted"
[ 12 bytes nonce ]
[ N bytes AES-GCM ciphertext ]
[ 16 bytes GCM tag ]            // GCM appends tag to ciphertext
```

`AesGcm.isEncrypted(blob)` checks the magic. A cleartext JSON file starts
with `{` (`0x7B`), so the magic is unambiguous.

### 6.2 SQLite DB

SQLCipher writes its own file format (with its own per-page HMAC). Cleartext
vs. encrypted is detectable by attempting `PRAGMA key` — a cleartext DB opened
with a key, or an encrypted DB opened without one, errors on first query. The
migration path (§6.3) handles this.

### 6.3 Migration: cleartext → encrypted on first encrypted launch

A user with an existing cleartext account who first runs with
`--master-key-fd` must not lose data. Procedure, run once at startup when a
provider key is present and the on-disk file is detected as cleartext:

1. **JSON blob:** read the cleartext file, re-`save()` under the new key. The
   existing `save()` already writes atomically (in-memory serialize →
   channel truncate). Add the encrypt step; one save migrates.
2. **SQLite DB:** attach a new SQLCipher database at a `.enc` path, `ATTACH`
   the old cleartext DB, `SELECT ... INTO` each table, then atomic-rename
   `.enc` over the original. This is a one-time migration; on success the
   cleartext file is overwritten (recoverable from backups only).
3. **Migration is one-way.** Going back to cleartext (removing
   `--master-key-fd`) requires the user to explicitly decrypt (a future
   `--decrypt-storage` command); absent that, signal-cli refuses to load an
   encrypted file without a key, with a clear diagnostic.

`SignalAccount.Storage` does **not** need a schema version bump for the JSON
blob — the `version: 10` field is unaffected (encryption is a file-layer
concern, not a JSON-schema concern). The magic header distinguishes the two
formats. The SQLite `DATABASE_VERSION` is unaffected (SQLCipher is
page-encryption, schema is unchanged).

---

## 7. Failure modes & diagnostics

| Case | Behavior |
|---|---|
| `--master-key-fd` set, fd not readable / short read | Abort at startup with: `master-key fd <N>: expected 32 bytes, got <k>`. |
| Encrypted file on disk, no provider key (user dropped the flag) | Abort with: `account file is encrypted; supply --master-key-fd (or decrypt with --decrypt-storage)`. Never silently fall back to cleartext. |
| Cleartext file on disk, provider key supplied | Run §6.3 migration, then proceed. Log: `migrated account file to encrypted storage`. |
| AES-GCM tag mismatch on JSON blob | Abort with: `account file integrity check failed (tampered or wrong key)`. |
| SQLCipher wrong-key error on first query | Same diagnostic as above. |

The cardinal rule: **never silently fall back to cleartext** when the user has
asked for encryption, and **never silently overwrite** an encrypted file with
cleartext.

## 8. Testing strategy

Unit tests (`lib/src/test/...`), no signal-cli binary or network needed:

- `AesGcmSpec`: round-trip; tamper-detection (flip a ciphertext byte →
  `decrypt` throws); magic-header detection; empty input.
- `MasterKeyProviderSpec`: `NullMasterKeyProvider` returns `null`;
  `MemoryChannelMasterKeyProvider` reads exactly 32 bytes from a pipe and
  closes it; short read throws.
- `SignalAccountEncryptionSpec`: create account with a provider → file on
  disk has magic header and is not valid JSON; reload with same key →
  fields equal; reload with wrong key → integrity error; reload with no key
  → clear diagnostic.
- `AccountDatabaseEncryptionSpec`: open DB with key, write rows, reopen with
  same key → rows present; reopen with wrong key → SQLCipher error; reopen
  with no key → error (do not silently open as cleartext).
- `MigrationSpec`: cleartext JSON + cleartext DB → run with key → both
  files encrypted → data round-trips.
- CLI: `--master-key-fd` end-to-end via a test harness that opens a pipe,
  writes a test key, and passes the fd (a small `MainTest` driver).

Existing tests run unmodified (no `--master-key-fd` ⇒
`NullMasterKeyProvider` ⇒ today's behavior).

## 9. Open questions for review

1. **SQLCipher JDBC driver artifact.** The storage-layer design is driver-
   agnostic, but the build must pin a maintained JVM SQLCipher driver. The
   implementing agent should spike this first and record the chosen artifact
   (and license — SQLCipher is GPLv3 with a commercial license option; the
   fork is already GPLv3 per signal-cli's `LICENSE`, so GPLv3 is compatible).
   Confirm license compatibility before adding the dependency.
2. **fd inheritance on Windows.** `--master-key-fd` is well-defined on POSIX.
   Windows has a different fd model. If Windows support is required, the
   stdin-prefix-framing variant (key as a length-prefixed first line of stdin,
   then JSON-RPC begins) is the portable fallback. Out of scope here unless
   the reviewer flags it; Seal runs on macOS/Linux.
3. **Key zeroization.** After `getMasterKey()` returns, the `byte[] lives in
   the provider's caller. Should signal-cli explicitly zero the array on
   shutdown? Java doesn't guarantee zeroing works (GC may have copied), but a
   best-effort `Arrays.fill(key, (byte)0)` on `SignalAccount.close()` is cheap
   defense-in-depth. Recommend yes.
4. **`--decrypt-storage` command.** Mentioned in §6.3 as a future command to
   revert to cleartext. Should it be in scope for this phase, or deferred?
   Recommend defer (encryption is the goal; decryption is a recovery escape
   hatch that can be added on request).

## 10. Relationship to upstream

This design implements the maintainer-endorsed route from
[#1707](https://github.com/AsamK/signal-cli/issues/1707) (one master key,
encrypt everything else) with a transport-agnostic seam. A PR upstreaming
the `MasterKeyProvider` interface + the two stock implementations + the stub
would be a natural contribution to #1707; the `MemoryChannelMasterKeyProvider`
is independently useful to any integrator that wants to supply a key from RAM
(a container orchestrator, a secrets-injection sidecar, etc.), and the
`KeyringMasterKeyProvider` stub is the explicit invitation for someone to add
the OS-keyring path.