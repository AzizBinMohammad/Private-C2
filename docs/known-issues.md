# Known Issues

Issues discovered while writing tests against the test plan. No application
code was changed.

---

## 1. HTTP API scope-check uses `strings.Contains` instead of `Scope.Contains`

**File:** `server/api/httpapi/handler.go:455`

**Symptom:** The `POST /api/engagements/{id}/scope-check` endpoint checks whether a
target is in scope by doing `strings.Contains(eng.ScopeConfig, body.Target)`. This
is a simple substring match on the raw JSON string, not a proper CIDR/hostname/domain
check. A target like `"10.0"` would match a scope config containing `"10.0.0.0/24"`
even though `10.0` is not a valid IP in that range.

**How to reproduce:**
1. Create an engagement with `scope_config: '{"cidrs":["10.0.0.0/24"]}'`
2. POST to `/api/engagements/{id}/scope-check` with `{"target":"10.0"}`
3. Response is `in_scope: true` — incorrect.

The `pkg/engagement.Scope.Contains` function does proper CIDR parsing, hostname
matching, domain suffix matching, and exclusion checks. The HTTP endpoint does not
use it.

---

## 2. Two incompatible audit hash algorithms

**File (library):** `pkg/audit/logger.go:96-114`
**File (API):** `server/api/httpapi/handler.go:851-857`

**Symptom:** The `pkg/audit` library computes hashes by JSON-serializing a struct
containing `{id, timestamp, operator_id, event_type, action, previous_hash}` and
then SHA-256 hashing the JSON. The API verification endpoint (`/api/audit/verify`)
computes hashes by concatenating raw bytes: `id + created_at_RFC3339Nano + action +
previous_hash`.

These produce different hashes for the same entry. Entries written by the library
will fail verification by the API endpoint, and vice versa.

**How to reproduce:**
1. Use `pkg/audit.Logger.Log()` to write entries with hash chaining
2. Store them in the database as `AuditEntry` records
3. Call `GET /api/audit/verify`
4. Verification fails because the hashes don't match

Currently no code writes `pkg/audit` entries to the database, so this has not caused
a runtime failure yet, but it will as soon as the two systems are connected.

---

## 3. `AuditEntry` GORM model and `audit.Entry` struct are separate types

**File:** `server/store/models/models.go:121-136`
**File:** `pkg/audit/logger.go:33-48`

**Symptom:** The `models.AuditEntry` (GORM model for database persistence) and
`audit.Entry` (library struct for hash computation) have similar but not identical
fields. There is no mapping function between them. The library struct uses
`Timestamp time.Time` while the model uses `CreatedAt time.Time`; the library has
`Metadata map[string]any` while the model has `Metadata string`. Any integration
between the two will require a manual mapping layer.

---

## 4. GORM SQLite in-memory migration fails with `PrepareStmt: true`

**File:** `server/store/db.go:36`

**Symptom:** When using `store.Open` with DSN `:memory:` and the default config
(which sets `PrepareStmt: true`), GORM's `AutoMigrate` fails with
`no such table: main.operators` after successfully executing the `CREATE TABLE`
statement. The `CREATE UNIQUE INDEX` that follows cannot find the table.

**How to reproduce:**
```go
db, _ := store.Open(store.Config{Dialect: "sqlite", DSN: ":memory:"})
store.Migrate(db) // fails
```

**Workaround:** Use a temp file path instead of `:memory:` for test databases.
- go vet warnings: several files use fmt.Sprintf("%s:%d", ...) for addresses, which breaks with IPv6 (net.Dial). Files: modules/ot/protocols/coap.go, modules/ot/protocols/common.go, modules/network/network.go, modules/ot/discovery.go, modules/ot/fingerprint.go, modules/ot/historian.go, modules/ot/hmi.go, modules/ot/segmentation.go, modules/ot/serial.go, modules/ot/wireless.go. Pre-existing, unrelated to refactor. Fix with net.JoinHostPort.

- go vet warnings: several files build addresses with fmt.Sprintf("%s:%d", ...)
  before net.Dial, which breaks with IPv6. Files: modules/ot/protocols/coap.go,
  modules/ot/protocols/common.go, modules/network/network.go,
  modules/ot/discovery.go, modules/ot/fingerprint.go, modules/ot/historian.go,
  modules/ot/hmi.go, modules/ot/segmentation.go, modules/ot/serial.go,
  modules/ot/wireless.go. Pre-existing, unrelated to the protocol refactor.
  Fix with net.JoinHostPort(host, port).
