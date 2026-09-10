# A case contract

- `id`: SQLite events primary key, generated only by A.
- `source_event_id`: original log identifier. Legacy `event_id` is accepted only
  when canonical `source_event_id` is absent (explicit null also takes precedence).
- `case_id`: optional attack-case string, independent of import batch.
- `evidence_event_ids`: references to SQLite events.id, unchanged by case grouping.

## Migration

Application initialization uses an additive, transactional and idempotent migration:
inspect events columns, add nullable case_id TEXT if absent, create idx_events_case_id.
Existing IDs, data and source IDs are preserved; old case_id remains NULL.
No production database is reset by this integration.

## Import and query

POST /api/events/import?case_id=case01 accepts existing B/C event arrays and applies
case01 at A's import boundary. Conflicting explicit event case IDs return 422 before
any inserts. Without the parameter, per-event case IDs are preserved.
GET /api/events?case_id=case01 and GET /api/attack-chain?case_id=case01 filter before
correlation. Without a filter all cases are returned, with case_id on each link.
Nodes retain existing host/IP identity; use the filter for a single-case view.
Legacy NULL cases can still resolve through detail.case_id then detail.batch_id,
matching D; this does not backfill old database rows or assign new case IDs.

Existing export orchestration can import both host and network parser JSON:

```text
python scripts/export_for_d.py <parser-events.json> --out <eventout.json> --case-id case01 --batch-id <upload-name>
```

Different uploads in the same attack use the same case ID, but can have different
batch IDs. Do not run concurrent imports of identical events with identical batch
labels during export: the current API provides no import transaction receipt.
The exporter normalizes legacy fields via A's schema, excludes pre-existing IDs,
and exports canonical backend records. Parsers need not generate case IDs or DB IDs.
Strict guards allow optional case_id while continuing to accept old parser fields
sets; canonical schema normalization handles legacy event_id before export.
