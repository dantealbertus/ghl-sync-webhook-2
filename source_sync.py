"""
Source sync — standalone, independent of the contact↔company sync.

Keeps the native `source` field equal between a contact and all its opportunities:
  - Contact source changed/filled      → all linked opportunities get that source
  - Opportunity source changed/filled  → the linked contact and all its other
                                         opportunities get that source

GHL sends no webhook for field-level changes, so we poll and keep an in-memory
snapshot per record. The first poll after a (re)start only builds the baseline;
records first seen later (= newly created) are baselined without syncing.
Clearing a source is never propagated.

Loop/staleness guard: GHL's list endpoints lag behind writes. Every value we write
is remembered as "pending" together with the record's updated-timestamp from the
PUT response. A read with an older timestamp is stale and ignored, so we never
revert our own write; a read with a newer timestamp is a real user change.
"""

import os, time, logging, threading
from collections import defaultdict
import requests

log = logging.getLogger(__name__)

BASE_URL      = "https://services.leadconnectorhq.com"
LOCATION_ID   = os.environ["GHL_LOCATION_ID"]
PIT_TOKEN     = os.environ["GHL_PIT_TOKEN"]
POLL_INTERVAL = int(os.environ.get("SOURCE_POLL_INTERVAL_SECONDS", "60"))
PAGE_SIZE     = 100
PENDING_TTL   = 300

CONTACT     = "contact"
OPPORTUNITY = "opportunity"
UPDATED_KEY = {CONTACT: "dateUpdated", OPPORTUNITY: "updatedAt"}


# ── GHL API ───────────────────────────────────────────────────────────────────
def _headers() -> dict:
    return {"Authorization": f"Bearer {PIT_TOKEN}", "Version": "2021-07-28",
            "Accept": "application/json", "Content-Type": "application/json"}


def _request(method: str, url: str, **kwargs) -> requests.Response:
    for attempt in range(3):
        r = requests.request(method, url, headers=_headers(), timeout=20, **kwargs)
        if r.status_code == 429 or r.status_code >= 500:
            time.sleep(2 ** attempt)
            continue
        break
    r.raise_for_status()
    return r


def _paginate(url: str, base_params: dict, key: str) -> list:
    """Cursor-paginate a GHL list endpoint. Raises on failure so a partial
    result never gets compared against the snapshot."""
    items, params = [], dict(base_params)
    while True:
        data  = _request("GET", url, params=params).json()
        batch = data.get(key, [])
        items.extend(batch)
        meta = data.get("meta", {})
        if len(batch) < PAGE_SIZE or not meta.get("startAfter"):
            return items
        params["startAfter"]   = meta["startAfter"]
        params["startAfterId"] = meta.get("startAfterId")


def fetch_contacts() -> list:
    return _paginate(f"{BASE_URL}/contacts/",
                     {"locationId": LOCATION_ID, "limit": PAGE_SIZE}, "contacts")


def fetch_opportunities() -> list:
    return _paginate(f"{BASE_URL}/opportunities/search",
                     {"location_id": LOCATION_ID, "limit": PAGE_SIZE}, "opportunities")


# ── State ─────────────────────────────────────────────────────────────────────
_snapshots   = {CONTACT: {}, OPPORTUNITY: {}}   # kind → {id: source}
_pending     = {}                               # (kind, id) → (written_at, expires_at)
_initialized = False


def _s(value) -> str:
    return "" if value is None else str(value).strip()


def set_source(kind: str, record_id: str, value: str):
    path = "contacts" if kind == CONTACT else "opportunities"
    data = _request("PUT", f"{BASE_URL}/{path}/{record_id}", json={"source": value}).json()
    written_at = _s((data.get(kind) or data).get(UPDATED_KEY[kind]))
    _snapshots[kind][record_id] = value
    _pending[(kind, record_id)] = (written_at, time.time() + PENDING_TTL)


def _detect(kind: str, records: list, baseline: bool) -> list:
    """Update the snapshot; return (record, old, new) for existing records whose
    source changed to a non-empty value."""
    snapshot, changes = _snapshots[kind], []
    for rec in records:
        rid = rec.get("id")
        if not rid:
            continue
        new = _s(rec.get("source"))
        pending = _pending.get((kind, rid))
        if pending:
            written_at, expires_at = pending
            if _s(rec.get(UPDATED_KEY[kind])) < written_at and time.time() < expires_at:
                continue   # stale read from before our own write
            del _pending[(kind, rid)]
        old = snapshot.get(rid)
        snapshot[rid] = new
        if baseline or old is None or not new or new == old:
            continue
        changes.append((rec, old, new))
    return changes


# ── Sync ──────────────────────────────────────────────────────────────────────
def _propagate(contact_id: str, origin_kind: str, origin_id: str, value: str,
               contact: dict | None, opportunities: list):
    targets = []
    if contact and origin_kind != CONTACT and _s(contact.get("source")) != value:
        targets.append((CONTACT, contact_id))
    for o in opportunities:
        is_origin = origin_kind == OPPORTUNITY and o["id"] == origin_id
        if not is_origin and _s(o.get("source")) != value:
            targets.append((OPPORTUNITY, o["id"]))

    done = []
    for kind, rid in targets:
        try:
            set_source(kind, rid, value)
            done.append(f"{kind}:{rid}")
        except Exception as e:
            log.error(f"[source-sync] failed to set {kind} {rid} source={value!r}: {e}")
    log.info(f"[source-sync] {origin_kind} {origin_id} source → {value!r}; "
             f"updated {len(done)}/{len(targets)}: {', '.join(done) or '-'}")


def poll():
    global _initialized
    contacts      = fetch_contacts()
    opportunities = fetch_opportunities()
    baseline      = not _initialized

    contacts_by_id  = {c["id"]: c for c in contacts if c.get("id")}
    opps_by_contact = defaultdict(list)
    for o in opportunities:
        if o.get("contactId"):
            opps_by_contact[o["contactId"]].append(o)

    # Per contact the most recent change wins, in case the contact and an
    # opportunity were both edited within one poll interval.
    winners = {}   # contact_id → (timestamp, kind, record_id, new)
    for c, old, new in _detect(CONTACT, contacts, baseline):
        candidate = (_s(c.get(UPDATED_KEY[CONTACT])), CONTACT, c["id"], new)
        winners[c["id"]] = max(winners.get(c["id"], candidate), candidate)
    for o, old, new in _detect(OPPORTUNITY, opportunities, baseline):
        cid = o.get("contactId")
        if not cid:
            continue
        candidate = (_s(o.get(UPDATED_KEY[OPPORTUNITY])), OPPORTUNITY, o["id"], new)
        winners[cid] = max(winners.get(cid, candidate), candidate)

    for cid, (_, kind, rid, value) in winners.items():
        _propagate(cid, kind, rid, value, contacts_by_id.get(cid), opps_by_contact.get(cid, []))

    if baseline:
        log.info(f"[source-sync] baseline built — {len(contacts)} contacts, {len(opportunities)} opportunities")
    _initialized = True


def _loop():
    while True:
        try:
            poll()
        except Exception as e:
            log.error(f"[source-sync] poll failed: {e}")
        time.sleep(POLL_INTERVAL)


def start():
    threading.Thread(target=_loop, daemon=True, name="source-sync").start()
    log.info(f"[source-sync] started — interval={POLL_INTERVAL}s")
