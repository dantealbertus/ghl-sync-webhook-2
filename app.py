#!/usr/bin/env python3
"""
GHL bidirectional sync: Contact ↔ Company
Webhook server deployed on Railway.

Syncs:
  - Contact tag added/removed        → company_tags on linked company  (via GHL webhook)
  - Contact type changed             → contact_type on linked company  (via GHL webhook)
  - Contact linked to company        → full sync to company            (via GHL webhook)
  - Company contact_type changed     → all linked contacts             (via background poll)
  - Company company_tags changed     → all linked contacts             (via background poll)

No GHL Workflows needed — company changes are detected via a background poller
that runs every POLL_INTERVAL_SECONDS seconds.
"""

from flask import Flask, request, jsonify
import requests, json, re, os, time, logging, threading
from rapidfuzz import fuzz, process

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── Config from environment variables ────────────────────────────────────────
BASE_URL      = "https://services.leadconnectorhq.com"
LOCATION_ID   = os.environ["GHL_LOCATION_ID"]
PIT_TOKEN     = os.environ["GHL_PIT_TOKEN"]
CLIENT_ID     = os.environ["GHL_CLIENT_ID"]
CLIENT_SECRET = os.environ["GHL_CLIENT_SECRET"]
COMPANY_ID    = os.environ["GHL_COMPANY_ID"]   # agency companyId

NUM_TAG_RE         = re.compile(r'^(\d{2})-(\d{2})\s+')
FUZZY_THRESHOLD    = 75
POLL_INTERVAL_SECS = int(os.environ.get("POLL_INTERVAL_SECONDS", "300"))
WEBHOOK_BASE_URL   = os.environ.get("WEBHOOK_BASE_URL", "").rstrip("/")
REDIRECT_URI       = os.environ.get("GHL_REDIRECT_URI",
                        f"{WEBHOOK_BASE_URL}/oauth/callback" if WEBHOOK_BASE_URL else "https://unbreakablesystems.nl/")
GHL_SCOPES         = "objects/schema.readonly objects/schema.write objects/record.readonly objects/record.write"
GHL_APP_VERSION_ID = CLIENT_ID.split("-")[0]   # base ID without the key suffix
WEBHOOK_NAME       = "GHL Contact Sync"
WEBHOOK_EVENTS     = ["ContactCreate", "ContactUpdate", "ContactTagUpdate"]

CONTACT_TYPE_MAP = {
    "kanaalpartner":          "kanaalpartner",
    "netwerkpartij":          "netwerkpartij",
    "media":                  "media",
    "medewerkersconcullegas": "medewerkersconcullegas",
    "leverancier":            "leverancier",
    "inkopers":               "inkoper",
    "inkoper":                "inkoper",
    "s":                      "kanaalpartner",
}

# ── Thread safety locks ───────────────────────────────────────────────────────
_token_lock    = threading.RLock()   # reentrant: get_oauth_token calls _refresh
_syncing_lock  = threading.Lock()
_snapshot_lock = threading.Lock()

# ── OAuth token cache ─────────────────────────────────────────────────────────
def _jwt_exp(token: str) -> float:
    """Read exp claim from JWT payload without verifying signature."""
    try:
        import base64
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.b64decode(payload)).get("exp", 0))
    except Exception:
        return 0.0

_initial_token = os.environ.get("GHL_LOCATION_TOKEN", "")
_token_cache = {
    "access_token":         _initial_token,
    "refresh_token":        os.environ.get("GHL_REFRESH_TOKEN", ""),       # location refresh (fallback)
    "agency_refresh_token": os.environ.get("GHL_AGENCY_REFRESH_TOKEN", ""), # agency refresh (preferred)
    "expires_at":           _jwt_exp(_initial_token) if _initial_token else 0,
}

def get_oauth_token() -> str:
    with _token_lock:
        if time.time() < _token_cache["expires_at"] - 300:
            return _token_cache["access_token"]
        return _refresh_oauth_token()

def _refresh_oauth_token() -> str:
    """Must be called with _token_lock held.
    Uses agency_refresh_token if available (preferred), falls back to location refresh token.
    """
    # Prefer agency refresh token — it reliably works with /oauth/token
    refresh_tok = (
        _token_cache.get("agency_refresh_token")
        or _token_cache.get("refresh_token")
        or os.environ.get("GHL_AGENCY_REFRESH_TOKEN", "")
        or os.environ.get("GHL_REFRESH_TOKEN", "")
    )
    if not refresh_tok:
        log.error("No refresh token — visit GET /oauth/url to re-authorize")
        return _token_cache["access_token"]

    resp = requests.post(
        f"{BASE_URL}/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type":    "refresh_token",
            "refresh_token": refresh_tok,
        },
        timeout=15
    )
    if resp.status_code not in (200, 201):
        log.error(f"Token refresh failed: {resp.status_code} {resp.text[:200]} — visit GET /oauth/url to re-authorize")
        return _token_cache["access_token"]

    agency_data = resp.json()
    # Save new agency refresh token if returned
    if agency_data.get("refresh_token"):
        _token_cache["agency_refresh_token"] = agency_data["refresh_token"]

    loc_resp = requests.post(
        f"{BASE_URL}/oauth/locationToken",
        headers={"Authorization": f"Bearer {agency_data['access_token']}",
                 "Version": "2021-07-28", "Content-Type": "application/json"},
        json={"companyId": COMPANY_ID, "locationId": LOCATION_ID},
        timeout=15
    )
    if loc_resp.status_code not in (200, 201):
        log.error(f"Location token failed: {loc_resp.status_code}")
        return _token_cache["access_token"]

    loc_data = loc_resp.json()
    _token_cache["access_token"]  = loc_data["access_token"]
    _token_cache["refresh_token"] = loc_data.get("refresh_token", _token_cache["refresh_token"])
    _token_cache["expires_at"]    = time.time() + loc_data.get("expires_in", 86400)
    log.info("OAuth token refreshed successfully")
    return _token_cache["access_token"]


def _exchange_code(code: str) -> dict:
    """Exchange an auth code for agency + location tokens. Saves agency_refresh_token."""
    resp = requests.post(
        f"{BASE_URL}/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  REDIRECT_URI,
        },
        timeout=15
    )
    if resp.status_code not in (200, 201):
        return {"error": f"Code exchange failed: {resp.status_code} {resp.text[:200]}"}

    agency_data = resp.json()

    loc_resp = requests.post(
        f"{BASE_URL}/oauth/locationToken",
        headers={"Authorization": f"Bearer {agency_data['access_token']}",
                 "Version": "2021-07-28", "Content-Type": "application/json"},
        json={"companyId": COMPANY_ID, "locationId": LOCATION_ID},
        timeout=15
    )
    if loc_resp.status_code not in (200, 201):
        return {"error": f"Location token failed: {loc_resp.status_code} {loc_resp.text[:200]}"}

    loc_data = loc_resp.json()
    with _token_lock:
        _token_cache["access_token"]         = loc_data["access_token"]
        _token_cache["refresh_token"]        = loc_data.get("refresh_token", "")
        _token_cache["agency_refresh_token"] = agency_data.get("refresh_token", "")
        _token_cache["expires_at"]           = time.time() + loc_data.get("expires_in", 86400)

    log.info("OAuth exchange complete — agency_refresh_token saved, auto-refresh enabled")
    return {"status": "ok", "expires_at": _token_cache["expires_at"]}

def pit_headers() -> dict:
    return {"Authorization": f"Bearer {PIT_TOKEN}", "Version": "2021-07-28", "Content-Type": "application/json"}

def oauth_headers() -> dict:
    return {"Authorization": f"Bearer {get_oauth_token()}", "Version": "2021-07-28", "Content-Type": "application/json"}

# ── Retry helper ──────────────────────────────────────────────────────────────
def _ghl_request(fn, retries: int = 2):
    """Call fn() which returns a requests.Response; retry on 429/5xx."""
    r = None
    for attempt in range(retries + 1):
        try:
            r = fn()
            if r.status_code in (429, 500, 502, 503, 504) and attempt < retries:
                wait = 2 ** attempt
                log.warning(f"GHL {r.status_code} on attempt {attempt+1}, retrying in {wait}s")
                time.sleep(wait)
                continue
            return r
        except requests.RequestException as e:
            if attempt < retries:
                time.sleep(2 ** attempt)
            else:
                log.error(f"GHL request failed after {retries+1} attempts: {e}")
                raise
    return r

# ── Debounce: prevent infinite sync loops ────────────────────────────────────
_syncing = {}
DEBOUNCE_S = 15

def is_syncing(key: str) -> bool:
    with _syncing_lock:
        return time.time() - _syncing.get(key, 0) < DEBOUNCE_S

def mark_syncing(key: str):
    with _syncing_lock:
        _syncing[key] = time.time()

# ── Field options cache ───────────────────────────────────────────────────────
_field_cache = {"tag_by_code": {}, "tag_by_label": {}, "loaded_at": 0}
CACHE_TTL = 3600

def get_field_options():
    if time.time() - _field_cache["loaded_at"] < CACHE_TTL:
        return _field_cache["tag_by_code"], _field_cache["tag_by_label"]
    try:
        fields = _ghl_request(lambda: requests.get(
            f"{BASE_URL}/objects/business",
            headers=oauth_headers(),
            params={"locationId": LOCATION_ID, "fetchProperties": True},
            timeout=15
        )).json().get("fields", [])

        tag_by_code, tag_by_label = {}, {}
        for f in fields:
            if "company_tags" in f.get("fieldKey", ""):
                for opt in f.get("options", []):
                    key   = opt.get("key") or opt.get("value", "")
                    label = opt.get("label", "")
                    m = NUM_TAG_RE.match(label)
                    if m:
                        tag_by_code[m.group(1) + m.group(2)] = key
                    tag_by_label[label.lower()] = key

        _field_cache.update({"tag_by_code": tag_by_code, "tag_by_label": tag_by_label, "loaded_at": time.time()})
        log.info(f"Field options cached: {len(tag_by_code)} codes, {len(tag_by_label)} labels")
    except Exception as e:
        log.error(f"Failed to load field options: {e}")
    return _field_cache["tag_by_code"], _field_cache["tag_by_label"]

def resolve_tag_key(tag_label: str):
    tag_by_code, tag_by_label = get_field_options()
    m = NUM_TAG_RE.match(tag_label.strip())
    if m:
        code = m.group(1) + m.group(2)
        if code in tag_by_code:
            return tag_by_code[code]
    if tag_label.lower() in tag_by_label:
        return tag_by_label[tag_label.lower()]
    match = process.extractOne(tag_label.lower(), list(tag_by_label.keys()), scorer=fuzz.token_sort_ratio)
    if match and match[1] >= FUZZY_THRESHOLD:
        return tag_by_label[match[0]]
    return None

def resolve_contact_type(raw_type: str):
    if not raw_type:
        return None
    val = raw_type.lower().strip()
    return CONTACT_TYPE_MAP.get(val)  # None for unknown types

# ── GHL API helpers ───────────────────────────────────────────────────────────
def get_contact(contact_id: str):
    try:
        r = _ghl_request(lambda: requests.get(
            f"{BASE_URL}/contacts/{contact_id}", headers=pit_headers(), timeout=15
        ))
        return r.json().get("contact") if r.status_code == 200 else None
    except Exception as e:
        log.error(f"get_contact {contact_id} failed: {e}")
        return None

def get_linked_contacts(company_id: str) -> list:
    """Fetch all contacts linked to a company using correct cursor pagination."""
    all_contacts = []
    params = {"locationId": LOCATION_ID, "limit": 100}
    while True:
        try:
            r = _ghl_request(lambda: requests.get(
                f"{BASE_URL}/contacts/", headers=pit_headers(), params=params, timeout=15
            ))
            if r.status_code != 200:
                log.error(f"get_linked_contacts failed: {r.status_code}")
                break
            data     = r.json()
            contacts = data.get("contacts", [])
            if not contacts:
                break
            all_contacts.extend([c for c in contacts if c.get("businessId") == company_id])
            if len(contacts) < 100:
                break
            # Cursor pagination from response meta (not from individual contact objects)
            meta           = data.get("meta", {})
            start_after    = meta.get("startAfter")
            start_after_id = meta.get("startAfterId") or meta.get("startAfterContact")
            if not start_after:
                break
            params["startAfter"] = start_after
            if start_after_id:
                params["startAfterId"] = start_after_id
        except Exception as e:
            log.error(f"get_linked_contacts error: {e}")
            break
    return all_contacts

def update_company(company_id: str, props: dict):
    if not props:
        return
    try:
        r = _ghl_request(lambda: requests.put(
            f"{BASE_URL}/objects/business/records/{company_id}",
            headers=oauth_headers(),
            params={"locationId": LOCATION_ID},
            json={"properties": props},
            timeout=15
        ))
        log.info(f"Update company {company_id}: {list(props.keys())} → {r.status_code}")
        return r
    except Exception as e:
        log.error(f"update_company {company_id} failed: {e}")

def update_contact(contact_id: str, payload: dict):
    try:
        r = _ghl_request(lambda: requests.put(
            f"{BASE_URL}/contacts/{contact_id}", headers=pit_headers(), json=payload, timeout=15
        ))
        log.info(f"Update contact {contact_id} → {r.status_code}")
        return r
    except Exception as e:
        log.error(f"update_contact {contact_id} failed: {e}")

# ── Sync logic ────────────────────────────────────────────────────────────────
def sync_contact_to_company(contact: dict):
    """Contact.type → company.contact_type, contact.tags → company.company_tags (add)."""
    company_id = contact.get("businessId")
    if not company_id:
        return

    if is_syncing(f"company_{company_id}"):
        log.info(f"Skipping company {company_id} (debounce)")
        return

    mark_syncing(f"contact_{contact['id']}")

    tags     = contact.get("tags", [])
    raw_type = (contact.get("type") or "").strip()
    ct_key   = resolve_contact_type(raw_type)

    tag_keys_to_add = [k for k in (resolve_tag_key(t) for t in tags) if k]
    unresolved = [t for t in tags if not resolve_tag_key(t)]
    if unresolved:
        log.warning(f"Unresolved tags (not in dropdown): {unresolved}")

    props = {}
    if ct_key:
        props["contact_type"] = ct_key
    if tag_keys_to_add:
        props["company_tags"] = {"add": tag_keys_to_add}

    if props:
        log.info(f"Contact {contact['id']} → company {company_id}: contact_type={ct_key}, company_tags add={tag_keys_to_add}")
        update_company(company_id, props)


def sync_company_to_contacts(company_id: str, contact_type=None, company_tags_added=None, company_tags_removed=None):
    """Company.contact_type → contact.type, company.company_tags → contact.tags (add/remove)."""
    if is_syncing(f"company_{company_id}"):
        return

    mark_syncing(f"company_{company_id}")
    linked = get_linked_contacts(company_id)
    log.info(f"Company {company_id} → {len(linked)} contacts: contact_type={contact_type}, tags_add={company_tags_added}, tags_remove={company_tags_removed}")

    _, tag_by_label = get_field_options()
    key_to_label    = {v: k for k, v in tag_by_label.items()}

    for contact in linked:
        if is_syncing(f"contact_{contact['id']}"):
            continue

        payload = {}

        if contact_type:
            reverse_map    = {v: k for k, v in CONTACT_TYPE_MAP.items()}
            payload["type"] = reverse_map.get(contact_type, contact_type)

        if company_tags_added or company_tags_removed:
            existing = set(contact.get("tags", []))
            for key in (company_tags_added or []):
                label = key_to_label.get(key)
                if label:
                    existing.add(label)
            for key in (company_tags_removed or []):
                label = key_to_label.get(key)
                if label:
                    existing.discard(label)
            payload["tags"] = list(existing)

        if payload:
            mark_syncing(f"contact_{contact['id']}")
            update_contact(contact["id"], payload)
            time.sleep(0.05)


# ── Webhook endpoints ─────────────────────────────────────────────────────────
@app.route("/webhook/contact", methods=["POST"])
def contact_webhook():
    data       = request.json or {}
    contact_id = data.get("id") or data.get("contactId") or data.get("contact", {}).get("id")
    log.info(f"Contact webhook: type={data.get('type')} id={contact_id}")

    if not contact_id:
        return jsonify({"status": "no contact_id"}), 200

    if is_syncing(f"contact_{contact_id}"):
        log.info(f"Contact {contact_id} debounced")
        return jsonify({"status": "debounced"}), 200

    contact = get_contact(contact_id)
    if not contact:
        log.warning(f"Could not fetch contact {contact_id}")
        return jsonify({"status": "contact_not_found"}), 200

    sync_contact_to_company(contact)
    return jsonify({"status": "ok"}), 200


@app.route("/webhook/company", methods=["POST"])
def company_webhook():
    data         = request.json or {}
    company_id   = data.get("companyId") or data.get("id") or data.get("objectId")
    contact_type = data.get("contact_type") or data.get("contactType")
    tags_added   = data.get("company_tags_added", [])
    tags_removed = data.get("company_tags_removed", [])
    if not tags_added and not tags_removed and data.get("company_tags"):
        tags_added = data.get("company_tags")

    if not company_id:
        return jsonify({"status": "no company_id"}), 200

    sync_company_to_contacts(company_id,
        contact_type=contact_type,
        company_tags_added=tags_added,
        company_tags_removed=tags_removed)
    return jsonify({"status": "ok"}), 200


@app.route("/webhook", methods=["POST"])
def generic_webhook():
    data       = request.json or {}
    event_type = data.get("type", "").lower()
    log.info(f"Webhook: type={event_type}")
    if any(k in event_type for k in ["contact", "tag"]):
        return contact_webhook()
    if any(k in event_type for k in ["company", "business", "object"]):
        return company_webhook()
    return jsonify({"status": "ignored", "type": event_type}), 200


@app.route("/health", methods=["GET"])
def health():
    with _token_lock:
        token_exp = _token_cache["expires_at"]
    hours_left = max(0, (token_exp - time.time()) / 3600)
    return jsonify({
        "status":           "ok",
        "location":         LOCATION_ID,
        "token_expires_in": f"{hours_left:.1f}h",
        "token_ok":         hours_left > 0,
    }), 200


@app.route("/reauth", methods=["POST"])
def reauth():
    """Inject a fresh location token without redeploying.

    POST /reauth
    { "location_token": "<new access token>", "refresh_token": "<optional>" }
    """
    data    = request.json or {}
    token   = data.get("location_token") or data.get("access_token")
    refresh = data.get("refresh_token")
    if not token:
        return jsonify({"error": "location_token required"}), 400
    with _token_lock:
        _token_cache["access_token"] = token
        _token_cache["expires_at"]   = _jwt_exp(token)
        if refresh:
            _token_cache["refresh_token"] = refresh
    exp = _token_cache["expires_at"]
    log.info(f"Token updated via /reauth — expires {time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))}")
    return jsonify({"status": "ok", "expires_at": exp}), 200


@app.route("/oauth/url", methods=["GET"])
def oauth_url():
    """Return the GHL authorization URL. Visit it in your browser to authorize."""
    from urllib.parse import urlencode
    url = "https://marketplace.gohighlevel.com/v2/oauth/chooselocation?" + urlencode({
        "response_type": "code",
        "redirect_uri":  REDIRECT_URI,
        "client_id":     CLIENT_ID,
        "scope":         GHL_SCOPES,
        "version_id":    GHL_APP_VERSION_ID,
    })
    return jsonify({"url": url, "redirect_uri": REDIRECT_URI}), 200


@app.route("/oauth/callback", methods=["GET"])
def oauth_callback():
    """GHL redirects here with ?code=... after user authorizes. Exchanges automatically."""
    code  = request.args.get("code", "").strip()
    error = request.args.get("error")
    if error:
        return f"<h2>OAuth error: {error}</h2>", 400
    if not code:
        return "<h2>No code received</h2>", 400
    result = _exchange_code(code)
    if "error" in result:
        return f"<h2>Exchange failed</h2><pre>{result['error']}</pre>", 400
    return "<h2>✅ Authorized!</h2><p>Tokens saved. Auto-refresh is now active. You can close this tab.</p>", 200


@app.route("/oauth/exchange", methods=["POST"])
def oauth_exchange():
    """Exchange an auth code for tokens.

    After visiting the URL from /oauth/url and authorizing, GHL redirects to
    REDIRECT_URI?code=<code>. Copy that code and POST it here:

    POST /oauth/exchange
    { "code": "abc123..." }
    """
    data = request.json or {}
    code = data.get("code", "").strip()
    if not code:
        return jsonify({"error": "code required"}), 400
    result = _exchange_code(code)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result), 200


@app.route("/sync/contact/<contact_id>", methods=["POST"])
def force_sync_contact(contact_id):
    contact = get_contact(contact_id)
    if not contact:
        return jsonify({"error": "contact not found"}), 404
    sync_contact_to_company(contact)
    return jsonify({"status": "ok"}), 200


@app.route("/sync/company/<company_id>", methods=["POST"])
def force_sync_company(company_id):
    body = request.json or {}
    sync_company_to_contacts(company_id,
        contact_type=body.get("contact_type"),
        company_tags_added=body.get("company_tags_added") or body.get("company_tags"),
        company_tags_removed=body.get("company_tags_removed"))
    return jsonify({"status": "ok"}), 200


@app.route("/sync-all", methods=["POST"])
def force_sync_all():
    """Force-sync all companies → their linked contacts (bypasses snapshot/debounce).
    Runs in background; returns immediately.
    """
    def _do():
        companies = _fetch_all_companies()
        count = 0
        for comp in companies:
            props = comp.get("properties", {})
            ct    = props.get("contact_type") or ""
            tags  = props.get("company_tags") or []
            if ct or tags:
                # Clear debounce so force-sync is never skipped
                with _syncing_lock:
                    _syncing.pop(f"company_{comp['id']}", None)
                sync_company_to_contacts(comp["id"],
                    contact_type=ct or None,
                    company_tags_added=tags or None)
                count += 1
                time.sleep(0.1)
        log.info(f"sync-all complete: {count}/{len(companies)} companies synced")
    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"status": "started"}), 200


# ── Background company poller ─────────────────────────────────────────────────
_company_snapshot: dict = {}


def _fetch_all_companies() -> list:
    all_records = []
    page = 1
    while True:
        try:
            resp = _ghl_request(lambda p=page: requests.post(
                f"{BASE_URL}/objects/business/records/search",
                headers=oauth_headers(),
                json={"locationId": LOCATION_ID, "page": p, "pageLimit": 100},
                timeout=30
            ))
            records = resp.json().get("records", [])
            if not records:
                break
            all_records.extend(records)
            if len(records) < 100:
                break
            page += 1
        except Exception as e:
            log.error(f"Error fetching companies page {page}: {e}")
            break
    return all_records


def poll_company_changes():
    log.info("Polling companies for changes...")
    try:
        companies = _fetch_all_companies()
    except Exception as e:
        log.error(f"Poll failed: {e}")
        return

    for comp in companies:
        comp_id      = comp["id"]
        props        = comp.get("properties", {})
        current_ct   = props.get("contact_type") or ""
        current_tags = sorted(props.get("company_tags") or [])

        with _snapshot_lock:
            prev = _company_snapshot.get(comp_id)

        if prev is None:
            with _snapshot_lock:
                _company_snapshot[comp_id] = {"contact_type": current_ct, "company_tags": current_tags}
            continue

        prev_ct      = prev.get("contact_type", "")
        prev_tags    = prev.get("company_tags", [])
        ct_changed   = current_ct != prev_ct
        tags_added   = [t for t in current_tags if t not in prev_tags]
        tags_removed = [t for t in prev_tags   if t not in current_tags]

        if ct_changed or tags_added or tags_removed:
            comp_name = props.get("name", comp_id)
            log.info(
                f"Company changed: '{comp_name}' | "
                f"contact_type: {prev_ct!r} → {current_ct!r} | "
                f"tags_added={tags_added} | tags_removed={tags_removed}"
            )
            sync_company_to_contacts(
                comp_id,
                contact_type=current_ct if ct_changed else None,
                company_tags_added=tags_added   or None,
                company_tags_removed=tags_removed or None,
            )

        with _snapshot_lock:
            _company_snapshot[comp_id] = {"contact_type": current_ct, "company_tags": current_tags}

    log.info(f"Poll complete — {len(companies)} companies checked")


def setup_webhooks():
    """Register GHL contact webhooks; delete stale ones with the same name but wrong URL."""
    if not WEBHOOK_BASE_URL:
        log.warning("WEBHOOK_BASE_URL not set — skipping webhook registration")
        return

    target_url = f"{WEBHOOK_BASE_URL}/webhook/contact"

    try:
        resp     = _ghl_request(lambda: requests.get(
            f"{BASE_URL}/webhooks/",
            headers=oauth_headers(),
            params={"locationId": LOCATION_ID},
            timeout=15
        ))
        existing = resp.json().get("webhooks", [])

        already_registered = False
        for wh in existing:
            if wh.get("name") == WEBHOOK_NAME and wh.get("url") != target_url:
                # Stale webhook from a previous deployment URL — delete it
                wh_id = wh.get("id")
                del_r = _ghl_request(lambda i=wh_id: requests.delete(
                    f"{BASE_URL}/webhooks/{i}",
                    headers=oauth_headers(),
                    params={"locationId": LOCATION_ID},
                    timeout=15
                ))
                log.info(f"Deleted stale webhook {wh_id} ({wh.get('url')}): {del_r.status_code}")
            elif wh.get("url") == target_url:
                already_registered = True

        if already_registered:
            log.info(f"Webhook already registered: {target_url}")
            return

        r = _ghl_request(lambda: requests.post(
            f"{BASE_URL}/webhooks/",
            headers=oauth_headers(),
            json={"locationId": LOCATION_ID, "name": WEBHOOK_NAME, "url": target_url, "events": WEBHOOK_EVENTS},
            timeout=15
        ))
        if r.status_code in (200, 201):
            log.info(f"Webhook registered: {target_url} events={WEBHOOK_EVENTS}")
        else:
            log.error(f"Webhook registration failed: {r.status_code} {r.text[:300]}")
    except Exception as e:
        log.error(f"setup_webhooks error: {e}")


def _poll_loop():
    setup_webhooks()
    while True:
        try:
            poll_company_changes()
        except Exception as e:
            log.error(f"Unhandled error in poll loop: {e}")
        time.sleep(POLL_INTERVAL_SECS)


def start_poller():
    t = threading.Thread(target=_poll_loop, daemon=True, name="company-poller")
    t.start()
    log.info(f"Company poller started (interval={POLL_INTERVAL_SECS}s)")


# Start background poller when module is imported (works with gunicorn)
start_poller()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    log.info(f"Starting GHL sync server on port {port}")
    get_oauth_token()
    get_field_options()
    app.run(host="0.0.0.0", port=port)
