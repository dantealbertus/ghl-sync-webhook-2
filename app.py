#!/usr/bin/env python3
"""
GHL bidirectional sync: Contact ↔ Company
Webhook server deployed on Railway.

Syncs:
  - Contact tag added/removed        → company_tag, company_tags, contact_type
  - Contact type changed             → company contact_type
  - Contact linked to company        → full sync to company
  - Company contact_type changed     → all linked contacts
  - Company company_tag changed      → all linked contacts
"""

from flask import Flask, request, jsonify
import requests, json, re, os, time, logging
from rapidfuzz import fuzz, process

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = Flask(__name__)

# ── Config from environment variables ────────────────────────────────────────
BASE_URL    = "https://services.leadconnectorhq.com"
LOCATION_ID = os.environ["GHL_LOCATION_ID"]
PIT_TOKEN   = os.environ["GHL_PIT_TOKEN"]
CLIENT_ID   = os.environ["GHL_CLIENT_ID"]
CLIENT_SECRET = os.environ["GHL_CLIENT_SECRET"]
COMPANY_ID  = os.environ["GHL_COMPANY_ID"]   # agency companyId

NUM_TAG_RE = re.compile(r'^(\d{2})-(\d{2})\s+')
FUZZY_THRESHOLD = 75

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

# ── OAuth token cache ─────────────────────────────────────────────────────────
_token_cache = {
    "access_token":  os.environ.get("GHL_LOCATION_TOKEN", ""),
    "refresh_token": os.environ.get("GHL_REFRESH_TOKEN", ""),
    "expires_at":    0,
}

def get_oauth_token():
    """Return valid OAuth token, refreshing if needed."""
    if time.time() < _token_cache["expires_at"] - 300:
        return _token_cache["access_token"]
    return _refresh_oauth_token()

def _refresh_oauth_token():
    refresh_tok = _token_cache.get("refresh_token") or os.environ.get("GHL_REFRESH_TOKEN", "")
    if not refresh_tok:
        log.error("No refresh token available")
        return _token_cache["access_token"]

    resp = requests.post(
        f"{BASE_URL}/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_id":     CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type":    "refresh_token",
            "refresh_token": refresh_tok,
        }
    )
    if resp.status_code not in (200, 201):
        log.error(f"Token refresh failed: {resp.status_code} {resp.text[:200]}")
        return _token_cache["access_token"]

    agency_data = resp.json()

    # Get location token
    loc_resp = requests.post(
        f"{BASE_URL}/oauth/locationToken",
        headers={"Authorization": f"Bearer {agency_data['access_token']}",
                 "Version": "2021-07-28", "Content-Type": "application/json"},
        json={"companyId": COMPANY_ID, "locationId": LOCATION_ID}
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

def pit_headers():
    return {"Authorization": f"Bearer {PIT_TOKEN}", "Version": "2021-07-28", "Content-Type": "application/json"}

def oauth_headers():
    return {"Authorization": f"Bearer {get_oauth_token()}", "Version": "2021-07-28", "Content-Type": "application/json"}

# ── Debounce: prevent infinite sync loops ────────────────────────────────────
_syncing = {}
DEBOUNCE_S = 15

def is_syncing(key):
    return time.time() - _syncing.get(key, 0) < DEBOUNCE_S

def mark_syncing(key):
    _syncing[key] = time.time()

# ── Field options cache ───────────────────────────────────────────────────────
_field_cache = {"tag_by_code": {}, "tag_by_label": {}, "loaded_at": 0}
CACHE_TTL = 3600

def get_field_options():
    if time.time() - _field_cache["loaded_at"] < CACHE_TTL:
        return _field_cache["tag_by_code"], _field_cache["tag_by_label"]
    try:
        fields = requests.get(
            f"{BASE_URL}/objects/business",
            headers=oauth_headers(),
            params={"locationId": LOCATION_ID, "fetchProperties": True}
        ).json().get("fields", [])

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
        log.info(f"Field options cached: {len(tag_by_code)} codes")
    except Exception as e:
        log.error(f"Failed to load field options: {e}")
    return _field_cache["tag_by_code"], _field_cache["tag_by_label"]

def resolve_tag_key(tag_label):
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

def resolve_contact_type(raw_type):
    if not raw_type:
        return None
    val = raw_type.lower().strip()
    if val in CONTACT_TYPE_MAP:
        return CONTACT_TYPE_MAP[val]
    return None  # don't pass unknown values to GHL

# ── GHL API helpers ───────────────────────────────────────────────────────────
def get_contact(contact_id):
    r = requests.get(f"{BASE_URL}/contacts/{contact_id}", headers=pit_headers())
    return r.json().get("contact") if r.status_code == 200 else None

def get_linked_contacts(company_id):
    """Fetch all contacts linked to a company."""
    all_contacts = []
    params = {"locationId": LOCATION_ID, "limit": 100}
    while True:
        contacts = requests.get(f"{BASE_URL}/contacts/", headers=pit_headers(), params=params).json().get("contacts", [])
        if not contacts:
            break
        all_contacts.extend([c for c in contacts if c.get("businessId") == company_id])
        if len(contacts) < 100:
            break
        last = contacts[-1].get("startAfter")
        if not last:
            break
        params["startAfterId"] = last[1]
        params["startAfter"]   = last[0]
    return all_contacts

def update_company(company_id, props):
    if not props:
        return
    r = requests.put(
        f"{BASE_URL}/objects/business/records/{company_id}",
        headers=oauth_headers(),
        params={"locationId": LOCATION_ID},
        json={"properties": props}
    )
    log.info(f"Update company {company_id}: {list(props.keys())} → {r.status_code}")
    return r

def update_contact(contact_id, payload):
    r = requests.put(f"{BASE_URL}/contacts/{contact_id}", headers=pit_headers(), json=payload)
    log.info(f"Update contact {contact_id} → {r.status_code}")
    return r

# ── Sync logic ────────────────────────────────────────────────────────────────
def sync_contact_to_company(contact):
    """Derive company fields from contact and update the linked company."""
    company_id = contact.get("businessId")
    if not company_id:
        return

    if is_syncing(f"company_{company_id}"):
        log.info(f"Skipping company {company_id} (debounce)")
        return

    mark_syncing(f"contact_{contact['id']}")

    tags = contact.get("tags", [])
    raw_type = (contact.get("type") or "").strip()

    # contact_type (single value)
    ct_key = resolve_contact_type(raw_type)

    # company_tag: lowest numeric tag (single select)
    best_code, best_key = None, None
    tag_by_code, _ = get_field_options()
    for tag in tags:
        m = NUM_TAG_RE.match(tag.strip())
        if m:
            code = m.group(1) + m.group(2)
            if code in tag_by_code and (best_code is None or code < best_code):
                best_code, best_key = code, tag_by_code[code]

    # company_tags: all tags (multi-select)
    tag_keys = [k for k in (resolve_tag_key(t) for t in tags) if k]

    props = {}
    if ct_key:
        props["contact_type"] = ct_key
    if best_key:
        props["company_tag"] = best_key
    if tag_keys:
        props["company_tags"] = {"add": tag_keys}

    if props:
        log.info(f"Syncing contact {contact['id']} → company {company_id}: {props}")
        update_company(company_id, props)


def sync_company_to_contacts(company_id, contact_type=None, company_tag=None):
    """Push company field changes to all linked contacts."""
    if is_syncing(f"company_{company_id}"):
        return

    mark_syncing(f"company_{company_id}")
    linked = get_linked_contacts(company_id)
    log.info(f"Syncing company {company_id} → {len(linked)} contacts")

    for contact in linked:
        if is_syncing(f"contact_{contact['id']}"):
            continue

        payload = {}

        # contact_type → contact.type
        if contact_type:
            # Map company key back to contact type value
            reverse_map = {v: k for k, v in CONTACT_TYPE_MAP.items()}
            contact_type_val = reverse_map.get(contact_type, contact_type)
            payload["type"] = contact_type_val

        # company_tag → add corresponding tag on contact
        if company_tag:
            tag_by_code, _ = get_field_options()
            # Find label for this key
            tag_label = next(
                (opt_label for opt_label, key in _field_cache["tag_by_label"].items() if key == company_tag),
                None
            )
            if tag_label:
                existing_tags = contact.get("tags", [])
                if tag_label not in existing_tags:
                    payload["tags"] = existing_tags + [tag_label]

        if payload:
            mark_syncing(f"contact_{contact['id']}")
            update_contact(contact["id"], payload)
            time.sleep(0.05)


# ── Webhook endpoints ─────────────────────────────────────────────────────────
@app.route("/webhook/contact", methods=["POST"])
def contact_webhook():
    """Receives GHL contact webhooks."""
    data = request.json or {}
    log.info(f"Contact webhook: type={data.get('type')} id={data.get('id') or data.get('contactId')}")

    contact_id = data.get("id") or data.get("contactId") or data.get("contact", {}).get("id")
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
    """
    Receives company update webhooks.
    Can be called from a GHL Workflow (Custom Webhook action) when a company is updated.
    Expected payload: {"companyId": "...", "contact_type": "...", "company_tag": "..."}
    """
    data = request.json or {}
    log.info(f"Company webhook: {data}")

    company_id   = data.get("companyId") or data.get("id") or data.get("objectId")
    contact_type = data.get("contact_type") or data.get("contactType")
    company_tag  = data.get("company_tag") or data.get("companyTag")

    if not company_id:
        return jsonify({"status": "no company_id"}), 200

    sync_company_to_contacts(company_id, contact_type=contact_type, company_tag=company_tag)
    return jsonify({"status": "ok"}), 200


@app.route("/webhook", methods=["POST"])
def generic_webhook():
    """
    Single catch-all endpoint — set this as your GHL webhook URL.
    GHL sends all events here; we route based on event type.
    """
    data = request.json or {}
    event_type = data.get("type", "").lower()
    log.info(f"Webhook: type={event_type}")

    # Contact events
    if any(k in event_type for k in ["contact", "tag"]):
        return contact_webhook()

    # Company / object events
    if any(k in event_type for k in ["company", "business", "object"]):
        return company_webhook()

    return jsonify({"status": "ignored", "type": event_type}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "location": LOCATION_ID}), 200


@app.route("/sync/contact/<contact_id>", methods=["POST"])
def force_sync_contact(contact_id):
    """Manually trigger a contact → company sync."""
    contact = get_contact(contact_id)
    if not contact:
        return jsonify({"error": "contact not found"}), 404
    sync_contact_to_company(contact)
    return jsonify({"status": "ok"}), 200


@app.route("/sync/company/<company_id>", methods=["POST"])
def force_sync_company(company_id):
    """Manually trigger a company → contacts sync."""
    body = request.json or {}
    sync_company_to_contacts(company_id,
        contact_type=body.get("contact_type"),
        company_tag=body.get("company_tag"))
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    log.info(f"Starting GHL sync server on port {port}")
    get_oauth_token()   # warm up token on startup
    get_field_options() # warm up field cache on startup
    app.run(host="0.0.0.0", port=port)
