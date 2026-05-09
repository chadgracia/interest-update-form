"""
interest_update_form.py
───────────────────────
Lambda URL handler for the buy/sell interest update form.

Cloned from deal_update_form.py. Operates on the **contact** (person) record,
not on any single deal. Handles three person-level multi-select fields:

  - Buy Interest  (custom_label_3322093)
  - Sell Interest (custom_label_3759156)
  - Holding       (custom_label_3740611, displayed read-only)

Plus the Broadcast preference (custom_label_3774841) — clicking the unsubscribe
button under the interests list sets Broadcast=No (entry 6535329) and leaves
the interest data untouched.

Routes:
  GET  ?person_id=X&token=Y                    → render pre-populated form
  POST (form submit)                            → update Pipeline, show success
  GET  ?action=unsubscribe&person_id=X&token=Y → set Broadcast=No, confirm

Security: HMAC-SHA256 token on person_id.
"""

import json
import logging
import urllib.request
import urllib.error
import urllib.parse
import os
import hmac
import hashlib
import base64
import html as html_lib
import boto3
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Config ────────────────────────────────────────────────────────────────────
HMAC_SECRET         = os.environ.get("HMAC_SECRET", "change-me-in-env")
SES_SENDER          = "agent@agent.graciagroup.com"
AGENT_EMAIL         = "agent@agent.graciagroup.com"
CHAD_EMAIL          = "cgracia@rainmakersecurities.com"
TRADES_URL          = "https://trades.graciagroup.com"
PIPELINE_JWT_BUCKET = "pipeline-token"
PIPELINE_JWT_KEY    = "pipeline-jwt.json"

# Person custom fields
HOLDING_FIELD       = "custom_label_3740611"
BUY_INTEREST_FIELD  = "custom_label_3322093"
SELL_INTEREST_FIELD = "custom_label_3759156"
BROADCAST_FIELD     = "custom_label_3774841"

# Broadcast dropdown entries
BROADCAST_YES  = 6535328
BROADCAST_NO   = 6535329
BROADCAST_HOLD = 6535330

# Pipeline custom-field-label IDs (for fetching dropdown definitions)
HOLDING_LABEL_ID       = 3740611
BUY_INTEREST_LABEL_ID  = 3322093
SELL_INTEREST_LABEL_ID = 3759156


# ── Helpers (unchanged from deal_update_form.py) ──────────────────────────────

def get_jwt():
    s3  = boto3.client('s3')
    obj = s3.get_object(Bucket=PIPELINE_JWT_BUCKET, Key=PIPELINE_JWT_KEY)
    return json.loads(obj['Body'].read())['jwt']


def make_token(id_value: int) -> str:
    msg = str(id_value).encode()
    sig = hmac.new(HMAC_SECRET.encode(), msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def verify_token(id_value: int, token: str) -> bool:
    expected = hmac.new(HMAC_SECRET.encode(), str(id_value).encode(), hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected).decode().rstrip("=")
    return hmac.compare_digest(expected_b64, token)


def call_pipeline_api(method, endpoint, payload=None, jwt=None):
    base = "https://api.pipelinecrm.com/api/v3"
    url  = f"{base}{endpoint}"
    headers = {
        "Authorization": f"Bearer {jwt}",
        "Content-Type":  "application/json"
    }
    data = json.dumps(payload).encode() if payload else None
    req  = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return {"status": r.status, "data": json.loads(r.read().decode())}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "data": e.read().decode()}
    except Exception as e:
        return {"status": 500, "data": str(e)}


def send_email(to_address: str, subject: str, body: str):
    ses = boto3.client("ses", region_name="us-east-1")
    ses.send_email(
        Source=SES_SENDER,
        Destination={"ToAddresses": [to_address]},
        Message={
            "Subject": {"Data": subject},
            "Body":    {"Text": {"Data": body}}
        }
    )


# ── Security-ID lookup (name ↔ id for each multi-select field) ────────────────
#
# The three interest fields store dropdown entry IDs, not names. To render
# chips we need id→name; to accept user-typed company names we need name→id.
#
# Loaded lazily on first use, cached for the warm Lambda lifetime.

_SECURITY_CACHE = None  # populated by load_security_maps()


def load_security_maps(jwt: str) -> dict:
    """
    Returns: {
      'buy':  {'id_to_name': {...}, 'name_to_id': {...}},
      'sell': {'id_to_name': {...}, 'name_to_id': {...}},
      'hold': {'id_to_name': {...}, 'name_to_id': {...}},
    }
    """
    global _SECURITY_CACHE
    if _SECURITY_CACHE is not None:
        return _SECURITY_CACHE

    out = {}
    for key, label_id in [
        ("buy",  BUY_INTEREST_LABEL_ID),
        ("sell", SELL_INTEREST_LABEL_ID),
        ("hold", HOLDING_LABEL_ID),
    ]:
        # Endpoint may differ — confirm against Pipeline API docs.
        # Likely path: /admin/person_custom_field_labels/{id}.json
        result = call_pipeline_api(
            "GET",
            f"/admin/person_custom_field_labels/{label_id}.json",
            jwt=jwt
        )
        entries = []
        if result["status"] == 200:
            data = result["data"]
            entries = (data.get("entry") or data).get("custom_field_label_dropdown_entries", [])
        id_to_name = {int(e["id"]): e["name"] for e in entries}
        # Lowercase key for case-insensitive add lookups
        name_to_id = {e["name"].strip().lower(): int(e["id"]) for e in entries}
        out[key] = {"id_to_name": id_to_name, "name_to_id": name_to_id}

    _SECURITY_CACHE = out
    return out


def cf_id_list(cf_value) -> list:
    """Normalise a multi-select custom_field value into a list of ints."""
    if cf_value is None or cf_value == "":
        return []
    if isinstance(cf_value, list):
        out = []
        for v in cf_value:
            try: out.append(int(v))
            except (ValueError, TypeError): pass
        return out
    try:
        return [int(cf_value)]
    except (ValueError, TypeError):
        return []


def parse_cf(cf, field):
    v = cf.get(field)
    if isinstance(v, list):
        return v[0] if v else None
    return v


# ── HTML shell (same styling as deal form, plus chip styles) ──────────────────

def html_response(body_html: str, status: int = 200) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "text/html; charset=utf-8"},
        "body": f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gracia Group — Your Interests</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5; color: #1a1a1a;
      min-height: 100vh; display: flex;
      align-items: center; justify-content: center;
      padding: 24px;
    }}
    .card {{
      background: #fff; border-radius: 12px;
      box-shadow: 0 2px 16px rgba(0,0,0,0.08);
      padding: 40px; max-width: 640px; width: 100%;
    }}
    .logo {{
      font-size: 13px; font-weight: 600;
      letter-spacing: 0.08em; text-transform: uppercase;
      color: #888; margin-bottom: 28px;
    }}
    h1 {{ font-size: 22px; font-weight: 700; margin-bottom: 6px; }}
    .subtitle {{ font-size: 14px; color: #666; margin-bottom: 28px; line-height: 1.5; }}
    .section {{ margin-bottom: 28px; }}
    .section-label {{
      font-size: 12px; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.05em;
      color: #888; margin-bottom: 10px;
    }}
    .chip-row {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }}
    .chip {{
      display: inline-flex; align-items: center; gap: 6px;
      padding: 5px 10px 5px 12px;
      background: #fff; border: 1px solid #ddd;
      border-radius: 999px; font-size: 13px; color: #333;
      cursor: pointer; user-select: none;
    }}
    .chip-buy, .chip-sell {{ border-color: #b8d8b8; background: #e8f5e8; color: #2b6e3f; }}
    .chip input[type=checkbox] {{ display: none; }}
    .chip.removed {{ border-color: #e8b8b8; background: #fde8e8; color: #8a3a3a; text-decoration: line-through; }}
    .chip.removed .chip-x {{ color: #c88; }}
    .chip-x {{ color: #aaa; font-size: 14px; line-height: 1; }}
    input[type=text] {{
      width: 100%; padding: 10px 14px;
      border: 1px solid #ddd; border-radius: 8px;
      font-size: 14px;
    }}
    input:focus {{ outline: none; border-color: #1a1a1a; }}
    .help {{ font-size: 12px; color: #888; margin-top: 6px; }}
    .btn-row {{ display: flex; gap: 12px; margin-top: 24px; }}
    .btn-primary {{
      flex: 1; background: #1a1a1a; color: #fff; border: none;
      padding: 13px; border-radius: 8px;
      font-size: 15px; font-weight: 600; cursor: pointer;
    }}
    .btn-cancel {{
      flex: 1; background: #fff; color: #666;
      border: 1px solid #ddd; padding: 13px;
      border-radius: 8px; font-size: 15px; cursor: pointer;
    }}
    .unsub-broadcast {{
      margin-top: 28px; padding-top: 24px;
      border-top: 1px solid #eee;
    }}
    .btn-unsub {{
      width: 100%; background: #fff; color: #8a3a3a;
      border: 1px solid #e8c8c8; padding: 11px;
      border-radius: 8px; font-size: 13px; cursor: pointer;
    }}
    .success-icon {{ font-size: 48px; text-align: center; margin-bottom: 16px; }}
    .countdown {{ font-size: 13px; color: #999; text-align: center; margin-top: 16px; }}
    .footer-note {{ text-align: center; margin-top: 20px; font-size: 11px; color: #bbb; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">Gracia Group</div>
    {body_html}
  </div>
  <script>
    function wireChip(cb) {{
      var chip = cb.closest('.chip');
      function sync() {{ chip.classList.toggle('removed', !cb.checked); }}
      cb.addEventListener('change', sync);
      sync();
    }}
    document.querySelectorAll('.chip input[type=checkbox]').forEach(wireChip);

    function tryAddChip(side, inputEl) {{
      var name = inputEl.value.trim();
      if (!name) return;
      var map = (typeof NAME_TO_ID !== 'undefined') ? NAME_TO_ID[side] : null;
      if (!map) return;
      var id = map[name];
      if (id == null) return;
      var row = document.getElementById('chip-row-' + side);
      if (!row) return;
      if (row.querySelector('input[name="keep_' + side + '"][value="' + id + '"]')) {{
        inputEl.value = '';
        return;
      }}
      var label = document.createElement('label');
      label.className = 'chip chip-' + side;
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.name = 'keep_' + side;
      cb.value = id;
      cb.checked = true;
      label.appendChild(cb);
      label.appendChild(document.createTextNode(name));
      var x = document.createElement('span');
      x.className = 'chip-x';
      x.textContent = '×';
      label.appendChild(x);
      row.appendChild(label);
      wireChip(cb);
      inputEl.value = '';
    }}

    document.querySelectorAll('.add-input').forEach(function(inp) {{
      var side = inp.id === 'add_buy_input' ? 'buy' : 'sell';
      inp.addEventListener('change', function() {{ tryAddChip(side, inp); }});
      inp.addEventListener('keydown', function(e) {{
        if (e.key === 'Enter') {{ e.preventDefault(); tryAddChip(side, inp); }}
      }});
    }});
  </script>
</body>
</html>"""
    }


def error_page(msg: str) -> dict:
    return html_response(f'<h1>Something went wrong</h1><p class="subtitle" style="margin-top:12px">{msg}</p>', 400)


# ── Form page ─────────────────────────────────────────────────────────────────

def render_form(person: dict, sec_maps: dict, person_id: int) -> dict:
    cf           = person.get("custom_fields", {})
    contact_name = person.get("full_name") or person.get("first_name") or ""

    buy_ids  = cf_id_list(cf.get(BUY_INTEREST_FIELD))
    sell_ids = cf_id_list(cf.get(SELL_INTEREST_FIELD))
    hold_ids = cf_id_list(cf.get(HOLDING_FIELD))

    def chip_html(ids, side, name_map):
        side_class = f"chip-{side}"
        field_name = f"keep_{side}"
        chips = []
        for i in ids:
            label = name_map.get(i, f"#{i}")
            chips.append(
                f'<label class="chip {side_class}">'
                f'<input type="checkbox" name="{field_name}" value="{i}" checked>'
                f'{html_lib.escape(label)}<span class="chip-x">×</span>'
                f'</label>'
            )
        return f'<div class="chip-row" id="chip-row-{side}">{"".join(chips)}</div>'

    def readonly_chips(ids, name_map):
        if not ids:
            return f'<p style="font-size:13px;color:#aaa;font-style:italic">None on file.</p>'
        chips = [f'<span class="chip">{html_lib.escape(name_map.get(i, f"#{i}"))}</span>' for i in ids]
        return f'<div class="chip-row">{"".join(chips)}</div>'

    def datalist_html(name_map, list_id):
        names = sorted(name_map.values(), key=lambda s: s.lower())
        options = "".join(
            f'<option value="{html_lib.escape(n, quote=True)}">' for n in names
        )
        return f'<datalist id="{list_id}">{options}</datalist>'

    buy_chips_html  = chip_html(buy_ids,  "buy",  sec_maps["buy"]["id_to_name"])
    sell_chips_html = chip_html(sell_ids, "sell", sec_maps["sell"]["id_to_name"])
    hold_chips_html = readonly_chips(hold_ids, sec_maps["hold"]["id_to_name"])

    buy_datalist  = datalist_html(sec_maps["buy"]["id_to_name"],  "buy_options")
    sell_datalist = datalist_html(sec_maps["sell"]["id_to_name"], "sell_options")

    buy_name_to_id  = {name: i for i, name in sec_maps["buy"]["id_to_name"].items()}
    sell_name_to_id = {name: i for i, name in sec_maps["sell"]["id_to_name"].items()}
    name_to_id_json = json.dumps({"buy": buy_name_to_id, "sell": sell_name_to_id})

    unsub_url = (
        f"?action=unsubscribe&person_id={person_id}&token={make_token(person_id)}"
    )

    form_html = f"""
    <h1>Your buy/sell interests</h1>
    <p class="subtitle">
      Hello{f" {contact_name.split()[0]}" if contact_name else ""}! These are the
      companies we have on file for you. Tap a chip to remove it, or add new
      names below. Changes save when you hit Update.
    </p>

    <form method="POST">
      <input type="hidden" name="person_id" value="{person_id}">

      <div class="section">
        <p class="section-label">Looking to buy</p>
        {buy_chips_html}
        <input type="text" id="add_buy_input" list="buy_options" class="add-input" placeholder="Type a company name..." autocomplete="off" style="margin-top:10px">
        {buy_datalist}
      </div>

      <div class="section">
        <p class="section-label">Looking to sell</p>
        {sell_chips_html}
        <input type="text" id="add_sell_input" list="sell_options" class="add-input" placeholder="Type a company name..." autocomplete="off" style="margin-top:10px">
        {sell_datalist}
      </div>

      <div class="section">
        <p class="section-label">Holdings (for our reference)</p>
        {hold_chips_html}
        <p class="help">If your holdings have changed, just reply to any of our emails and we'll update.</p>
      </div>

      <div class="btn-row">
        <button type="submit" name="submit_action" value="confirm" class="btn-primary">✓ Update</button>
        <button type="submit" name="submit_action" value="cancel" class="btn-cancel">Cancel</button>
      </div>

      <div class="unsub-broadcast">
        <button type="submit" name="submit_action" value="unsubscribe_broadcast" class="btn-unsub" formnovalidate>
          Unsubscribe from interest updates
        </button>
        <p class="help" style="text-align:center;margin-top:8px">
          We'll stop sending the daily buy/sell update. Your interest data above stays as-is.
        </p>
      </div>
      <script>
        var NAME_TO_ID = {name_to_id_json};
      </script>
    </form>

    <div class="footer-note">Reference only. Not an offer to buy or sell securities.</div>
    """
    return html_response(form_html)


# ── Success page (cloned from deal form) ──────────────────────────────────────

def success_page(message: str, sub: str = "") -> dict:
    sub_html = f'<p class="subtitle" style="text-align:center;margin-top:8px">{sub}</p>' if sub else ""
    html = f"""
    <div class="success-icon">✓</div>
    <h1 style="text-align:center">{message}</h1>
    {sub_html}
    <div class="countdown" id="cd">Redirecting to the marketplace in <span id="n">3</span> seconds…</div>
    <script>
      var n = 3;
      var el = document.getElementById('n');
      var iv = setInterval(function() {{
        n--;
        el.textContent = n;
        if (n <= 0) {{ clearInterval(iv); window.location.href = '{TRADES_URL}'; }}
      }}, 1000);
    </script>
    """
    return html_response(html)


# ── GET handler ───────────────────────────────────────────────────────────────

def handle_get(params: dict) -> dict:
    action = params.get("action", "")
    person_id_str = params.get("person_id", "")
    token         = params.get("token", "")

    try:
        person_id = int(person_id_str)
    except (ValueError, TypeError):
        return error_page("Invalid link.")
    if not verify_token(person_id, token):
        return error_page("Invalid or expired link.")

    jwt = get_jwt()

    # One-click unsubscribe from interest broadcast (Broadcast=No)
    if action == "unsubscribe":
        payload = {"person": {"custom_fields": {BROADCAST_FIELD: BROADCAST_NO}}}
        result  = call_pipeline_api("PUT", f"/people/{person_id}.json", payload, jwt=jwt)
        if result["status"] != 200:
            logger.error(f"Broadcast unsub failed: {result}")
            send_email(
                CHAD_EMAIL,
                f"⚠ Broadcast unsub failed — person {person_id}",
                f"Pipeline write failed: HTTP {result['status']}: {result['data']}\n"
                f"https://app.pipelinecrm.com/people/{person_id}"
            )
            return error_page("We couldn't save that right now. Chad has been notified.")
        return success_page(
            "Unsubscribed",
            "You won't receive daily interest updates anymore. Your interest data is unchanged."
        )

    # Default: render form
    result = call_pipeline_api("GET", f"/people/{person_id}.json", jwt=jwt)
    if result["status"] != 200:
        return error_page(f"Contact not found (ID {person_id}).")
    person = result["data"]

    sec_maps = load_security_maps(jwt)
    return render_form(person, sec_maps, person_id)


# ── POST handler ──────────────────────────────────────────────────────────────

def handle_post(body_str: str, qs: dict = None) -> dict:
    # Manual parse so we can collect repeated keys (multiple keep_buy=N)
    raw_pairs = []
    for part in body_str.split("&"):
        if "=" in part:
            k, v = part.split("=", 1)
            raw_pairs.append((urllib.parse.unquote_plus(k), urllib.parse.unquote_plus(v)))

    # Gather repeated checkbox values
    keep_buy  = [v for k, v in raw_pairs if k == "keep_buy"]
    keep_sell = [v for k, v in raw_pairs if k == "keep_sell"]
    # Singletons — last value wins
    singles = {k: v for k, v in raw_pairs}

    if qs:
        for k, v in qs.items():
            if k not in singles:
                singles[k] = v

    person_id_str = singles.get("person_id", "")
    submit_action = singles.get("submit_action", "confirm")

    try:
        person_id = int(person_id_str)
    except (ValueError, TypeError):
        return error_page("Invalid submission.")

    jwt = get_jwt()

    # ── Cancel: do nothing, just bounce to marketplace ────────────────────────
    if submit_action == "cancel":
        return success_page("No changes made")

    # ── Unsubscribe button under interests list ───────────────────────────────
    if submit_action == "unsubscribe_broadcast":
        payload = {"person": {"custom_fields": {BROADCAST_FIELD: BROADCAST_NO}}}
        result  = call_pipeline_api("PUT", f"/people/{person_id}.json", payload, jwt=jwt)
        if result["status"] != 200:
            logger.error(f"Broadcast unsub (POST) failed: {result}")
            send_email(
                CHAD_EMAIL,
                f"⚠ Broadcast unsub failed — person {person_id}",
                f"Pipeline write failed: HTTP {result['status']}: {result['data']}\n"
                f"https://app.pipelinecrm.com/people/{person_id}"
            )
            return error_page("We couldn't save that right now. Chad has been notified.")
        send_email(
            CHAD_EMAIL,
            f"Broadcast unsubscribe via interest form: person {person_id}",
            f"Contact opted out of daily interest updates (Broadcast=No). "
            f"Interest data unchanged.\n"
            f"https://app.pipelinecrm.com/people/{person_id}"
        )
        return success_page(
            "Unsubscribed",
            "You won't receive daily interest updates anymore. Your interest data is unchanged."
        )

    # ── Confirm: write Buy/Sell interest arrays ───────────────────────────────
    sec_maps = load_security_maps(jwt)

    def parse_kept(values):
        out = []
        for v in values:
            try: out.append(int(v))
            except (ValueError, TypeError): pass
        return out

    new_buy_kept  = parse_kept(keep_buy)
    new_sell_kept = parse_kept(keep_sell)

    # Dedup while preserving order
    def dedup(seq):
        seen, out = set(), []
        for x in seq:
            if x not in seen:
                seen.add(x); out.append(x)
        return out

    final_buy  = dedup(new_buy_kept)
    final_sell = dedup(new_sell_kept)

    # Fetch current values for diff in Chad's notification email
    current = call_pipeline_api("GET", f"/people/{person_id}.json", jwt=jwt)
    cur_cf  = (current.get("data") or {}).get("custom_fields", {}) if current["status"] == 200 else {}
    old_buy  = set(cf_id_list(cur_cf.get(BUY_INTEREST_FIELD)))
    old_sell = set(cf_id_list(cur_cf.get(SELL_INTEREST_FIELD)))
    contact_name = (current.get("data") or {}).get("full_name", "client") if current["status"] == 200 else "client"

    payload = {"person": {"custom_fields": {
        BUY_INTEREST_FIELD:  final_buy,
        SELL_INTEREST_FIELD: final_sell,
    }}}
    result = call_pipeline_api("PUT", f"/people/{person_id}.json", payload, jwt=jwt)
    if result["status"] != 200:
        logger.error(f"Interest update failed: {result}")
        send_email(
            CHAD_EMAIL,
            f"⚠ Interest update failed — person {person_id}",
            f"Pipeline write failed: HTTP {result['status']}: {result['data']}\n"
            f"https://app.pipelinecrm.com/people/{person_id}"
        )
        return error_page("We couldn't save your update right now. Chad has been notified.")

    # Build diff summary
    new_buy_set, new_sell_set = set(final_buy), set(final_sell)
    buy_added   = [sec_maps["buy"]["id_to_name"].get(i, f"#{i}")  for i in new_buy_set  - old_buy]
    buy_removed = [sec_maps["buy"]["id_to_name"].get(i, f"#{i}")  for i in old_buy      - new_buy_set]
    sell_added   = [sec_maps["sell"]["id_to_name"].get(i, f"#{i}") for i in new_sell_set - old_sell]
    sell_removed = [sec_maps["sell"]["id_to_name"].get(i, f"#{i}") for i in old_sell     - new_sell_set]

    lines = [
        f"Interest update from {contact_name}",
        f"https://app.pipelinecrm.com/people/{person_id}",
        "",
    ]
    if buy_added:    lines.append(f"Buy Interest added:    {', '.join(buy_added)}")
    if buy_removed:  lines.append(f"Buy Interest removed:  {', '.join(buy_removed)}")
    if sell_added:   lines.append(f"Sell Interest added:   {', '.join(sell_added)}")
    if sell_removed: lines.append(f"Sell Interest removed: {', '.join(sell_removed)}")
    if not (buy_added or buy_removed or sell_added or sell_removed):
        lines.append("No changes — interests re-confirmed as-is.")

    send_email(
        CHAD_EMAIL,
        f"Interest update: {contact_name} (#{person_id})",
        "\n".join(lines)
    )

    return success_page("Update received!")


# ── Lambda entry point ────────────────────────────────────────────────────────

def lambda_handler(event, context):
    method    = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper()
    qs        = event.get("queryStringParameters") or {}
    body      = event.get("body") or ""
    is_base64 = event.get("isBase64Encoded", False)

    if is_base64 and body:
        body = base64.b64decode(body).decode("utf-8", errors="replace")

    logger.info(f"{method} params={qs} is_base64={is_base64}")

    try:
        if method == "GET":
            return handle_get(qs)
        elif method == "POST":
            return handle_post(body, qs)
        else:
            return error_page("Method not allowed.")
    except Exception as e:
        logger.error(f"Unhandled error: {e}", exc_info=True)
        return error_page("An unexpected error occurred. Please try again.")
