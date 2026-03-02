"""
Minimal reproduction of a second Rootly Python SDK bug on the UPDATE path.

Bug:  UpdateAlertsSource.from_dict() raises TypeError when an urgency rule
      in the payload has conditionable_type=None (null).

      This is the same root cause as the previously reported and fixed bug
      on the GET/list response path (AlertsSourceAlertSourceUrgencyRulesAttributesItem).
      The vendor fixed the read-path check functions, but the corresponding
      check functions on the UPDATE path were not fixed.

Affected module (NOT yet fixed):
  rootly_sdk/models/
  update_alerts_source_data_attributes_alert_source_urgency_rules_attributes_item_conditionable_type.py

Already fixed (by vendor, in a prior release):
  rootly_sdk/models/
  alerts_source_alert_source_urgency_rules_attributes_item_conditionable_type.py

SDK version: rootly>=1.1.0  (check with: pip show rootly)
Python:       3.x
Reported:     2026-03-02

Steps to reproduce
------------------
1. Call GET /v1/alert_sources to fetch an alert source whose urgency rule has
   conditionable_type=null (the Rootly API legitimately returns null here when
   the rule was created without specifying a conditionable).
2. Take the fetched attributes dict and pass it to UpdateAlertsSource.from_dict()
   — as you would when implementing an idempotent import (read → compare → write).

The fix applied to the read path (adding a `if value is None: return None` guard)
should be applied identically to all three UPDATE-path check functions:
  - check_update_alerts_source_data_attributes_alert_source_urgency_rules_attributes_item_conditionable_type
  - check_update_alerts_source_data_attributes_alert_source_urgency_rules_attributes_item_operator
  - check_update_alerts_source_data_attributes_alert_source_urgency_rules_attributes_item_kind

Expected behaviour: null conditionable_type (and null operator/kind) should be
                    treated as absent/unset, matching the read-path behaviour.
Actual behaviour:   TypeError is raised inside from_dict(), aborting the update.
"""

import os
import sys

from rootly_sdk import AuthenticatedClient
from rootly_sdk.api.alert_sources import list_alerts_sources
from rootly_sdk.models.update_alerts_source import UpdateAlertsSource

# ---------------------------------------------------------------------------
# Part 1: Model-level reproduction (no API key required)
# ---------------------------------------------------------------------------

print("=== Part 1: Model-level reproduction (no API key needed) ===\n")

# This is the exact shape of a payload you would construct when round-tripping
# a GET response into a PATCH/update call.  The Rootly API legitimately returns
# conditionable_type=null for urgency rules that have no conditionable set.
update_payload_with_null_conditionable = {
    "data": {
        "type": "alert_sources",
        "attributes": {
            "name": "My Alert Source",
            "source_type": "sentry",
            "alert_source_urgency_rules_attributes": [
                {
                    "json_path": "$.data.action",
                    "operator": "is_not",      # valid SDK value
                    "value": "critical",
                    "conditionable_type": None, # <-- null as returned by the API
                    "conditionable_id": None,
                    "kind": "payload",          # valid SDK value
                    "alert_urgency_id": "00000000-0000-0000-0000-000000000001",
                }
            ],
        },
    }
}

print("Calling UpdateAlertsSource.from_dict() with an urgency rule that has")
print("conditionable_type=None (as returned by the Rootly API) ...\n")

try:
    payload = UpdateAlertsSource.from_dict(update_payload_with_null_conditionable)
    print("SUCCESS (unexpected — bug may be fixed in this SDK version)")
except TypeError as exc:
    print(f"TypeError raised (bug confirmed):\n  {exc}\n")
    print(
        "Root cause:\n"
        "  check_update_alerts_source_data_attributes_alert_source_urgency_rules_\n"
        "  attributes_item_conditionable_type() does not handle None.\n\n"
        "The same guard added to the read-path fix should be applied here:\n"
        "  if value is None:\n"
        "      return None\n\n"
        "Affected file:\n"
        "  rootly_sdk/models/update_alerts_source_data_attributes_alert_source_\n"
        "  urgency_rules_attributes_item_conditionable_type.py  (line 12)\n\n"
        "Same fix needed in the operator and kind variants of that module."
    )

# ---------------------------------------------------------------------------
# Part 2: Live API reproduction (requires ROOTLY_API_KEY in environment)
# ---------------------------------------------------------------------------

print("\n=== Part 2: Live API reproduction (requires ROOTLY_API_KEY) ===\n")

api_key = os.environ.get("ROOTLY_API_KEY")
if not api_key:
    print("ROOTLY_API_KEY not set — skipping live API test.")
    print("To run the live test:  ROOTLY_API_KEY=<key> python repro_update_sdk_bug.py")
    sys.exit(0)

client = AuthenticatedClient(base_url="https://api.rootly.com", token=api_key)

print("Step 1: Fetching alert sources via GET /v1/alert_sources ...")
with client as c:
    response = list_alerts_sources.sync_detailed(client=c, pagesize=100)

if response.status_code != 200 or response.parsed is None:
    print(f"Failed to fetch alert sources: {response.status_code}")
    sys.exit(1)

sources = response.parsed.data
print(f"  Fetched {len(sources)} alert source(s).\n")

# Find one that has urgency rules with conditionable_type=None.
target = None
for source in sources:
    rules = source.attributes.alert_source_urgency_rules_attributes
    if rules and rules is not __import__("rootly_sdk.types", fromlist=["UNSET"]).UNSET:
        for rule in rules:
            if rule.conditionable_type is None:
                target = source
                break
    if target:
        break

if target is None:
    print(
        "No alert source with a null-conditionable_type urgency rule found on this account.\n"
        "Part 1 above already demonstrates the bug at the model level.\n"
        "To trigger it with live data, create an alert source with a payload-based\n"
        "urgency rule (conditionable_type is typically null for those)."
    )
    sys.exit(0)

print(f"Step 2: Found alert source '{target.attributes.name}' (id: {target.id})")
print("        with an urgency rule that has conditionable_type=None.\n")

# Simulate what an idempotent import script does: take the GET response attributes
# and feed them into UpdateAlertsSource.from_dict() to build an update payload.
raw_attrs = target.attributes.to_dict()
# Strip server-generated top-level fields (status, secret, etc.) — same as an
# import script would do — but intentionally leave conditionable_type=None in
# the urgency rules to trigger the bug.
for key in ("status", "secret", "created_at", "updated_at", "email", "webhook_endpoint"):
    raw_attrs.pop(key, None)

print("Step 3: Calling UpdateAlertsSource.from_dict() with the raw GET response")
print("        attributes (conditionable_type=None still present in urgency rules) ...")

try:
    payload = UpdateAlertsSource.from_dict({
        "data": {
            "type": "alert_sources",
            "attributes": raw_attrs,
        }
    })
    print("\nSUCCESS (unexpected — bug may be fixed in this SDK version)")
except TypeError as exc:
    print(f"\nTypeError raised (bug confirmed):\n  {exc}")
    print(
        "\nThis error occurs when trying to use data fetched from the Rootly API\n"
        "directly in an update call — a natural pattern for idempotent management\n"
        "scripts.  The GET response path was fixed in a prior release; the UPDATE\n"
        "path (update_alerts_source_data_attributes_..._conditionable_type.py)\n"
        "needs the same fix."
    )
