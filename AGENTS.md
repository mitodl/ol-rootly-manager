# ol-rootly-manager Agent Guide

## Overview

This repository manages Rootly resources (services, alert sources, alert routes, escalation policies, etc.) as code via `data.py` and `main.py`. Changes are applied to Rootly by running `main.py --import`.

## Authentication

The Rootly API key is stored in 1Password:

```bash
export ROOTLY_API_KEY=$(op item get "Rootly API Key" --fields credential --reveal)
```

Then run any command with:

```bash
ROOTLY_API_KEY="$ROOTLY_API_KEY" uv run python main.py --import
```

## Key IDs

| Resource | Name | ID |
|----------|------|----|
| Team/Group | Platform Engineering | `9f00e9f1-2f13-470e-a856-50ab5003f260` |
| Escalation Policy | Default Escalation Policy | `96629210-cc41-4e57-b059-b182a0f01c5b` |
| Escalation Policy | QA Non-Paging Escalation Policy | `d63b7456-0d9f-44e8-80a5-4fc3df7e986b` |
| Alert Source | PIngdom (Pingdom) | `0b59c848-f764-4a31-a90f-1d473cc2b134` |
| Alert Source | Cloudwatch - Critical | `6e5745ec-7cef-4a20-a524-cb8829846167` |
| Alert Source | Cloudwatch - Warning | `40ceb0c8-93cb-438d-9c2a-7a19f79ef53b` |
| Alert Source | Grafana Prometheus - Production | `90cda8ea-ff34-4553-b0c3-8744ee74200d` |
| Alert Route | Pingdom Service Route | `548c23ea-bcc9-4a83-823e-1563aef5aa14` |
| Alert Route | Pingdom Catch-All Route | `0708c4a1-248a-409b-be08-02fb589c7868` |
| Alert Route | Cloudwatch Service Route | `61d2fb04-f85f-4d9c-a1bc-1a6afad7ca0f` |
| Alert Route | Grafana Service Route | `c1e812d2-e14b-4233-a368-c240e9a03d17` |
| Alert Route | Sentry Service Route | `57544c42-bef8-40f2-99bb-9e5041c0927f` |

## data.py Structure

`data.py` contains Python module-level lists:

- `SERVICES` — Rootly services (applications, databases, etc.)
- `ALERT_SOURCES` — inbound webhook integrations (Pingdom, Cloudwatch, Grafana, Sentry, etc.)
- `ALERT_ROUTES` — routing rules that direct alerts to services or escalation policies
- `ESCALATION_POLICIES` — on-call escalation chains

`main.py --import` reads `data.py` and creates/updates all resources via the Rootly API. Running `main.py --export` overwrites `data.py` with the current live state from Rootly (useful for syncing after UI changes).

## Alert Route Rules

Each alert route has a `rules` list. Rules are evaluated in `position` order. The last rule is typically `"fallback_rule": True`.

### Rule destinations

| `target_type` | Behavior |
|---------------|----------|
| `"Service"` | Alert assigned to the service; service's escalation policy is triggered (paging) |
| `"EscalationPolicy"` | Alert directly triggers the escalation policy (paging) |
| `"Group"` | Alert notifies group members via their personal preferences (non-paging) |

### Making an alert non-paging

Route the alert to `"Group"` with the Platform Engineering team ID instead of a `Service` or `EscalationPolicy`:

```python
{
    "alerts_source_id": None,
    "condition_type": "all",
    "enabled": True,
    "destination": {
        "target_type": "Group",
        "target_id": "9f00e9f1-2f13-470e-a856-50ab5003f260",
    },
    "owning_teams": [],
    "name": "My Check to Platform Engineering Team (Non-Paging)",
    "destinations": [
        {
            "target_type": "Group",
            "target_id": "9f00e9f1-2f13-470e-a856-50ab5003f260",
        }
    ],
    "condition_groups": [
        {
            "conditions": [
                {
                    "property_field_condition_type": "contains",
                    "property_field_type": "payload",
                    "property_field_name": "$.check_name",
                    "property_field_value": "My Check Name",
                    "property_field_values": [],
                    "conditionable_type": None,
                    "conditionable_id": None,
                }
            ],
            "position": 1,
        }
    ],
    "position": 23,  # insert before fallback; bump fallback position up by 1
    "fallback_rule": False,
},
```

### Pingdom check names

Pingdom alerts include `$.check_name` in their payload. To find the check name for a specific alert, look up the alert via the API:

```bash
curl -s -H "Authorization: Bearer $ROOTLY_API_KEY" "https://api.rootly.com/v1/alerts/<short_id>" | python3 -m json.tool
```

The `check_name` is under `data.data.check_name`.

### Important: services used as route destinations require an escalation policy

Rootly **rejects route updates** (422) if any rule in the route points to a `Service` that has no `escalation_policy_id`. If you see a 422 error like:

```
Rule '...': target_id Service being added as a destination needs to be attached to an Escalation Policy.
```

Fix the service in `data.py` by adding:

```python
"escalation_policy_id": "96629210-cc41-4e57-b059-b182a0f01c5b",
```

before the `alert_broadcast_enabled` line in the service's dict.

## Cloudwatch routing

Cloudwatch alert payloads use `$.Message.AlarmName`. Rules match on `AlarmName` substrings (e.g., `mitlearn`, `rds`, `elasticache`, `mitxonline`).

## Common workflows

### Add a new Pingdom routing rule for a service

1. Find the Pingdom check name by looking at a live alert in the Rootly UI or via the API.
2. Find or create the target service in `SERVICES` (ensure it has `escalation_policy_id` set).
3. Add a new rule dict to the Pingdom Service Route `rules` list in `ALERT_ROUTES`, positioned before the fallback rule.
4. Increment the fallback rule's `position` by 1.
5. Run `ROOTLY_API_KEY=... uv run python main.py --import`.

### Export current state from Rootly

```bash
ROOTLY_API_KEY=... uv run python main.py --export
```

This overwrites `data.py`. Review the diff before committing.

### Print a report of managed resources

```bash
ROOTLY_API_KEY=... uv run python main.py --report
```

### Look up a Rootly alert by short ID

```bash
ROOTLY_API_KEY=$(op item get "Rootly API Key" --fields credential --reveal)
curl -s -H "Authorization: Bearer $ROOTLY_API_KEY" "https://api.rootly.com/v1/alerts/<short_id>" | python3 -m json.tool
```

### Look up alert route details

```bash
curl -s -H "Authorization: Bearer $ROOTLY_API_KEY" "https://api.rootly.com/v1/alert_routes/<route_id>" | python3 -c "
import json, sys
d = json.load(sys.stdin)
rules = d['data']['attributes']['rules']
for rule in rules:
    dests = ', '.join(f'{x[\"target_type\"]}:{x[\"target_id\"]}' for x in rule.get('destinations', []))
    print(f'[{rule[\"position\"]}] {rule[\"name\"]} -> {dests}')
"
```
