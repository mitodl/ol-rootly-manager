import argparse
import importlib.util
import os
import pprint

from rootly_sdk import AuthenticatedClient
from rootly_sdk.api.services import create_service, list_services, update_service
from rootly_sdk.api.roles import create_role, list_roles, update_role
from rootly_sdk.models.new_service import NewService
from rootly_sdk.models.new_role import NewRole
from rootly_sdk.models.update_service import UpdateService
from rootly_sdk.models.update_role import UpdateRole
from rootly_sdk.types import UNSET

DATA_FILE = os.path.join(os.path.dirname(__file__), "data.py")

# Writable service fields that are readable from the Service response model.
# Excludes read-only fields (created_at, updated_at, slug, alerts_email_address)
# and fields present in NewServiceDataAttributes but absent from Service
# (opsgenie_team_id, show_uptime, show_uptime_last_days).
_SERVICE_SIMPLE_WRITABLE = [
    "name", "description", "public_description", "notify_emails", "color", "position",
    "backstage_id", "pagerduty_id", "external_id", "opsgenie_id", "cortex_id",
    "service_now_ci_sys_id", "github_repository_name", "github_repository_branch",
    "gitlab_repository_name", "gitlab_repository_branch", "environment_ids",
    "service_ids", "owner_group_ids", "owner_user_ids", "kubernetes_deployment_name",
    "alerts_email_enabled", "alert_urgency_id", "escalation_policy_id",
    "alert_broadcast_enabled", "incident_broadcast_enabled",
]

# All writable permission list fields on roles.
_ROLE_PERMISSION_FIELDS = [
    "alerts_permissions", "api_keys_permissions", "audits_permissions",
    "billing_permissions", "environments_permissions", "form_fields_permissions",
    "functionalities_permissions", "groups_permissions", "incident_causes_permissions",
    "incident_feedbacks_permissions", "incident_roles_permissions", "incident_types_permissions",
    "incidents_permissions", "integrations_permissions", "invitations_permissions",
    "playbooks_permissions", "private_incidents_permissions", "pulses_permissions",
    "retrospective_permissions", "roles_permissions", "secrets_permissions",
    "services_permissions", "severities_permissions", "status_pages_permissions",
    "webhooks_permissions", "workflows_permissions",
]


# --- Pagination helpers ---

def fetch_all_services(client: AuthenticatedClient) -> list:
    """Fetch every service from Rootly, handling pagination."""
    items = []
    page = 1
    while True:
        response = list_services.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"Error fetching services (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        if response.parsed.links.next_ is None:
            break
        page += 1
    return items


def fetch_all_roles(client: AuthenticatedClient) -> list:
    """Fetch every role from Rootly, handling pagination."""
    items = []
    page = 1
    while True:
        response = list_roles.sync_detailed(client=client, pagenumber=page, pagesize=100)
        if response.status_code != 200 or response.parsed is None:
            print(f"Error fetching roles (page {page}): {response.status_code}")
            break
        items.extend(response.parsed.data)
        if response.parsed.links.next_ is None:
            break
        page += 1
    return items


# --- Conversion helpers ---

def service_to_writable_dict(item) -> dict:
    """Extract only writable attributes from a ServiceListDataItem."""
    attrs = item.attributes
    d = {}

    for field in _SERVICE_SIMPLE_WRITABLE:
        val = getattr(attrs, field)
        if val is not UNSET and val is not None:
            d[field] = val

    # Complex fields whose values are SDK objects that need serialization.
    if attrs.slack_channels is not UNSET and attrs.slack_channels is not None:
        d["slack_channels"] = [ch.to_dict() for ch in attrs.slack_channels]
    if attrs.slack_aliases is not UNSET and attrs.slack_aliases is not None:
        d["slack_aliases"] = [a.to_dict() for a in attrs.slack_aliases]
    if attrs.alert_broadcast_channel is not UNSET and attrs.alert_broadcast_channel is not None:
        d["alert_broadcast_channel"] = attrs.alert_broadcast_channel.to_dict()
    if attrs.incident_broadcast_channel is not UNSET and attrs.incident_broadcast_channel is not None:
        d["incident_broadcast_channel"] = attrs.incident_broadcast_channel.to_dict()

    return d


def role_to_writable_dict(item) -> dict:
    """Extract only writable attributes from a RoleListDataItem."""
    attrs = item.attributes
    # name and slug are always present on a Role response.
    d = {"name": attrs.name, "slug": attrs.slug}

    if attrs.incident_permission_set_id is not UNSET and attrs.incident_permission_set_id is not None:
        d["incident_permission_set_id"] = attrs.incident_permission_set_id

    for field in _ROLE_PERMISSION_FIELDS:
        val = getattr(attrs, field)
        # val is a list (possibly empty); only include if non-empty.
        if val is not UNSET and len(val) > 0:
            d[field] = list(val)

    return d


# --- Report field specs ---
#
# Each entry is a (label, extractor_fn) tuple where:
#   extractor_fn(item, context) -> str
#
# 'context' is a dict with:
#   "id_to_name": dict[str, str]  - maps service id -> service name
#
# The first field in each list is printed as the item heading (no label/indent).
# All subsequent fields are printed indented with aligned labels.
# To add a new field, append a tuple here.

def _resolve_service_names(ids, id_to_name: dict) -> str:
    if not ids or ids is UNSET:
        return "(none)"
    return ", ".join(id_to_name.get(sid, sid) for sid in ids)


SERVICE_REPORT_FIELDS = [
    ("Name",         lambda item, ctx: item.attributes.name),
    ("ID",           lambda item, ctx: item.id),
    ("Dependencies", lambda item, ctx: _resolve_service_names(
        item.attributes.service_ids
        if item.attributes.service_ids not in (None, UNSET)
        else [],
        ctx["id_to_name"],
    )),
]

ROLE_REPORT_FIELDS = [
    ("Name", lambda item, ctx: item.attributes.name),
    ("Slug", lambda item, ctx: item.attributes.slug),
]


def print_report(client: AuthenticatedClient) -> None:
    """Print a human-readable report of all services and roles."""
    print("Fetching all services...")
    service_items = fetch_all_services(client)
    print("Fetching all roles...")
    role_items = fetch_all_roles(client)

    id_to_name = {item.id: item.attributes.name for item in service_items}
    context = {"id_to_name": id_to_name}

    svc_label_width = max((len(label) for label, _ in SERVICE_REPORT_FIELDS[1:]), default=0)
    role_label_width = max((len(label) for label, _ in ROLE_REPORT_FIELDS[1:]), default=0)

    print(f"\nServices ({len(service_items)})")
    print("=" * 60)
    for item in service_items:
        heading_label, heading_fn = SERVICE_REPORT_FIELDS[0]
        print(heading_fn(item, context))
        for label, extractor in SERVICE_REPORT_FIELDS[1:]:
            print(f"  {label:<{svc_label_width}}: {extractor(item, context)}")
        print()

    print(f"\nRoles ({len(role_items)})")
    print("=" * 60)
    for item in role_items:
        heading_label, heading_fn = ROLE_REPORT_FIELDS[0]
        print(heading_fn(item, context))
        for label, extractor in ROLE_REPORT_FIELDS[1:]:
            print(f"  {label:<{role_label_width}}: {extractor(item, context)}")
        print()


# --- Export ---

def export_to_data_file(client: AuthenticatedClient) -> None:
    """Fetch all services and roles from Rootly and overwrite data.py."""
    print("Fetching all services...")
    service_items = fetch_all_services(client)
    services = [service_to_writable_dict(s) for s in service_items]
    print(f"  Fetched {len(services)} services.")

    print("Fetching all roles...")
    role_items = fetch_all_roles(client)
    roles = [role_to_writable_dict(r) for r in role_items]
    print(f"  Fetched {len(roles)} roles.")

    services_repr = pprint.pformat(services, indent=4, sort_dicts=False)
    roles_repr = pprint.pformat(roles, indent=4, sort_dicts=False)
    content = f"SERVICES = {services_repr}\n\nROLES = {roles_repr}\n"

    with open(DATA_FILE, "w") as f:
        f.write(content)

    print(f"\nWrote {len(services)} services and {len(roles)} roles to {DATA_FILE}")


# --- Find helpers (used by ensure functions) ---

def find_existing_service(client: AuthenticatedClient, name: str) -> str | None:
    """Find a service by name and return its id, or None if not found."""
    response = list_services.sync_detailed(client=client, filtername=name)
    if response.status_code != 200 or response.parsed is None:
        return None
    for svc in response.parsed.data:
        if svc.attributes.name == name:
            return svc.id
    return None


def find_existing_role(client: AuthenticatedClient, name: str) -> str | None:
    """Find a role by name and return its id, or None if not found."""
    response = list_roles.sync_detailed(client=client, filtername=name)
    if response.status_code != 200 or response.parsed is None:
        return None
    for r in response.parsed.data:
        if r.attributes.name == name:
            return r.id
    return None


# --- Ensure (idempotent create/update) ---

def ensure_service(client: AuthenticatedClient, service_dict: dict) -> None:
    """Create a service if it doesn't exist, or update it if it does."""
    name = service_dict["name"]
    existing_id = find_existing_service(client, name)

    if existing_id is not None:
        payload = UpdateService.from_dict({
            "data": {
                "type": "services",
                "attributes": service_dict,
            }
        })
        response = update_service.sync_detailed(
            existing_id, client=client, body=payload
        )
        if response.status_code == 200:
            print(f"Updated service: {name} (id: {existing_id})")
        else:
            print(f"Failed to update service '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")
    else:
        payload = NewService.from_dict({
            "data": {
                "type": "services",
                "attributes": service_dict,
            }
        })
        response = create_service.sync_detailed(client=client, body=payload)
        if response.status_code == 201:
            result = response.parsed
            print(f"Created service: {name} (id: {result.data.id})")
        else:
            print(f"Failed to create service '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")


def ensure_role(client: AuthenticatedClient, role_dict: dict) -> None:
    """Create a role if it doesn't exist, or update it if it does."""
    name = role_dict["name"]
    existing_id = find_existing_role(client, name)

    if existing_id is not None:
        payload = UpdateRole.from_dict({
            "data": {
                "type": "roles",
                "attributes": role_dict,
            }
        })
        response = update_role.sync_detailed(
            existing_id, client=client, body=payload
        )
        if response.status_code == 200:
            print(f"Updated role: {name} (id: {existing_id})")
        else:
            print(f"Failed to update role '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")
    else:
        payload = NewRole.from_dict({
            "data": {
                "type": "roles",
                "attributes": role_dict,
            }
        })
        response = create_role.sync_detailed(client=client, body=payload)
        if response.status_code == 201:
            result = response.parsed
            print(f"Created role: {name} (id: {result.data.id})")
        else:
            print(f"Failed to create role '{name}': {response.status_code}")
            if response.parsed:
                print(f"  Error: {response.parsed}")


# --- Import ---

def load_data_file(path: str) -> tuple[list, list]:
    """Dynamically load SERVICES and ROLES from a Python file."""
    abs_path = os.path.abspath(path)
    spec = importlib.util.spec_from_file_location("_rootly_data", abs_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.SERVICES, module.ROLES


def run_import(client: AuthenticatedClient, path: str) -> None:
    """Load definitions from a file and ensure them in Rootly."""
    services, roles = load_data_file(path)
    print(f"Loaded {len(services)} services and {len(roles)} roles from {path}")

    print("\nEnsuring services...")
    for service_dict in services:
        ensure_service(client, service_dict)

    print("\nEnsuring roles...")
    for role_dict in roles:
        ensure_role(client, role_dict)


# --- Entry point ---

def main():
    parser = argparse.ArgumentParser(description="Manage Rootly services and roles")
    parser.add_argument(
        "--import",
        dest="import_file",
        nargs="?",
        const="data.py",
        default=None,
        metavar="FILE",
        help="Create/update services and roles from FILE (default: data.py)",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Fetch all services and roles from Rootly and overwrite data.py",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a report of all current services and roles",
    )
    args = parser.parse_args()

    if not (args.import_file or args.export or args.report):
        parser.print_help()
        return

    api_key = os.environ.get("ROOTLY_API_KEY")
    if not api_key:
        print("Error: ROOTLY_API_KEY environment variable not set")
        return

    client = AuthenticatedClient(
        base_url="https://api.rootly.com",
        token=api_key,
    )

    with client as client:
        if args.import_file:
            run_import(client, args.import_file)
        elif args.export:
            export_to_data_file(client)
        elif args.report:
            print_report(client)


if __name__ == "__main__":
    main()
