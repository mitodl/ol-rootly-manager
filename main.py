import os

from rootly_sdk import AuthenticatedClient
from rootly_sdk.api.services import create_service, list_services, update_service
from rootly_sdk.api.roles import create_role, list_roles, update_role
from rootly_sdk.models.new_service import NewService
from rootly_sdk.models.new_role import NewRole
from rootly_sdk.models.update_service import UpdateService
from rootly_sdk.models.update_role import UpdateRole

from data import SERVICES, ROLES


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


def main():
    api_key = os.environ.get("ROOTLY_API_KEY")
    if not api_key:
        print("Error: ROOTLY_API_KEY environment variable not set")
        return

    client = AuthenticatedClient(
        base_url="https://api.rootly.com",
        token=api_key,
    )

    with client as client:
        print("Ensuring services...")
        for service_dict in SERVICES:
            ensure_service(client, service_dict)

        print("\nEnsuring roles...")
        for role_dict in ROLES:
            ensure_role(client, role_dict)


if __name__ == "__main__":
    main()
