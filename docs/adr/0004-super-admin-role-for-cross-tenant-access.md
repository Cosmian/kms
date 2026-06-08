# Super-admin role for cross-tenant operations

A distinct `super-admin` role sits above `admin` in the hierarchy and is the only role that
bypasses the tenant boundary. Admin remains tenant-scoped by default. Super-admin is granted
via server configuration (not IdP claims), making it a break-glass mechanism for platform
operators who need cross-tenant visibility.

## Considered Options

- **Tenant-list claim in JWT**: The IdP token carries an explicit list of accessible tenant IDs.
  Locate uses `WHERE tenant_id IN (...)`. Rejected because it requires IdP cooperation for every
  cross-tenant admin, and there's no way to express "all tenants" without a magic value.
- **Null-tenant = global scope**: If `subject.tenant_id` is null and role is admin, skip the
  tenant filter. Rejected because null-tenant is already used for "missing claim" scenarios
  (service accounts, misconfigured IdP) and overloading it creates ambiguity.
- **Super-admin role (chosen)**: Explicit, named, server-config-granted. The DB query for
  super-admin has no `WHERE tenant_id` clause. Policy can still restrict super-admin via
  algorithm allowlists or other rules.

## Consequences

- The role hierarchy becomes 4 levels: super-admin > admin > operator > auditor. All policy
  bundles (default and custom) must account for this.
- Super-admin membership is declared in server config, not the IdP. This means platform
  operators don't need IdP admin access to grant break-glass cross-tenant privileges.
- Audit logs for super-admin actions should be flagged distinctly (cross-tenant operations
  are high-sensitivity events).
