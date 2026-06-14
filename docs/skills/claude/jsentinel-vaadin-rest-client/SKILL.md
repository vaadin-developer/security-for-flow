---
name: jsentinel-vaadin-rest-client
description: Hybrid skill — patches the `jsentinel-vaadin` output so the Vaadin frontend delegates authentication and authorization to an existing jSentinel-secured REST backend (built with the `jsentinel-rest` skill). Replaces the local `UserDirectory`-backed `AuthenticationService` with an HTTP-client variant that POSTs `/api/auth/login` and stores the returned Bearer token in the Vaadin session; replaces `AuthorizationService` so role/permission lookups consult `/api/whoami`; the `AdminRolesView` proxies its CRUD to the REST endpoints. Prerequisite: a project that already ran `jsentinel-vaadin`. The REST backend URL is the only required slot. Adds NO new persistence (server holds the truth), removes the local `UserDirectory*` and `InMemoryUserDirectory` from the previous output (the Vaadin app no longer keeps users locally). Does NOT cover offline mode, retry policies, refresh-token rotation — those belong on the REST side or in a separate hardening skill.
---

# jSentinel Vaadin → REST backend — hybrid

A small additive skill that turns the layer-1 `jsentinel-vaadin`
output into a "thin Vaadin frontend" that talks to a `jsentinel-rest`
backend. The Vaadin app keeps its UI shell (`MainLayout`,
`PublicHomeView`, `DashboardView`, admin views), but every
authentication / role / user-management call routes through HTTP.

## Slots

| Slot | Default |
|---|---|
| `{{REST_BASE_URL}}` | `http://localhost:8081` |

## Templates

| Template | Target | Source |
|---|---|---|
| `RestBackendClient.java.tmpl` | `security/RestBackendClient.java` | NEW |
| `AuthenticationService.java.tmpl` | OVERWRITE existing | NEW |
| `AuthorizationService.java.tmpl` | OVERWRITE existing | NEW |

Delete after applying:
- `security/model/InMemoryUserDirectory.java`
- `security/model/UserDirectory.java`
- `security/model/UserDirectoryProvider.java`

## Architecture

```
Vaadin frontend                          REST backend (jsentinel-rest)
  MyAuthenticationService    POST /api/auth/login
    → RestBackendClient   ──────────────→ AuthHandler.login
                                            ↓
                          ← {"token":"...","user":"..."}
    → store token in VaadinSession

  MyAuthorizationService     GET /api/whoami (Bearer)
    → RestBackendClient   ──────────────→ AuthHandler.whoami
                          ← {"roles":[...],"permissions":[...]}
```

The `RestBackendClient` is a thin `HttpClient` wrapper. Token lives
in `VaadinSession.getCurrent().setAttribute("jsentinel.token", t)`
so every later authz check can include the `Authorization: Bearer`
header.

## Pitfalls

### Server holds the truth

Once this skill is applied the Vaadin module no longer has any local
users. Pre-seeded admin/admin only works because the REST backend
seeded it. The Vaadin's own `MainLayout` drawer / `SecuredUi`
visibility still works because the role / permission set is fetched
from `/api/whoami` and stored on the subject in the SubjectStore.

### Test seam

For Vaadin browser-tests, start an in-process `RestServer` (from
`demo-jsentinel-rest`) on a different port and inject the URL via
the slot — that's the demo pattern in
`demo-jsentinel-vaadin-rest-client`.
