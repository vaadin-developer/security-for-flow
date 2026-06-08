# Decision table — V00.72 DX

| Situation | Recommended path |
|---|---|
| Interface available, want runtime proxy | `SecuredProxy.wrap(...)` |
| Concrete class without interface | `@Secured` + generated `<Type>Secured` wrapper (security-processor) |
| Vaadin button / link / menu | `SecuredUi.button(...) / .link() / .menuItem(...)` |
| ServiceLoader configuration | `@SecurityAutoService` |
| Bootstrap-side wiring | `VaadinSecurity.bootstrap()` / `RestSecurity.bootstrap()` / `StandaloneSecurity.bootstrap()` |
| Production setup | Adapter facade + `productionDefaults()` profile + `SecurityDiagnostics.inspect()` for sanity |

## When to use

- **`SecuredProxy`** — small interface, dynamic-proxy is fine; runtime
  cost is negligible. Test fixtures love this.
- **`@Secured` + `<Type>Secured`** — production hot path, no interface,
  zero per-call reflection. Catches `final` / `private` / `static`
  guarded methods at compile time.
- **`SecuredUi.*`** — declarative Vaadin UI. Hides / disables on a
  denied subject without imperative `if`-trees.
- **`@SecurityAutoService`** — drops the burden of hand-written
  `META-INF/services` files for every SPI implementation.
- **Adapter facades** — typed fluent bootstrap; same `CommonSecurityBootstrap<B>`
  contract across Vaadin, REST and Standalone.

## When NOT to use

- Don't use `SecuredProxy` if you can use `@Secured`: the compile-time
  path is always faster and clearer.
- Don't use `@SecurityAutoService` for SPIs you intentionally want to
  *not* register globally (e.g. test doubles).
- Don't use `SecuredUi.requiresPolicy(...)` in V00.72 — the underlying
  `SecuredVisibility.Requirement` does not yet model policy enforcement.
  Use `@SecureRoute(policy = ...)` on the route class instead.
