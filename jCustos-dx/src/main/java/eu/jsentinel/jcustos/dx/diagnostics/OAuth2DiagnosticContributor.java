package eu.jsentinel.jcustos.dx.diagnostics;

/**
 * Contributes the OAuth2 Relying-Party findings to {@code JCustosDiagnostics.inspect()}
 * (Konzept §13.3, V00.77). Reads the non-secret {@link OAuth2DiagnosticState}
 * snapshot recorded by {@code .oauth2(...)} and warns on the two configuration
 * risks that are silent at bootstrap time: a public client that disabled PKCE,
 * and an introspection endpoint with caching switched off (a per-request
 * round-trip = DoS amplification). Registered via {@code META-INF/services}
 * (jCustos-dx carries no AutoService processor).
 */
public final class OAuth2DiagnosticContributor implements DiagnosticContributor {

  /** ServiceLoader requires a public no-arg constructor. */
  public OAuth2DiagnosticContributor() {
  }

  @Override
  public String id() {
    return "oauth2";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    OAuth2DiagnosticState.current().ifPresent(snapshot -> {
      if (snapshot.publicClient() && !snapshot.pkceRequired()) {
        builder.addWarning(new ServiceWarning(
            "oauth2/pkce-required-but-disabled",
            "A public OAuth2 client (no client secret) disabled PKCE.",
            "Call .oauth2(o -> o.pkceRequired(true)) — public clients must use PKCE (S256)."));
      }
      if (snapshot.introspectionConfigured() && snapshot.introspectionCacheDisabled()) {
        builder.addWarning(new ServiceWarning(
            "oauth2/introspection-cache-disabled",
            "Token introspection is configured with caching disabled (ttl = 0).",
            "Set a positive .introspectionCacheTtl(...) — uncached introspection is a per-request "
                + "round-trip and a DoS amplifier."));
      }
    });
  }
}
