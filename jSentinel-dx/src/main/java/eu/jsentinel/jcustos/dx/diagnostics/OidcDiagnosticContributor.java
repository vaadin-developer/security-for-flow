package eu.jsentinel.jcustos.dx.diagnostics;

/**
 * Contributes the OIDC Relying-Party findings to {@code JCustosDiagnostics.inspect()}
 * (V00.78). Reads the non-secret {@link OidcDiagnosticState} snapshot recorded by
 * {@code .oidc(...)} and warns on the configuration risk that is silent at bootstrap
 * time: a disabled {@code nonce} check (the primary login-CSRF / replay defence for
 * the authorization-code flow). Registered via {@code META-INF/services}.
 */
public final class OidcDiagnosticContributor implements DiagnosticContributor {

  public OidcDiagnosticContributor() {
  }

  @Override
  public String id() {
    return "oidc";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    OidcDiagnosticState.current().ifPresent(snapshot -> {
      if (!snapshot.nonceRequired()) {
        builder.addWarning(new ServiceWarning(
            "oidc/nonce-disabled",
            "OIDC is configured with the nonce check disabled.",
            "Call .oidc(o -> o.requireNonce(true)) — nonce binds the ID token to the "
                + "authorization request and is the primary replay / login-CSRF defence."));
      }
    });
  }
}
