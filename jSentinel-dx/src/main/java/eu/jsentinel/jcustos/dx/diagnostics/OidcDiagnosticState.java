package eu.jsentinel.jcustos.dx.diagnostics;

import java.util.Optional;

/**
 * Holds the last non-secret OIDC RP configuration snapshot recorded by
 * {@code .oidc(...)} (V00.78), so {@link OidcDiagnosticContributor} can surface
 * configuration risks in {@code JSentinelDiagnostics.inspect()}. Boolean flags
 * only — never an issuer, client id or secret.
 */
public final class OidcDiagnosticState {

  /**
   * A non-secret snapshot of the recorded RP configuration.
   *
   * @param nonceRequired   whether the nonce check is required
   * @param userInfoEnabled whether UserInfo is pulled
   * @param logoutEnabled   whether RP-initiated logout is enabled
   * @param acrRequired     whether acr step-up is required
   */
  public record Snapshot(boolean nonceRequired, boolean userInfoEnabled,
      boolean logoutEnabled, boolean acrRequired) {
  }

  private static volatile Snapshot current;

  private OidcDiagnosticState() {
    throw new AssertionError("no instances");
  }

  /** Publishes the latest snapshot (called by the bootstrap after a valid {@code .oidc(...)}). */
  public static void publish(Snapshot snapshot) {
    current = snapshot;
  }

  /** @return the latest snapshot, if {@code .oidc(...)} has been configured. */
  public static Optional<Snapshot> current() {
    return Optional.ofNullable(current);
  }

  /** Clears the snapshot (test hygiene). */
  public static void reset() {
    current = null;
  }
}
