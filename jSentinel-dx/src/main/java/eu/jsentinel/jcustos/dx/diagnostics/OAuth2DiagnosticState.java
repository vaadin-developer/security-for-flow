package eu.jsentinel.jcustos.dx.diagnostics;

import java.util.Optional;

/**
 * Holds the last non-secret OAuth2 Relying-Party configuration snapshot recorded
 * by {@code .oauth2(...)} (V00.77), so {@link OAuth2DiagnosticContributor} can
 * surface configuration risks in {@code JCustosDiagnostics.inspect()}. Only
 * boolean flags are kept — never a client id, endpoint URI or any secret.
 */
public final class OAuth2DiagnosticState {

  /**
   * A non-secret snapshot of the recorded RP configuration.
   *
   * @param publicClient              true when the RP authenticates with no client secret (PKCE-only)
   * @param pkceRequired              whether PKCE is required
   * @param introspectionConfigured   whether an introspection endpoint was set
   * @param introspectionCacheDisabled whether the introspection cache TTL is zero
   */
  public record Snapshot(boolean publicClient, boolean pkceRequired,
      boolean introspectionConfigured, boolean introspectionCacheDisabled) {
  }

  private static volatile Snapshot current;

  private OAuth2DiagnosticState() {
    throw new AssertionError("no instances");
  }

  /** Publishes the latest snapshot (called by the bootstrap after a valid {@code .oauth2(...)}). */
  public static void publish(Snapshot snapshot) {
    current = snapshot;
  }

  /** @return the latest snapshot, if {@code .oauth2(...)} has been configured. */
  public static Optional<Snapshot> current() {
    return Optional.ofNullable(current);
  }

  /** Clears the snapshot (test hygiene). */
  public static void reset() {
    current = null;
  }
}
