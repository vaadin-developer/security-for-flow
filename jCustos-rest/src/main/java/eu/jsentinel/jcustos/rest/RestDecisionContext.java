package eu.jsentinel.jcustos.rest;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Process-wide holder for the decision mapper a bootstrap configured.
 *
 * <p>Exists because the two layers cannot see each other directly: the
 * enforcing {@code RestAuthorizationFilter} lives in {@code jCustos-rest}
 * and applications construct it themselves, while
 * {@code RestJCustosBootstrap.decisionMapper(...)} lives one module up in
 * {@code jCustos-dx-rest}. Before V00.83 a configured mapper was recorded
 * for diagnostics and never reached the filter (JS-SEC-026); publishing
 * it here closes that gap without inverting the module dependency.
 *
 * <p>The filter reads this holder <strong>per request</strong> rather
 * than snapshotting it at construction, so an application may build its
 * filter before running the bootstrap — a real ordering, since
 * {@code DemoHttpRouter} holds its filter in a constructor field.
 *
 * <p>This is process-global state, and the most recent bootstrap owns it.
 * That matches how the framework treats every other pluggable service —
 * {@code JCustosServiceResolver.setSessionPolicy} and friends replace
 * rather than refuse — and it keeps repeated installs in one JVM (tests,
 * redeploys) working. It differs from {@code RestCorsContext}, which
 * compares record values and can therefore detect a genuine conflict; a
 * mapper is a service instance with no value identity, so every install
 * would look like a conflict.
 *
 * @since 00.83.00
 */
public final class RestDecisionContext {

  private static final AtomicReference<RestDecisionMapping> MAPPER =
      new AtomicReference<>();

  private RestDecisionContext() {
  }

  /**
   * Publishes the mapper the enforcement path should use, replacing any
   * previously published one.
   *
   * @param mapper the configured mapper (non-null)
   */
  public static void publish(RestDecisionMapping mapper) {
    MAPPER.set(java.util.Objects.requireNonNull(mapper, "mapper"));
  }

  /**
   * @return the published mapper, or empty when no bootstrap configured one
   */
  public static Optional<RestDecisionMapping> mapper() {
    return Optional.ofNullable(MAPPER.get());
  }

  /** Clears the holder. Intended for tests and redeploys. */
  public static void reset() {
    MAPPER.set(null);
  }
}
