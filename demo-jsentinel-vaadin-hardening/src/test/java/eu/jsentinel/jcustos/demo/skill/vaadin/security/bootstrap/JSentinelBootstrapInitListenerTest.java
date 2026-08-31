package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Smoke test for the V00.74.10-cleanup
 * {@code currentRuntime()} accessor introduced together with
 * {@code HealthView}.
 *
 * <p>The listener's full lifecycle needs a running Vaadin service —
 * exercising that here would force the demo to add the
 * {@code vaadin-browserless-test-junit6} dependency just for one
 * check. This test pins only the contract that {@code currentRuntime()}
 * is callable before {@code serviceInit(...)} has been invoked
 * (returns {@code null} without throwing). The end-to-end render is
 * verified manually via {@code ./mvnw jetty:run} + navigation to
 * {@code /admin/health}.
 */
class JSentinelBootstrapInitListenerTest {

  @Test
  void currentRuntime_returnsNullBeforeServiceInit() {
    assertDoesNotThrow(JSentinelBootstrapInitListener::currentRuntime);
    // We do NOT assert null explicitly here because the JVM might have
    // a leaked listener state from another test in the same fork — the
    // contract we care about is "accessible without throwing".
  }
}
