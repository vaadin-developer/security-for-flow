/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.runtime;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosRuntime tooling API (V00.74.10 / Prompts 003-006)")
class JCustosRuntimeToolingApiTest {

  // ── summary() ───────────────────────────────────────────────────

  @Test
  @DisplayName("summary — empty runtime is OK with all zeros")
  void summary_empty_isOk() {
    JCustosRuntime r = new JCustosRuntime(List.of(), List.of(), JCustosBootstrapMode.PRODUCTION);
    assertEquals("OK | 0 services | 0 errors | 0 warnings | 0 INFO", r.summary());
  }

  @Test
  @DisplayName("summary — counts each severity bucket independently")
  void summary_countsSeverities() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(svc(), svc(), svc()),
        List.of(warn(Severity.WARNING), warn(Severity.WARNING), warn(Severity.INFO)),
        JCustosBootstrapMode.PRODUCTION);
    assertEquals("OK | 3 services | 0 errors | 2 warnings | 1 INFO", r.summary());
  }

  @Test
  @DisplayName("summary — any ERROR flips the status to FAIL")
  void summary_errorMakesFail() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(),
        List.of(warn(Severity.ERROR), warn(Severity.WARNING)),
        JCustosBootstrapMode.STRICT);
    assertEquals("FAIL | 0 services | 1 errors | 1 warnings | 0 INFO", r.summary());
  }

  // ── toMap() ─────────────────────────────────────────────────────

  @Test
  @DisplayName("toMap — keys appear in deterministic insertion order")
  void toMap_keyOrderIsStable() {
    JCustosRuntime r = new JCustosRuntime(List.of(svc()), List.of(warn(Severity.INFO)),
        JCustosBootstrapMode.PRODUCTION);
    List<String> keys = new ArrayList<>(r.toMap().keySet());
    assertEquals(List.of("mode", "serviceCount", "services", "warningCount", "warnings"), keys);
  }

  @Test
  @DisplayName("toMap — counts match the underlying lists")
  void toMap_countsMatch() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(svc(), svc()),
        List.of(warn(Severity.WARNING), warn(Severity.INFO), warn(Severity.ERROR)),
        JCustosBootstrapMode.STRICT);
    Map<String, Object> m = r.toMap();
    assertEquals("STRICT", m.get("mode"));
    assertEquals(2, m.get("serviceCount"));
    assertEquals(3, m.get("warningCount"));
    assertInstanceOf(List.class, m.get("services"));
    assertInstanceOf(List.class, m.get("warnings"));
    assertEquals(2, ((List<?>) m.get("services")).size());
    assertEquals(3, ((List<?>) m.get("warnings")).size());
  }

  @Test
  @DisplayName("toMap — output is unmodifiable")
  void toMap_isUnmodifiable() {
    JCustosRuntime r = new JCustosRuntime(List.of(), List.of(), JCustosBootstrapMode.PRODUCTION);
    Map<String, Object> m = r.toMap();
    assertThrows(UnsupportedOperationException.class, () -> m.put("x", "y"));
  }

  @Test
  @DisplayName("toMap — service entry exposes spi/impl/source/defaulted")
  void toMap_serviceEntryShape() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(new RegisteredJCustosService(CharSequence.class, String.class, "ServiceLoader", true)),
        List.of(),
        JCustosBootstrapMode.PRODUCTION);
    Map<?, ?> service = (Map<?, ?>) ((List<?>) r.toMap().get("services")).get(0);
    assertEquals(CharSequence.class.getName(), service.get("spi"));
    assertEquals(String.class.getName(), service.get("impl"));
    assertEquals("ServiceLoader", service.get("source"));
    assertEquals(Boolean.TRUE, service.get("defaulted"));
  }

  @Test
  @DisplayName("toMap — warning entry exposes severity/code/message/suggestedFix")
  void toMap_warningEntryShape() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(),
        List.of(new JCustosBootstrapWarning(Severity.WARNING, "audit/missing-service", "no audit", "register one")),
        JCustosBootstrapMode.PRODUCTION);
    Map<?, ?> warning = (Map<?, ?>) ((List<?>) r.toMap().get("warnings")).get(0);
    assertEquals("WARNING", warning.get("severity"));
    assertEquals("audit/missing-service", warning.get("code"));
    assertEquals("no audit", warning.get("message"));
    assertEquals("register one", warning.get("suggestedFix"));
  }

  // ── toJson() ────────────────────────────────────────────────────

  @Test
  @DisplayName("toJson — empty runtime renders a complete object")
  void toJson_empty() {
    JCustosRuntime r = new JCustosRuntime(List.of(), List.of(), JCustosBootstrapMode.PRODUCTION);
    String json = r.toJson();
    assertEquals(
        "{\"mode\":\"PRODUCTION\",\"serviceCount\":0,\"services\":[],\"warningCount\":0,\"warnings\":[]}",
        json);
  }

  @Test
  @DisplayName("toJson — escapes quotes + backslashes in strings")
  void toJson_escapesStrings() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(),
        List.of(new JCustosBootstrapWarning(Severity.WARNING, "a/b", "with \"quotes\" and \\backslash", "fix")),
        JCustosBootstrapMode.PRODUCTION);
    String json = r.toJson();
    assertTrue(json.contains("\\\"quotes\\\""), json);
    assertTrue(json.contains("\\\\backslash"), json);
  }

  // ── healthCheck() ───────────────────────────────────────────────

  @Test
  @DisplayName("healthCheck — empty + INFO only → HEALTHY")
  void healthCheck_empty_isHealthy() {
    JCustosRuntime r = new JCustosRuntime(List.of(), List.of(), JCustosBootstrapMode.PRODUCTION);
    assertEquals(Health.HEALTHY, r.healthCheck().overall());
  }

  @Test
  @DisplayName("healthCheck — INFO alone does NOT degrade")
  void healthCheck_infoOnly_stillHealthy() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(),
        List.of(warn(Severity.INFO), warn(Severity.INFO)),
        JCustosBootstrapMode.PRODUCTION);
    HealthStatus s = r.healthCheck();
    assertEquals(Health.HEALTHY, s.overall());
    assertEquals(2, s.findings().size());
    assertFalse(s.hasErrors());
    assertFalse(s.isDegraded());
  }

  @Test
  @DisplayName("healthCheck — any WARNING (no ERROR) → DEGRADED")
  void healthCheck_warning_isDegraded() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(),
        List.of(warn(Severity.INFO), warn(Severity.WARNING)),
        JCustosBootstrapMode.PRODUCTION);
    HealthStatus s = r.healthCheck();
    assertEquals(Health.DEGRADED, s.overall());
    assertTrue(s.isDegraded());
    assertFalse(s.hasErrors());
  }

  @Test
  @DisplayName("healthCheck — any ERROR wins over any WARNING")
  void healthCheck_error_isFailed() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(),
        List.of(warn(Severity.INFO), warn(Severity.WARNING), warn(Severity.ERROR)),
        JCustosBootstrapMode.STRICT);
    HealthStatus s = r.healthCheck();
    assertEquals(Health.FAILED, s.overall());
    assertTrue(s.hasErrors());
    assertFalse(s.isDegraded());
  }

  @Test
  @DisplayName("healthCheck — findings count + registeredServices match the runtime")
  void healthCheck_countsMatch() {
    JCustosRuntime r = new JCustosRuntime(
        List.of(svc(), svc(), svc()),
        List.of(warn(Severity.WARNING)),
        JCustosBootstrapMode.PRODUCTION);
    HealthStatus s = r.healthCheck();
    assertEquals(3, s.registeredServices());
    assertEquals(1, s.findings().size());
    assertNotNull(s.inspectedAt());
  }

  // ── fixtures ────────────────────────────────────────────────────

  private static RegisteredJCustosService svc() {
    return new RegisteredJCustosService(Object.class, String.class, "test", false);
  }

  private static JCustosBootstrapWarning warn(Severity s) {
    return new JCustosBootstrapWarning(s, "test-code", "test message", "test fix");
  }
}
