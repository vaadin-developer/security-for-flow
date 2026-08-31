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
package eu.jsentinel.jcustos.dx.bootstrap;

import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.roles.RoleHierarchy;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.api.roles.StaticRoleHierarchy;
import eu.jsentinel.jcustos.dx.internal.AbstractJSentinelBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJSentinelService;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JSentinelRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("RoleBootstrap real surface (V00.73)")
class RoleBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".hierarchy(...) registers the hierarchy via JSentinelServiceResolver")
  void hierarchyRegistersAndAppearsInRuntime() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(new RoleName("ROLE_ADMIN")).inheritsFrom(new RoleName("ROLE_USER"))
        .role(new RoleName("ROLE_USER"))
        .build();

    JSentinelRuntime runtime = new TestBootstrap()
        .roles(r -> r.hierarchy(hierarchy))
        .install();

    assertSame(hierarchy, JSentinelServiceResolver.findRoleHierarchy().orElseThrow());
    boolean entry = runtime.services().stream()
        .anyMatch(s -> RoleHierarchy.class.equals(s.spi())
            && hierarchy.getClass().equals(s.impl())
            && "bootstrap-explicit".equals(s.source()));
    assertTrue(entry, "expected RoleHierarchy entry in runtime");
  }

  @Test
  @DisplayName("empty .roles(r -> {}) records INFO roles/missing-hierarchy")
  void emptyRolesRecordsInfo() {
    JSentinelRuntime runtime = new TestBootstrap()
        .roles(r -> { })
        .install();
    assertTrue(runtime.warnings().stream()
        .anyMatch(w -> "roles/missing-hierarchy".equals(w.code())
            && w.severity() == Severity.INFO));
  }

  @Test
  @DisplayName("RoleBootstrap surface stays minimal: no .mapping(...) and no .resolver(...) in V00.73")
  void surfaceStaysMinimal() {
    List<String> methodNames = Arrays.stream(RoleBootstrap.class.getMethods())
        .map(Method::getName)
        .toList();
    assertEquals(List.of("hierarchy"), methodNames,
        "RoleBootstrap V00.73 must expose only hierarchy(...) — got " + methodNames);
  }

  // ── adapter test double ──────────────────────────────────────────

  private static final class TestBootstrap
      extends AbstractJSentinelBootstrap<TestBootstrap> {
    @Override
    public JSentinelRuntime install() {
      List<RegisteredJSentinelService> services = new ArrayList<>();
      List<JSentinelBootstrapWarning> warnings = new ArrayList<>();
      applyAuditConfiguration(services, warnings);
      applySessionConfiguration(AdapterKind.VAADIN, services, warnings);
      applyRoleConfiguration(services, warnings);
      JSentinelBootstrapMode mode = state.mode();
      if (mode == JSentinelBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR)) {
        throw new JSentinelBootstrapException(warnings);
      }
      return new JSentinelRuntime(services, warnings, mode);
    }
  }
}
