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
package com.svenruppert.vaadin.security.dx.bootstrap;

import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.api.roles.StaticRoleHierarchy;
import com.svenruppert.vaadin.security.dx.internal.AbstractSecurityBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapWarning;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;
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
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".hierarchy(...) registers the hierarchy via SecurityServiceResolver")
  void hierarchyRegistersAndAppearsInRuntime() {
    RoleHierarchy hierarchy = StaticRoleHierarchy.builder()
        .role(new RoleName("ROLE_ADMIN")).inheritsFrom(new RoleName("ROLE_USER"))
        .role(new RoleName("ROLE_USER"))
        .build();

    SecurityRuntime runtime = new TestBootstrap()
        .roles(r -> r.hierarchy(hierarchy))
        .install();

    assertSame(hierarchy, SecurityServiceResolver.findRoleHierarchy().orElseThrow());
    boolean entry = runtime.services().stream()
        .anyMatch(s -> RoleHierarchy.class.equals(s.spi())
            && hierarchy.getClass().equals(s.impl())
            && "bootstrap-explicit".equals(s.source()));
    assertTrue(entry, "expected RoleHierarchy entry in runtime");
  }

  @Test
  @DisplayName("empty .roles(r -> {}) records INFO roles/missing-hierarchy")
  void emptyRolesRecordsInfo() {
    SecurityRuntime runtime = new TestBootstrap()
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
      extends AbstractSecurityBootstrap<TestBootstrap> {
    @Override
    public SecurityRuntime install() {
      List<RegisteredSecurityService> services = new ArrayList<>();
      List<SecurityBootstrapWarning> warnings = new ArrayList<>();
      applyAuditConfiguration(services, warnings);
      applySessionConfiguration(AdapterKind.VAADIN, services, warnings);
      applyRoleConfiguration(services, warnings);
      SecurityBootstrapMode mode = state.mode();
      if (mode == SecurityBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR)) {
        throw new SecurityBootstrapException(warnings);
      }
      return new SecurityRuntime(services, warnings, mode);
    }
  }
}
