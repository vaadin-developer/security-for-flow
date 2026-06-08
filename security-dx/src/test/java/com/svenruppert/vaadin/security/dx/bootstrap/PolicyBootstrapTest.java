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
import com.svenruppert.vaadin.security.dx.internal.AbstractSecurityBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapWarning;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.SubjectPredicates;
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;
import com.svenruppert.vaadin.security.policy.spi.ResourceResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("PolicyBootstrap real surface (V00.73)")
class PolicyBootstrapTest {

  @BeforeEach
  @AfterEach
  void resetResolver() {
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".register(policy) lands in the default PolicyRegistry from SecurityServiceResolver")
  void registerLandsInDefaultRegistry() {
    Policy policy = Policy.named("docs.viewer")
        .allowIf(SubjectPredicates.hasRole("ROLE_USER"))
        .deny("not a user")
        .build();
    new TestBootstrap()
        .policies(p -> p.register(policy))
        .install();
    assertTrue(SecurityServiceResolver.policyRegistry().find("docs.viewer").isPresent());
  }

  @Test
  @DisplayName(".registry(external) replaces the default via SecurityServiceResolver.setPolicyRegistry")
  void externalRegistryReplacesDefault() {
    RecordingPolicyRegistry external = new RecordingPolicyRegistry();
    Policy policy = Policy.named("docs.owner")
        .allowIf(SubjectPredicates.hasRole("ROLE_ADMIN"))
        .deny("not admin")
        .build();
    new TestBootstrap()
        .policies(p -> p.registry(external).register(policy))
        .install();
    assertSame(external, SecurityServiceResolver.policyRegistry());
    assertTrue(external.registered.containsKey("docs.owner"));
  }

  @Test
  @DisplayName(".resourceResolver(r) lands in the active ResourceResolverRegistry")
  void resourceResolverLandsInRegistry() {
    StringResourceResolver resolver = new StringResourceResolver();
    new TestBootstrap()
        .policies(p -> p.resourceResolver(resolver))
        .install();
    assertTrue(SecurityServiceResolver.resourceResolverRegistry()
        .find("document").isPresent());
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static final class TestBootstrap
      extends AbstractSecurityBootstrap<TestBootstrap> {
    @Override
    public SecurityRuntime install() {
      List<RegisteredSecurityService> services = new ArrayList<>();
      List<SecurityBootstrapWarning> warnings = new ArrayList<>();
      applyAuditConfiguration(services, warnings);
      applySessionConfiguration(AdapterKind.VAADIN, services, warnings);
      applyRoleConfiguration(services, warnings);
      applyCredentialConfiguration(services, warnings);
      applyPolicyConfiguration(services, warnings);
      SecurityBootstrapMode mode = state.mode();
      if (mode == SecurityBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR)) {
        throw new SecurityBootstrapException(warnings);
      }
      return new SecurityRuntime(services, warnings, mode);
    }
  }

  private static final class RecordingPolicyRegistry implements PolicyRegistry {
    final Map<String, Policy> registered = new LinkedHashMap<>();
    @Override public void register(Policy policy) {
      registered.put(policy.name(), policy);
    }
    @Override public Optional<Policy> find(String name) {
      return Optional.ofNullable(registered.get(name));
    }
    @Override public com.svenruppert.vaadin.security.policy.api.PolicyDecision evaluate(
        String name, com.svenruppert.vaadin.security.policy.api.PolicyContext context) {
      Policy p = registered.get(name);
      if (p == null) {
        return new com.svenruppert.vaadin.security.policy.api.PolicyDecision.Denied(
            "unknown policy: " + name);
      }
      return p.evaluate(context);
    }
  }

  private static final class StringResourceResolver implements ResourceResolver<String> {
    @Override public String resourceType() { return "document"; }
    @Override public Optional<String> resolve(String id) {
      return Optional.of("doc-" + id);
    }
    @Override public Map<String, Object> attributes(String resource) {
      return Map.of("name", resource);
    }
  }
}
