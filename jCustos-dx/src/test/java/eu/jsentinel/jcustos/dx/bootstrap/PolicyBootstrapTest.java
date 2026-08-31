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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.dx.internal.AbstractJCustosBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJCustosService;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.policy.api.Policy;
import eu.jsentinel.jcustos.policy.api.SubjectPredicates;
import eu.jsentinel.jcustos.policy.spi.PolicyRegistry;
import eu.jsentinel.jcustos.policy.spi.ResourceResolver;
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
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName(".register(policy) lands in the default PolicyRegistry from JCustosServiceResolver")
  void registerLandsInDefaultRegistry() {
    Policy policy = Policy.named("docs.viewer")
        .allowIf(SubjectPredicates.hasRole("ROLE_USER"))
        .deny("not a user")
        .build();
    new TestBootstrap()
        .policies(p -> p.register(policy))
        .install();
    assertTrue(JCustosServiceResolver.policyRegistry().find("docs.viewer").isPresent());
  }

  @Test
  @DisplayName(".registry(external) replaces the default via JCustosServiceResolver.setPolicyRegistry")
  void externalRegistryReplacesDefault() {
    RecordingPolicyRegistry external = new RecordingPolicyRegistry();
    Policy policy = Policy.named("docs.owner")
        .allowIf(SubjectPredicates.hasRole("ROLE_ADMIN"))
        .deny("not admin")
        .build();
    new TestBootstrap()
        .policies(p -> p.registry(external).register(policy))
        .install();
    assertSame(external, JCustosServiceResolver.policyRegistry());
    assertTrue(external.registered.containsKey("docs.owner"));
  }

  @Test
  @DisplayName(".resourceResolver(r) lands in the active ResourceResolverRegistry")
  void resourceResolverLandsInRegistry() {
    StringResourceResolver resolver = new StringResourceResolver();
    new TestBootstrap()
        .policies(p -> p.resourceResolver(resolver))
        .install();
    assertTrue(JCustosServiceResolver.resourceResolverRegistry()
        .find("document").isPresent());
  }

  // ── helpers ──────────────────────────────────────────────────────

  private static final class TestBootstrap
      extends AbstractJCustosBootstrap<TestBootstrap> {
    @Override
    public JCustosRuntime install() {
      List<RegisteredJCustosService> services = new ArrayList<>();
      List<JCustosBootstrapWarning> warnings = new ArrayList<>();
      applyAuditConfiguration(services, warnings);
      applySessionConfiguration(AdapterKind.VAADIN, services, warnings);
      applyRoleConfiguration(services, warnings);
      applyCredentialConfiguration(services, warnings);
      applyPolicyConfiguration(services, warnings);
      JCustosBootstrapMode mode = state.mode();
      if (mode == JCustosBootstrapMode.STRICT
          && warnings.stream().anyMatch(w -> w.severity() == Severity.ERROR)) {
        throw new JCustosBootstrapException(warnings);
      }
      return new JCustosRuntime(services, warnings, mode);
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
    @Override public eu.jsentinel.jcustos.policy.api.PolicyDecision evaluate(
        String name, eu.jsentinel.jcustos.policy.api.PolicyContext context) {
      Policy p = registered.get(name);
      if (p == null) {
        return new eu.jsentinel.jcustos.policy.api.PolicyDecision.Denied(
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
