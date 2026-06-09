/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.policy.impl;

import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.PolicyContext;
import com.svenruppert.vaadin.security.policy.api.PolicyDecision;
import com.svenruppert.vaadin.security.policy.api.SubjectPredicates;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryPolicyRegistryTest {

  private static PolicyContext ctxWithSubject(JSentinelSubject subject, String policyName) {
    return new PolicyContext(
        new AccessContext(Optional.of(subject), "rest-endpoint", "/x", "read", Map.of()),
        policyName);
  }

  private static PolicyContext anonymousCtx(String policyName) {
    return new PolicyContext(
        new AccessContext(Optional.empty(), "rest-endpoint", "/x", "read", Map.of()),
        policyName);
  }

  @Test
  @DisplayName("register rejects null policy")
  void registerRejectsNull() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    assertThrows(NullPointerException.class, () -> registry.register(null));
  }

  @Test
  @DisplayName("find returns empty for null and unknown names")
  void findEmpty() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    assertTrue(registry.find(null).isEmpty());
    assertTrue(registry.find("nope").isEmpty());
  }

  @Test
  @DisplayName("register then find returns the registered policy")
  void registerThenFind() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    Policy policy = Policy.named("p").allowIf(c -> true).build();
    registry.register(policy);

    Optional<Policy> found = registry.find("p");
    assertTrue(found.isPresent());
    assertSame(policy, found.orElseThrow());
  }

  @Test
  @DisplayName("re-registering the same name replaces the previous entry")
  void reRegisterReplaces() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    Policy first = Policy.named("p").allowIf(c -> true).build();
    Policy second = Policy.named("p").allowIf(c -> false).deny("nope").build();
    registry.register(first);
    registry.register(second);

    assertSame(second, registry.find("p").orElseThrow());
  }

  @Test
  @DisplayName("evaluate rejects null context")
  void evaluateRejectsNullContext() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    assertThrows(NullPointerException.class, () -> registry.evaluate("p", null));
  }

  @Test
  @DisplayName("evaluate returns Denied('unknown policy: <name>') when no policy is registered")
  void evaluateUnknownPolicy() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    PolicyDecision decision = registry.evaluate("missing", anonymousCtx("missing"));
    PolicyDecision.Denied denied =
        assertInstanceOf(PolicyDecision.Denied.class, decision);
    assertEquals("unknown policy: missing", denied.reason());
  }

  @Test
  @DisplayName("evaluate returns Denied('unknown policy: <blank>') for blank name")
  void evaluateBlankName() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    PolicyDecision decision = registry.evaluate("   ", anonymousCtx("ignored"));
    PolicyDecision.Denied denied =
        assertInstanceOf(PolicyDecision.Denied.class, decision);
    assertEquals("unknown policy: <blank>", denied.reason());
  }

  @Test
  @DisplayName("evaluate delegates to the registered policy")
  void evaluateDelegates() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    registry.register(Policy.named("p")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .deny("must be ADMIN")
        .build());

    JSentinelSubject admin = new JSentinelSubject(
        "u-1", "u-1", Set.of(new RoleName("ADMIN")), Set.of());
    JSentinelSubject user = new JSentinelSubject(
        "u-2", "u-2", Set.of(new RoleName("USER")), Set.of());

    assertInstanceOf(PolicyDecision.Allowed.class,
        registry.evaluate("p", ctxWithSubject(admin, "p")));
    PolicyDecision.Denied denied = assertInstanceOf(PolicyDecision.Denied.class,
        registry.evaluate("p", ctxWithSubject(user, "p")));
    assertEquals("must be ADMIN", denied.reason());
  }

  @Test
  @DisplayName("document.owner-or-admin example: admin role or document:write permission grants access")
  void documentOwnerOrAdminExample() {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    registry.register(Policy.named("document.owner-or-admin")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .orIf(SubjectPredicates.hasPermission("document:write"))
        .deny("must be admin or document:write holder")
        .build());

    JSentinelSubject admin = new JSentinelSubject(
        "u-admin", "admin", Set.of(new RoleName("ADMIN")), Set.of());
    JSentinelSubject writer = new JSentinelSubject(
        "u-writer", "writer", Set.of(), Set.of(new PermissionName("document:write")));
    JSentinelSubject reader = new JSentinelSubject(
        "u-reader", "reader", Set.of(), Set.of(new PermissionName("document:read")));

    assertInstanceOf(PolicyDecision.Allowed.class, registry.evaluate(
        "document.owner-or-admin", ctxWithSubject(admin, "document.owner-or-admin")));
    assertInstanceOf(PolicyDecision.Allowed.class, registry.evaluate(
        "document.owner-or-admin", ctxWithSubject(writer, "document.owner-or-admin")));

    PolicyDecision.Denied deniedReader = assertInstanceOf(PolicyDecision.Denied.class,
        registry.evaluate("document.owner-or-admin",
            ctxWithSubject(reader, "document.owner-or-admin")));
    assertEquals("must be admin or document:write holder", deniedReader.reason());

    PolicyDecision.Denied deniedAnonymous = assertInstanceOf(PolicyDecision.Denied.class,
        registry.evaluate("document.owner-or-admin",
            anonymousCtx("document.owner-or-admin")));
    assertEquals("must be admin or document:write holder", deniedAnonymous.reason());
  }

  @Test
  @DisplayName("registry survives concurrent register and evaluate")
  void concurrentRegisterAndEvaluate() throws Exception {
    InMemoryPolicyRegistry registry = new InMemoryPolicyRegistry();
    Policy allowAll = Policy.named("allow-all").allowIf(c -> true).build();
    registry.register(allowAll);

    int threadCount = 16;
    int iterationsPerThread = 1_000;
    Thread[] threads = new Thread[threadCount];
    boolean[] sawAllowed = new boolean[threadCount];

    for (int i = 0; i < threadCount; i++) {
      final int slot = i;
      threads[i] = new Thread(() -> {
        for (int it = 0; it < iterationsPerThread; it++) {
          PolicyDecision decision = registry.evaluate("allow-all", anonymousCtx("allow-all"));
          if (decision instanceof PolicyDecision.Allowed) {
            sawAllowed[slot] = true;
          }
        }
      });
    }

    for (Thread t : threads) t.start();
    for (Thread t : threads) t.join();

    for (boolean b : sawAllowed) {
      assertTrue(b, "all threads should have observed at least one Allowed decision");
    }
    assertFalse(registry.find("allow-all").isEmpty());
  }
}
