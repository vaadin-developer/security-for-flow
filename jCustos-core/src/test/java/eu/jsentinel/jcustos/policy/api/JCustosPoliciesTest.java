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
package eu.jsentinel.jcustos.policy.api;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.policy.spi.ResourceResolver;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosPolicies common-pattern factories")
class JCustosPoliciesTest {

  // ── ownerOrAdmin ─────────────────────────────────────────────────

  @Test
  @DisplayName("ownerOrAdmin grants when subject holds an admin role")
  void ownerOrAdminAllowsAdmin() {
    Policy p = JCustosPolicies.ownerOrAdmin("document", "ownerId");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of("ROLE_ADMIN"), Set.of(), Map.of()));
    assertInstanceOf(PolicyDecision.Allowed.class, d);
  }

  @Test
  @DisplayName("ownerOrAdmin denies non-admin non-owner")
  void ownerOrAdminDeniesOther() {
    Policy p = JCustosPolicies.ownerOrAdmin("document", "ownerId");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of("ROLE_USER"), Set.of(), Map.of()));
    assertInstanceOf(PolicyDecision.Denied.class, d);
  }

  @Test
  @DisplayName("ownerOrAdmin accepts custom admin roles")
  void ownerOrAdminCustomRole() {
    Policy p = JCustosPolicies.ownerOrAdmin("document", "ownerId", "ROLE_OPS", "ROLE_SUPER");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of("ROLE_OPS"), Set.of(), Map.of()));
    assertInstanceOf(PolicyDecision.Allowed.class, d);
  }

  @Test
  @DisplayName("policy name follows the resourceType.owner-or-admin convention")
  void ownerOrAdminPolicyName() {
    Policy p = JCustosPolicies.ownerOrAdmin("invoice", "ownerId");
    assertEquals("invoice.owner-or-admin", p.name());
  }

  // ── timeWindow ──────────────────────────────────────────────────

  @Test
  @DisplayName("timeWindow allows inside the window")
  void timeWindowInside() {
    Clock fixed = Clock.fixed(Instant.parse("2026-06-09T11:00:00Z"), ZoneId.of("UTC"));
    Policy p = JCustosPolicies.timeWindow("business-hours",
        LocalTime.of(9, 0), LocalTime.of(17, 0),
        ZoneId.of("UTC"), fixed);
    assertInstanceOf(PolicyDecision.Allowed.class,
        p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of())));
  }

  @Test
  @DisplayName("timeWindow denies before window")
  void timeWindowBefore() {
    Clock fixed = Clock.fixed(Instant.parse("2026-06-09T05:00:00Z"), ZoneId.of("UTC"));
    Policy p = JCustosPolicies.timeWindow("business-hours",
        LocalTime.of(9, 0), LocalTime.of(17, 0),
        ZoneId.of("UTC"), fixed);
    assertInstanceOf(PolicyDecision.Denied.class,
        p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of())));
  }

  @Test
  @DisplayName("timeWindow denies after window (exclusive upper bound)")
  void timeWindowAfter() {
    Clock fixed = Clock.fixed(Instant.parse("2026-06-09T17:00:00Z"), ZoneId.of("UTC"));
    Policy p = JCustosPolicies.timeWindow("business-hours",
        LocalTime.of(9, 0), LocalTime.of(17, 0),
        ZoneId.of("UTC"), fixed);
    assertInstanceOf(PolicyDecision.Denied.class,
        p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of())));
  }

  // ── sameTenant ──────────────────────────────────────────────────

  @Test
  @DisplayName("sameTenant grants when both sides share the tenant attribute")
  void sameTenantMatching() {
    Policy p = JCustosPolicies.sameTenant("docs.same-tenant");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(),
        Map.of("tenantId", "acme")));
    assertInstanceOf(PolicyDecision.Allowed.class, d);
  }

  @Test
  @DisplayName("sameTenant denies on mismatch (different keys, mismatching values)")
  void sameTenantMismatch() {
    Policy p = JCustosPolicies.sameTenant("docs.same-tenant",
        "subjectTenantId", "resourceTenantId");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(),
        Map.of("subjectTenantId", "acme", "resourceTenantId", "globex")));
    assertInstanceOf(PolicyDecision.Denied.class, d);
  }

  @Test
  @DisplayName("sameTenant denies when attribute is missing")
  void sameTenantMissing() {
    Policy p = JCustosPolicies.sameTenant("docs.same-tenant");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of()));
    assertInstanceOf(PolicyDecision.Denied.class, d);
  }

  // ── requireStepUp / requireMfa ──────────────────────────────────

  @Test
  @DisplayName("requireMfa always returns StepUpRequired with the MFA method")
  void requireMfaAlwaysStepsUp() {
    Policy p = JCustosPolicies.requireMfa("sensitive.mfa");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of("ROLE_ADMIN"), Set.of(), Map.of()));
    PolicyDecision.StepUpRequired step = assertInstanceOf(PolicyDecision.StepUpRequired.class, d);
    assertEquals(PolicyDecision.StepUpMethod.MFA, step.method());
  }

  // ── anyRoleOrPermission ─────────────────────────────────────────

  @Test
  @DisplayName("anyRoleOrPermission grants on role match")
  void anyRoleOrPermissionRoleMatch() {
    Policy p = JCustosPolicies.anyRoleOrPermission("doc.editor",
        Set.of("ROLE_EDITOR"), Set.of("doc:write"));
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of("ROLE_EDITOR"), Set.of(), Map.of()));
    assertInstanceOf(PolicyDecision.Allowed.class, d);
  }

  @Test
  @DisplayName("anyRoleOrPermission grants on permission match")
  void anyRoleOrPermissionPermissionMatch() {
    Policy p = JCustosPolicies.anyRoleOrPermission("doc.editor",
        Set.of("ROLE_EDITOR"), Set.of("doc:write"));
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of("ROLE_USER"),
        Set.of("doc:write"), Map.of()));
    assertInstanceOf(PolicyDecision.Allowed.class, d);
  }

  @Test
  @DisplayName("anyRoleOrPermission denies on no match")
  void anyRoleOrPermissionNoMatch() {
    Policy p = JCustosPolicies.anyRoleOrPermission("doc.editor",
        Set.of("ROLE_EDITOR"), Set.of("doc:write"));
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of("ROLE_USER"),
        Set.of("doc:read"), Map.of()));
    assertInstanceOf(PolicyDecision.Denied.class, d);
  }

  @Test
  @DisplayName("anyRoleOrPermission rejects empty roles AND empty permissions")
  void anyRoleOrPermissionEmpty() {
    assertThrows(IllegalArgumentException.class, () ->
        JCustosPolicies.anyRoleOrPermission("x", Set.of(), Set.of()));
  }

  // ── ipAllowList ─────────────────────────────────────────────────

  @Test
  @DisplayName("ipAllowList grants for IPs inside the CIDR")
  void ipAllowListInside() {
    Policy p = JCustosPolicies.ipAllowList("intranet", "clientAddress", "10.0.0.0/8");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(),
        Map.of("clientAddress", "10.20.30.40")));
    assertInstanceOf(PolicyDecision.Allowed.class, d);
  }

  @Test
  @DisplayName("ipAllowList denies for IPs outside any CIDR")
  void ipAllowListOutside() {
    Policy p = JCustosPolicies.ipAllowList("intranet", "clientAddress",
        "10.0.0.0/8", "192.168.0.0/16");
    PolicyDecision d = p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(),
        Map.of("clientAddress", "8.8.8.8")));
    assertInstanceOf(PolicyDecision.Denied.class, d);
  }

  @Test
  @DisplayName("ipAllowList denies when attribute is missing or non-string")
  void ipAllowListMissing() {
    Policy p = JCustosPolicies.ipAllowList("intranet", "clientAddress", "10.0.0.0/8");
    assertInstanceOf(PolicyDecision.Denied.class,
        p.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of())));
  }

  // ── allOf / anyOf combinators ──────────────────────────────────

  @Test
  @DisplayName("allOf passes only if every child policy allows")
  void allOfHappy() {
    Policy alwaysAllow = Policy.named("ok1").allowIf(c -> true).deny("never").build();
    Policy alsoAllow = Policy.named("ok2").allowIf(c -> true).deny("never").build();
    Policy combined = JCustosPolicies.allOf("combined.all", alwaysAllow, alsoAllow);
    assertInstanceOf(PolicyDecision.Allowed.class,
        combined.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of())));
  }

  @Test
  @DisplayName("allOf denies if any child policy denies")
  void allOfShortCircuitsOnDeny() {
    Policy allow = Policy.named("ok").allowIf(c -> true).deny("never").build();
    Policy deny = Policy.named("nope").allowIf(c -> false).deny("always").build();
    Policy combined = JCustosPolicies.allOf("combined.all", allow, deny);
    assertInstanceOf(PolicyDecision.Denied.class,
        combined.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of())));
  }

  @Test
  @DisplayName("anyOf grants if at least one child allows")
  void anyOfShortCircuitsOnAllow() {
    Policy deny = Policy.named("nope").allowIf(c -> false).deny("always").build();
    Policy allow = Policy.named("ok").allowIf(c -> true).deny("never").build();
    Policy combined = JCustosPolicies.anyOf("combined.any", deny, allow);
    assertInstanceOf(PolicyDecision.Allowed.class,
        combined.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of())));
  }

  @Test
  @DisplayName("anyOf denies if every child denies")
  void anyOfAllDeny() {
    Policy deny1 = Policy.named("n1").allowIf(c -> false).deny("always").build();
    Policy deny2 = Policy.named("n2").allowIf(c -> false).deny("always").build();
    Policy combined = JCustosPolicies.anyOf("combined.any", deny1, deny2);
    assertInstanceOf(PolicyDecision.Denied.class,
        combined.evaluate(ctxWithSubject("alice", Set.of(), Set.of(), Map.of())));
  }

  @Test
  @DisplayName("allOf / anyOf reject empty children")
  void combinatorsRejectEmpty() {
    assertThrows(IllegalArgumentException.class, () -> JCustosPolicies.allOf("x"));
    assertThrows(IllegalArgumentException.class, () -> JCustosPolicies.anyOf("x"));
  }

  // ── helpers ─────────────────────────────────────────────────────

  private static PolicyContext ctxWithSubject(String subjectId,
                                              Set<String> roles,
                                              Set<String> permissions,
                                              Map<String, Object> attributes) {
    JCustosSubject subject = new JCustosSubject(
        subjectId,
        subjectId,
        toRoleNames(roles),
        toPermissionNames(permissions));
    AccessContext ac = new AccessContext(
        Optional.of(subject),
        "test",
        "test-resource",
        "evaluate",
        attributes == null ? Map.of() : new LinkedHashMap<>(attributes));
    return new PolicyContext(ac, "test-policy");
  }

  private static Set<RoleName> toRoleNames(Set<String> roles) {
    java.util.LinkedHashSet<RoleName> out = new java.util.LinkedHashSet<>();
    for (String r : roles) out.add(new RoleName(r));
    return out;
  }

  private static Set<PermissionName> toPermissionNames(Set<String> perms) {
    java.util.LinkedHashSet<PermissionName> out = new java.util.LinkedHashSet<>();
    for (String p : perms) out.add(new PermissionName(p));
    return out;
  }
}
