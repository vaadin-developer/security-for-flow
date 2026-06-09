/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.policy.api;

import java.time.Clock;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Pre-built policies for the most common access-control patterns.
 *
 * <p>Every factory method returns a fully-constructed {@link Policy}
 * ready to register with a {@code PolicyRegistry} or to pass into
 * {@code .policies(p -> p.register(...))} on the fluent bootstrap.
 *
 * <p>The patterns covered here are deliberately conservative — they
 * cover the 80 % of common cases without inventing new semantics.
 * Anything more sophisticated should be assembled directly via the
 * {@link Policy#named(String)} DSL.
 *
 * @since 00.74.00
 */
public final class JSentinelPolicies {

  private JSentinelPolicies() {
    throw new AssertionError("no instances");
  }

  /**
   * The classic "owner-or-admin" pattern: an admin role passes,
   * otherwise the subject must own the resource (the resource
   * resolver's owner attribute equals the subject id).
   *
   * @param resourceType   resource-type name as registered with the
   *                       {@code ResourceResolverRegistry}
   * @param ownerAttribute attribute key returned by the
   *                       {@code ResourceResolver} that holds the
   *                       owner id
   * @param adminRoles     one or more admin role names that always pass
   * @return ready-to-register policy named
   *         {@code "<resourceType>.owner-or-admin"}
   */
  public static Policy ownerOrAdmin(String resourceType,
                                    String ownerAttribute,
                                    String... adminRoles) {
    Objects.requireNonNull(resourceType, "resourceType");
    Objects.requireNonNull(ownerAttribute, "ownerAttribute");
    String[] roles = adminRoles == null || adminRoles.length == 0
        ? new String[]{"ROLE_ADMIN"}
        : adminRoles;
    return Policy.named(resourceType + ".owner-or-admin")
        .allowIf(SubjectPredicates.hasAnyRole(roles))
        .orIf(ResourcePredicates.ownerMatchesSubject(resourceType, ownerAttribute))
        .deny("must be " + String.join("/", roles) + " or own the " + resourceType)
        .build();
  }

  /**
   * Time-of-day gate: access permitted only inside the
   * {@code [start, end)} window in the JVM-default timezone.
   * Useful for "business hours only" patterns.
   *
   * @param policyName non-blank policy name
   * @param start      inclusive lower bound (e.g. {@code 09:00})
   * @param end        exclusive upper bound (e.g. {@code 17:00})
   */
  public static Policy timeWindow(String policyName, LocalTime start, LocalTime end) {
    return timeWindow(policyName, start, end, ZoneId.systemDefault(), Clock.systemDefaultZone());
  }

  /**
   * Time-of-day gate with explicit timezone and clock.
   * Test-friendly: pass a fixed {@link Clock} to make the policy
   * deterministic.
   */
  public static Policy timeWindow(String policyName,
                                  LocalTime start,
                                  LocalTime end,
                                  ZoneId zone,
                                  Clock clock) {
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(start, "start");
    Objects.requireNonNull(end, "end");
    Objects.requireNonNull(zone, "zone");
    Objects.requireNonNull(clock, "clock");
    Predicate<PolicyContext> inWindow = ctx -> {
      LocalTime now = LocalTime.now(clock.withZone(zone));
      return !now.isBefore(start) && now.isBefore(end);
    };
    return Policy.named(policyName)
        .allowIf(inWindow)
        .deny("outside business hours [" + start + ", " + end + ") in " + zone)
        .build();
  }

  /**
   * Tenant-isolation pattern: subject and resource must carry the
   * same {@code tenantId} attribute. Both context attributes are
   * looked up — the policy denies when either is missing.
   *
   * <p>For multi-tenant applications, register one instance per
   * resource type so the {@code ResourceResolver} can hydrate the
   * resource side.
   *
   * @param policyName       non-blank policy name
   * @param subjectTenantKey context attribute key on the subject side
   *                         (usually {@code "tenantId"})
   * @param resourceTenantKey context attribute key on the resource
   *                         side
   */
  public static Policy sameTenant(String policyName,
                                  String subjectTenantKey,
                                  String resourceTenantKey) {
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(subjectTenantKey, "subjectTenantKey");
    Objects.requireNonNull(resourceTenantKey, "resourceTenantKey");
    Predicate<PolicyContext> sameTenant = ctx -> {
      Object subjectTenant = ctx.accessContext().attributes().get(subjectTenantKey);
      Object resourceTenant = ctx.accessContext().attributes().get(resourceTenantKey);
      return subjectTenant != null && subjectTenant.equals(resourceTenant);
    };
    return Policy.named(policyName)
        .allowIf(sameTenant)
        .deny("subject and resource must share the same tenant")
        .build();
  }

  /**
   * Convenience variant of {@link #sameTenant(String, String, String)}
   * using the conventional key {@code "tenantId"} on both sides.
   */
  public static Policy sameTenant(String policyName) {
    return sameTenant(policyName, "tenantId", "tenantId");
  }

  /**
   * Step-up gate: every access request is approved only after the
   * caller satisfies a step-up authentication (typically MFA).
   * The policy returns {@code StepUpRequired} unconditionally — the
   * adapter then triggers the configured step-up route.
   *
   * @param policyName non-blank policy name
   * @param method     requested step-up mechanism
   * @param reason     adapter-neutral diagnostic shown to the caller
   */
  public static Policy requireStepUp(String policyName,
                                     PolicyDecision.StepUpMethod method,
                                     String reason) {
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(method, "method");
    Objects.requireNonNull(reason, "reason");
    return Policy.named(policyName)
        .stepUpRequiredIf(ctx -> true, method, reason)
        .build();
  }

  /**
   * Convenience: step-up required with MFA, default reason
   * "Multi-factor authentication required".
   */
  public static Policy requireMfa(String policyName) {
    return requireStepUp(policyName,
        PolicyDecision.StepUpMethod.MFA,
        "Multi-factor authentication required");
  }

  /**
   * Any-of: subject passes if it holds any of the given roles
   * or any of the given permissions. Useful when the policy
   * represents "anybody in this group".
   *
   * @param policyName  non-blank policy name
   * @param roles       roles that pass the gate (any-of)
   * @param permissions permissions that pass the gate (any-of)
   */
  public static Policy anyRoleOrPermission(String policyName,
                                           Set<String> roles,
                                           Set<String> permissions) {
    Objects.requireNonNull(policyName, "policyName");
    Set<String> r = roles == null ? Set.of() : Set.copyOf(roles);
    Set<String> p = permissions == null ? Set.of() : Set.copyOf(permissions);
    if (r.isEmpty() && p.isEmpty()) {
      throw new IllegalArgumentException(
          "anyRoleOrPermission needs at least one role or permission");
    }
    PolicyBuilder b = Policy.named(policyName);
    boolean first = true;
    if (!r.isEmpty()) {
      b = b.allowIf(SubjectPredicates.hasAnyRole(r.toArray(new String[0])));
      first = false;
    }
    for (String perm : p) {
      b = first
          ? b.allowIf(SubjectPredicates.hasPermission(perm))
          : b.orIf(SubjectPredicates.hasPermission(perm));
      first = false;
    }
    return b.deny("must hold one of roles=" + r + " or permissions=" + p).build();
  }

  /**
   * IP allow-list pattern: subject's request must come from an
   * address in {@code allowedCidrs} (CIDR notation, e.g.
   * {@code "10.0.0.0/8"}). The request IP is read from the access
   * context attribute keyed by {@code ipAttributeKey} (typically
   * {@code "clientAddress"} in REST setups).
   *
   * <p>The CIDR check is rudimentary on purpose — it supports IPv4
   * prefixes only; for IPv6 / proxy-chain scenarios use a custom
   * predicate.
   *
   * @param policyName     non-blank policy name
   * @param ipAttributeKey context attribute key holding the request IP
   * @param allowedCidrs   IPv4 CIDR ranges (e.g. {@code "10.0.0.0/8"})
   */
  public static Policy ipAllowList(String policyName,
                                   String ipAttributeKey,
                                   String... allowedCidrs) {
    Objects.requireNonNull(policyName, "policyName");
    Objects.requireNonNull(ipAttributeKey, "ipAttributeKey");
    if (allowedCidrs == null || allowedCidrs.length == 0) {
      throw new IllegalArgumentException("ipAllowList needs at least one CIDR");
    }
    Set<String> cidrs = new LinkedHashSet<>(Arrays.asList(allowedCidrs));
    Predicate<PolicyContext> allowed = ctx -> {
      Object ip = ctx.accessContext().attributes().get(ipAttributeKey);
      if (!(ip instanceof String ipStr)) {
        return false;
      }
      return cidrs.stream().anyMatch(c -> ipv4InCidr(ipStr, c));
    };
    return Policy.named(policyName)
        .allowIf(allowed)
        .deny("request IP not in allow-list " + cidrs)
        .build();
  }

  /**
   * Combinator: all sub-policies must pass.
   * Each child policy is evaluated; the first child that does not
   * return {@code Allowed} wins (deny or step-up).
   *
   * @param policyName  non-blank policy name for the combined policy
   * @param children    at least one child policy
   */
  public static Policy allOf(String policyName, Policy... children) {
    Objects.requireNonNull(policyName, "policyName");
    if (children == null || children.length == 0) {
      throw new IllegalArgumentException("allOf needs at least one child");
    }
    Policy[] copy = children.clone();
    Predicate<PolicyContext> allAllowed = ctx -> {
      for (Policy child : copy) {
        if (!(child.evaluate(ctx) instanceof PolicyDecision.Allowed)) {
          return false;
        }
      }
      return true;
    };
    return Policy.named(policyName)
        .allowIf(allAllowed)
        .deny("not all child policies passed")
        .build();
  }

  /**
   * Combinator: any sub-policy passing is enough.
   * Children are tried in order; the first {@code Allowed} wins.
   */
  public static Policy anyOf(String policyName, Policy... children) {
    Objects.requireNonNull(policyName, "policyName");
    if (children == null || children.length == 0) {
      throw new IllegalArgumentException("anyOf needs at least one child");
    }
    Policy[] copy = children.clone();
    Predicate<PolicyContext> anyAllowed = ctx -> {
      for (Policy child : copy) {
        if (child.evaluate(ctx) instanceof PolicyDecision.Allowed) {
          return true;
        }
      }
      return false;
    };
    return Policy.named(policyName)
        .allowIf(anyAllowed)
        .deny("no child policy passed")
        .build();
  }

  // ── IPv4-CIDR matching, deliberately minimal ───────────────────

  private static boolean ipv4InCidr(String ip, String cidr) {
    try {
      int slash = cidr.indexOf('/');
      if (slash < 0) {
        return false;
      }
      int prefix = Integer.parseInt(cidr.substring(slash + 1));
      if (prefix < 0 || prefix > 32) {
        return false;
      }
      long ipBits = ipv4ToLong(ip);
      long cidrBits = ipv4ToLong(cidr.substring(0, slash));
      if (ipBits < 0 || cidrBits < 0) {
        return false;
      }
      long mask = prefix == 0 ? 0L : (~0L << (32 - prefix)) & 0xFFFFFFFFL;
      return (ipBits & mask) == (cidrBits & mask);
    } catch (NumberFormatException e) {
      return false;
    }
  }

  private static long ipv4ToLong(String ip) {
    String[] parts = ip.split("\\.");
    if (parts.length != 4) {
      return -1;
    }
    long out = 0;
    for (String p : parts) {
      int n = Integer.parseInt(p);
      if (n < 0 || n > 255) {
        return -1;
      }
      out = (out << 8) | n;
    }
    return out & 0xFFFFFFFFL;
  }
}
