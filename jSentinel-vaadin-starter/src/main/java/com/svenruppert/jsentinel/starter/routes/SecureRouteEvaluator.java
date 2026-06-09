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
package com.svenruppert.jsentinel.starter.routes;

import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import com.svenruppert.jsentinel.authorization.api.AuthorizationEvaluator;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.permissions.HasPermissions;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.HasRoles;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;
import com.svenruppert.jsentinel.policy.api.Policy;
import com.svenruppert.jsentinel.policy.api.PolicyContext;
import com.svenruppert.jsentinel.policy.api.PolicyDecision;
import com.svenruppert.jsentinel.policy.spi.PolicyRegistry;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Evaluator backing {@link SecureRoute}. Combines role, permission and
 * policy checks with the most-restrictive-wins precedence documented
 * on {@link SecureRoute}.
 *
 * @since 00.72.00
 */
public final class SecureRouteEvaluator implements AuthorizationEvaluator<SecureRoute> {

  @Override
  public AuthorizationDecision evaluate(AccessContext context, SecureRoute annotation) {
    Optional<JSentinelSubject> maybeSubject = context.subject();
    if (maybeSubject.isEmpty()) {
      // Treat any check as Unauthenticated when no subject is bound.
      if (annotation.roles().length == 0
          && annotation.permissions().length == 0
          && annotation.policy().isEmpty()) {
        return new AuthorizationDecision.Granted();
      }
      return new AuthorizationDecision.Unauthenticated(
          "No subject bound; @SecureRoute requires authentication.");
    }

    AuthorizationDecision worst = new AuthorizationDecision.Granted();

    if (annotation.roles().length > 0) {
      worst = combine(worst, evaluateRoles(maybeSubject.get(), annotation.roles()));
    }
    if (annotation.permissions().length > 0) {
      worst = combine(worst, evaluatePermissions(maybeSubject.get(), annotation.permissions()));
    }
    if (!annotation.policy().isEmpty()) {
      // V00.73 (Prompt 012): real PolicyRegistry evaluation.
      worst = combine(worst, evaluatePolicy(context, maybeSubject.get(), annotation.policy()));
    }
    return worst;
  }

  private static AuthorizationDecision evaluatePolicy(AccessContext context,
                                                      JSentinelSubject subject,
                                                      String policyName) {
    PolicyRegistry registry = JSentinelServiceResolver.policyRegistry();
    Optional<Policy> known = registry.find(policyName);
    if (known.isEmpty()) {
      return new AuthorizationDecision.Forbidden(
          "@SecureRoute(policy=\"" + policyName + "\") — PolicyRegistry has no entry.");
    }
    PolicyContext pc = new PolicyContext(context, policyName);
    PolicyDecision decision = registry.evaluate(policyName, pc);
    if (decision instanceof PolicyDecision.Allowed) {
      return new AuthorizationDecision.Granted();
    }
    if (decision instanceof PolicyDecision.StepUpRequired stepUp) {
      // SecureRoute does not declare a specific step-up method; use
      // the policy's reason as the diagnostic.
      String reason = stepUp.reason();
      return new AuthorizationDecision.StepUpRequired(
          reason == null || reason.isEmpty()
              ? "step-up required for policy \"" + policyName + "\""
              : reason,
          stepUp.method().name());
    }
    // Denied — fail closed
    String reason = decision instanceof PolicyDecision.Denied d
        ? d.reason()
        : "policy \"" + policyName + "\" denied access";
    return new AuthorizationDecision.Forbidden(
        reason == null || reason.isEmpty()
            ? "policy \"" + policyName + "\" denied access"
            : reason);
  }

  // Roles: any-of
  private static AuthorizationDecision evaluateRoles(JSentinelSubject subject, String[] roles) {
    Set<RoleName> subjectRoles = subject instanceof HasRoles hr
        ? copy(hr.roleNames()) : Collections.emptySet();
    boolean any = Arrays.stream(roles).anyMatch(r -> subjectRoles.contains(new RoleName(r)));
    return any
        ? new AuthorizationDecision.Granted()
        : new AuthorizationDecision.Forbidden(
            "Subject lacks any of the required roles: " + Arrays.toString(roles));
  }

  // Permissions: all-of
  private static AuthorizationDecision evaluatePermissions(JSentinelSubject subject, String[] perms) {
    Set<PermissionName> subjectPerms = subject instanceof HasPermissions hp
        ? copy(hp.permissionNames()) : Collections.emptySet();
    boolean missing = Arrays.stream(perms).anyMatch(p -> !subjectPerms.contains(new PermissionName(p)));
    return missing
        ? new AuthorizationDecision.Forbidden(
            "Subject lacks one or more required permissions: " + Arrays.toString(perms))
        : new AuthorizationDecision.Granted();
  }

  private static <T> Set<T> copy(Collection<T> coll) {
    return coll == null ? Collections.emptySet() : new HashSet<>(coll);
  }

  /**
   * Combines two decisions according to the precedence:
   * Unauthenticated &gt; Forbidden &gt; StepUpRequired &gt; Granted.
   */
  private static AuthorizationDecision combine(AuthorizationDecision a, AuthorizationDecision b) {
    return rank(a) >= rank(b) ? a : b;
  }

  private static int rank(AuthorizationDecision d) {
    return switch (d) {
      case AuthorizationDecision.Unauthenticated ignored -> 3;
      case AuthorizationDecision.Forbidden ignored -> 2;
      case AuthorizationDecision.StepUpRequired ignored -> 1;
      case AuthorizationDecision.Granted ignored -> 0;
    };
  }
}
