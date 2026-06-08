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
package com.svenruppert.vaadin.security.starter.routes;

import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.HasRoles;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;

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
    Optional<SecuritySubject> maybeSubject = context.subject();
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
      // V00.72 limitation: PolicyRegistry lookup is owned by the
      // adapter starter integration (Prompt 019). Until that lands,
      // a non-empty policy() acts as "deny by default" to avoid a
      // silent grant.
      worst = combine(worst, new AuthorizationDecision.Forbidden(
          "@SecureRoute(policy=\"" + annotation.policy()
              + "\") requires the starter's PolicyRegistry integration."));
    }
    return worst;
  }

  // Roles: any-of
  private static AuthorizationDecision evaluateRoles(SecuritySubject subject, String[] roles) {
    Set<RoleName> subjectRoles = subject instanceof HasRoles hr
        ? copy(hr.roleNames()) : Collections.emptySet();
    boolean any = Arrays.stream(roles).anyMatch(r -> subjectRoles.contains(new RoleName(r)));
    return any
        ? new AuthorizationDecision.Granted()
        : new AuthorizationDecision.Forbidden(
            "Subject lacks any of the required roles: " + Arrays.toString(roles));
  }

  // Permissions: all-of
  private static AuthorizationDecision evaluatePermissions(SecuritySubject subject, String[] perms) {
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
