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
package com.svenruppert.vaadin.security.action;

import com.svenruppert.vaadin.security.audit.ActionDenied;
import com.svenruppert.vaadin.security.audit.JSentinelAuditService;
import com.svenruppert.vaadin.security.authorization.api.AccessDeniedException;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

/**
 * Default {@link ActionAuthorizationService} that checks an
 * {@link ActionPermission} against the subject's permission set obtained
 * via the configured {@link AuthorizationService}.
 * <p>
 * The action's {@link ActionPermission#name() name} is matched
 * case-sensitively against the {@link PermissionName#value() value} of
 * each permission returned by
 * {@link AuthorizationService#permissionsFor(Object)}, so applications
 * can keep a single string vocabulary across both APIs while opting
 * into the typed action layer.
 * <p>
 * On {@code requireAllowed} denial, this implementation emits an
 * {@link ActionDenied} audit event before throwing.
 *
 * @param <U> subject type
 */
public final class StaticActionAuthorizationService<U> implements ActionAuthorizationService<U> {

  private final AuthorizationService<U> authorizationService;
  private final JSentinelAuditService auditService;

  /**
   * Builds a service that resolves the {@link AuthorizationService} via
   * {@link JSentinelServiceResolver}. Audit events are routed to
   * {@link JSentinelServiceResolver#securityAuditService()} at check time.
   *
   * @param subjectType compile-time helper — kept on the constructor so
   *                    the generic parameter is inferable; not stored
   */
  @SuppressWarnings("unused")
  public StaticActionAuthorizationService(Class<U> subjectType) {
    this(JSentinelServiceResolver.<U>authorizationService(), null);
  }

  /**
   * @param authorizationService the application's authorization service
   * @param auditService         audit sink, or {@code null} to resolve
   *                             from {@link JSentinelServiceResolver}
   *                             at each check
   */
  public StaticActionAuthorizationService(
      AuthorizationService<U> authorizationService,
      JSentinelAuditService auditService) {
    this.authorizationService = Objects.requireNonNull(
        authorizationService, "authorizationService");
    this.auditService = auditService;
  }

  @Override
  public boolean isAllowed(U subject, ActionPermission permission) {
    if (subject == null || permission == null) {
      return false;
    }
    return authorizationService.permissionsFor(subject).permissionNames().stream()
        .map(PermissionName::value)
        .anyMatch(value -> value.equals(permission.name()));
  }

  @Override
  public void requireAllowed(U subject, ActionPermission permission) {
    if (isAllowed(subject, permission)) {
      return;
    }

    String actionName = permission == null ? "<null>" : permission.name();
    auditDenied(subject, actionName);
    throw new AccessDeniedException("Missing action permission: " + actionName);
  }

  private void auditDenied(U subject, String actionName) {
    JSentinelAuditService sink = auditService != null
        ? auditService
        : JSentinelServiceResolver.securityAuditService();
    try {
      String subjectId = subject == null ? null
          : subject.getClass().getSimpleName()
              + "@" + Integer.toHexString(System.identityHashCode(subject));
      sink.publish(new ActionDenied(
          Instant.now(Clock.systemUTC()), subjectId, actionName));
    } catch (RuntimeException auditFailure) {
      // never block the AccessDeniedException because the audit sink failed
    }
  }
}
