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
package com.svenruppert.vaadin.security.authorization.vaadin;

import com.svenruppert.vaadin.security.audit.SecurityAuditEvent;
import com.svenruppert.vaadin.security.audit.SecurityAuditEventType;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.LogoutContext;
import com.svenruppert.vaadin.security.authorization.api.LogoutPolicy;
import com.svenruppert.vaadin.security.authorization.api.LogoutService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;

import java.util.Objects;

/**
 * Vaadin-aware {@link LogoutService}. Drops the subject from the
 * {@link SubjectStore}, optionally invalidates the underlying servlet
 * session and closes the Vaadin session, and triggers a browser redirect
 * to the configured target route.
 * <p>
 * Order of operations:
 * <ol>
 *   <li>Subject removed from {@link SubjectStore}.</li>
 *   <li>Browser redirect scheduled via {@code Page.setLocation(...)} —
 *       the response carries the redirect, so the next request creates a
 *       fresh session even if invalidation happens below.</li>
 *   <li>HTTP session invalidated (when policy demands it).</li>
 *   <li>Vaadin session closed (when policy demands it).</li>
 * </ol>
 *
 * <p>The Vaadin static APIs are isolated behind {@link VaadinLogoutGateway}
 * so this service can be unit-tested without a Vaadin runtime.
 *
 * @param <U> subject type
 */
public final class VaadinLogoutService<U> implements LogoutService {

  private final SubjectStore subjectStore;
  private final Class<U> subjectType;
  private final VaadinLogoutGateway gateway;
  private final SecurityAuditService auditService;

  public VaadinLogoutService(SubjectStore subjectStore, Class<U> subjectType) {
    this(subjectStore, subjectType, new DefaultVaadinLogoutGateway(), null);
  }

  public VaadinLogoutService(
      SubjectStore subjectStore,
      Class<U> subjectType,
      VaadinLogoutGateway gateway) {
    this(subjectStore, subjectType, gateway, null);
  }

  /**
   * @param subjectStore subject store to clear
   * @param subjectType  subject type token
   * @param gateway      Vaadin-side gateway for session/redirect calls
   * @param auditService audit sink, or {@code null} to resolve from
   *                     {@link SecurityServiceResolver#securityAuditService()}
   *                     at logout time
   */
  public VaadinLogoutService(
      SubjectStore subjectStore,
      Class<U> subjectType,
      VaadinLogoutGateway gateway,
      SecurityAuditService auditService) {
    this.subjectStore = Objects.requireNonNull(subjectStore, "subjectStore");
    this.subjectType = Objects.requireNonNull(subjectType, "subjectType");
    this.gateway = Objects.requireNonNull(gateway, "gateway");
    this.auditService = auditService;
  }

  @Override
  public void logout(LogoutContext context) {
    Objects.requireNonNull(context, "context");
    LogoutPolicy policy = context.policy();

    auditLogout(context, policy);

    subjectStore.deleteCurrentSubject(subjectType);
    gateway.redirectTo(policy.targetRoute());

    if (policy.clearSubjectOnly()) {
      return;
    }
    if (policy.invalidateHttpSession()) {
      gateway.invalidateHttpSession();
    }
    if (policy.closeVaadinSession()) {
      gateway.closeVaadinSession();
    }
  }

  private void auditLogout(LogoutContext context, LogoutPolicy policy) {
    SecurityAuditService sink = auditService != null
        ? auditService
        : SecurityServiceResolver.securityAuditService();
    try {
      sink.record(SecurityAuditEvent.builder(SecurityAuditEventType.LOGOUT)
          .route(policy.targetRoute())
          .decision(policy.clearSubjectOnly() ? "CLEAR_SUBJECT" : "INVALIDATE_SESSION")
          .attribute("closeVaadinSession", String.valueOf(policy.closeVaadinSession()))
          .attribute("invalidateHttpSession", String.valueOf(policy.invalidateHttpSession()))
          .attributes(context.attributes() == null ? null : toStringMap(context.attributes()))
          .build());
    } catch (RuntimeException auditFailure) {
      // never block a logout because the audit sink failed
    }
  }

  private static java.util.Map<String, String> toStringMap(java.util.Map<String, Object> in) {
    java.util.Map<String, String> out = new java.util.LinkedHashMap<>();
    in.forEach((k, v) -> {
      if (v != null) {
        out.put(k, v.toString());
      }
    });
    return out;
  }
}
