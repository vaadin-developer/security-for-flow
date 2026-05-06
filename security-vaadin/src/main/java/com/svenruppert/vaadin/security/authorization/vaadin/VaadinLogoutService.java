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

import com.svenruppert.vaadin.security.authorization.api.LogoutContext;
import com.svenruppert.vaadin.security.authorization.api.LogoutPolicy;
import com.svenruppert.vaadin.security.authorization.api.LogoutService;
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

  public VaadinLogoutService(SubjectStore subjectStore, Class<U> subjectType) {
    this(subjectStore, subjectType, new DefaultVaadinLogoutGateway());
  }

  public VaadinLogoutService(
      SubjectStore subjectStore,
      Class<U> subjectType,
      VaadinLogoutGateway gateway) {
    this.subjectStore = Objects.requireNonNull(subjectStore, "subjectStore");
    this.subjectType = Objects.requireNonNull(subjectType, "subjectType");
    this.gateway = Objects.requireNonNull(gateway, "gateway");
  }

  @Override
  public void logout(LogoutContext context) {
    Objects.requireNonNull(context, "context");
    LogoutPolicy policy = context.policy();

    subjectStore.deleteCurrentSubject(subjectType);
    gateway.redirectTo(policy.targetRoute());

    if (policy.clearSubjectOnly()) return;
    if (policy.invalidateHttpSession()) gateway.invalidateHttpSession();
    if (policy.closeVaadinSession()) gateway.closeVaadinSession();
  }
}
