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
package com.svenruppert.vaadin.security.authorization.impl;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.vaadin.flow.router.BeforeEnterEvent;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Creates core {@link AccessContext} instances from Vaadin navigation
 * events.
 * <p>
 * Reads the current authenticated subject (via {@link SubjectStores}) and
 * adapts it to a {@link JSentinelSubject} so generic
 * {@code AuthorizationEvaluator} implementations (such as
 * {@code RequiresRoleEvaluator} and {@code RequiresPermissionEvaluator}
 * shipped in {@code security-core}) see the subject's roles and
 * permissions through {@link AccessContext#subject()}.
 * <p>
 * The legacy {@code RoleBasedAccessEvaluator} family reads the subject
 * directly from {@link SubjectStores} and is unaffected by this change.
 */
public final class VaadinAccessContextFactory {

  /** Creates a new factory. */
  public VaadinAccessContextFactory() {
  }

  /**
   * Creates an access context from a Vaadin event.
   *
   * @param event the before-enter event
   * @return access context
   */
  public AccessContext create(BeforeEnterEvent event) {
    Map<String, Object> attributes = new LinkedHashMap<>();
    attributes.put("location", event.getLocation());
    attributes.put("path", event.getLocation().getPath());
    attributes.put("target", event.getNavigationTarget());
    return new AccessContext(
        currentJSentinelSubject(),
        "vaadin-view",
        event.getNavigationTarget().getSimpleName(),
        "navigate",
        Map.copyOf(attributes));
  }

  /**
   * Builds a {@link JSentinelSubject} snapshot for the current
   * Vaadin-session subject so generic evaluators can read roles and
   * permissions from the {@link AccessContext}. Returns
   * {@link Optional#empty()} if no subject is authenticated or the
   * security services are not (yet) wired.
   */
  @SuppressWarnings({"rawtypes", "unchecked"})
  private static Optional<JSentinelSubject> currentJSentinelSubject() {
    Class subjectType;
    try {
      AuthenticationService<?, ?> authentication = JSentinelServiceResolver.authenticationService();
      if (authentication == null) return Optional.empty();
      subjectType = authentication.subjectType();
      if (subjectType == null) return Optional.empty();
    } catch (RuntimeException e) {
      return Optional.empty();
    }
    Optional<Object> subjectOpt = SubjectStores.subjectStore().currentSubject(subjectType);
    if (subjectOpt.isEmpty()) return Optional.empty();
    Object subject = subjectOpt.get();

    AuthorizationService<Object> authorization;
    try {
      authorization = JSentinelServiceResolver.authorizationService();
      if (authorization == null) return Optional.empty();
    } catch (RuntimeException e) {
      return Optional.empty();
    }

    Set<RoleName> roles;
    Set<PermissionName> permissions;
    try {
      roles = authorization.rolesFor(subject).roleNames().stream()
          .collect(Collectors.toUnmodifiableSet());
      permissions = authorization.permissionsFor(subject).permissionNames().stream()
          .collect(Collectors.toUnmodifiableSet());
    } catch (RuntimeException e) {
      return Optional.empty();
    }

    String subjectId = subject.getClass().getSimpleName() + "@"
        + Integer.toHexString(System.identityHashCode(subject));
    String displayName = subject.toString();
    if (displayName == null || displayName.isBlank()) displayName = subjectId;
    return Optional.of(new JSentinelSubject(subjectId, displayName, roles, permissions));
  }
}
