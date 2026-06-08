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
package com.svenruppert.vaadin.security.demo.restclient.security;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.demo.restclient.security.resource.DemoDocumentResolver;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.vaadin.bootstrap.VaadinSecurity;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.PolicyDecision;
import com.svenruppert.vaadin.security.policy.api.ResourcePredicates;
import com.svenruppert.vaadin.security.policy.api.SubjectPredicates;
import com.svenruppert.vaadin.security.starter.profile.VaadinSecurityStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * <strong>V00.72 reference: the simplest possible Vaadin-side bootstrap.</strong>
 * <p>
 * This file is the entire security-init surface of {@code demo-vaadin-rest-client}.
 * Everything else is wired through {@code @SecurityAutoService}:
 * <ul>
 *   <li>{@code RestBackedAuthenticationService}  — {@code @SecurityAutoService(AuthenticationService.class)}</li>
 *   <li>{@code RestBackedAuthorizationService}   — {@code @SecurityAutoService(AuthorizationService.class)}</li>
 *   <li>{@code BackedLoginListener}              — {@code @SecurityAutoService(LoginListener.class)}</li>
 *   <li>{@code ProjectRoleAccessEvaluator}       — {@code @SecurityAutoService(AuthorizationEvaluator.class)}</li>
 * </ul>
 * No hand-written {@code META-INF/services/*} files for those SPIs.
 * <p>
 * The {@link #serviceInit(ServiceInitEvent)} body shows the V00.72 way:
 * one fluent call to {@link VaadinSecurity#bootstrap()}, the
 * {@code VaadinSecurityStarter.developmentDefaults()} profile, and a
 * {@code .policies(...)} lambda that registers the three demo policies
 * (V00.71 PolicyRegistry calls — V00.73 will fold these into the
 * fluent surface so this file shrinks further).
 */
public final class DemoPolicyInitListener implements VaadinServiceInitListener {

  /** Name of the role-or-permission demo policy. */
  public static final String POLICY_EDITOR_OR_ADMIN = "documents.editor-or-admin";

  /** Name of the resource-based demo policy. */
  public static final String POLICY_DOCUMENT_OWNER_OR_ADMIN = "document.owner-or-admin";

  /**
   * Demo policy that unconditionally returns
   * {@link PolicyDecision.StepUpMethod#MFA StepUpRequired(MFA)} —
   * lets the Vaadin adapter reroute to the registered step-up route
   * without needing a real MFA backend.
   */
  public static final String POLICY_SENSITIVE_REQUIRES_MFA = "sensitive.requires-mfa";

  private static final AtomicBoolean DONE = new AtomicBoolean();

  @Override
  public void serviceInit(ServiceInitEvent event) {
    if (!DONE.compareAndSet(false, true)) {
      return;
    }
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElseThrow(() -> new IllegalStateException(
            "No AuthenticationService registered. "
                + "Expected RestBackedAuthenticationService via @SecurityAutoService."));
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElseThrow(() -> new IllegalStateException(
            "No AuthorizationService registered. "
                + "Expected RestBackedAuthorizationService via @SecurityAutoService."));

    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinSecurityStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        .stepUpRoute("step-up")
        .policies(p -> registerDemoPolicies())
        .install();

    System.out.println(runtime.log());
  }

  /**
   * Registers the three demo policies plus the document resource
   * resolver. V00.72 hosts these through the PolicyRegistry /
   * ResourceResolverRegistry SPIs directly; the fluent
   * {@code .policies(...)} sub-builder is a recorded-only placeholder
   * in V00.72 (see its JavaDoc) and folds into actual wiring in V00.73.
   */
  private static void registerDemoPolicies() {
    SecurityServiceResolver.resourceResolverRegistry().register(new DemoDocumentResolver());

    var registry = SecurityServiceResolver.policyRegistry();

    registry.register(Policy.named(POLICY_EDITOR_OR_ADMIN)
        .allowIf(SubjectPredicates.hasAnyRole("ROLE_ADMIN", "ROLE_EDITOR"))
        .orIf(SubjectPredicates.hasPermission("document:write"))
        .deny("must be ADMIN/EDITOR or hold document:write")
        .build());

    registry.register(Policy.named(POLICY_DOCUMENT_OWNER_OR_ADMIN)
        .allowIf(SubjectPredicates.hasRole("ROLE_ADMIN"))
        .orIf(ResourcePredicates.ownerMatchesSubject(
            DemoDocumentResolver.RESOURCE_TYPE,
            DemoDocumentResolver.OWNER_ATTRIBUTE))
        .deny("must be ADMIN or document owner")
        .build());

    registry.register(Policy.named(POLICY_SENSITIVE_REQUIRES_MFA)
        .stepUpRequiredIf(ctx -> true, PolicyDecision.StepUpMethod.MFA,
            "MFA challenge required for sensitive operations")
        .build());
  }
}
