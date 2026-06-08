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
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;
import com.svenruppert.vaadin.security.policy.spi.ResourceResolverRegistry;
import com.svenruppert.vaadin.security.starter.profile.VaadinSecurityStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Registers the demo-side policies and resource resolvers into the
 * {@link PolicyRegistry} and {@link ResourceResolverRegistry}
 * resolved through {@link SecurityServiceResolver}. Discovered via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 *
 * <p>Two demo policies ship with this listener:
 * <ul>
 *   <li>{@link #POLICY_EDITOR_OR_ADMIN} — combines role- and
 *       permission-based admission in a single rule.</li>
 *   <li>{@link #POLICY_DOCUMENT_OWNER_OR_ADMIN} — combines role-based
 *       admission with per-resource ownership lookup via
 *       {@link ResourcePredicates#ownerMatchesSubject(String, String)}.</li>
 * </ul>
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

  private static final AtomicBoolean DX_BOOTSTRAP_DONE = new AtomicBoolean();

  @Override
  public void serviceInit(ServiceInitEvent event) {
    registerResourceResolvers();
    registerPolicies();
    if (DX_BOOTSTRAP_DONE.compareAndSet(false, true)) {
      runDxBootstrap();
    }
  }

  // V00.72: the Vaadin-side fluent bootstrap. Authenticates against the
  // demo-rest backend via the @SecurityAutoService-registered
  // RestBackedAuthenticationService / RestBackedAuthorizationService.
  private static void runDxBootstrap() {
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElse(null);
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElse(null);
    if (authn == null || authz == null) {
      return;
    }
    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinSecurityStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        .stepUpRoute("step-up")
        .install();
    System.out.println(runtime.log());
  }

  private static void registerResourceResolvers() {
    ResourceResolverRegistry registry = SecurityServiceResolver.resourceResolverRegistry();
    registry.register(new DemoDocumentResolver());
  }

  private static void registerPolicies() {
    PolicyRegistry registry = SecurityServiceResolver.policyRegistry();

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
