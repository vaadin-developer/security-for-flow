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
package com.svenruppert.jsentinel.demo.app.security.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.credential.password.PasswordHashingServices;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.vaadin.bootstrap.VaadinSecurity;
import com.svenruppert.jsentinel.policy.api.JSentinelPolicies;
import com.svenruppert.jsentinel.starter.profile.VaadinJSentinelStarter;

import java.util.Set;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Eagerly initializes {@link BootstrapWiring} on Vaadin service start so the
 * setup banner (transient mode) or the file path message (persistent mode)
 * is shown immediately — without having to first navigate to {@code /login}.
 * <p>
 * <strong>V00.72:</strong> the listener also runs the new fluent bootstrap
 * once per JVM ({@link VaadinSecurity#bootstrap()} with the
 * {@link VaadinJSentinelStarter#developmentDefaults()} profile), pulling the
 * {@code @JSentinelAutoService}-registered SPIs through {@code ServiceLoader}
 * and printing the resulting {@link JSentinelRuntime#log()} so the operator
 * sees which services are active at startup.
 */
public class BootstrapServiceInitListener implements VaadinServiceInitListener {

  private static final AtomicBoolean DX_BOOTSTRAP_DONE = new AtomicBoolean();

  @Override
  public void serviceInit(ServiceInitEvent event) {
    BootstrapWiring.instance();
    if (DX_BOOTSTRAP_DONE.compareAndSet(false, true)) {
      runDxBootstrap();
    }
  }

  private static void runDxBootstrap() {
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElse(null);
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElse(null);
    if (authn == null || authz == null) {
      // Falls back to the legacy ServiceLoader path; the V00.72 bootstrap is
      // additive and not required for the demo to function.
      return;
    }
    // V00.73: typed sub-builders. .audit(...) surfaces a logging sink
    // and an in-memory ring buffer in JSentinelDiagnostics; .credentials(...)
    // exposes the V00.71 password-hashing pipeline that BootstrapWiring
    // already uses internally so it shows up in JSentinelRuntime.services().
    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinJSentinelStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        .stepUpRoute("step-up")
        .audit(a -> a.ringBuffer(256).logging())
        .credentials(c -> c.hashing(PasswordHashingServices.defaults()))
        // V00.73 + V00.74: register a Policy so the PermissionDemoCard's
        // Pattern D "SecuredUi.button(...).requiresPolicy(...)" entry has a
        // real policy to evaluate against. anyRoleOrPermission() is the
        // simplest pre-built shape: allow if ADMIN or holding demo:edit.
        .policies(p -> p.register(JSentinelPolicies.anyRoleOrPermission(
            "demo.admin-or-edit", Set.of("ADMIN"), Set.of("demo:edit"))))
        .install();
    System.out.println(runtime.log());
  }
}
