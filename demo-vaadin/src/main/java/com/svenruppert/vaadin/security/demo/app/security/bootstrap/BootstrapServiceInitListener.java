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
package com.svenruppert.vaadin.security.demo.app.security.bootstrap;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.vaadin.bootstrap.VaadinSecurity;
import com.svenruppert.vaadin.security.starter.profile.VaadinSecurityStarter;
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
 * {@link VaadinSecurityStarter#developmentDefaults()} profile), pulling the
 * {@code @SecurityAutoService}-registered SPIs through {@code ServiceLoader}
 * and printing the resulting {@link SecurityRuntime#log()} so the operator
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
    SecurityRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinSecurityStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        .stepUpRoute("step-up")
        .install();
    System.out.println(runtime.log());
  }
}
