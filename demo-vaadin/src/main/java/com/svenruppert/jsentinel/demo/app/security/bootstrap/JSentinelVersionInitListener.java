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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.demo.app.views.MyLoginView;
import com.svenruppert.jsentinel.session.JSentinelVersionEnforcer;
import com.svenruppert.jsentinel.session.JSentinelVersionStore;
import com.svenruppert.jsentinel.session.vaadin.JSentinelVersionEnforcerListener;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.shared.Registration;

import java.util.Optional;

/**
 * Registers the framework's {@link JSentinelVersionEnforcerListener}
 * on every UI so drifted sessions reroute to {@link MyLoginView}.
 * <p>
 * The listener only fires when the {@code LoginView} captured a
 * {@code JSentinelVersion} snapshot at login time — which itself
 * requires both an SPI-registered {@link JSentinelVersionStore} and
 * a {@code SubjectIdResolver}. This demo registers
 * {@link com.svenruppert.jsentinel.session.InMemoryJSentinelVersionStore}
 * and {@link com.svenruppert.jsentinel.demo.app.security.services.DemoSubjectIdResolver}
 * via {@code META-INF/services} so the loop is closed end-to-end.
 * <p>
 * Without an SPI-registered store this initialiser logs a warning
 * and skips registration — the demo still runs, but with drift
 * detection silently disabled.
 */
public class JSentinelVersionInitListener
    implements VaadinServiceInitListener, HasLogger {

  /** Creates a new instance. */
  public JSentinelVersionInitListener() {
  }

  @Override
  public void serviceInit(ServiceInitEvent event) {
    Optional<JSentinelVersionStore> storeOpt =
        JSentinelServiceResolver.findJSentinelVersionStore();
    if (storeOpt.isEmpty()) {
      logger().warn("JSentinelVersionStore SPI not registered — "
          + "Phase 4c drift detection disabled in demo-vaadin");
      return;
    }
    JSentinelVersionEnforcer enforcer = new JSentinelVersionEnforcer(
        storeOpt.get(), JSentinelServiceResolver.securityAuditService());
    event.getSource().addUIInitListener((UIInitListener) uiInitEvent -> {
      JSentinelVersionEnforcerListener listener =
          new JSentinelVersionEnforcerListener(enforcer, MyLoginView.class);
      Registration reg = uiInitEvent.getUI().addBeforeEnterListener(listener);
      uiInitEvent.getUI().addDetachListener(detach -> reg.remove());
    });
  }
}
