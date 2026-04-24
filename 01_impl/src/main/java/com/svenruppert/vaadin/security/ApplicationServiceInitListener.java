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
package com.svenruppert.vaadin.security;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.shared.Registration;

/**
 * Vaadin service initializer that registers the {@link com.svenruppert.vaadin.security.authorization.LoginListener}
 * as a {@link com.vaadin.flow.router.BeforeEnterListener} on every UI.
 * <p>
 * Registered via {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 */
public class ApplicationServiceInitListener
    implements VaadinServiceInitListener, HasLogger {

  /** Creates a new instance. */
  public ApplicationServiceInitListener() {
  }

  @Override
  public void serviceInit(ServiceInitEvent e) {
    e.getSource()
        .addUIInitListener((UIInitListener) uiInitEvent -> {
          UI ui = uiInitEvent.getUI();
          logger().info("init LoginListener for .. {}", ui);
          SecurityServiceResolver.findLoginListener()
              .ifPresentOrElse(
                  loginListener -> {
                    Registration reg = ui.addBeforeEnterListener(loginListener);
                    ui.addDetachListener(detach -> reg.remove());
                  },
                  () -> logger().warn("Unable to resolve LoginListener — "
                      + "no implementation found in META-INF/services/"
                      + "com.svenruppert.vaadin.security.authorization.LoginListener"));
        });
  }
}