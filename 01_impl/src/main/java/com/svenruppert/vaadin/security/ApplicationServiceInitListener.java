/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.svenruppert.vaadin.security;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.vaadin.flow.component.UI;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.shared.Registration;

public class ApplicationServiceInitListener
    implements VaadinServiceInitListener, HasLogger {

  @Override
  public void serviceInit(ServiceInitEvent e) {
    e.getSource()
        .addUIInitListener((UIInitListener) uiInitEvent -> {
          UI ui = uiInitEvent.getUI();
          logger().info("init LoginListener for .. " + ui);
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
