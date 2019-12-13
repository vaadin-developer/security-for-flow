/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.rapidpm.vaadin.security;

import com.vaadin.flow.component.UI;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.UIInitListener;
import com.vaadin.flow.server.VaadinServiceInitListener;
import com.vaadin.flow.shared.Registration;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.vaadin.security.authorization.LoginListener;
import org.rapidpm.vaadin.security.authorization.LoginListenerProvider;

public class ApplicationServiceInitListener
    implements VaadinServiceInitListener, HasLogger {

  private Registration loginRegistration;

  @Override
  public void serviceInit(ServiceInitEvent e) {
    e.getSource()
     .addUIInitListener((UIInitListener) uiInitEvent -> {
       UI ui = uiInitEvent.getUI();
       logger().info("init LoginListener for .. " + ui.getRouter());

       final LoginListener loginListener = new LoginListenerProvider().load();
       loginRegistration = ui.addBeforeEnterListener(loginListener);

     });
  }
}
