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
package com.svenruppert.vaadin.security.logout.vaadin;

import com.vaadin.flow.internal.CurrentInstance;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Validates that the gateway is safe to call from threads where Vaadin's
 * thread-locals (UI/VaadinSession) are not bound — which is exactly what
 * happens during a logout that is initiated from outside the request thread.
 */
@DisplayName("DefaultVaadinLogoutGateway — no-current guards")
class DefaultVaadinLogoutGatewayTest {

  private final DefaultVaadinLogoutGateway gateway = new DefaultVaadinLogoutGateway();

  @BeforeEach
  void clearVaadinThreadLocals() {
    CurrentInstance.clearAll();
  }

  @AfterEach
  void restoreThreadLocals() {
    CurrentInstance.clearAll();
  }

  @Test
  @DisplayName("redirectTo is a safe no-op when no current UI is bound")
  void redirectTo_noUI() {
    assertDoesNotThrow(() -> gateway.redirectTo("/login"));
  }

  @Test
  @DisplayName("closeVaadinSession is a safe no-op when no current session is bound")
  void closeVaadinSession_noSession() {
    assertDoesNotThrow(gateway::closeVaadinSession);
  }

  @Test
  @DisplayName("invalidateHttpSession is a safe no-op when no current session is bound")
  void invalidateHttpSession_noSession() {
    assertDoesNotThrow(gateway::invalidateHttpSession);
  }
}
