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
package com.svenruppert.jsentinel.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionDecisionTest {

  @Test
  @DisplayName("Continue.INSTANCE is a stable singleton")
  void continueSingleton() {
    assertSame(SessionDecision.Continue.INSTANCE, SessionDecision.Continue.INSTANCE);
    assertSame(SessionDecision.Continue.INSTANCE, SessionDecision.cont());
  }

  @Test
  @DisplayName("RequireLogin carries the configured loginRoute")
  void requireLogin() {
    SessionDecision.RequireLogin r = new SessionDecision.RequireLogin("/login");
    assertEquals("/login", r.loginRoute());
  }

  @Test
  @DisplayName("Invalidate carries reason and loginRoute")
  void invalidate() {
    SessionDecision.Invalidate i = new SessionDecision.Invalidate("idle", "/login");
    assertEquals("idle", i.reason());
    assertEquals("/login", i.loginRoute());
  }

  @Test
  @DisplayName("sealed switch covers every variant")
  void sealedSwitch() {
    SessionDecision[] decisions = {
        SessionDecision.Continue.INSTANCE,
        new SessionDecision.RequireLogin("/login"),
        new SessionDecision.Invalidate("expired", "/login")
    };

    for (SessionDecision d : decisions) {
      String label = switch (d) {
        case SessionDecision.Continue() -> "continue";
        case SessionDecision.RequireLogin(String r) -> "require:" + r;
        case SessionDecision.Invalidate(String reason, String r) -> "invalidate:" + reason;
      };
      assertTrue(label != null && !label.isEmpty());
    }
  }
}
