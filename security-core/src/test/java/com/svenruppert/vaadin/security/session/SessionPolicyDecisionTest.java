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
package com.svenruppert.vaadin.security.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

class SessionPolicyDecisionTest {

  @Test
  @DisplayName("active() returns the singleton Active instance")
  void activeSingleton() {
    assertSame(SessionPolicyDecision.Active.INSTANCE, SessionPolicyDecision.active());
    assertSame(SessionPolicyDecision.active(), SessionPolicyDecision.active());
  }

  @Test
  @DisplayName("idleTimeout() returns the singleton IdleTimeout instance")
  void idleTimeoutSingleton() {
    assertSame(SessionPolicyDecision.IdleTimeout.INSTANCE,
        SessionPolicyDecision.idleTimeout());
  }

  @Test
  @DisplayName("absoluteLifetimeExceeded() returns the singleton instance")
  void absoluteLifetimeSingleton() {
    assertSame(SessionPolicyDecision.AbsoluteLifetimeExceeded.INSTANCE,
        SessionPolicyDecision.absoluteLifetimeExceeded());
  }

  @Test
  @DisplayName("sealed switch covers every variant exhaustively")
  void exhaustiveSwitch() {
    SessionPolicyDecision[] decisions = {
        SessionPolicyDecision.active(),
        SessionPolicyDecision.idleTimeout(),
        SessionPolicyDecision.absoluteLifetimeExceeded()
    };

    for (SessionPolicyDecision d : decisions) {
      String label = switch (d) {
        case SessionPolicyDecision.Active() -> "active";
        case SessionPolicyDecision.IdleTimeout() -> "idle";
        case SessionPolicyDecision.AbsoluteLifetimeExceeded() -> "absolute";
      };
      assertNotNull(label);
      assertEquals(false, label.isEmpty());
    }
  }
}
