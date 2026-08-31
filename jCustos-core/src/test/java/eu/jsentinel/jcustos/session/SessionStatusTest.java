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
package eu.jsentinel.jcustos.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SessionStatus")
class SessionStatusTest {

  @Test
  @DisplayName("enum has exactly three values: ACTIVE / EXPIRED / REVOKED")
  void hasThreeValues() {
    assertEquals(3, SessionStatus.values().length);
    SessionStatus.valueOf("ACTIVE");
    SessionStatus.valueOf("EXPIRED");
    SessionStatus.valueOf("REVOKED");
  }

  @Test
  @DisplayName("isActive() returns true only for ACTIVE")
  void isActive() {
    assertTrue(SessionStatus.ACTIVE.isActive());
    assertFalse(SessionStatus.EXPIRED.isActive());
    assertFalse(SessionStatus.REVOKED.isActive());
  }
}
