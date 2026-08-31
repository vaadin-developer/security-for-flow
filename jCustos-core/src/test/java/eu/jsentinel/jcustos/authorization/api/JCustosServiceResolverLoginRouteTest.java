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
package eu.jsentinel.jcustos.authorization.api;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosServiceResolver — configurable login route (R025)")
class JCustosServiceResolverLoginRouteTest {

  @AfterEach
  void tearDown() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("loginRouteName() returns the default 'login' when nothing was configured")
  void defaultRouteName() {
    assertEquals(JCustosServiceResolver.DEFAULT_LOGIN_ROUTE_NAME,
        JCustosServiceResolver.loginRouteName());
    assertEquals("login", JCustosServiceResolver.DEFAULT_LOGIN_ROUTE_NAME);
    assertTrue(JCustosServiceResolver.findLoginRouteName().isEmpty());
  }

  @Test
  @DisplayName("setLoginRouteName overrides the default")
  void overrideRouteName() {
    JCustosServiceResolver.setLoginRouteName("sign-in");
    assertEquals("sign-in", JCustosServiceResolver.loginRouteName());
    assertEquals(Optional.of("sign-in"), JCustosServiceResolver.findLoginRouteName());
  }

  @Test
  @DisplayName("setLoginRouteName(null) resets to the default")
  void resetRouteName() {
    JCustosServiceResolver.setLoginRouteName("sign-in");
    JCustosServiceResolver.setLoginRouteName(null);
    assertEquals(JCustosServiceResolver.DEFAULT_LOGIN_ROUTE_NAME,
        JCustosServiceResolver.loginRouteName());
  }

  @Test
  @DisplayName("setLoginRouteName rejects a blank route name")
  void rejectsBlank() {
    assertThrows(IllegalArgumentException.class,
        () -> JCustosServiceResolver.setLoginRouteName(""));
    assertThrows(IllegalArgumentException.class,
        () -> JCustosServiceResolver.setLoginRouteName("   "));
  }

  @Test
  @DisplayName("resetAll() clears the configured login route name")
  void resetAllClears() {
    JCustosServiceResolver.setLoginRouteName("sign-in");
    JCustosServiceResolver.resetAll();
    assertEquals(JCustosServiceResolver.DEFAULT_LOGIN_ROUTE_NAME,
        JCustosServiceResolver.loginRouteName());
  }
}
