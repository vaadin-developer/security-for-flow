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
package eu.jsentinel.jcustos.authorization.navigation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("NavigationAccessDecision factory methods")
class NavigationAccessDecisionTest {

  @Test
  @DisplayName("allowed() returns Allowed instance")
  void allowed() {
    var decision = NavigationAccessDecision.allowed();
    assertInstanceOf(NavigationAccessDecision.Allowed.class, decision);
  }

  @Test
  @DisplayName("loginRequired() returns LoginRequired instance")
  void loginRequired() {
    var decision = NavigationAccessDecision.loginRequired();
    assertInstanceOf(NavigationAccessDecision.LoginRequired.class, decision);
  }

  @Test
  @DisplayName("alreadyLoggedIn() returns AlreadyLoggedIn instance")
  void alreadyLoggedIn() {
    var decision = NavigationAccessDecision.alreadyLoggedIn();
    assertInstanceOf(NavigationAccessDecision.AlreadyLoggedIn.class, decision);
  }

  @Test
  @DisplayName("accessDenied() carries route and forward flag")
  void accessDenied() {
    var decision = NavigationAccessDecision.accessDenied("error-page", true);
    assertInstanceOf(NavigationAccessDecision.AccessDenied.class, decision);
    var denied = (NavigationAccessDecision.AccessDenied) decision;
    assertEquals("error-page", denied.alternativeRoute());
    assertTrue(denied.asForward());
  }
}
