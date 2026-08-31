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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosServiceResolver — JS-SEC-024 deny-by-default flag")
class JCustosServiceResolverDenyByDefaultTest {

  @AfterEach
  void reset() {
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("default is allow-by-omission (deny-by-default off)")
  void defaultIsFalse() {
    JCustosServiceResolver.resetAll();
    assertFalse(JCustosServiceResolver.isDenyByDefault());
  }

  @Test
  @DisplayName("setter toggles the flag both ways")
  void setterToggles() {
    JCustosServiceResolver.setDenyByDefault(true);
    assertTrue(JCustosServiceResolver.isDenyByDefault());
    JCustosServiceResolver.setDenyByDefault(false);
    assertFalse(JCustosServiceResolver.isDenyByDefault());
  }

  @Test
  @DisplayName("resetAll clears the flag back to allow-by-omission")
  void resetClearsFlag() {
    JCustosServiceResolver.setDenyByDefault(true);
    JCustosServiceResolver.resetAll();
    assertFalse(JCustosServiceResolver.isDenyByDefault());
  }
}
