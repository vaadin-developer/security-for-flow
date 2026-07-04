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
package com.svenruppert.jsentinel.authorization.api;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JSentinelServiceResolver — JS-SEC-024 deny-by-default flag")
class JSentinelServiceResolverDenyByDefaultTest {

  @AfterEach
  void reset() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("default is allow-by-omission (deny-by-default off)")
  void defaultIsFalse() {
    JSentinelServiceResolver.resetAll();
    assertFalse(JSentinelServiceResolver.isDenyByDefault());
  }

  @Test
  @DisplayName("setter toggles the flag both ways")
  void setterToggles() {
    JSentinelServiceResolver.setDenyByDefault(true);
    assertTrue(JSentinelServiceResolver.isDenyByDefault());
    JSentinelServiceResolver.setDenyByDefault(false);
    assertFalse(JSentinelServiceResolver.isDenyByDefault());
  }

  @Test
  @DisplayName("resetAll clears the flag back to allow-by-omission")
  void resetClearsFlag() {
    JSentinelServiceResolver.setDenyByDefault(true);
    JSentinelServiceResolver.resetAll();
    assertFalse(JSentinelServiceResolver.isDenyByDefault());
  }
}
