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
package com.svenruppert.jsentinel.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BootstrapStatus")
class BootstrapStatusTest {

  @Test
  @DisplayName("never exposes a token field")
  void noTokenField() {
    boolean hasTokenField = Arrays.stream(BootstrapStatus.class.getRecordComponents())
        .map(RecordComponent::getName)
        .anyMatch(name -> name.toLowerCase().contains("token"));
    assertFalse(hasTokenField, "BootstrapStatus must not expose a token field");
  }

  @Test
  @DisplayName("from(state) snapshots required + mode")
  void fromState() {
    AdministratorAccountStore admins = new AdministratorAccountStore() {
      @Override public boolean hasAnyAdministrator() { return false; }
      @Override public void createAdministrator(NewAdministrator n) { }
    };
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.PERSISTENT_FILE);
    BootstrapStatus snapshot = BootstrapStatus.from(state);
    assertTrue(snapshot.bootstrapRequired());
    assertEquals(BootstrapMode.PERSISTENT_FILE, snapshot.mode());
  }
}
