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
package com.svenruppert.vaadin.security.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;

class NoopSecurityAuditServiceTest {

  @Test
  @DisplayName("INSTANCE returns the singleton")
  void singletonInstance() {
    assertSame(NoopSecurityAuditService.INSTANCE, NoopSecurityAuditService.INSTANCE);
  }

  @Test
  @DisplayName("record() never throws — neither for null nor for any populated event")
  void neverThrows() {
    SecurityAuditService service = NoopSecurityAuditService.INSTANCE;
    assertDoesNotThrow(() -> service.record(null));
    assertDoesNotThrow(() -> service.record(SecurityAuditEvent.of(SecurityAuditEventType.LOGOUT)));
  }
}
