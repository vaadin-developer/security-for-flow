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

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("NoopSecurityAuditService")
class NoopSecurityAuditServiceTest {

  @Test
  @DisplayName("publish silently discards the event")
  void publishIsSilent() {
    NoopSecurityAuditService.INSTANCE.publish(
        new LoginSucceeded(Instant.now(), "alice", null, null));
    // no exception, no side effect to assert; the type contract is that it must not throw
  }

  @Test
  @DisplayName("publish tolerates null events without throwing")
  void publishTolerantOfNull() {
    NoopSecurityAuditService.INSTANCE.publish(null);
  }

  @Test
  @DisplayName("query returns an empty list regardless of the filter")
  void queryReturnsEmpty() {
    assertTrue(NoopSecurityAuditService.INSTANCE.query(AuditQuery.all()).isEmpty());
    assertTrue(NoopSecurityAuditService.INSTANCE
        .query(AuditQuery.ofType(LoginSucceeded.class)).isEmpty());
  }
}
