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
package eu.jsentinel.jcustos.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DefaultCompositeAuditService")
class DefaultCompositeAuditServiceTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");

  @Test
  @DisplayName("publish stores the event in the ring buffer (queryable)")
  void publishGoesToRingBuffer() {
    DefaultCompositeAuditService svc = new DefaultCompositeAuditService();
    svc.publish(new LoginSucceeded(T0, "alice", "127.0.0.1", "sid"));

    assertEquals(1, svc.query(AuditQuery.all()).size());
    assertTrue(svc.query(AuditQuery.all()).get(0) instanceof LoginSucceeded);
  }

  @Test
  @DisplayName("query delegates through to the underlying buffer")
  void queryDelegates() {
    DefaultCompositeAuditService svc = new DefaultCompositeAuditService();
    svc.publish(new LoginSucceeded(T0, "alice", null, null));
    svc.publish(new LoginFailed(T0.plusSeconds(1), "alice", null, "bad-pw"));

    assertEquals(2, svc.query(AuditQuery.all()).size());
  }

  @Test
  @DisplayName("ringBuffer() exposes the buffer used by query")
  void ringBufferAccessor() {
    DefaultCompositeAuditService svc = new DefaultCompositeAuditService();
    RingBufferAuditSink buffer = svc.ringBuffer();
    assertNotNull(buffer);

    svc.publish(new LoginSucceeded(T0, "alice", null, null));
    // Buffer + service must observe the same record set
    assertEquals(svc.query(AuditQuery.all()).size(),
        buffer.query(AuditQuery.all()).size());
  }
}
