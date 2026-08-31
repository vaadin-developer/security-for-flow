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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Verifies the V00.75.10 split of {@link JSentinelServiceResolver} into a
 * static facade over a per-instance {@link JSentinelContext}.
 * <p>
 * No mocks — a tiny real {@link JSentinelAuditService} captures published
 * events so isolation can be asserted on a genuine service instance.
 */
class JSentinelContextTest {

  /** Minimal real audit service — no mock framework. */
  private static final class RecordingAudit implements JSentinelAuditService {
    private final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.copyOf(events);
    }
  }

  @BeforeEach
  @AfterEach
  void resetDefault() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  void isolatedContextsDoNotLeakStepUpRouteName() {
    JSentinelContext a = JSentinelContext.createIsolated();
    JSentinelContext b = JSentinelContext.createIsolated();

    assertNotSame(a, b);

    a.setStepUpRouteName("step-up-a");

    assertEquals("step-up-a", a.stepUpRouteName());
    assertTrue(a.findStepUpRouteName().isPresent());

    // b is untouched — it still reports the default and no configured value.
    assertEquals(JSentinelServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME, b.stepUpRouteName());
    assertFalse(b.findStepUpRouteName().isPresent());
  }

  @Test
  void isolatedContextsDoNotLeakServices() {
    JSentinelContext a = JSentinelContext.createIsolated();
    JSentinelContext b = JSentinelContext.createIsolated();

    RecordingAudit auditA = new RecordingAudit();
    a.setJSentinelAuditService(auditA);

    assertSame(auditA, a.securityAuditService());
    assertTrue(a.findJSentinelAuditService().isPresent());

    // b never received the service — it falls back to the noop and reports
    // "no SPI" through the Optional accessor.
    assertFalse(b.findJSentinelAuditService().isPresent());
    assertNotSame(auditA, b.securityAuditService());
  }

  @Test
  void staticFacadeAndCurrentContextShareState() {
    JSentinelContext current = JSentinelServiceResolver.current();

    // facade -> current
    JSentinelServiceResolver.setStepUpRouteName("via-facade");
    assertEquals("via-facade", current.stepUpRouteName());

    // current -> facade
    current.setStepUpRouteName("via-context");
    assertEquals("via-context", JSentinelServiceResolver.stepUpRouteName());

    // same for a service: set through the facade, read through current
    RecordingAudit audit = new RecordingAudit();
    JSentinelServiceResolver.setJSentinelAuditService(audit);
    assertSame(audit, current.securityAuditService());

    // and the reverse: set through current, read through the facade
    RecordingAudit audit2 = new RecordingAudit();
    current.setJSentinelAuditService(audit2);
    assertSame(audit2, JSentinelServiceResolver.securityAuditService());
  }

  @Test
  void currentReturnsTheSameDefaultContextEachCall() {
    assertSame(JSentinelServiceResolver.current(), JSentinelServiceResolver.current());
  }

  @Test
  void instanceResetAllClearsOnlyThatInstance() {
    JSentinelContext a = JSentinelContext.createIsolated();
    JSentinelContext b = JSentinelContext.createIsolated();

    a.setStepUpRouteName("route-a");
    b.setStepUpRouteName("route-b");

    a.resetAll();

    // a is back to default; b is untouched.
    assertEquals(JSentinelServiceResolver.DEFAULT_STEP_UP_ROUTE_NAME, a.stepUpRouteName());
    assertFalse(a.findStepUpRouteName().isPresent());
    assertEquals("route-b", b.stepUpRouteName());
  }
}
