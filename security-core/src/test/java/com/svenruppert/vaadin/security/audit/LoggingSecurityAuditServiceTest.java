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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoggingSecurityAuditServiceTest {

  @Test
  @DisplayName("record(null) is a safe no-op")
  void nullEventIsIgnored() {
    LoggingSecurityAuditService service = new LoggingSecurityAuditService();
    service.record(null);
  }

  @Test
  @DisplayName("record() emits exactly one log line at the configured level")
  void emitsOneLineAtLevel() {
    Logger logger = Logger.getLogger("test.audit." + System.nanoTime());
    logger.setUseParentHandlers(false);
    logger.setLevel(Level.INFO);
    CapturingHandler handler = new CapturingHandler();
    logger.addHandler(handler);

    LoggingSecurityAuditService service = new LoggingSecurityAuditService(logger, Level.INFO);
    service.record(SecurityAuditEvent.of(SecurityAuditEventType.LOGIN_SUCCESS));

    assertEquals(1, handler.records.size());
    assertEquals(Level.INFO, handler.records.get(0).getLevel());
  }

  @Test
  @DisplayName("event below the logger threshold is skipped")
  void belowThresholdIsSkipped() {
    Logger logger = Logger.getLogger("test.audit." + System.nanoTime());
    logger.setUseParentHandlers(false);
    logger.setLevel(Level.SEVERE);
    CapturingHandler handler = new CapturingHandler();
    logger.addHandler(handler);

    LoggingSecurityAuditService service = new LoggingSecurityAuditService(logger, Level.INFO);
    service.record(SecurityAuditEvent.of(SecurityAuditEventType.LOGIN_SUCCESS));

    assertTrue(handler.records.isEmpty(),
        "INFO event must not reach a SEVERE-only handler");
  }

  @Test
  @DisplayName("formatted line carries every populated field and the AUDIT prefix")
  void formatCarriesAllFields() {
    SecurityAuditEvent event = new SecurityAuditEvent(
        Instant.parse("2026-05-08T10:00:00Z"),
        SecurityAuditEventType.ACCESS_DENIED,
        "u1", "alice", "/admin", "DENIED",
        "10.0.0.1", "sess-42",
        Map.of("reason", "missing_role"));

    String line = LoggingSecurityAuditService.format(event);

    assertTrue(line.startsWith("AUDIT type=ACCESS_DENIED"));
    assertTrue(line.contains("subjectId=u1"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("route=/admin"));
    assertTrue(line.contains("decision=DENIED"));
    assertTrue(line.contains("client=10.0.0.1"));
    assertTrue(line.contains("session=sess-42"));
    assertTrue(line.contains("reason=missing_role"));
  }

  @Test
  @DisplayName("missing optional fields are omitted from the formatted line")
  void formatOmitsNulls() {
    String line = LoggingSecurityAuditService.format(
        SecurityAuditEvent.of(SecurityAuditEventType.LOGOUT));

    assertTrue(line.startsWith("AUDIT type=LOGOUT"));
    assertFalse(line.contains("subjectId="));
    assertFalse(line.contains("subject="));
    assertFalse(line.contains("attrs="));
  }

  @Test
  @DisplayName("logger throwing during publish must not propagate")
  void loggerExceptionsAreSwallowed() {
    Logger logger = Logger.getLogger("test.audit.boom." + System.nanoTime());
    logger.setUseParentHandlers(false);
    logger.setLevel(Level.INFO);
    logger.addHandler(new Handler() {
      @Override public void publish(LogRecord record) { throw new RuntimeException("boom"); }
      @Override public void flush() { }
      @Override public void close() { }
    });

    LoggingSecurityAuditService service = new LoggingSecurityAuditService(logger, Level.INFO);
    service.record(SecurityAuditEvent.of(SecurityAuditEventType.LOGIN_FAILURE));
  }

  static final class CapturingHandler extends Handler {
    final List<LogRecord> records = new ArrayList<>();

    @Override
    public void publish(LogRecord record) {
      records.add(record);
    }

    @Override
    public void flush() {
    }

    @Override
    public void close() {
    }
  }
}
