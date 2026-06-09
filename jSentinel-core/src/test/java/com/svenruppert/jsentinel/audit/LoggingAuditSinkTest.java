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
package com.svenruppert.jsentinel.audit;

import com.svenruppert.jsentinel.logout.LogoutScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("LoggingAuditSink")
class LoggingAuditSinkTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");

  @Test
  @DisplayName("LoginSucceeded is logged with user/client/session fields")
  void logsLoginSucceeded() {
    RecordingHandler handler = new RecordingHandler();
    Logger logger = isolatedLogger(handler);
    new LoggingAuditSink(logger).accept(
        new LoginSucceeded(T0, "alice", "127.0.0.1", "S-1"));

    String line = handler.firstMessage();
    assertTrue(line.contains("type=LoginSucceeded"), line);
    assertTrue(line.contains("user=alice"), line);
    assertTrue(line.contains("client=127.0.0.1"), line);
    assertTrue(line.contains("session=S-1"), line);
  }

  @Test
  @DisplayName("LogoutPerformed is logged with subject/session/scope")
  void logsLogoutPerformed() {
    RecordingHandler handler = new RecordingHandler();
    Logger logger = isolatedLogger(handler);
    new LoggingAuditSink(logger).accept(
        new LogoutPerformed(T0, "alice", "tok-7", LogoutScope.AllSessionsOfSubject));

    String line = handler.firstMessage();
    assertTrue(line.contains("type=LogoutPerformed"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("session=tok-7"));
    assertTrue(line.contains("scope=AllSessionsOfSubject"));
  }

  @Test
  @DisplayName("BruteForceLimitReached logs failedAttempts and lockoutSeconds")
  void logsBruteForce() {
    RecordingHandler handler = new RecordingHandler();
    Logger logger = isolatedLogger(handler);
    new LoggingAuditSink(logger).accept(new BruteForceLimitReached(
        T0, "alice", "127.0.0.1", 5, Duration.ofMinutes(15)));

    String line = handler.firstMessage();
    assertTrue(line.contains("type=BruteForceLimitReached"));
    assertTrue(line.contains("failedAttempts=5"));
    assertTrue(line.contains("lockoutSeconds=900"));
  }

  @Test
  @DisplayName("Null event is silently dropped")
  void nullEventDropped() {
    RecordingHandler handler = new RecordingHandler();
    Logger logger = isolatedLogger(handler);
    new LoggingAuditSink(logger).accept(null);
    assertEquals(0, handler.records.size());
  }

  @Test
  @DisplayName("Fields with null values are omitted from the log line")
  void nullFieldsAreOmitted() {
    RecordingHandler handler = new RecordingHandler();
    Logger logger = isolatedLogger(handler);
    new LoggingAuditSink(logger).accept(
        new AccessGranted(T0, null, null));

    String line = handler.firstMessage();
    assertTrue(line.contains("type=AccessGranted"));
    assertTrue(!line.contains("subject="), "null subject must not be logged: " + line);
    assertTrue(!line.contains("route="), "null route must not be logged: " + line);
  }

  private static Logger isolatedLogger(RecordingHandler handler) {
    Logger logger = Logger.getLogger("test." + System.nanoTime());
    logger.setUseParentHandlers(false);
    logger.setLevel(Level.ALL);
    logger.addHandler(handler);
    return logger;
  }

  private static final class RecordingHandler extends Handler {
    final List<LogRecord> records = new ArrayList<>();

    @Override public void publish(LogRecord record) {
      records.add(record);
    }

    @Override public void flush() {
    }

    @Override public void close() {
    }

    String firstMessage() {
      assertEquals(1, records.size(), "expected exactly one log line");
      return records.get(0).getMessage();
    }
  }
}
