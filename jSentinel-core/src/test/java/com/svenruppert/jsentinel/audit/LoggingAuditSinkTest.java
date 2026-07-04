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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("LoggingAuditSink")
class LoggingAuditSinkTest {

  private static final Instant T0 = Instant.parse("2026-05-11T10:00:00Z");

  @Test
  @DisplayName("JS-SEC-031: CR/LF in a logged field is scrubbed so it cannot forge a second log line")
  void scrubsCrlfInLoggedField() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(
        new LoginSucceeded(T0, "alice\r\nfake=INJECTED", "127.0.0.1", "S-1"));

    String line = logger.firstMessage();
    assertFalse(line.contains("\n"), "log line must not contain a newline: " + line);
    assertFalse(line.contains("\r"), "log line must not contain a CR: " + line);
    assertTrue(line.contains("user=alice??fake=INJECTED"), line);
  }

  @Test
  @DisplayName("LoginSucceeded is logged with user/client/session fields")
  void logsLoginSucceeded() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(
        new LoginSucceeded(T0, "alice", "127.0.0.1", "S-1"));

    String line = logger.firstMessage();
    assertTrue(line.contains("type=LoginSucceeded"), line);
    assertTrue(line.contains("user=alice"), line);
    assertTrue(line.contains("client=127.0.0.1"), line);
    assertTrue(line.contains("session=S-1"), line);
  }

  @Test
  @DisplayName("LogoutPerformed is logged with subject/session/scope")
  void logsLogoutPerformed() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(
        new LogoutPerformed(T0, "alice", "tok-7", LogoutScope.AllSessionsOfSubject));

    String line = logger.firstMessage();
    assertTrue(line.contains("type=LogoutPerformed"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("session=tok-7"));
    assertTrue(line.contains("scope=AllSessionsOfSubject"));
  }

  @Test
  @DisplayName("BruteForceLimitReached logs failedAttempts and lockoutSeconds")
  void logsBruteForce() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(new BruteForceLimitReached(
        T0, "alice", "127.0.0.1", 5, Duration.ofMinutes(15)));

    String line = logger.firstMessage();
    assertTrue(line.contains("type=BruteForceLimitReached"));
    assertTrue(line.contains("failedAttempts=5"));
    assertTrue(line.contains("lockoutSeconds=900"));
  }

  @Test
  @DisplayName("Null event is silently dropped")
  void nullEventDropped() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(null);
    assertEquals(0, logger.messages.size());
  }

  @Test
  @DisplayName("Fields with null values are omitted from the log line")
  void nullFieldsAreOmitted() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAuditSink(logger).accept(
        new AccessGranted(T0, null, null));

    String line = logger.firstMessage();
    assertTrue(line.contains("type=AccessGranted"));
    assertTrue(!line.contains("subject="), "null subject must not be logged: " + line);
    assertTrue(!line.contains("route="), "null route must not be logged: " + line);
  }

  @Test
  @DisplayName("R036: a throwing audit logger is swallowed (accept never throws)")
  void throwingLoggerIsSwallowed() {
    RecordingSlf4jLogger throwing = new RecordingSlf4jLogger() {
      @Override
      public void info(String msg) {
        throw new RuntimeException("logger boom");
      }
    };
    // Must not propagate — the WARN goes to the framework static logger.
    new LoggingAuditSink(throwing).accept(new LoginSucceeded(T0, "alice", "127.0.0.1", "S-1"));
  }
}
