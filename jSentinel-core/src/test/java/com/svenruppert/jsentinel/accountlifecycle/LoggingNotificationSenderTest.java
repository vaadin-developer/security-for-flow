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
package com.svenruppert.jsentinel.accountlifecycle;

import com.svenruppert.jsentinel.audit.RecordingSlf4jLogger;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("LoggingNotificationSender + JSentinelNotification")
class LoggingNotificationSenderTest {

  @Test
  @DisplayName("notification is written as a single NOTIFY line with stable key=value pairs")
  void writesStableLine() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();

    LoggingNotificationSender sender = new LoggingNotificationSender(logger);
    sender.send(new JSentinelNotification(
        JSentinelNotification.Kind.PASSWORD_RESET_REQUESTED,
        new SubjectId("alice"),
        TenantId.DEFAULT,
        Instant.parse("2026-01-01T00:00:00Z"),
        Map.of("tokenPlain", "abc", "expiresAt", "2026-01-02T00:00:00Z")));

    assertEquals(1, logger.messages.size());
    String line = logger.messages.get(0);
    assertTrue(line.startsWith("NOTIFY "));
    assertTrue(line.contains("type=PASSWORD_RESET_REQUESTED"));
    assertTrue(line.contains("subject=alice"));
    assertTrue(line.contains("tenant=default"));
    // R020: the plaintext token is redacted, never written verbatim (CWE-532).
    assertTrue(line.contains("tokenPlain=***"));
    assertFalse(line.contains("abc"), "the plaintext token must not appear in the log line");
    assertTrue(line.contains("expiresAt=2026-01-02T00:00:00Z")); // non-secret attr unchanged
  }

  @Test
  @DisplayName("JS-SEC-045: CR/LF + spaces in a field cannot forge a second NOTIFY line or key=value token")
  void scrubsFieldForging() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingNotificationSender(logger).send(new JSentinelNotification(
        JSentinelNotification.Kind.PASSWORD_RESET_REQUESTED,
        new SubjectId("alice"),
        TenantId.DEFAULT,
        Instant.parse("2026-01-01T00:00:00Z"),
        Map.of("email", "x@evil.com\r\nNOTIFY type=PASSWORD_RESET_COMPLETED subject=admin")));

    assertEquals(1, logger.messages.size());
    String line = logger.messages.get(0);
    assertFalse(line.contains("\n"), line);
    assertFalse(line.contains("\r"), line);
    // the injected " subject=admin" cannot appear as a standalone token — every space became '?'.
    assertFalse(line.contains(" subject=admin"), line);
    assertTrue(line.contains("x@evil.com??NOTIFY?type=PASSWORD_RESET_COMPLETED?subject=admin"), line);
  }

  @Test
  @DisplayName("null notification is silently ignored")
  void nullNotificationIgnored() {
    new LoggingNotificationSender().send(null);
  }

  @Test
  @DisplayName("logger throwing does not propagate")
  void loggerExceptionIsSwallowed() {
    RecordingSlf4jLogger throwing = new RecordingSlf4jLogger() {
      @Override public void info(String msg) { throw new RuntimeException("boom"); }
    };

    new LoggingNotificationSender(throwing).send(new JSentinelNotification(
        JSentinelNotification.Kind.EMAIL_VERIFIED,
        new SubjectId("alice"), null, Instant.now(), Map.of()));
  }

  @Test
  @DisplayName("JSentinelNotification rejects null components (except attributes which become empty)")
  void notificationInvariants() {
    Instant now = Instant.now();
    assertThrows(NullPointerException.class,
        () -> new JSentinelNotification(null, new SubjectId("a"), TenantId.DEFAULT, now, Map.of()));
    assertThrows(NullPointerException.class,
        () -> new JSentinelNotification(JSentinelNotification.Kind.EMAIL_VERIFIED,
            null, TenantId.DEFAULT, now, Map.of()));
    assertThrows(NullPointerException.class,
        () -> new JSentinelNotification(JSentinelNotification.Kind.EMAIL_VERIFIED,
            new SubjectId("a"), TenantId.DEFAULT, null, Map.of()));

    JSentinelNotification n = new JSentinelNotification(
        JSentinelNotification.Kind.EMAIL_VERIFIED,
        new SubjectId("a"), null /* → DEFAULT */, now, null /* → empty map */);
    assertEquals(TenantId.DEFAULT, n.tenant());
    assertTrue(n.attributes().isEmpty());
  }

  @Test
  @DisplayName("constructor rejects null logger")
  void rejectsNullLogger() {
    assertThrows(NullPointerException.class, () -> new LoggingNotificationSender(null));
  }
}
