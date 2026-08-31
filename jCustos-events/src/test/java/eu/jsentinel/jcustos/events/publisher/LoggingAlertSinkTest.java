package eu.jsentinel.jcustos.events.publisher;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventId;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Marker;
import org.slf4j.event.Level;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("LoggingAlertSink")
class LoggingAlertSinkTest {

  private static JCustosAlert alert(String detail) {
    return new JCustosAlert(EventType.of("SignatureInvalid"),
        JCustosEventSeverity.CRITICAL, TenantId.DEFAULT, SubjectId.of("system"),
        EventId.of("evt-1"), Instant.parse("2026-06-24T10:15:30Z"), detail);
  }

  @Test
  @DisplayName("writes the stable one-line ALERT format (golden line)")
  void goldenLine() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAlertSink(logger).accept(alert("SignatureInvalidEvent"));

    assertEquals("ALERT type=SignatureInvalid severity=CRITICAL tenant=default "
            + "subject=system event=evt-1 detail=SignatureInvalidEvent",
        logger.firstMessage());
  }

  @Test
  @DisplayName("CWE-117: a hostile detail is scrubbed before logging")
  void hostileDetailIsScrubbed() {
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    new LoggingAlertSink(logger).accept(alert("boom\nALERT forged=line"));

    String line = logger.firstMessage();
    assertTrue(line.endsWith("detail=boom?ALERT?forged=line"),
        "expected scrubbed detail in: " + line);
    assertFalse(line.contains("\n"), "raw newline leaked into: " + line);
  }

  @Test
  @DisplayName("never throws — a throwing logger is swallowed (R036)")
  void neverThrows() {
    RecordingSlf4jLogger throwing = new RecordingSlf4jLogger() {
      @Override
      protected void handleNormalizedLoggingCall(Level level, Marker marker,
          String messagePattern, Object[] arguments, Throwable throwable) {
        throw new IllegalStateException("logger boom");
      }
    };
    LoggingAlertSink sink = new LoggingAlertSink(throwing);
    assertDoesNotThrow(() -> sink.accept(alert("x")));
    assertDoesNotThrow(() -> sink.accept(null));
  }
}
