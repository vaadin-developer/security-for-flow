package eu.jsentinel.jcustos.audit.integrity.listener;

/*-
 * #%L
 * jCustos Audit Integrity — tamper-evident audit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.RateLimitExceeded;
import eu.jsentinel.jcustos.audit.integrity.chain.AuditChainException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AuditEventCanonicalizer — deterministic bytes for core audit events")
class AuditEventCanonicalizerTest {

  private static final Instant AT = Instant.parse("2026-07-19T10:15:30Z");

  @Test
  @DisplayName("golden document: null components are omitted, keys are sorted")
  void goldenDocument() {
    LoginSucceeded event = new LoginSucceeded(AT, "alice", "127.0.0.1", null);
    String json = new String(AuditEventCanonicalizer.canonicalize(event),
        StandardCharsets.UTF_8);
    assertEquals("{\"fields\":{"
            + "\"clientAddress\":\"127.0.0.1\""
            + ",\"timestamp\":\"2026-07-19T10:15:30Z\""
            + ",\"username\":\"alice\"}"
            + ",\"type\":\"LoginSucceeded\""
            + ",\"v\":1}",
        json);
  }

  @Test
  @DisplayName("Instant, Duration and int render with their stable forms")
  void temporalAndNumericRendering() {
    RateLimitExceeded event = new RateLimitExceeded(AT, "login", "alice",
        10, Duration.ofSeconds(90), 11);
    String json = new String(AuditEventCanonicalizer.canonicalize(event),
        StandardCharsets.UTF_8);
    assertTrue(json.contains("\"window\":\"PT1M30S\""), json);
    assertTrue(json.contains("\"limit\":\"10\""), json);
    assertTrue(json.contains("\"timestamp\":\"2026-07-19T10:15:30Z\""), json);
  }

  @Test
  @DisplayName("two runs produce identical bytes")
  void deterministic() {
    LoginSucceeded event = new LoginSucceeded(AT, "alice", "127.0.0.1", "session-1");
    assertArrayEquals(AuditEventCanonicalizer.canonicalize(event),
        AuditEventCanonicalizer.canonicalize(event));
  }

  private record NotCanonicalizable(List<String> entries) {
  }

  @Test
  @DisplayName("an unsupported component type fails loud, never silently")
  void unsupportedTypeFailsLoud() {
    AuditChainException ex = assertThrows(AuditChainException.class, () ->
        AuditEventCanonicalizer.renderRecord(new NotCanonicalizable(List.of("x"))));
    assertEquals(AuditEventCanonicalizer.CODE_NOT_CANONICALIZABLE, ex.code());
  }
}
