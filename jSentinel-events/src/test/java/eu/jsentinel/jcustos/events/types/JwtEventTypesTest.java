package eu.jsentinel.jcustos.events.types;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JSentinelEventCategory;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.events.codec.CanonicalJSentinelEventPayload;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("V00.76 JWT/JWKS event types canonicalise only safe fields (R03 guardrail)")
class JwtEventTypesTest {

  private final RecordReflectionCanonicalizer canonicalizer = new RecordReflectionCanonicalizer();

  private static EventMetadata meta() {
    return new EventMetadata(EventId.of("evt-1"), TenantId.DEFAULT, SubjectId.of("system"),
        Instant.parse("2026-06-25T12:00:00Z"), JSentinelEventSeverity.INFO);
  }

  @Test
  @DisplayName("JwtValidationSucceeded canonicalises issuer/keyId/algorithm only — no raw token")
  void succeeded() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new JwtValidationSucceededEvent(meta(), "https://idp.example/", "k1", "RS256"));
    assertEquals("JwtValidationSucceeded", p.eventType());
    assertEquals(JSentinelEventCategory.TOKEN.name(), p.category());
    assertEquals(Set.of("issuer", "keyId", "algorithm"), p.attributes().keySet());
  }

  @Test
  @DisplayName("JwtValidationFailed canonicalises the failure code only — no token / message")
  void failed() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new JwtValidationFailedEvent(meta(), "jwt/signature-invalid"));
    assertEquals(Set.of("failureCode"), p.attributes().keySet());
    assertEquals("jwt/signature-invalid", p.attributes().get("failureCode"));
  }

  @Test
  @DisplayName("JwksRefreshed canonicalises keyCount/ttlSeconds only")
  void refreshed() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new JwksRefreshedEvent(meta(), 3, 300));
    assertEquals(Set.of("keyCount", "ttlSeconds"), p.attributes().keySet());
  }

  @Test
  @DisplayName("JwksRefreshFailed canonicalises the error class name only — no stack trace")
  void refreshFailed() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new JwksRefreshFailedEvent(meta(), "ConnectException"));
    assertEquals(Set.of("errorClass"), p.attributes().keySet());
    assertEquals("ConnectException", p.attributes().get("errorClass"));
  }
}
