package eu.jsentinel.jcustos.events.types;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEventCategory;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.codec.CanonicalJCustosEventPayload;
import eu.jsentinel.jcustos.events.codec.RecordReflectionCanonicalizer;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("V00.77 OAuth2 event types canonicalise only non-secret fields (no tokens)")
class OAuth2EventTypesTest {

  private final RecordReflectionCanonicalizer canonicalizer = new RecordReflectionCanonicalizer();

  private static EventMetadata meta() {
    return new EventMetadata(EventId.of("evt-1"), TenantId.DEFAULT, SubjectId.of("system"),
        Instant.parse("2026-06-26T12:00:00Z"), JCustosEventSeverity.INFO);
  }

  @Test
  @DisplayName("OAuth2TokenObtained carries grantType + audienceHash only — never a token")
  void tokenObtained() {
    CanonicalJCustosEventPayload p = canonicalizer.canonicalize(
        new OAuth2TokenObtainedEvent(meta(), "authorization_code", "ad5f...hash"));
    assertEquals("OAuth2TokenObtained", p.eventType());
    assertEquals(JCustosEventCategory.TOKEN.name(), p.category());
    assertEquals(Set.of("grantType", "audienceHash"), p.attributes().keySet());
  }

  @Test
  @DisplayName("OAuth2TokenFailed carries grantType + the stable error code only")
  void tokenFailed() {
    CanonicalJCustosEventPayload p = canonicalizer.canonicalize(
        new OAuth2TokenFailedEvent(meta(), "refresh_token", "oauth2/protocol-error:invalid_grant"));
    assertEquals(Set.of("grantType", "errorCode"), p.attributes().keySet());
    assertEquals("oauth2/protocol-error:invalid_grant", p.attributes().get("errorCode"));
  }

  @Test
  @DisplayName("RefreshTokenReuseDetected carries only the non-secret family id")
  void reuseDetected() {
    CanonicalJCustosEventPayload p = canonicalizer.canonicalize(
        new RefreshTokenReuseDetectedEvent(meta(), "family-7f3a"));
    assertEquals("RefreshTokenReuseDetected", p.eventType());
    assertEquals(Set.of("familyId"), p.attributes().keySet());
  }

  @Test
  @DisplayName("the device-grant events canonicalise to DEVICE with no secret payload")
  void deviceEvents() {
    assertEquals(JCustosEventCategory.DEVICE.name(),
        canonicalizer.canonicalize(new DeviceAuthorizationStartedEvent(meta())).category());
    assertEquals(JCustosEventCategory.DEVICE.name(),
        canonicalizer.canonicalize(new DeviceAuthorizationCompletedEvent(meta())).category());
    CanonicalJCustosEventPayload denied = canonicalizer.canonicalize(
        new DeviceAuthorizationDeniedEvent(meta(), "access_denied"));
    assertEquals(Set.of("reason"), denied.attributes().keySet());
    assertEquals("access_denied", denied.attributes().get("reason"));
  }

  @Test
  @DisplayName("OAuth2StateInvalid is an AUTHORIZATION event carrying only the reason code")
  void stateInvalid() {
    CanonicalJCustosEventPayload p = canonicalizer.canonicalize(
        new OAuth2StateInvalidEvent(meta(), "oauth2/state-already-consumed"));
    assertEquals(JCustosEventCategory.AUTHORIZATION.name(), p.category());
    assertEquals(Set.of("reason"), p.attributes().keySet());
  }
}
