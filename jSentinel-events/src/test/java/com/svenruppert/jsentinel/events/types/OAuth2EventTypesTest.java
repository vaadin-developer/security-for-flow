package com.svenruppert.jsentinel.events.types;

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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventId;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.JSentinelEventCategory;
import com.svenruppert.jsentinel.events.api.JSentinelEventSeverity;
import com.svenruppert.jsentinel.events.codec.CanonicalJSentinelEventPayload;
import com.svenruppert.jsentinel.events.codec.RecordReflectionCanonicalizer;
import com.svenruppert.jsentinel.logout.SubjectId;
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
        Instant.parse("2026-06-26T12:00:00Z"), JSentinelEventSeverity.INFO);
  }

  @Test
  @DisplayName("OAuth2TokenObtained carries grantType + audienceHash only — never a token")
  void tokenObtained() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new OAuth2TokenObtainedEvent(meta(), "authorization_code", "ad5f...hash"));
    assertEquals("OAuth2TokenObtained", p.eventType());
    assertEquals(JSentinelEventCategory.TOKEN.name(), p.category());
    assertEquals(Set.of("grantType", "audienceHash"), p.attributes().keySet());
  }

  @Test
  @DisplayName("OAuth2TokenFailed carries grantType + the stable error code only")
  void tokenFailed() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new OAuth2TokenFailedEvent(meta(), "refresh_token", "oauth2/protocol-error:invalid_grant"));
    assertEquals(Set.of("grantType", "errorCode"), p.attributes().keySet());
    assertEquals("oauth2/protocol-error:invalid_grant", p.attributes().get("errorCode"));
  }

  @Test
  @DisplayName("RefreshTokenReuseDetected carries only the non-secret family id")
  void reuseDetected() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new RefreshTokenReuseDetectedEvent(meta(), "family-7f3a"));
    assertEquals("RefreshTokenReuseDetected", p.eventType());
    assertEquals(Set.of("familyId"), p.attributes().keySet());
  }

  @Test
  @DisplayName("the device-grant events canonicalise to DEVICE with no secret payload")
  void deviceEvents() {
    assertEquals(JSentinelEventCategory.DEVICE.name(),
        canonicalizer.canonicalize(new DeviceAuthorizationStartedEvent(meta())).category());
    assertEquals(JSentinelEventCategory.DEVICE.name(),
        canonicalizer.canonicalize(new DeviceAuthorizationCompletedEvent(meta())).category());
    CanonicalJSentinelEventPayload denied = canonicalizer.canonicalize(
        new DeviceAuthorizationDeniedEvent(meta(), "access_denied"));
    assertEquals(Set.of("reason"), denied.attributes().keySet());
    assertEquals("access_denied", denied.attributes().get("reason"));
  }

  @Test
  @DisplayName("OAuth2StateInvalid is an AUTHORIZATION event carrying only the reason code")
  void stateInvalid() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new OAuth2StateInvalidEvent(meta(), "oauth2/state-already-consumed"));
    assertEquals(JSentinelEventCategory.AUTHORIZATION.name(), p.category());
    assertEquals(Set.of("reason"), p.attributes().keySet());
  }
}
