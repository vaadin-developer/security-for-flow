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

@DisplayName("V00.78 OIDC event types canonicalise only non-secret fields (no tokens/claims)")
class OidcEventTypesTest {

  private final RecordReflectionCanonicalizer canonicalizer = new RecordReflectionCanonicalizer();

  private static EventMetadata meta() {
    return new EventMetadata(EventId.of("evt-1"), TenantId.DEFAULT, SubjectId.of("system"),
        Instant.parse("2026-06-26T12:00:00Z"), JSentinelEventSeverity.INFO);
  }

  @Test
  @DisplayName("IdTokenValidated carries the issuer only")
  void idTokenValidated() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new IdTokenValidatedEvent(meta(), "https://idp.example/"));
    assertEquals("IdTokenValidated", p.eventType());
    assertEquals(JSentinelEventCategory.TOKEN.name(), p.category());
    assertEquals(Set.of("issuer"), p.attributes().keySet());
  }

  @Test
  @DisplayName("IdTokenValidationFailed carries the stable error code only")
  void idTokenValidationFailed() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new IdTokenValidationFailedEvent(meta(), "oidc/nonce-mismatch"));
    assertEquals(Set.of("errorCode"), p.attributes().keySet());
    assertEquals("oidc/nonce-mismatch", p.attributes().get("errorCode"));
  }

  @Test
  @DisplayName("OidcLoginSucceeded is an AUTHENTICATION event carrying the issuer only")
  void loginSucceeded() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new OidcLoginSucceededEvent(meta(), "https://idp.example/"));
    assertEquals(JSentinelEventCategory.AUTHENTICATION.name(), p.category());
    assertEquals(Set.of("issuer"), p.attributes().keySet());
  }

  @Test
  @DisplayName("OidcLogout is a SESSION event carrying the issuer only")
  void logout() {
    CanonicalJSentinelEventPayload p = canonicalizer.canonicalize(
        new OidcLogoutEvent(meta(), "https://idp.example/"));
    assertEquals(JSentinelEventCategory.SESSION.name(), p.category());
    assertEquals(Set.of("issuer"), p.attributes().keySet());
  }
}
