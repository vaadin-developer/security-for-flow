package eu.jsentinel.jcustos.events.types;

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
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventCategory;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosEvent concrete types")
class EventTypesTest {

  private static EventMetadata meta() {
    return EventMetadata.create(TenantId.DEFAULT, SubjectId.of("alice"),
        Instant.parse("2026-06-24T10:15:30Z"), JCustosEventSeverity.INFO);
  }

  @Test
  @DisplayName("metadata accessors delegate through EventMetadata")
  void delegatesMetadata() {
    EventMetadata m = meta();
    LoginSucceededEvent event = new LoginSucceededEvent(m, "password");
    assertEquals(m.eventId(), event.eventId());
    assertEquals(TenantId.DEFAULT, event.tenantId());
    assertEquals(SubjectId.of("alice"), event.subjectId());
    assertEquals(Instant.parse("2026-06-24T10:15:30Z"), event.occurredAt());
    assertEquals(JCustosEventSeverity.INFO, event.severity());
    assertEquals(m, event.metadata());
  }

  @Test
  @DisplayName("eventType is a stable constant per type")
  void eventTypeIsStableConstant() {
    LoginSucceededEvent a = new LoginSucceededEvent(meta(), "password");
    LoginSucceededEvent b = new LoginSucceededEvent(meta(), "api-key");
    assertSame(a.eventType(), b.eventType());
    assertSame(LoginSucceededEvent.TYPE, a.eventType());
    assertEquals(EventType.of("LoginSucceeded"), a.eventType());
  }

  @Test
  @DisplayName("each category maps to the expected domain")
  void categoriesAreCorrect() {
    assertEquals(JCustosEventCategory.AUTHENTICATION,
        new LoginFailedEvent(meta(), "bad-credentials").category());
    assertEquals(JCustosEventCategory.AUTHORIZATION,
        new PermissionDeniedEvent(meta(), "doc:delete").category());
    assertEquals(JCustosEventCategory.POLICY,
        new PolicyDeniedEvent(meta(), "owner-or-admin").category());
    assertEquals(JCustosEventCategory.SESSION,
        new SessionRevokedEvent(meta(), "sid-1", "admin-revoked").category());
    assertEquals(JCustosEventCategory.ROLE,
        new RoleAssignedEvent(meta(), "ROLE_ADMIN").category());
    assertEquals(JCustosEventCategory.TOKEN,
        new ApiKeyIssuedEvent(meta(), "ak-1").category());
    assertEquals(JCustosEventCategory.DEVICE,
        new DeviceTrustedEvent(meta(), "dev-1").category());
    assertEquals(JCustosEventCategory.RATE_LIMIT,
        new RateLimitExceededEvent(meta(), "login").category());
    assertEquals(JCustosEventCategory.INTEGRITY,
        new ReplayDetectedEvent(meta(), "env-9").category());
    assertEquals(JCustosEventCategory.SYSTEM,
        new BusStartedEvent(meta()).category());
    assertEquals(JCustosEventCategory.ADMIN,
        new TenantPolicyChangedEvent(meta(), "pwd-policy").category());
  }

  @Test
  @DisplayName("null metadata is rejected by every event")
  void nullMetadataRejected() {
    assertThrows(NullPointerException.class, () -> new LoginSucceededEvent(null, "x"));
    assertThrows(NullPointerException.class, () -> new SequenceViolationEvent(null, "p", 1, 2));
    assertThrows(NullPointerException.class, () -> new BusStartedEvent(null));
  }

  @Test
  @DisplayName("the shipped event TYPE names are all distinct")
  void eventTypeNamesAreUnique() {
    List<JCustosEvent> all = List.of(
        new LoginSucceededEvent(meta(), "password"),
        new LoginFailedEvent(meta(), "bad"),
        new LogoutSucceededEvent(meta(), "sid"),
        new PasswordResetRequestedEvent(meta(), "t"),
        new PasswordResetCompletedEvent(meta()),
        new EmailVerifiedEvent(meta(), "fp"),
        new PermissionDeniedEvent(meta(), "p"),
        new PolicyEvaluatedEvent(meta(), "pol", "allow"),
        new PolicyDeniedEvent(meta(), "pol"),
        new StepUpRequiredEvent(meta(), "totp"),
        new SessionCreatedEvent(meta(), "sid"),
        new SessionExpiredEvent(meta(), "sid"),
        new SessionRevokedEvent(meta(), "sid", "r"),
        new RoleAssignedEvent(meta(), "ROLE_X"),
        new RoleRevokedEvent(meta(), "ROLE_X"),
        new TenantPolicyChangedEvent(meta(), "pol"),
        new RememberMeTokenIssuedEvent(meta(), "t"),
        new RememberMeTokenRevokedEvent(meta(), "t"),
        new ApiKeyIssuedEvent(meta(), "ak"),
        new ApiKeyRevokedEvent(meta(), "ak"),
        new RefreshTokenRotatedEvent(meta(), "t"),
        new DeviceTrustedEvent(meta(), "d"),
        new RateLimitExceededEvent(meta(), "l"),
        new BruteForceThresholdReachedEvent(meta(), "id"),
        new BusStartedEvent(meta()),
        new BusStoppedEvent(meta()),
        new EnvelopeRejectedEvent(meta(), "env", "r"),
        new ReplayDetectedEvent(meta(), "env"),
        new SignatureInvalidEvent(meta(), "env"),
        new SequenceViolationEvent(meta(), "p", 1, 2),
        new ListenerFailedEvent(meta(), "ln", "fc"),
        new DeadLetteredEvent(meta(), "env", "r"),
        new KeyRotatedEvent(meta(), "k"),
        new ProducerRegisteredEvent(meta(), "p"));

    Set<String> names = new HashSet<>();
    for (JCustosEvent event : all) {
      assertNotNull(event.eventType());
      assertNotNull(event.category());
      boolean fresh = names.add(event.eventType().value());
      assertTrue(fresh, "duplicate eventType: " + event.eventType().value());
    }
    assertEquals(34, names.size(), "expected 34 distinct shipped event types");
  }
}
