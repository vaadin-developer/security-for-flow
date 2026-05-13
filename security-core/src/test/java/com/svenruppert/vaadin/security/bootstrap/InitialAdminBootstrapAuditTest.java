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
package com.svenruppert.vaadin.security.bootstrap;

import com.svenruppert.vaadin.security.authentication.Pbkdf2PasswordHasher;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.BootstrapAdminCreated;
import com.svenruppert.vaadin.security.audit.BootstrapTokenRejected;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@DisplayName("InitialAdminBootstrapService — audit emits")
class InitialAdminBootstrapAuditTest {

  private static final String OK_PASSWORD = "correct horse battery staple";

  private RecordingAudit audit;

  @BeforeEach
  void wireAudit() {
    SecurityServiceResolver.resetAll();
    audit = new RecordingAudit();
    SecurityServiceResolver.setSecurityAuditService(audit);
  }

  @AfterEach
  void clearAudit() {
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName("createInitialAdmin emits BootstrapAdminCreated on success")
  void emitsAdminCreated() {
    InMemoryAdminStore admins = new InMemoryAdminStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());

    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8));

    InitialAdminCreationResult result = service.createInitialAdmin(
        new CreateInitialAdminCommand(
            tokens.load().orElseThrow().value(),
            "root", OK_PASSWORD.toCharArray(), "Root", null));

    assertInstanceOf(InitialAdminCreationResult.Created.class, result);
    assertEquals(1, audit.events.size());
    assertEquals("root", ((BootstrapAdminCreated) audit.events.get(0)).username());
  }

  @Test
  @DisplayName("createInitialAdmin emits BootstrapTokenRejected with reason=Mismatch on wrong token")
  void emitsTokenRejectedOnMismatch() {
    InMemoryAdminStore admins = new InMemoryAdminStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    BootstrapStartup.initializeIfRequired(
        state, tokens, new BootstrapTokenGenerator(),
        new ConsoleBootstrapTokenOutput(new PrintStream(new ByteArrayOutputStream()), ""),
        BootstrapConfiguration.transientConsole());

    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8));

    InitialAdminCreationResult result = service.createInitialAdmin(
        new CreateInitialAdminCommand("WRONG-TOKEN-1234", "root",
            OK_PASSWORD.toCharArray(), "Root", null));

    assertInstanceOf(InitialAdminCreationResult.InvalidBootstrapToken.class, result);
    assertEquals(1, audit.events.size());
    assertEquals("Mismatch", ((BootstrapTokenRejected) audit.events.get(0)).reason());
  }

  @Test
  @DisplayName("createInitialAdmin emits BootstrapTokenRejected with reason=Expired on stale token")
  void emitsTokenRejectedOnExpired() {
    InMemoryAdminStore admins = new InMemoryAdminStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    Instant tokenCreated = Instant.parse("2026-05-11T10:00:00Z");
    Instant requestAt = tokenCreated.plus(Duration.ofHours(1));
    String tokenValue = "STALE-TOKEN-VALUE";
    tokens.save(new BootstrapToken(tokenValue, tokenCreated));

    Duration shortValidity = Duration.ofMinutes(5);
    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8),
        shortValidity,
        Clock.fixed(requestAt, ZoneOffset.UTC));

    InitialAdminCreationResult result = service.createInitialAdmin(
        new CreateInitialAdminCommand(tokenValue, "root", OK_PASSWORD.toCharArray(), "Root", null));

    assertInstanceOf(InitialAdminCreationResult.InvalidBootstrapToken.class, result);
    assertEquals(1, audit.events.size());
    assertEquals("Expired", ((BootstrapTokenRejected) audit.events.get(0)).reason());
  }

  @Test
  @DisplayName("createInitialAdmin emits BootstrapTokenRejected with reason=Unknown when no token is stored")
  void emitsTokenRejectedOnUnknown() {
    InMemoryAdminStore admins = new InMemoryAdminStore();
    InMemoryBootstrapTokenStore tokens = new InMemoryBootstrapTokenStore();
    BootstrapStateService state = new BootstrapStateService(admins, BootstrapMode.TRANSIENT_CONSOLE);
    // intentionally NO BootstrapStartup.initializeIfRequired — store stays empty

    InitialAdminBootstrapService service = new InitialAdminBootstrapService(
        state, tokens, admins, new Pbkdf2PasswordHasher(),
        new MinimumLengthPasswordPolicy(8));

    InitialAdminCreationResult result = service.createInitialAdmin(
        new CreateInitialAdminCommand("ABCD-1234", "root",
            OK_PASSWORD.toCharArray(), "Root", null));

    assertInstanceOf(InitialAdminCreationResult.InvalidBootstrapToken.class, result);
    assertEquals(1, audit.events.size());
    assertEquals("Unknown", ((BootstrapTokenRejected) audit.events.get(0)).reason());
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private static final class RecordingAudit implements SecurityAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }

  private static final class InMemoryAdminStore implements AdministratorAccountStore {
    private final List<NewAdministrator> admins = new ArrayList<>();

    @Override public synchronized boolean hasAnyAdministrator() {
      return !admins.isEmpty();
    }

    @Override public synchronized void createAdministrator(NewAdministrator newAdministrator) {
      admins.add(newAdministrator);
    }
  }
}
