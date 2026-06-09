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
package com.svenruppert.vaadin.security.standalone;

import com.svenruppert.vaadin.security.audit.AuditEvent;
import com.svenruppert.vaadin.security.audit.AuditQuery;
import com.svenruppert.vaadin.security.audit.LoginFailed;
import com.svenruppert.vaadin.security.audit.LoginSucceeded;
import com.svenruppert.vaadin.security.audit.JSentinelAuditService;
import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.JSentinelServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptContext;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptDecision;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StandaloneLoginFlow")
class StandaloneLoginFlowTest {

  private static final Instant T0 = Instant.parse("2026-05-13T10:00:00Z");

  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final CountingPolicy policy = new CountingPolicy();
  private final StubAuth auth = new StubAuth();

  @BeforeEach
  void setUp() {
    JSentinelServiceResolver.resetAll();
    JSentinelServiceResolver.setJSentinelAuditService(audit);
    JSentinelServiceResolver.setLoginAttemptPolicy(policy);
    // Reset the cached SubjectStore so every test starts clean — the
    // SPI-registered ThreadLocalSubjectStore is recreated lazily.
    SubjectStores.reset();
    InMemoryStore.clear();
    SubjectStores.setSubjectStore(new InMemoryStore());
  }

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
    SubjectStores.reset();
    InMemoryStore.clear();
  }

  // ── Success path ───────────────────────────────────────────────

  @Test
  @DisplayName("Valid credentials → Success(subject), policy.recordSuccess called, LoginSucceeded audited, subject bound")
  void successPath() {
    StandaloneLoginFlow<String, String> flow =
        new StandaloneLoginFlow<>(auth, Clock.fixed(T0, ZoneOffset.UTC));

    StandaloneLoginFlow.LoginResult<String> result = flow.login("alice", "alice");

    StandaloneLoginFlow.LoginResult.Success<String> success =
        assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class, result);
    assertEquals("alice", success.subject());

    assertEquals(1, policy.recordSuccessCalls,
        "successful login must call policy.recordSuccess(...)");
    assertEquals(0, policy.recordFailureCalls);

    LoginSucceeded ev = audit.single(LoginSucceeded.class);
    assertEquals("alice", ev.username());
    assertEquals(T0, ev.timestamp(), "audit timestamp must come from the injected clock");

    assertEquals("alice",
        SubjectStores.subjectStore().currentSubject(String.class).orElseThrow(),
        "successful login must bind the subject under authenticationService.subjectType()");
  }

  // ── Wrong-credentials path ─────────────────────────────────────

  @Test
  @DisplayName("Wrong password → Rejected, policy.recordFailure called, LoginFailed audited, no subject bound")
  void rejectedPath() {
    StandaloneLoginFlow<String, String> flow =
        new StandaloneLoginFlow<>(auth, Clock.fixed(T0, ZoneOffset.UTC));

    StandaloneLoginFlow.LoginResult<String> result = flow.login("WRONG", "alice");

    assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class, result);
    assertEquals(0, policy.recordSuccessCalls);
    assertEquals(1, policy.recordFailureCalls,
        "failed login must call policy.recordFailure(...)");

    LoginFailed ev = audit.single(LoginFailed.class);
    assertEquals("alice", ev.username());
    assertEquals("Credentials rejected", ev.reason(),
        "audit reason must explain the rejection cause");

    assertFalse(SubjectStores.subjectStore().currentSubject(String.class).isPresent(),
        "no subject must be bound after a rejected login");
  }

  @Test
  @DisplayName("loadSubject returning null surfaces as Rejected with reason 'Subject lookup returned null'")
  void rejectedWhenLoadSubjectReturnsNull() {
    StubAuth nullLoader = new StubAuth() {
      @Override public String loadSubject(String credentials) { return null; }
    };
    StandaloneLoginFlow<String, String> flow =
        new StandaloneLoginFlow<>(nullLoader, Clock.fixed(T0, ZoneOffset.UTC));

    StandaloneLoginFlow.LoginResult<String> result = flow.login("alice", "alice");

    assertInstanceOf(StandaloneLoginFlow.LoginResult.Rejected.class, result);
    LoginFailed ev = audit.single(LoginFailed.class);
    assertEquals("Subject lookup returned null", ev.reason(),
        "null loadSubject(...) must be reported as a separate failure reason");
    assertEquals(1, policy.recordFailureCalls);
  }

  // ── Lockout short-circuit ──────────────────────────────────────

  @Test
  @DisplayName("LockedOut decision → LockedOut(decision), no credentials check, no audit, no recordSuccess/Failure")
  void lockedOutShortCircuits() {
    LoginAttemptDecision.LockedOut decision = new LoginAttemptDecision.LockedOut(
        Duration.ofMinutes(5), 7);
    policy.next = decision;

    StandaloneLoginFlow<String, String> flow =
        new StandaloneLoginFlow<>(auth, Clock.fixed(T0, ZoneOffset.UTC));
    StandaloneLoginFlow.LoginResult<String> result = flow.login("alice", "alice");

    StandaloneLoginFlow.LoginResult.LockedOut<String> locked =
        assertInstanceOf(StandaloneLoginFlow.LoginResult.LockedOut.class, result);
    assertSame(decision, locked.decision(),
        "LockedOut.decision must carry the policy's decision verbatim");

    assertEquals(0, auth.checkCredentialsCalls,
        "a locked-out attempt must NOT delegate to AuthenticationService.checkCredentials");
    assertEquals(0, policy.recordSuccessCalls);
    assertEquals(0, policy.recordFailureCalls,
        "the policy short-circuit must not record success or failure");
    assertTrue(audit.events().isEmpty(),
        "no audit event must be emitted on a lockout short-circuit");
    assertFalse(SubjectStores.subjectStore().currentSubject(String.class).isPresent());
  }

  // ── Audit-sink resilience ──────────────────────────────────────

  @Test
  @DisplayName("A throwing audit sink does NOT block a successful login")
  void throwingAuditSinkDoesNotBlockSuccess() {
    JSentinelServiceResolver.setJSentinelAuditService(new JSentinelAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery q) { return List.of(); }
    });
    StandaloneLoginFlow<String, String> flow =
        new StandaloneLoginFlow<>(auth, Clock.fixed(T0, ZoneOffset.UTC));

    StandaloneLoginFlow.LoginResult<String> result = flow.login("alice", "alice");

    assertInstanceOf(StandaloneLoginFlow.LoginResult.Success.class, result,
        "a throwing audit sink must not prevent a successful credential check");
    assertEquals("alice",
        SubjectStores.subjectStore().currentSubject(String.class).orElseThrow());
  }

  // ── Logout ─────────────────────────────────────────────────────

  @Test
  @DisplayName("logout removes the subject from the SubjectStore")
  void logoutClearsSubject() {
    StandaloneLoginFlow<String, String> flow =
        new StandaloneLoginFlow<>(auth, Clock.fixed(T0, ZoneOffset.UTC));
    flow.login("alice", "alice");
    assertTrue(SubjectStores.subjectStore().currentSubject(String.class).isPresent());

    flow.logout();

    assertFalse(SubjectStores.subjectStore().currentSubject(String.class).isPresent(),
        "logout must remove the subject for the configured subjectType");
  }

  // ── Constructor null-guarding ──────────────────────────────────

  @Test
  @DisplayName("Constructor rejects a null AuthenticationService")
  void nullAuthRejected() {
    Clock c = Clock.systemUTC();
    org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class,
        () -> new StandaloneLoginFlow<String, String>(null, c));
  }

  @Test
  @DisplayName("Constructor rejects a null Clock")
  void nullClockRejected() {
    org.junit.jupiter.api.Assertions.assertThrows(NullPointerException.class,
        () -> new StandaloneLoginFlow<String, String>(auth, null));
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private static class StubAuth implements AuthenticationService<String, String> {
    int checkCredentialsCalls = 0;

    @Override public boolean checkCredentials(String credentials) {
      checkCredentialsCalls++;
      return "alice".equals(credentials);
    }

    @Override public String loadSubject(String credentials) { return credentials; }

    @Override public Class<String> subjectType() { return String.class; }
  }

  private static final class CountingPolicy implements LoginAttemptPolicy {
    LoginAttemptDecision next = LoginAttemptDecision.allowed();
    int recordSuccessCalls = 0;
    int recordFailureCalls = 0;

    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext ctx) { return next; }
    @Override public void recordSuccess(LoginAttemptContext ctx) { recordSuccessCalls++; }
    @Override public void recordFailure(LoginAttemptContext ctx) { recordFailureCalls++; }
  }

  /** Tiny in-memory SubjectStore so tests don't rely on SPI resolution. */
  private static final class InMemoryStore implements com.svenruppert.vaadin.security.authorization.api.SubjectStore {
    private static final Map<Class<?>, Object> STORE = new HashMap<>();

    static void clear() { STORE.clear(); }

    @Override public <T> java.util.Optional<T> currentSubject(Class<T> subjectType) {
      return java.util.Optional.ofNullable(subjectType.cast(STORE.get(subjectType)));
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      STORE.put(subjectType, subject);
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      STORE.remove(subjectType);
    }
  }
}
