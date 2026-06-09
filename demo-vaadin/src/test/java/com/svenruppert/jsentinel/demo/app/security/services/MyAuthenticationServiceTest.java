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
package com.svenruppert.jsentinel.demo.app.security.services;

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.AuditQuery;
import com.svenruppert.jsentinel.audit.LoginSucceeded;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptContext;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptDecision;
import com.svenruppert.jsentinel.bruteforce.LoginAttemptPolicy;
import com.svenruppert.jsentinel.demo.app.security.model.Credentials;
import com.svenruppert.jsentinel.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.jsentinel.demo.app.security.model.MyUser;
import com.svenruppert.jsentinel.demo.app.security.roles.AuthorizationRole;
import com.svenruppert.jsentinel.test.RecordingAuditSink;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("MyAuthenticationService — checkCredentials / loadSubject")
class MyAuthenticationServiceTest {

  private final MyAuthenticationService service = new MyAuthenticationService();
  private final RecordingAuditSink audit = new RecordingAuditSink();
  private final CountingPolicy policy = new CountingPolicy();

  @BeforeEach
  void wire() {
    JSentinelServiceResolver.resetAll();
    JSentinelServiceResolver.setJSentinelAuditService(audit);
    JSentinelServiceResolver.setLoginAttemptPolicy(policy);
    DemoUserDirectoryProvider.reset();
    DemoUserDirectoryProvider.directory().addUser("admin", "admin",
        new MyUser(1L, "Admin",
            EnumSet.of(AuthorizationRole.ADMIN, AuthorizationRole.USER)));
    // Clear UserCreated events emitted by addUser + the seeded user/demo
    audit.clear();
  }

  @AfterEach
  void reset() {
    JSentinelServiceResolver.resetAll();
    DemoUserDirectoryProvider.reset();
  }

  @Test
  @DisplayName("null credentials → false, policy never consulted, no audit")
  void nullCredentialsRejected() {
    assertFalse(service.checkCredentials(null));
    assertEquals(0, policy.beforeAttemptCalls);
    assertEquals(0, audit.events().size());
  }

  @Test
  @DisplayName("Lockout decision short-circuits — no directory check, no success audit")
  void lockoutShortCircuits() {
    policy.next = new LoginAttemptDecision.LockedOut(Duration.ofMinutes(5), 7);

    assertFalse(service.checkCredentials(new Credentials("admin", "admin")));

    assertEquals(1, policy.beforeAttemptCalls);
    assertEquals(0, policy.recordSuccessCalls,
        "recordSuccess must not fire when the gate denies the attempt");
    assertEquals(0, policy.recordFailureCalls,
        "recordFailure must not fire when the policy itself shorted the attempt");
    assertTrue(audit.events().stream().noneMatch(LoginSucceeded.class::isInstance),
        "no LoginSucceeded event for a lockout");
  }

  @Test
  @DisplayName("Valid credentials → true, recordSuccess + LoginSucceeded audit")
  void successPathRecordsAndAudits() {
    policy.next = new LoginAttemptDecision.Allowed();

    assertTrue(service.checkCredentials(new Credentials("admin", "admin")));

    assertEquals(1, policy.recordSuccessCalls);
    assertEquals(0, policy.recordFailureCalls);
    LoginSucceeded event = audit.events().stream()
        .filter(LoginSucceeded.class::isInstance)
        .map(LoginSucceeded.class::cast)
        .findFirst()
        .orElseThrow();
    assertEquals("admin", event.username());
  }

  @Test
  @DisplayName("Wrong password → false, recordFailure, no audit")
  void failurePathRecords() {
    policy.next = new LoginAttemptDecision.Allowed();

    assertFalse(service.checkCredentials(new Credentials("admin", "WRONG")));

    assertEquals(0, policy.recordSuccessCalls);
    assertEquals(1, policy.recordFailureCalls);
    assertTrue(audit.events().stream().noneMatch(LoginSucceeded.class::isInstance),
        "failed logins must not emit LoginSucceeded");
  }

  @Test
  @DisplayName("Audit-sink RuntimeException is swallowed — login still returns true")
  void auditFailureDoesNotBlockLogin() {
    policy.next = new LoginAttemptDecision.Allowed();
    JSentinelServiceResolver.setJSentinelAuditService(new JSentinelAuditService() {
      @Override public void publish(AuditEvent event) { throw new RuntimeException("boom"); }
      @Override public List<AuditEvent> query(AuditQuery q) { return List.of(); }
    });

    assertTrue(service.checkCredentials(new Credentials("admin", "admin")),
        "successful credentials must still authenticate even if audit publish throws");
  }

  @Test
  @DisplayName("loadSubject returns the directory user; missing creds → null")
  void loadSubjectMirrorsDirectory() {
    MyUser loaded = service.loadSubject(new Credentials("admin", "admin"));
    assertNotNull(loaded);
    assertEquals(1L, loaded.id());

    assertNull(service.loadSubject(new Credentials("admin", "wrong")));
    assertNull(service.loadSubject(new Credentials("missing", "x")));
  }

  @Test
  @DisplayName("subjectType is MyUser.class")
  void subjectTypeIsExpected() {
    assertSame(MyUser.class, service.subjectType());
  }

  @Test
  @DisplayName("LoginAttemptContext is built from the credentials' username")
  void contextCarriesUsername() {
    policy.next = new LoginAttemptDecision.Allowed();
    service.checkCredentials(new Credentials("admin", "wrong"));

    assertEquals(1, policy.beforeAttemptCalls);
    assertNotNull(policy.lastContext);
    assertEquals("admin", policy.lastContext.username());
  }

  @Test
  @DisplayName("Lockout decision is recognised by sealed-type pattern match")
  void lockoutIsLockedOutInstance() {
    policy.next = new LoginAttemptDecision.LockedOut(Duration.ofSeconds(30), 3);
    service.checkCredentials(new Credentials("admin", "admin"));
    assertInstanceOf(LoginAttemptDecision.LockedOut.class, policy.next);
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private static final class CountingPolicy implements LoginAttemptPolicy {
    LoginAttemptDecision next = new LoginAttemptDecision.Allowed();
    int beforeAttemptCalls = 0;
    int recordSuccessCalls = 0;
    int recordFailureCalls = 0;
    LoginAttemptContext lastContext;

    @Override public LoginAttemptDecision beforeAttempt(LoginAttemptContext ctx) {
      beforeAttemptCalls++;
      lastContext = ctx;
      return next;
    }

    @Override public void recordSuccess(LoginAttemptContext ctx) { recordSuccessCalls++; }

    @Override public void recordFailure(LoginAttemptContext ctx) { recordFailureCalls++; }
  }
}
