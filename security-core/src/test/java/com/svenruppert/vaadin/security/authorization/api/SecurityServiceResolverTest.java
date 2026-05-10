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
package com.svenruppert.vaadin.security.authorization.api;

import com.svenruppert.vaadin.security.action.ActionAuthorizationService;
import com.svenruppert.vaadin.security.action.ActionPermission;
import com.svenruppert.vaadin.security.audit.NoopSecurityAuditService;
import com.svenruppert.vaadin.security.audit.SecurityAuditEvent;
import com.svenruppert.vaadin.security.audit.SecurityAuditEventType;
import com.svenruppert.vaadin.security.audit.SecurityAuditService;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptContext;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptDecision;
import com.svenruppert.vaadin.security.bruteforce.LoginAttemptPolicy;
import com.svenruppert.vaadin.security.bruteforce.NoopLoginAttemptPolicy;
import com.svenruppert.vaadin.security.session.NoopSessionPolicy;
import com.svenruppert.vaadin.security.session.SessionContext;
import com.svenruppert.vaadin.security.session.SessionDecision;
import com.svenruppert.vaadin.security.session.SessionPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SecurityServiceResolver")
class SecurityServiceResolverTest {

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
  }

  @Test
  @DisplayName("missing AuthenticationService SPI produces actionable error message")
  void missingAuthenticationService_throwsWithMessage() {
    // In a test environment without META-INF/services registration,
    // the resolver should throw with a clear, actionable message.
    var ex = assertThrows(IllegalStateException.class,
        SecurityServiceResolver::authenticationService);

    assertTrue(ex.getMessage().contains("AuthenticationService"),
        "Error message should mention the missing service type");
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "Error message should mention META-INF/services registration");
  }

  @Test
  @DisplayName("findAuthenticationService returns empty when no SPI registered")
  void findAuthenticationService_empty() {
    var result = SecurityServiceResolver.findAuthenticationService();
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("multiple AuthenticationService implementations fail explicitly")
  void multipleAuthenticationServices_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> SecurityServiceResolver.requireSingleService(
            AuthenticationService.class,
            java.util.List.of(new FirstAuthenticationService(), new SecondAuthenticationService())));

    assertTrue(ex.getMessage().contains("multiple implementations"));
    assertTrue(ex.getMessage().contains(FirstAuthenticationService.class.getName()));
    assertTrue(ex.getMessage().contains(SecondAuthenticationService.class.getName()));
  }

  @Test
  @DisplayName("missing AuthorizationService SPI produces actionable error message")
  void missingAuthorizationService_throwsWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        SecurityServiceResolver::authorizationService);

    assertTrue(ex.getMessage().contains("AuthorizationService"),
        "Error message should mention the missing service type");
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "Error message should mention META-INF/services registration");
  }

  @Test
  @DisplayName("findAuthorizationService returns empty when no SPI registered")
  void findAuthorizationService_empty() {
    var result = SecurityServiceResolver.findAuthorizationService();
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("multiple AuthorizationService implementations fail explicitly")
  void multipleAuthorizationServices_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> SecurityServiceResolver.requireSingleService(
            AuthorizationService.class,
            java.util.List.of(new FirstAuthorizationService(), new SecondAuthorizationService())));

    assertTrue(ex.getMessage().contains("multiple implementations"));
    assertTrue(ex.getMessage().contains(FirstAuthorizationService.class.getName()));
    assertTrue(ex.getMessage().contains(SecondAuthorizationService.class.getName()));
  }

  @Test
  @DisplayName("resetAll clears cached services")
  void resetAll_clearsCaches() {
    // After reset, a subsequent call should attempt SPI lookup again.
    // Since no SPI is registered in the test env, it should throw.
    SecurityServiceResolver.resetAll();
    assertThrows(IllegalStateException.class,
        SecurityServiceResolver::authenticationService);
  }

  @Test
  @DisplayName("resetAll also clears the SubjectStore cache")
  void resetAll_clearsSubjectStore() {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    assertTrue(SubjectStores.findSubjectStore().isPresent(),
        "precondition: subject store cached");

    SecurityServiceResolver.resetAll();

    assertTrue(SubjectStores.findSubjectStore().isEmpty(),
        "resetAll() must reset SubjectStores too");
  }

  @Test
  @DisplayName("findSingleService returns the only registered service")
  void findSingleService_singleEntry() {
    FirstAuthenticationService only = new FirstAuthenticationService();

    var found = SecurityServiceResolver.findSingleService(
        AuthenticationService.class,
        java.util.List.of(only));

    assertTrue(found.isPresent());
    assertSame(only, found.get());
  }

  @Test
  @DisplayName("findSingleService returns empty for an empty service iterable")
  void findSingleService_empty() {
    var found = SecurityServiceResolver.findSingleService(
        AuthenticationService.class, java.util.List.of());

    assertTrue(found.isEmpty());
  }

  @Test
  @DisplayName("requireSingleService returns the only registered service")
  void requireSingleService_singleEntry() {
    FirstAuthenticationService only = new FirstAuthenticationService();

    AuthenticationService<?, ?> resolved = SecurityServiceResolver.requireSingleService(
        AuthenticationService.class,
        java.util.List.of(only));

    assertSame(only, resolved);
  }

  static class FirstAuthenticationService implements AuthenticationService<String, String> {
    @Override
    public boolean checkCredentials(String credentials) {
      return false;
    }

    @Override
    public String loadSubject(String credentials) {
      return credentials;
    }

    @Override
    public Class<String> subjectType() {
      return String.class;
    }
  }

  static final class SecondAuthenticationService extends FirstAuthenticationService {
  }

  static class FirstAuthorizationService implements AuthorizationService<String> {
    @Override
    public com.svenruppert.vaadin.security.authorization.api.roles.HasRoles rolesFor(String subject) {
      return java.util.List::of;
    }
  }

  static final class SecondAuthorizationService extends FirstAuthorizationService {
  }

  // ── SecurityAuditService ─────────────────────────────────────

  @Test
  @DisplayName("securityAuditService falls back to NoopSecurityAuditService when no SPI is registered")
  void auditService_defaultsToNoop() {
    SecurityAuditService service = SecurityServiceResolver.securityAuditService();
    assertSame(NoopSecurityAuditService.INSTANCE, service);
  }

  @Test
  @DisplayName("findSecurityAuditService returns empty when no SPI is registered")
  void findAuditService_emptyByDefault() {
    assertTrue(SecurityServiceResolver.findSecurityAuditService().isEmpty());
  }

  @Test
  @DisplayName("setSecurityAuditService overrides the cached service for both accessors")
  void setSecurityAuditService_overrides() {
    RecordingAuditService recorder = new RecordingAuditService();
    SecurityServiceResolver.setSecurityAuditService(recorder);

    assertSame(recorder, SecurityServiceResolver.securityAuditService());
    assertSame(recorder, SecurityServiceResolver.findSecurityAuditService().orElseThrow());
  }

  @Test
  @DisplayName("recorded events flow through the configured audit service")
  void recordedEventsAreCaptured() {
    RecordingAuditService recorder = new RecordingAuditService();
    SecurityServiceResolver.setSecurityAuditService(recorder);

    SecurityServiceResolver.securityAuditService()
        .record(SecurityAuditEvent.of(SecurityAuditEventType.LOGIN_SUCCESS));

    assertEquals(1, recorder.events.size());
    assertSame(SecurityAuditEventType.LOGIN_SUCCESS, recorder.events.get(0).type());
  }

  @Test
  @DisplayName("resetAll clears the audit-service cache")
  void resetAll_clearsAuditService() {
    SecurityServiceResolver.setSecurityAuditService(new RecordingAuditService());

    SecurityServiceResolver.resetAll();

    assertSame(NoopSecurityAuditService.INSTANCE,
        SecurityServiceResolver.securityAuditService());
  }

  static final class RecordingAuditService implements SecurityAuditService {
    final List<SecurityAuditEvent> events = new ArrayList<>();

    @Override
    public void record(SecurityAuditEvent event) {
      events.add(event);
    }
  }

  // ── ActionAuthorizationService ───────────────────────────────

  @Test
  @DisplayName("actionAuthorizationService throws when no SPI is registered")
  void actionAuthorizationService_missing_throws() {
    assertThrows(IllegalStateException.class,
        SecurityServiceResolver::actionAuthorizationService);
  }

  @Test
  @DisplayName("findActionAuthorizationService returns empty when no SPI is registered")
  void findActionAuthorizationService_emptyByDefault() {
    assertTrue(SecurityServiceResolver.findActionAuthorizationService().isEmpty());
  }

  @Test
  @DisplayName("setActionAuthorizationService overrides the cached service for both accessors")
  void setActionAuthorizationService_overrides() {
    AlwaysDeny<String> svc = new AlwaysDeny<>();
    SecurityServiceResolver.setActionAuthorizationService(svc);

    assertSame(svc, SecurityServiceResolver.<String>actionAuthorizationService());
    assertSame(svc, SecurityServiceResolver.<String>findActionAuthorizationService().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the action-authorization-service cache")
  void resetAll_clearsActionAuthService() {
    SecurityServiceResolver.setActionAuthorizationService(new AlwaysDeny<>());

    SecurityServiceResolver.resetAll();

    assertThrows(IllegalStateException.class,
        SecurityServiceResolver::actionAuthorizationService);
  }

  static final class AlwaysDeny<U> implements ActionAuthorizationService<U> {
    @Override
    public boolean isAllowed(U subject, ActionPermission permission) {
      return false;
    }
  }

  // ── LoginAttemptPolicy ────────────────────────────────────────

  @Test
  @DisplayName("loginAttemptPolicy falls back to NoopLoginAttemptPolicy when no SPI is registered")
  void loginAttemptPolicy_defaultsToNoop() {
    assertSame(NoopLoginAttemptPolicy.INSTANCE,
        SecurityServiceResolver.loginAttemptPolicy());
  }

  @Test
  @DisplayName("findLoginAttemptPolicy returns empty when no SPI is registered")
  void findLoginAttemptPolicy_emptyByDefault() {
    assertTrue(SecurityServiceResolver.findLoginAttemptPolicy().isEmpty());
  }

  @Test
  @DisplayName("setLoginAttemptPolicy overrides the cached policy for both accessors")
  void setLoginAttemptPolicy_overrides() {
    BlockEverything blocker = new BlockEverything();
    SecurityServiceResolver.setLoginAttemptPolicy(blocker);

    assertSame(blocker, SecurityServiceResolver.loginAttemptPolicy());
    assertSame(blocker, SecurityServiceResolver.findLoginAttemptPolicy().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the login-attempt-policy cache")
  void resetAll_clearsLoginAttemptPolicy() {
    SecurityServiceResolver.setLoginAttemptPolicy(new BlockEverything());

    SecurityServiceResolver.resetAll();

    assertSame(NoopLoginAttemptPolicy.INSTANCE,
        SecurityServiceResolver.loginAttemptPolicy());
  }

  static final class BlockEverything implements LoginAttemptPolicy {
    @Override
    public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
      return LoginAttemptDecision.lockedOut(java.time.Duration.ofSeconds(60), 99);
    }

    @Override
    public void recordSuccess(LoginAttemptContext context) {
    }

    @Override
    public void recordFailure(LoginAttemptContext context) {
    }
  }

  // ── SessionPolicy ─────────────────────────────────────────────

  @Test
  @DisplayName("sessionPolicy falls back to NoopSessionPolicy when no SPI is registered")
  void sessionPolicy_defaultsToNoop() {
    SessionPolicy<String> policy = SecurityServiceResolver.sessionPolicy();
    assertTrue(policy instanceof NoopSessionPolicy<?>);
  }

  @Test
  @DisplayName("findSessionPolicy returns empty when no SPI is registered")
  void findSessionPolicy_emptyByDefault() {
    assertTrue(SecurityServiceResolver.findSessionPolicy().isEmpty());
  }

  @Test
  @DisplayName("setSessionPolicy overrides the cached policy for both accessors")
  void setSessionPolicy_overrides() {
    AlwaysInvalidate<String> custom = new AlwaysInvalidate<>();
    SecurityServiceResolver.setSessionPolicy(custom);

    assertSame(custom, SecurityServiceResolver.<String>sessionPolicy());
    assertSame(custom, SecurityServiceResolver.<String>findSessionPolicy().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the session-policy cache")
  void resetAll_clearsSessionPolicy() {
    SecurityServiceResolver.setSessionPolicy(new AlwaysInvalidate<String>());

    SecurityServiceResolver.resetAll();

    SessionPolicy<String> after = SecurityServiceResolver.sessionPolicy();
    assertTrue(after instanceof NoopSessionPolicy<?>);
  }

  static final class AlwaysInvalidate<U> implements SessionPolicy<U> {
    @Override
    public SessionDecision beforeNavigation(SessionContext<U> context) {
      return new SessionDecision.Invalidate("test", "/login");
    }
  }
}
