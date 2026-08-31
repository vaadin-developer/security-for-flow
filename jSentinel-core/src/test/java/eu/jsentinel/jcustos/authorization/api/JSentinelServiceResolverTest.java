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
package eu.jsentinel.jcustos.authorization.api;

import eu.jsentinel.jcustos.action.ActionAuthorizationService;
import eu.jsentinel.jcustos.action.ActionPermission;
import eu.jsentinel.jcustos.audit.NoopJSentinelAuditService;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.audit.LoginSucceeded;
import eu.jsentinel.jcustos.audit.JSentinelAuditService;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.logout.LogoutListener;
import eu.jsentinel.jcustos.logout.LogoutScope;
import eu.jsentinel.jcustos.logout.LogoutService;
import eu.jsentinel.jcustos.logout.NoopLogoutService;
import eu.jsentinel.jcustos.logout.SubjectId;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptContext;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptDecision;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.bruteforce.NoopLoginAttemptPolicy;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.session.InMemoryJSentinelVersionStore;
import eu.jsentinel.jcustos.session.NoopSessionPolicy;
import eu.jsentinel.jcustos.session.JSentinelVersionStore;
import eu.jsentinel.jcustos.session.SessionContext;
import eu.jsentinel.jcustos.session.SessionDecision;
import eu.jsentinel.jcustos.session.SessionPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JSentinelServiceResolver")
class JSentinelServiceResolverTest {

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("missing AuthenticationService SPI produces actionable error message")
  void missingAuthenticationService_throwsWithMessage() {
    // In a test environment without META-INF/services registration,
    // the resolver should throw with a clear, actionable message.
    var ex = assertThrows(IllegalStateException.class,
        JSentinelServiceResolver::authenticationService);

    assertTrue(ex.getMessage().contains("AuthenticationService"),
        "Error message should mention the missing service type");
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "Error message should mention META-INF/services registration");
  }

  @Test
  @DisplayName("findAuthenticationService returns empty when no SPI registered")
  void findAuthenticationService_empty() {
    var result = JSentinelServiceResolver.findAuthenticationService();
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("multiple AuthenticationService implementations fail explicitly")
  void multipleAuthenticationServices_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> JSentinelServiceResolver.requireSingleService(
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
        JSentinelServiceResolver::authorizationService);

    assertTrue(ex.getMessage().contains("AuthorizationService"),
        "Error message should mention the missing service type");
    assertTrue(ex.getMessage().contains("META-INF/services"),
        "Error message should mention META-INF/services registration");
  }

  @Test
  @DisplayName("findAuthorizationService returns empty when no SPI registered")
  void findAuthorizationService_empty() {
    var result = JSentinelServiceResolver.findAuthorizationService();
    assertTrue(result.isEmpty());
  }

  @Test
  @DisplayName("multiple AuthorizationService implementations fail explicitly")
  void multipleAuthorizationServices_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> JSentinelServiceResolver.requireSingleService(
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
    JSentinelServiceResolver.resetAll();
    assertThrows(IllegalStateException.class,
        JSentinelServiceResolver::authenticationService);
  }

  @Test
  @DisplayName("resetAll also clears the SubjectStore cache")
  void resetAll_clearsSubjectStore() {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    assertTrue(SubjectStores.findSubjectStore().isPresent(),
        "precondition: subject store cached");

    JSentinelServiceResolver.resetAll();

    assertTrue(SubjectStores.findSubjectStore().isEmpty(),
        "resetAll() must reset SubjectStores too");
  }

  @Test
  @DisplayName("findSingleService returns the only registered service")
  void findSingleService_singleEntry() {
    FirstAuthenticationService only = new FirstAuthenticationService();

    var found = JSentinelServiceResolver.findSingleService(
        AuthenticationService.class,
        java.util.List.of(only));

    assertTrue(found.isPresent());
    assertSame(only, found.get());
  }

  @Test
  @DisplayName("findSingleService returns empty for an empty service iterable")
  void findSingleService_empty() {
    var found = JSentinelServiceResolver.findSingleService(
        AuthenticationService.class, java.util.List.of());

    assertTrue(found.isEmpty());
  }

  @Test
  @DisplayName("requireSingleService returns the only registered service")
  void requireSingleService_singleEntry() {
    FirstAuthenticationService only = new FirstAuthenticationService();

    AuthenticationService<?, ?> resolved = JSentinelServiceResolver.requireSingleService(
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
    public eu.jsentinel.jcustos.authorization.api.roles.HasRoles rolesFor(String subject) {
      return java.util.List::of;
    }
  }

  static final class SecondAuthorizationService extends FirstAuthorizationService {
  }

  // ── JSentinelAuditService ─────────────────────────────────────

  @Test
  @DisplayName("securityAuditService falls back to NoopJSentinelAuditService when no SPI is registered")
  void auditService_defaultsToNoop() {
    JSentinelAuditService service = JSentinelServiceResolver.securityAuditService();
    assertSame(NoopJSentinelAuditService.INSTANCE, service);
  }

  @Test
  @DisplayName("findJSentinelAuditService returns empty when no SPI is registered")
  void findAuditService_emptyByDefault() {
    assertTrue(JSentinelServiceResolver.findJSentinelAuditService().isEmpty());
  }

  @Test
  @DisplayName("setJSentinelAuditService overrides the cached service for both accessors")
  void setJSentinelAuditService_overrides() {
    RecordingAuditService recorder = new RecordingAuditService();
    JSentinelServiceResolver.setJSentinelAuditService(recorder);

    assertSame(recorder, JSentinelServiceResolver.securityAuditService());
    assertSame(recorder, JSentinelServiceResolver.findJSentinelAuditService().orElseThrow());
  }

  @Test
  @DisplayName("recorded events flow through the configured audit service")
  void recordedEventsAreCaptured() {
    RecordingAuditService recorder = new RecordingAuditService();
    JSentinelServiceResolver.setJSentinelAuditService(recorder);

    JSentinelServiceResolver.securityAuditService()
        .publish(new LoginSucceeded(Instant.now(), "alice", null, null));

    assertEquals(1, recorder.events.size());
    assertTrue(recorder.events.get(0) instanceof LoginSucceeded);
  }

  @Test
  @DisplayName("resetAll clears the audit-service cache")
  void resetAll_clearsAuditService() {
    JSentinelServiceResolver.setJSentinelAuditService(new RecordingAuditService());

    JSentinelServiceResolver.resetAll();

    assertSame(NoopJSentinelAuditService.INSTANCE,
        JSentinelServiceResolver.securityAuditService());
  }

  static final class RecordingAuditService implements JSentinelAuditService {
    final List<AuditEvent> events = new ArrayList<>();

    @Override
    public void publish(AuditEvent event) {
      events.add(event);
    }

    @Override
    public List<AuditEvent> query(AuditQuery query) {
      return List.of();
    }
  }

  // ── ActionAuthorizationService ───────────────────────────────

  @Test
  @DisplayName("actionAuthorizationService throws when no SPI is registered")
  void actionAuthorizationService_missing_throws() {
    assertThrows(IllegalStateException.class,
        JSentinelServiceResolver::actionAuthorizationService);
  }

  @Test
  @DisplayName("findActionAuthorizationService returns empty when no SPI is registered")
  void findActionAuthorizationService_emptyByDefault() {
    assertTrue(JSentinelServiceResolver.findActionAuthorizationService().isEmpty());
  }

  @Test
  @DisplayName("setActionAuthorizationService overrides the cached service for both accessors")
  void setActionAuthorizationService_overrides() {
    AlwaysDeny<String> svc = new AlwaysDeny<>();
    JSentinelServiceResolver.setActionAuthorizationService(svc);

    assertSame(svc, JSentinelServiceResolver.<String>actionAuthorizationService());
    assertSame(svc, JSentinelServiceResolver.<String>findActionAuthorizationService().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the action-authorization-service cache")
  void resetAll_clearsActionAuthService() {
    JSentinelServiceResolver.setActionAuthorizationService(new AlwaysDeny<>());

    JSentinelServiceResolver.resetAll();

    assertThrows(IllegalStateException.class,
        JSentinelServiceResolver::actionAuthorizationService);
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
        JSentinelServiceResolver.loginAttemptPolicy());
  }

  @Test
  @DisplayName("findLoginAttemptPolicy returns empty when no SPI is registered")
  void findLoginAttemptPolicy_emptyByDefault() {
    assertTrue(JSentinelServiceResolver.findLoginAttemptPolicy().isEmpty());
  }

  @Test
  @DisplayName("setLoginAttemptPolicy overrides the cached policy for both accessors")
  void setLoginAttemptPolicy_overrides() {
    BlockEverything blocker = new BlockEverything();
    JSentinelServiceResolver.setLoginAttemptPolicy(blocker);

    assertSame(blocker, JSentinelServiceResolver.loginAttemptPolicy());
    assertSame(blocker, JSentinelServiceResolver.findLoginAttemptPolicy().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the login-attempt-policy cache")
  void resetAll_clearsLoginAttemptPolicy() {
    JSentinelServiceResolver.setLoginAttemptPolicy(new BlockEverything());

    JSentinelServiceResolver.resetAll();

    assertSame(NoopLoginAttemptPolicy.INSTANCE,
        JSentinelServiceResolver.loginAttemptPolicy());
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
    SessionPolicy<String> policy = JSentinelServiceResolver.sessionPolicy();
    assertTrue(policy instanceof NoopSessionPolicy<?>);
  }

  @Test
  @DisplayName("findSessionPolicy returns empty when no SPI is registered")
  void findSessionPolicy_emptyByDefault() {
    assertTrue(JSentinelServiceResolver.findSessionPolicy().isEmpty());
  }

  @Test
  @DisplayName("setSessionPolicy overrides the cached policy for both accessors")
  void setSessionPolicy_overrides() {
    AlwaysInvalidate<String> custom = new AlwaysInvalidate<>();
    JSentinelServiceResolver.setSessionPolicy(custom);

    assertSame(custom, JSentinelServiceResolver.<String>sessionPolicy());
    assertSame(custom, JSentinelServiceResolver.<String>findSessionPolicy().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the session-policy cache")
  void resetAll_clearsSessionPolicy() {
    JSentinelServiceResolver.setSessionPolicy(new AlwaysInvalidate<String>());

    JSentinelServiceResolver.resetAll();

    SessionPolicy<String> after = JSentinelServiceResolver.sessionPolicy();
    assertTrue(after instanceof NoopSessionPolicy<?>);
  }

  static final class AlwaysInvalidate<U> implements SessionPolicy<U> {
    @Override
    public SessionDecision beforeNavigation(SessionContext<U> context) {
      return new SessionDecision.Invalidate("test", "/login");
    }
  }

  // ── PasswordHasher ────────────────────────────────────────────

  @Test
  @DisplayName("passwordHashingService falls back to Pbkdf2PasswordHasher when no SPI is registered")
  void passwordHashingService_defaultsToPbkdf2() {
    eu.jsentinel.jcustos.authentication.PasswordHasher hasher =
        JSentinelServiceResolver.passwordHashingService();
    assertTrue(hasher instanceof eu.jsentinel.jcustos.authentication.Pbkdf2PasswordHasher,
        "default fallback must be Pbkdf2PasswordHasher");
  }

  @Test
  @DisplayName("findPasswordHashingService returns empty when only the default fallback is cached")
  void findPasswordHashingService_emptyByDefault() {
    JSentinelServiceResolver.passwordHashingService();
    assertTrue(JSentinelServiceResolver.findPasswordHashingService().isEmpty(),
        "the default Pbkdf2 fallback must NOT be reported as an SPI registration");
  }

  @Test
  @DisplayName("setPasswordHashingService overrides the cached hasher for both accessors")
  void setPasswordHashingService_overrides() {
    RecordingHasher custom = new RecordingHasher();
    JSentinelServiceResolver.setPasswordHashingService(custom);

    assertSame(custom, JSentinelServiceResolver.passwordHashingService());
    assertSame(custom, JSentinelServiceResolver.findPasswordHashingService().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the password-hasher cache so the next call returns a fresh fallback")
  void resetAll_clearsPasswordHasher() {
    JSentinelServiceResolver.setPasswordHashingService(new RecordingHasher());

    JSentinelServiceResolver.resetAll();

    eu.jsentinel.jcustos.authentication.PasswordHasher after =
        JSentinelServiceResolver.passwordHashingService();
    assertTrue(after instanceof eu.jsentinel.jcustos.authentication.Pbkdf2PasswordHasher);
  }

  static final class RecordingHasher implements eu.jsentinel.jcustos.authentication.PasswordHasher {
    @Override public String hash(char[] rawPassword) { return "stub"; }
    @Override public boolean verify(char[] rawPassword, String storedHash) { return false; }
  }

  // ── LogoutService ─────────────────────────────────────────────

  @Test
  @DisplayName("logoutService falls back to NoopLogoutService when no SPI is registered")
  void logoutService_defaultsToNoop() {
    assertSame(NoopLogoutService.INSTANCE, JSentinelServiceResolver.logoutService());
  }

  @Test
  @DisplayName("findLogoutService returns empty when only the noop fallback is cached")
  void findLogoutService_emptyByDefault() {
    JSentinelServiceResolver.logoutService();
    assertTrue(JSentinelServiceResolver.findLogoutService().isEmpty());
  }

  @Test
  @DisplayName("setLogoutService overrides the cached service for both accessors")
  void setLogoutService_overrides() {
    RecordingLogoutService custom = new RecordingLogoutService();
    JSentinelServiceResolver.setLogoutService(custom);

    assertSame(custom, JSentinelServiceResolver.logoutService());
    assertSame(custom, JSentinelServiceResolver.findLogoutService().orElseThrow());
  }

  @Test
  @DisplayName("resetAll clears the logout-service cache")
  void resetAll_clearsLogoutService() {
    JSentinelServiceResolver.setLogoutService(new RecordingLogoutService());

    JSentinelServiceResolver.resetAll();

    assertSame(NoopLogoutService.INSTANCE, JSentinelServiceResolver.logoutService());
  }

  static final class RecordingLogoutService implements LogoutService {
    @Override public void logout(SubjectId subjectId, LogoutScope scope) {
    }

    @Override public void addListener(LogoutListener listener) {
    }

    @Override public void removeListener(LogoutListener listener) {
    }
  }

  // ── JSentinelVersionStore / SubjectIdResolver (Phase 4c-Followup) ──

  @Test
  @DisplayName("findJSentinelVersionStore returns empty when no SPI is registered")
  void findJSentinelVersionStore_emptyByDefault() {
    assertTrue(JSentinelServiceResolver.findJSentinelVersionStore().isEmpty());
  }

  @Test
  @DisplayName("setJSentinelVersionStore overrides the cached store; resetAll clears it")
  void setJSentinelVersionStore_overrides() {
    InMemoryJSentinelVersionStore store = new InMemoryJSentinelVersionStore();
    JSentinelServiceResolver.setJSentinelVersionStore(store);

    Optional<JSentinelVersionStore> resolved = JSentinelServiceResolver.findJSentinelVersionStore();
    assertSame(store, resolved.orElseThrow());

    JSentinelServiceResolver.resetAll();
    assertTrue(JSentinelServiceResolver.findJSentinelVersionStore().isEmpty());
  }

  @Test
  @DisplayName("findSubjectIdResolver returns empty when no SPI is registered")
  void findSubjectIdResolver_emptyByDefault() {
    assertTrue(JSentinelServiceResolver.<String>findSubjectIdResolver().isEmpty());
  }

  @Test
  @DisplayName("setSubjectIdResolver overrides the cached resolver and survives lookups; resetAll clears it")
  void setSubjectIdResolver_overrides() {
    SubjectIdResolver<String> resolver = new SubjectIdResolver<String>() {
      @Override public SubjectId resolve(String s) { return new SubjectId(s); }
      @Override public TenantId tenantFor(String s) { return new TenantId("acme"); }
    };
    JSentinelServiceResolver.setSubjectIdResolver(resolver);

    SubjectIdResolver<String> read = JSentinelServiceResolver.<String>findSubjectIdResolver()
        .orElseThrow();
    assertSame(resolver, read);
    assertEquals(new SubjectId("alice"), read.resolve("alice"));
    assertEquals(new TenantId("acme"), read.tenantFor("alice"));

    JSentinelServiceResolver.resetAll();
    assertTrue(JSentinelServiceResolver.<String>findSubjectIdResolver().isEmpty());
  }

  @Test
  @DisplayName("SubjectIdResolver default tenantFor returns TenantId.DEFAULT")
  void subjectIdResolver_defaultTenant() {
    SubjectIdResolver<String> resolver = s -> new SubjectId(s);
    assertSame(TenantId.DEFAULT, resolver.tenantFor("alice"));
  }
}
