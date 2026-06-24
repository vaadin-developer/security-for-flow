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
package com.svenruppert.jsentinel.logout.vaadin;

import com.svenruppert.jsentinel.logout.InMemorySubjectSessionRegistry;
import com.svenruppert.jsentinel.logout.LogoutListener;
import com.svenruppert.jsentinel.logout.LogoutScope;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.credential.propagation.BearerToken;
import com.svenruppert.jsentinel.credential.propagation.InMemoryTokenCredentialStore;
import com.svenruppert.jsentinel.logout.SubjectId;
import com.svenruppert.jsentinel.authorization.api.SubjectStore;
import com.svenruppert.jsentinel.logout.SubjectSessionRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("VaadinLogoutService — (SubjectId, LogoutScope) API")
class VaadinLogoutServiceTest {

  private final SubjectId alice = SubjectId.of("alice");

  @AfterEach
  void resetResolver() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("CurrentSession drops subject, redirects, then invalidates http + closes vaadin")
  void currentSession_fullFlow() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();

    new VaadinLogoutService<>(store, String.class, gateway,
        "/login", true, true)
        .logout(alice, LogoutScope.CurrentSession);

    assertEquals(String.class, store.deletedFor);
    assertEquals("/login", gateway.redirectTarget);
    assertEquals(1, gateway.closedVaadin);
    assertEquals(1, gateway.invalidatedHttp);
    // redirect must happen before invalidation, so the response carries it
    assertTrue(gateway.redirectAt < gateway.invalidatedHttpAt);
    assertTrue(gateway.redirectAt < gateway.closedVaadinAt);
  }

  @Test
  @DisplayName("CurrentSession with both invalidate flags false: only redirect + subject drop")
  void currentSession_clearSubjectOnly() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();

    new VaadinLogoutService<>(store, String.class, gateway,
        "/login", false, false)
        .logout(alice, LogoutScope.CurrentSession);

    assertEquals(String.class, store.deletedFor);
    assertEquals("/login", gateway.redirectTarget);
    assertEquals(0, gateway.closedVaadin);
    assertEquals(0, gateway.invalidatedHttp);
  }

  @Test
  @DisplayName("CurrentSession with only invalidateHttpSession: redirect + http invalidate, no vaadin close")
  void currentSession_invalidateHttpOnly() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();

    new VaadinLogoutService<>(store, String.class, gateway,
        "/login", false, true)
        .logout(alice, LogoutScope.CurrentSession);

    assertEquals(1, gateway.invalidatedHttp);
    assertEquals(0, gateway.closedVaadin);
  }

  @Test
  @DisplayName("AllSessionsOfSubject enumerates the registry but skips Vaadin redirect / invalidate")
  void allSessions_doesNotInvalidateCurrentVaadinSession() {
    SubjectSessionRegistry registry = new InMemorySubjectSessionRegistry();
    registry.register(alice, "tok-1");
    registry.register(alice, "tok-2");
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    RecordingListener listener = new RecordingListener();

    VaadinLogoutService<String> service = new VaadinLogoutService<>(
        store, String.class, gateway,
        "/login", true, true, registry);
    service.addListener(listener);

    service.logout(alice, LogoutScope.AllSessionsOfSubject);

    assertEquals(null, store.deletedFor,
        "AllSessionsOfSubject does not touch the current-thread SubjectStore");
    assertEquals(null, gateway.redirectTarget,
        "AllSessionsOfSubject does not redirect the current request");
    assertEquals(0, gateway.closedVaadin);
    assertEquals(0, gateway.invalidatedHttp);
    assertTrue(registry.sessionsOf(alice).isEmpty(),
        "registry must have been cleared");
    assertEquals(2, listener.invocations.size(),
        "listeners fire once per session id");
  }

  @Test
  @DisplayName("CurrentSession notifies SessionPolicy.onLogout")
  void currentSession_notifiesSessionPolicy() {
    RecordingSessionPolicy<String> policy = new RecordingSessionPolicy<>();
    JSentinelServiceResolver.setSessionPolicy(policy);

    new VaadinLogoutService<>(new RecordingSubjectStore(), String.class,
        new RecordingGateway(), "/login", true, true)
        .logout(alice, LogoutScope.CurrentSession);

    assertEquals(1, policy.onLogoutCalls);
  }

  @Test
  @DisplayName("AllSessionsOfSubject does NOT notify SessionPolicy.onLogout (current-thread concern)")
  void allSessions_doesNotNotifySessionPolicy() {
    RecordingSessionPolicy<String> policy = new RecordingSessionPolicy<>();
    JSentinelServiceResolver.setSessionPolicy(policy);

    new VaadinLogoutService<>(new RecordingSubjectStore(), String.class,
        new RecordingGateway(), "/login", true, true)
        .logout(alice, LogoutScope.AllSessionsOfSubject);

    assertEquals(0, policy.onLogoutCalls);
  }

  @Test
  @DisplayName("addListener / removeListener delegate to the core service")
  void listenerDelegation() {
    RecordingListener listener = new RecordingListener();
    VaadinLogoutService<String> service = new VaadinLogoutService<>(
        new RecordingSubjectStore(), String.class,
        new RecordingGateway(), "/login", false, false);
    service.addListener(listener);

    service.logout(alice, LogoutScope.CurrentSession);
    assertEquals(1, listener.invocations.size());

    service.removeListener(listener);
    service.logout(alice, LogoutScope.CurrentSession);
    assertEquals(1, listener.invocations.size(),
        "after removeListener no further notifications");
  }

  @Test
  @DisplayName("CurrentSession clears the bound TokenCredentialStore so it cannot re-authenticate (R026)")
  void currentSession_clearsBoundTokenCredential() {
    InMemoryTokenCredentialStore tokenStore = new InMemoryTokenCredentialStore();
    tokenStore.bind(token());
    JSentinelServiceResolver.setTokenCredentialStore(tokenStore);
    assertTrue(tokenStore.current().isPresent(), "precondition: a credential is bound");

    // Even with both invalidate flags false (session kept), the token must go.
    new VaadinLogoutService<>(new RecordingSubjectStore(), String.class,
        new RecordingGateway(), "/login", false, false)
        .logout(alice, LogoutScope.CurrentSession);

    assertTrue(tokenStore.current().isEmpty(),
        "logout must clear the bound token credential, not only the subject");
  }

  @Test
  @DisplayName("AllSessionsOfSubject does NOT clear the current-thread TokenCredentialStore")
  void allSessions_doesNotClearTokenCredential() {
    InMemoryTokenCredentialStore tokenStore = new InMemoryTokenCredentialStore();
    tokenStore.bind(token());
    JSentinelServiceResolver.setTokenCredentialStore(tokenStore);

    new VaadinLogoutService<>(new RecordingSubjectStore(), String.class,
        new RecordingGateway(), "/login", true, true)
        .logout(alice, LogoutScope.AllSessionsOfSubject);

    assertTrue(tokenStore.current().isPresent(),
        "AllSessionsOfSubject is not a current-thread concern and must not touch it");
  }

  private static BearerToken token() {
    return new BearerToken("tok-abc", Optional.empty(), Optional.empty(), Optional.empty());
  }

  // ── Fixtures ──────────────────────────────────────────────────

  static final class RecordingSubjectStore implements SubjectStore {
    Class<?> deletedFor;

    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.empty();
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      deletedFor = subjectType;
    }
  }

  static final class RecordingGateway implements VaadinLogoutGateway {
    String redirectTarget;
    int closedVaadin;
    int invalidatedHttp;
    long redirectAt;
    long closedVaadinAt;
    long invalidatedHttpAt;
    private long counter;

    @Override public void redirectTo(String routePath) {
      redirectTarget = routePath;
      redirectAt = ++counter;
    }

    @Override public void closeVaadinSession() {
      closedVaadin++;
      closedVaadinAt = ++counter;
    }

    @Override public void invalidateHttpSession() {
      invalidatedHttp++;
      invalidatedHttpAt = ++counter;
    }
  }

  static final class RecordingListener implements LogoutListener {
    final List<String> invocations = new ArrayList<>();

    @Override public void onLogout(SubjectId subjectId, String sessionId, LogoutScope scope) {
      invocations.add(subjectId.value() + "/" + sessionId + "/" + scope);
    }
  }

  static final class RecordingSessionPolicy<U>
      implements com.svenruppert.jsentinel.session.SessionPolicy<U> {
    int onLogoutCalls;

    @Override
    public com.svenruppert.jsentinel.session.SessionDecision beforeNavigation(
        com.svenruppert.jsentinel.session.SessionContext<U> context) {
      return com.svenruppert.jsentinel.session.SessionDecision.Continue.INSTANCE;
    }

    @Override
    public void onLogout(com.svenruppert.jsentinel.session.SessionContext<U> context) {
      onLogoutCalls++;
    }
  }
}
