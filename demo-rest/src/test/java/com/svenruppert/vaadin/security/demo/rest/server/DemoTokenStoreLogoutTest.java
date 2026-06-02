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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.logout.LogoutScope;
import com.svenruppert.vaadin.security.logout.SubjectClearingLogoutService;
import com.svenruppert.vaadin.security.logout.SubjectId;
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
import com.svenruppert.vaadin.security.credential.password.PasswordHashingServices;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUser;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUserStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DemoTokenStore as SubjectSessionRegistry + LogoutService integration")
class DemoTokenStoreLogoutTest {

  @Test
  @DisplayName("issue registers the token under the user's SubjectId; revoke removes it")
  void issueAndRevokeMaintainTheIndex() {
    DemoTokenStore tokens = new DemoTokenStore();
    DemoUser alice = aUser();
    SubjectId aliceId = SubjectId.of(alice.username());

    String t1 = tokens.issue(alice);
    String t2 = tokens.issue(alice);

    assertEquals(2, tokens.sessionsOf(aliceId).size());
    assertTrue(tokens.sessionsOf(aliceId).contains(t1));
    assertTrue(tokens.sessionsOf(aliceId).contains(t2));

    tokens.revoke(t1);
    assertEquals(1, tokens.sessionsOf(aliceId).size());
    assertFalse(tokens.sessionsOf(aliceId).contains(t1));
  }

  @Test
  @DisplayName("LogoutService.logout(AllSessionsOfSubject) revokes every token of the subject")
  void logoutAllSessionsRevokesAllUserTokens() {
    DemoTokenStore tokens = new DemoTokenStore();
    DemoUser alice = aUser();

    String t1 = tokens.issue(alice);
    String t2 = tokens.issue(alice);
    String t3 = tokens.issue(alice);

    SubjectClearingLogoutService<DemoUser> service = new SubjectClearingLogoutService<>(
        new NoopStore(), DemoUser.class, tokens, null);
    service.addListener((subjectId, sessionId, scope) -> {
      if (sessionId != null) tokens.revoke(sessionId);
    });

    service.logout(SubjectId.of(alice.username()), LogoutScope.AllSessionsOfSubject);

    assertTrue(tokens.resolve(t1).isEmpty(), "t1 must be revoked");
    assertTrue(tokens.resolve(t2).isEmpty(), "t2 must be revoked");
    assertTrue(tokens.resolve(t3).isEmpty(), "t3 must be revoked");
    assertTrue(tokens.sessionsOf(SubjectId.of(alice.username())).isEmpty(),
        "the per-user index must be empty after AllSessionsOfSubject");
  }

  @Test
  @DisplayName("LogoutService.logout(CurrentSession) does not touch other tokens of the same subject")
  void logoutCurrentSessionDoesNotTouchOtherTokens() {
    DemoTokenStore tokens = new DemoTokenStore();
    DemoUser alice = aUser();

    String current = tokens.issue(alice);
    String other = tokens.issue(alice);

    SubjectClearingLogoutService<DemoUser> service = new SubjectClearingLogoutService<>(
        new NoopStore(), DemoUser.class, tokens, null);
    service.addListener((subjectId, sessionId, scope) -> {
      if (sessionId != null) tokens.revoke(sessionId);
    });

    // The handler-level revoke happens before the service call —
    // mirroring DemoHandlers.logout(...).
    tokens.revoke(current);
    service.logout(SubjectId.of(alice.username()), LogoutScope.CurrentSession);

    assertTrue(tokens.resolve(current).isEmpty(), "current must be revoked");
    assertTrue(tokens.resolve(other).isPresent(),
        "the other session of the same subject must remain valid");
  }

  // ── Fixtures ───────────────────────────────────────────────────

  private static DemoUser aUser() {
    DemoUserStore store = new DemoUserStore(PasswordHashingServices.defaults(), false);
    return store.authenticate("admin", "admin").orElseThrow();
  }

  private static final class NoopStore implements SubjectStore {
    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.empty();
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
    }
  }
}
