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
package com.svenruppert.vaadin.security.test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FakeAuthenticationServiceTest {

  private record User(String id) {
  }

  @Test
  @DisplayName("forType rejects null subject type")
  void forTypeRejectsNullSubjectType() {
    assertThrows(NullPointerException.class,
        () -> FakeAuthenticationService.forType(null));
  }

  @Test
  @DisplayName("subjectType returns the configured class token")
  void subjectTypeIsConfigured() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.forType(User.class);
    assertSame(User.class, auth.subjectType());
  }

  @Test
  @DisplayName("register then checkCredentials returns true; loadSubject returns the bound subject")
  void registerAndCheck() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.forType(User.class);
    User alice = new User("u-alice");
    auth.register("alice", alice);

    assertTrue(auth.checkCredentials("alice"));
    assertSame(alice, auth.loadSubject("alice"));
  }

  @Test
  @DisplayName("unregistered credentials are rejected")
  void unregisteredRejected() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.forType(User.class);
    assertFalse(auth.checkCredentials("ghost"));
    assertNull(auth.loadSubject("ghost"));
  }

  @Test
  @DisplayName("null credentials are rejected without throwing")
  void nullCredentialsRejected() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.forType(User.class);
    assertFalse(auth.checkCredentials(null));
    assertNull(auth.loadSubject(null));
  }

  @Test
  @DisplayName("register rejects null credentials and null subject")
  void registerRejectsNulls() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.forType(User.class);
    assertThrows(NullPointerException.class,
        () -> auth.register(null, new User("u")));
    assertThrows(NullPointerException.class,
        () -> auth.register("x", null));
  }

  @Test
  @DisplayName("re-registering the same credentials replaces the bound subject")
  void reRegisterReplaces() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.forType(User.class);
    User first = new User("u-1");
    User second = new User("u-2");
    auth.register("k", first);
    auth.register("k", second);
    assertSame(second, auth.loadSubject("k"));
  }

  @Test
  @DisplayName("withFallback: registered credentials win over the fallback")
  void fallbackRegisteredWins() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.withFallback(
            User.class, key -> new User("fallback-" + key));
    User alice = new User("u-alice");
    auth.register("alice", alice);

    assertSame(alice, auth.loadSubject("alice"));
  }

  @Test
  @DisplayName("withFallback: fallback returns subject for unregistered credentials")
  void fallbackHandlesUnregistered() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.withFallback(
            User.class, key -> new User("fallback-" + key));
    assertTrue(auth.checkCredentials("ghost"));
    assertEquals("fallback-ghost", auth.loadSubject("ghost").id());
  }

  @Test
  @DisplayName("withFallback: fallback returning null counts as rejection")
  void fallbackNullCountsAsReject() {
    FakeAuthenticationService<String, User> auth =
        FakeAuthenticationService.withFallback(User.class, key -> null);
    assertFalse(auth.checkCredentials("ghost"));
    assertNull(auth.loadSubject("ghost"));
  }

  @Test
  @DisplayName("withFallback rejects null fallback function")
  void withFallbackRejectsNullFallback() {
    assertThrows(NullPointerException.class,
        () -> FakeAuthenticationService.withFallback(User.class, null));
  }
}
