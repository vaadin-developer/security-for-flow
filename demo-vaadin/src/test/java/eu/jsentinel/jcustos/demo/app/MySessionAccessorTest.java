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
package eu.jsentinel.jcustos.demo.app;

import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.demo.app.security.model.MyUser;
import eu.jsentinel.jcustos.demo.app.security.roles.AuthorizationRole;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static eu.jsentinel.jcustos.demo.app.MySessionAccessor.isCurrentUserAuthorizedFor;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("MySessionAccessor.isCurrentUserAuthorizedFor")
class MySessionAccessorTest {

  private final InMemorySubjectStore store = new InMemorySubjectStore();

  @BeforeEach
  void installSubjectStore() {
    SubjectStores.setSubjectStore(store);
  }

  @AfterEach
  void resetSubjectStore() {
    store.clear();
    SubjectStores.reset();
  }

  @Test
  @DisplayName("null roles array → always authorized")
  void nullArgumentAuthorizes() {
    assertTrue(isCurrentUserAuthorizedFor((AuthorizationRole[]) null));
  }

  @Test
  @DisplayName("empty roles array → always authorized")
  void emptyArrayAuthorizes() {
    assertTrue(isCurrentUserAuthorizedFor());
  }

  @Test
  @DisplayName("No current subject → not authorized for any role")
  void anonymousIsRejected() {
    assertFalse(isCurrentUserAuthorizedFor(AuthorizationRole.USER));
  }

  @Test
  @DisplayName("Subject without the required role → rejected")
  void wrongRoleIsRejected() {
    store.setCurrentSubject(
        new MyUser(1L, "Alice", EnumSet.of(AuthorizationRole.USER)),
        MyUser.class);

    assertFalse(isCurrentUserAuthorizedFor(AuthorizationRole.ADMIN));
  }

  @Test
  @DisplayName("Subject with one of the required roles → authorized")
  void matchingRoleAuthorizes() {
    store.setCurrentSubject(
        new MyUser(2L, "Bob", EnumSet.of(AuthorizationRole.NERD, AuthorizationRole.USER)),
        MyUser.class);

    assertTrue(isCurrentUserAuthorizedFor(AuthorizationRole.NERD));
    assertTrue(isCurrentUserAuthorizedFor(AuthorizationRole.ADMIN, AuthorizationRole.NERD));
    assertFalse(isCurrentUserAuthorizedFor(AuthorizationRole.ADMIN));
  }

  // ── Fixtures ──────────────────────────────────────────────────

  private static final class InMemorySubjectStore implements SubjectStore {
    private final Map<Class<?>, Object> store = new HashMap<>();

    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.ofNullable(subjectType.cast(store.get(subjectType)));
    }

    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      store.put(subjectType, subject);
    }

    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      store.remove(subjectType);
    }

    void clear() {
      store.clear();
    }
  }
}
