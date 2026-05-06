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
package com.svenruppert.vaadin.security.authorization.vaadin;

import com.svenruppert.vaadin.security.authorization.api.LogoutContext;
import com.svenruppert.vaadin.security.authorization.api.LogoutPolicy;
import com.svenruppert.vaadin.security.authorization.api.SubjectStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("VaadinLogoutService")
class VaadinLogoutServiceTest {

  @Test
  @DisplayName("clearSubjectOnly drops subject + redirects but skips session invalidation")
  void clearSubjectOnly() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    new VaadinLogoutService<>(store, String.class, gateway)
        .logout(LogoutContext.of(LogoutPolicy.clearSubjectOnly("/login")));

    assertEquals(String.class, store.deletedFor);
    assertEquals("/login", gateway.redirectTarget);
    assertEquals(0, gateway.closedVaadin);
    assertEquals(0, gateway.invalidatedHttp);
  }

  @Test
  @DisplayName("fullInvalidate drops subject, redirects, then invalidates http and closes vaadin")
  void fullInvalidate() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    new VaadinLogoutService<>(store, String.class, gateway)
        .logout(LogoutContext.of(LogoutPolicy.fullInvalidate("/login")));

    assertEquals(String.class, store.deletedFor);
    assertEquals("/login", gateway.redirectTarget);
    assertEquals(1, gateway.closedVaadin);
    assertEquals(1, gateway.invalidatedHttp);
    // redirect must happen before invalidation, so the response carries it
    assertTrue(gateway.redirectAt < gateway.invalidatedHttpAt);
    assertTrue(gateway.redirectAt < gateway.closedVaadinAt);
  }

  @Test
  @DisplayName("invalidateHttpSession-only policy keeps Vaadin session alive")
  void invalidateHttpOnly() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    RecordingGateway gateway = new RecordingGateway();
    new VaadinLogoutService<>(store, String.class, gateway)
        .logout(LogoutContext.of(LogoutPolicy.invalidateHttpSession("/login")));

    assertEquals(1, gateway.invalidatedHttp);
    assertEquals(0, gateway.closedVaadin);
  }

  // ── Test fixtures ─────────────────────────────────────────────

  static final class RecordingSubjectStore implements SubjectStore {
    Class<?> deletedFor;
    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) { return Optional.empty(); }
    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) { }
    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) { deletedFor = subjectType; }
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
}
