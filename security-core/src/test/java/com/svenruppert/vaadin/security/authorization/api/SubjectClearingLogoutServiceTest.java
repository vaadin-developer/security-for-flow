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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SubjectClearingLogoutService")
class SubjectClearingLogoutServiceTest {

  @Test
  @DisplayName("delegates to SubjectStore.deleteCurrentSubject")
  void clearsSubject() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    LogoutService service = new SubjectClearingLogoutService<>(store, String.class);
    service.logout(LogoutContext.of(LogoutPolicy.clearSubjectOnly("/login")));
    assertEquals(String.class, store.deletedFor);
  }

  @Test
  @DisplayName("works for any policy variant — core never inspects session flags")
  void coreIgnoresSessionFlags() {
    RecordingSubjectStore store = new RecordingSubjectStore();
    LogoutService service = new SubjectClearingLogoutService<>(store, String.class);
    service.logout(LogoutContext.of(LogoutPolicy.fullInvalidate("/login")));
    assertEquals(String.class, store.deletedFor);
  }

  static final class RecordingSubjectStore implements SubjectStore {
    Class<?> deletedFor;
    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) { return Optional.empty(); }
    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) { }
    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) { deletedFor = subjectType; }
  }
}
