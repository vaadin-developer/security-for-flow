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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SubjectStores")
class SubjectStoresTest {

  @AfterEach
  void tearDown() {
    SubjectStores.reset();
  }

  @Test
  @DisplayName("subjectStore returns configured store")
  void subjectStore_returnsConfigured() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(store);

    assertSame(store, SubjectStores.subjectStore());
  }

  @Test
  @DisplayName("configured store can round-trip subjects")
  void configuredStore_roundTrip() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    SubjectStores.setSubjectStore(store);

    SubjectStores.subjectStore().setCurrentSubject("alice", String.class);

    var result = SubjectStores.subjectStore().currentSubject(String.class);
    assertTrue(result.isPresent());
    assertEquals("alice", result.get());
  }

  @Test
  @DisplayName("reset clears configured store")
  void reset_clearsConfiguredStore() {
    SubjectStores.setSubjectStore(new InMemorySubjectStore());
    SubjectStores.reset();

    assertThrows(IllegalStateException.class, SubjectStores::subjectStore);
  }

  @Test
  @DisplayName("findSubjectStore returns empty when no SPI registered")
  void findSubjectStore_empty() {
    assertTrue(SubjectStores.findSubjectStore().isEmpty());
  }

  @Test
  @DisplayName("multiple SubjectStore implementations fail explicitly")
  void multipleSubjectStores_throwWithMessage() {
    var ex = assertThrows(IllegalStateException.class,
        () -> SecurityServiceResolver.requireSingleService(
            SubjectStore.class,
            java.util.List.of(new FirstSubjectStore(), new SecondSubjectStore())));

    assertTrue(ex.getMessage().contains("multiple implementations"));
    assertTrue(ex.getMessage().contains(FirstSubjectStore.class.getName()));
    assertTrue(ex.getMessage().contains(SecondSubjectStore.class.getName()));
  }

  static class FirstSubjectStore extends InMemorySubjectStore {
  }

  static final class SecondSubjectStore extends InMemorySubjectStore {
  }
}
