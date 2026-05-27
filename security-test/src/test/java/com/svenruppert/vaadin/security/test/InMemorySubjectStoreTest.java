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
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemorySubjectStoreTest {

  @Test
  @DisplayName("currentSubject returns empty for unbound type")
  void emptyByDefault() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    assertTrue(store.currentSubject(String.class).isEmpty());
  }

  @Test
  @DisplayName("set then currentSubject returns the bound value")
  void setThenGet() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    store.setCurrentSubject("alice", String.class);
    assertEquals("alice", store.currentSubject(String.class).orElseThrow());
  }

  @Test
  @DisplayName("set replaces a prior binding for the same type")
  void setReplaces() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    store.setCurrentSubject("alice", String.class);
    store.setCurrentSubject("bob", String.class);
    assertEquals("bob", store.currentSubject(String.class).orElseThrow());
  }

  @Test
  @DisplayName("delete removes the binding for the given type")
  void deleteRemoves() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    store.setCurrentSubject("alice", String.class);
    store.deleteCurrentSubject(String.class);
    assertTrue(store.currentSubject(String.class).isEmpty());
  }

  @Test
  @DisplayName("bindings for distinct subject types are independent")
  void typesAreIndependent() {
    InMemorySubjectStore store = new InMemorySubjectStore();
    store.setCurrentSubject("alice", String.class);
    store.setCurrentSubject(42, Integer.class);
    assertEquals("alice", store.currentSubject(String.class).orElseThrow());
    assertEquals(42, store.currentSubject(Integer.class).orElseThrow());
  }
}
