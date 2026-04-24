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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SessionAccessor with replaceable SubjectStore")
class SessionAccessorTest {

  private InMemorySubjectStore store;

  @BeforeEach
  void setUp() {
    store = new InMemorySubjectStore();
    SessionAccessor.setSubjectStore(store);
    SessionAccessor.setSubjectType(String.class);
  }

  @AfterEach
  void tearDown() {
    SessionAccessor.reset();
  }

  @Test
  @DisplayName("currentSubject returns absent when store is empty")
  void currentSubject_empty() {
    var result = SessionAccessor.<String>currentSubject();
    assertTrue(result.isAbsent());
  }

  @Test
  @DisplayName("setCurrentSubject and currentSubject round-trip")
  void setAndGet() {
    SessionAccessor.setCurrentSubject("alice");
    var result = SessionAccessor.<String>currentSubject();
    assertTrue(result.isPresent());
    assertEquals("alice", result.get());
  }

  @Test
  @DisplayName("deleteCurrentSubject clears the subject")
  void delete() {
    SessionAccessor.setCurrentSubject("alice");
    SessionAccessor.deleteCurrentSubject();
    assertTrue(SessionAccessor.<String>currentSubject().isAbsent());
  }

  @Test
  @DisplayName("subjectStore returns the configured store")
  void subjectStore_returnsConfigured() {
    assertSame(store, SessionAccessor.subjectStore());
  }

  @Test
  @DisplayName("reset restores default state")
  void reset_restoresDefault() {
    SessionAccessor.setCurrentSubject("alice");
    SessionAccessor.reset();
    // After reset, store is a fresh VaadinSessionSubjectStore
    assertInstanceOf(VaadinSessionSubjectStore.class, SessionAccessor.subjectStore());
  }

  @Test
  @DisplayName("setSubjectType allows using a custom type without SPI")
  void customSubjectType() {
    SessionAccessor.setSubjectType(Integer.class);
    SessionAccessor.setSubjectStore(new InMemorySubjectStore());
    SessionAccessor.setCurrentSubject(42);
    var result = SessionAccessor.<Integer>currentSubject();
    assertTrue(result.isPresent());
    assertEquals(42, result.get());
  }
}
