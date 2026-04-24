package com.svenruppert.vaadin.security.authorization.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("InMemorySubjectStore (SubjectStore contract)")
class SubjectStoreTest {

  private InMemorySubjectStore store;

  @BeforeEach
  void setUp() {
    store = new InMemorySubjectStore();
  }

  @Test
  @DisplayName("empty store returns empty Optional")
  void empty_returnsEmpty() {
    assertTrue(store.currentSubject(String.class).isEmpty());
    assertFalse(store.hasSubject(String.class));
  }

  @Test
  @DisplayName("set and retrieve subject")
  void setAndRetrieve() {
    store.setCurrentSubject("alice", String.class);

    var result = store.currentSubject(String.class);
    assertTrue(result.isPresent());
    assertEquals("alice", result.get());
    assertTrue(store.hasSubject(String.class));
  }

  @Test
  @DisplayName("delete subject clears it")
  void deleteClears() {
    store.setCurrentSubject("alice", String.class);
    store.deleteCurrentSubject(String.class);

    assertTrue(store.currentSubject(String.class).isEmpty());
    assertFalse(store.hasSubject(String.class));
  }

  @Test
  @DisplayName("different types are independent")
  void differentTypes_independent() {
    store.setCurrentSubject("alice", String.class);
    store.setCurrentSubject(42, Integer.class);

    assertEquals("alice", store.currentSubject(String.class).orElseThrow());
    assertEquals(42, store.currentSubject(Integer.class).orElseThrow());

    store.deleteCurrentSubject(String.class);
    assertTrue(store.currentSubject(String.class).isEmpty());
    assertTrue(store.currentSubject(Integer.class).isPresent());
  }
}
