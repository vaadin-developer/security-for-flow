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
package com.svenruppert.jsentinel.standalone;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("ThreadLocalSubjectStore")
class ThreadLocalSubjectStoreTest {

  @Test
  @DisplayName("set / get round-trip")
  void setAndGet() {
    ThreadLocalSubjectStore store = new ThreadLocalSubjectStore();
    store.setCurrentSubject("alice", String.class);

    assertTrue(store.currentSubject(String.class).isPresent());
    assertEquals("alice", store.currentSubject(String.class).orElseThrow());
  }

  @Test
  @DisplayName("delete removes the binding")
  void deleteClears() {
    ThreadLocalSubjectStore store = new ThreadLocalSubjectStore();
    store.setCurrentSubject("alice", String.class);
    store.deleteCurrentSubject(String.class);

    assertFalse(store.currentSubject(String.class).isPresent());
  }

  @Test
  @DisplayName("bindings are per-thread — a background thread sees no subject")
  void perThreadIsolation() throws ExecutionException, InterruptedException {
    ThreadLocalSubjectStore store = new ThreadLocalSubjectStore();
    store.setCurrentSubject("alice", String.class);

    boolean seenOnOtherThread = CompletableFuture
        .supplyAsync(() -> store.currentSubject(String.class).isPresent())
        .get();

    assertFalse(seenOnOtherThread,
        "ThreadLocalSubjectStore must NOT leak the subject into a background thread");
  }

  @Test
  @DisplayName("clear() wipes the binding for the current thread")
  void clearWipes() {
    ThreadLocalSubjectStore store = new ThreadLocalSubjectStore();
    store.setCurrentSubject("alice", String.class);
    store.clear();

    assertFalse(store.currentSubject(String.class).isPresent(),
        "clear() must remove the current-thread binding");
  }

  @Test
  @DisplayName("different subject types coexist on the same thread")
  void differentTypesCoexist() {
    ThreadLocalSubjectStore store = new ThreadLocalSubjectStore();
    store.setCurrentSubject("alice", String.class);
    store.setCurrentSubject(42, Integer.class);

    assertEquals("alice", store.currentSubject(String.class).orElseThrow());
    assertEquals(42, store.currentSubject(Integer.class).orElseThrow());

    store.deleteCurrentSubject(String.class);
    assertFalse(store.currentSubject(String.class).isPresent());
    assertTrue(store.currentSubject(Integer.class).isPresent(),
        "deleting one subject type must not affect bindings for other types");
  }
}
