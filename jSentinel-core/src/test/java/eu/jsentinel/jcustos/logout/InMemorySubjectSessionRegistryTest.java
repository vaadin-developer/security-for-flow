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
package eu.jsentinel.jcustos.logout;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemorySubjectSessionRegistryTest {

  private final InMemorySubjectSessionRegistry registry = new InMemorySubjectSessionRegistry();
  private final SubjectId alice = SubjectId.of("alice");
  private final SubjectId bob = SubjectId.of("bob");

  @Test
  @DisplayName("register + sessionsOf round-trip preserves insertion order")
  void registerRoundTrip() {
    registry.register(alice, "A");
    registry.register(alice, "B");
    registry.register(alice, "C");

    Collection<String> snapshot = registry.sessionsOf(alice);

    assertEquals(java.util.List.of("A", "B", "C"), java.util.List.copyOf(snapshot));
  }

  @Test
  @DisplayName("register is idempotent for the same (subject, session) pair")
  void registerIsIdempotent() {
    registry.register(alice, "A");
    registry.register(alice, "A");
    registry.register(alice, "A");

    assertEquals(1, registry.sessionsOf(alice).size());
  }

  @Test
  @DisplayName("sessions of different subjects don't bleed into each other")
  void subjectIsolation() {
    registry.register(alice, "A");
    registry.register(bob, "B");

    assertEquals(java.util.List.of("A"), java.util.List.copyOf(registry.sessionsOf(alice)));
    assertEquals(java.util.List.of("B"), java.util.List.copyOf(registry.sessionsOf(bob)));
  }

  @Test
  @DisplayName("unregister removes one specific (subject, session) pair")
  void unregisterRemovesPair() {
    registry.register(alice, "A");
    registry.register(alice, "B");

    registry.unregister(alice, "A");

    assertEquals(java.util.List.of("B"), java.util.List.copyOf(registry.sessionsOf(alice)));
  }

  @Test
  @DisplayName("unregister of an unknown pair is a no-op")
  void unregisterUnknownNoop() {
    registry.register(alice, "A");

    registry.unregister(alice, "B");
    registry.unregister(bob, "A");

    assertEquals(1, registry.sessionsOf(alice).size());
  }

  @Test
  @DisplayName("clearAll removes every session for the subject and returns the snapshot")
  void clearAllReturnsSnapshot() {
    registry.register(alice, "A");
    registry.register(alice, "B");
    registry.register(bob, "C");

    Collection<String> removed = registry.clearAll(alice);

    assertEquals(2, removed.size());
    assertTrue(removed.contains("A"));
    assertTrue(removed.contains("B"));
    assertTrue(registry.sessionsOf(alice).isEmpty());
    assertEquals(1, registry.sessionsOf(bob).size(),
        "clearAll must not touch other subjects");
  }

  @Test
  @DisplayName("clearAll on an unknown subject returns an empty snapshot")
  void clearAllUnknownReturnsEmpty() {
    Collection<String> removed = registry.clearAll(alice);
    assertTrue(removed.isEmpty());
  }

  @Test
  @DisplayName("sessionsOf returns an empty snapshot for unknown subjects")
  void sessionsOfUnknown() {
    assertTrue(registry.sessionsOf(alice).isEmpty());
  }

  @Test
  @DisplayName("register rejects null arguments")
  void registerRejectsNulls() {
    assertThrows(NullPointerException.class, () -> registry.register(null, "A"));
    assertThrows(NullPointerException.class, () -> registry.register(alice, null));
  }

  @Test
  @DisplayName("unregister of a null subject or session is a safe no-op")
  void unregisterNullSafe() {
    registry.unregister(null, "A");
    registry.unregister(alice, null);
    registry.unregister(null, null);
    // no throw, no state change
  }

  @Test
  @DisplayName("snapshot is independent of later registrations")
  void snapshotIsIndependent() {
    registry.register(alice, "A");
    Collection<String> snapshot = registry.sessionsOf(alice);

    registry.register(alice, "B");

    assertEquals(1, snapshot.size(),
        "earlier snapshot must not see later registrations");
  }
}
