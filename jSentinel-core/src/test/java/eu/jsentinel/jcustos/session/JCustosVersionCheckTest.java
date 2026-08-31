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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosVersionCheck")
class JCustosVersionCheckTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final JCustosVersionKey ALICE_KEY =
      new JCustosVersionKey(TenantId.DEFAULT, ALICE);

  @Test
  @DisplayName("INITIAL snapshot against a fresh store reports Current")
  void freshStoreIsCurrent() {
    InMemoryJCustosVersionStore store = new InMemoryJCustosVersionStore();
    JCustosVersionCheck check = new JCustosVersionCheck(store);

    JCustosVersionStatus status = check.check(ALICE_KEY, JCustosVersion.INITIAL);
    assertTrue(status.isCurrent());
    assertFalse(status.isDrifted());
    assertEquals(JCustosVersion.INITIAL, status.snapshot());
    assertEquals(JCustosVersion.INITIAL, status.current());
    assertInstanceOf(JCustosVersionStatus.Current.class, status);
  }

  @Test
  @DisplayName("snapshot behind current reports Drifted with both values")
  void snapshotBehindCurrentIsDrifted() {
    InMemoryJCustosVersionStore store = new InMemoryJCustosVersionStore();
    store.increment(ALICE_KEY); // current → 1
    store.increment(ALICE_KEY); // current → 2

    JCustosVersionCheck check = new JCustosVersionCheck(store);
    JCustosVersionStatus status = check.check(ALICE_KEY, JCustosVersion.INITIAL);

    assertTrue(status.isDrifted());
    assertFalse(status.isCurrent());
    assertEquals(JCustosVersion.INITIAL, status.snapshot());
    assertEquals(new JCustosVersion(2L), status.current());
    JCustosVersionStatus.Drifted drifted =
        assertInstanceOf(JCustosVersionStatus.Drifted.class, status);
    assertEquals(JCustosVersion.INITIAL, drifted.snapshot());
    assertEquals(new JCustosVersion(2L), drifted.current());
  }

  @Test
  @DisplayName("snapshot ahead of current (after reset) is also Drifted")
  void snapshotAheadAfterResetIsDrifted() {
    InMemoryJCustosVersionStore store = new InMemoryJCustosVersionStore();
    JCustosVersion snapshot = store.increment(ALICE_KEY); // current → 1
    store.reset(ALICE_KEY);                                 // current → 0

    JCustosVersionCheck check = new JCustosVersionCheck(store);
    JCustosVersionStatus status = check.check(ALICE_KEY, snapshot);

    assertTrue(status.isDrifted());
    assertEquals(new JCustosVersion(1L), status.snapshot());
    assertEquals(JCustosVersion.INITIAL, status.current());
  }

  @Test
  @DisplayName("after re-increment to the snapshot value, status flips back to Current")
  void reincrementingToSnapshotFlipsToCurrent() {
    InMemoryJCustosVersionStore store = new InMemoryJCustosVersionStore();
    store.increment(ALICE_KEY); // current → 1
    JCustosVersionCheck check = new JCustosVersionCheck(store);

    JCustosVersionStatus before = check.check(ALICE_KEY, new JCustosVersion(1L));
    assertTrue(before.isCurrent());

    store.increment(ALICE_KEY); // current → 2
    JCustosVersionStatus drifted = check.check(ALICE_KEY, new JCustosVersion(1L));
    assertTrue(drifted.isDrifted());
  }

  @Test
  @DisplayName("SessionRecord convenience overload builds the key from tenant + subject")
  void sessionRecordOverloadHitsTheRightKey() {
    InMemoryJCustosVersionStore store = new InMemoryJCustosVersionStore();
    JCustosVersionCheck check = new JCustosVersionCheck(store);

    Instant now = Instant.parse("2026-01-01T00:00:00Z");
    SessionRecord session = new SessionRecord(
        new SessionId("sid-1"), ALICE, TenantId.DEFAULT,
        now, now, JCustosVersion.INITIAL, SessionStatus.ACTIVE);

    assertTrue(check.check(session).isCurrent());
    store.increment(ALICE_KEY);
    assertTrue(check.check(session).isDrifted());
  }

  @Test
  @DisplayName("null arguments are rejected uniformly")
  void rejectNulls() {
    InMemoryJCustosVersionStore store = new InMemoryJCustosVersionStore();
    JCustosVersionCheck check = new JCustosVersionCheck(store);

    assertThrows(NullPointerException.class, () -> new JCustosVersionCheck(null));
    assertThrows(NullPointerException.class,
        () -> check.check((JCustosVersionKey) null, JCustosVersion.INITIAL));
    assertThrows(NullPointerException.class,
        () -> check.check(ALICE_KEY, null));
    assertThrows(NullPointerException.class,
        () -> check.check((SessionRecord) null));
  }

  @Test
  @DisplayName("Drifted record refuses equal snapshot/current and rejects null components")
  void driftedRecordEnforcesInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new JCustosVersionStatus.Drifted(JCustosVersion.INITIAL, JCustosVersion.INITIAL));
    assertThrows(NullPointerException.class,
        () -> new JCustosVersionStatus.Drifted(null, JCustosVersion.INITIAL));
    assertThrows(NullPointerException.class,
        () -> new JCustosVersionStatus.Drifted(JCustosVersion.INITIAL, null));
    assertThrows(NullPointerException.class,
        () -> new JCustosVersionStatus.Current(null));
  }
}
