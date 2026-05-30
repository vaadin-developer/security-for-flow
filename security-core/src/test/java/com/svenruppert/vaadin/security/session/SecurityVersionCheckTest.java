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
package com.svenruppert.vaadin.security.session;

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SecurityVersionCheck")
class SecurityVersionCheckTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SecurityVersionKey ALICE_KEY =
      new SecurityVersionKey(TenantId.DEFAULT, ALICE);

  @Test
  @DisplayName("INITIAL snapshot against a fresh store reports Current")
  void freshStoreIsCurrent() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    SecurityVersionCheck check = new SecurityVersionCheck(store);

    SecurityVersionStatus status = check.check(ALICE_KEY, SecurityVersion.INITIAL);
    assertTrue(status.isCurrent());
    assertFalse(status.isDrifted());
    assertEquals(SecurityVersion.INITIAL, status.snapshot());
    assertEquals(SecurityVersion.INITIAL, status.current());
    assertInstanceOf(SecurityVersionStatus.Current.class, status);
  }

  @Test
  @DisplayName("snapshot behind current reports Drifted with both values")
  void snapshotBehindCurrentIsDrifted() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    store.increment(ALICE_KEY); // current → 1
    store.increment(ALICE_KEY); // current → 2

    SecurityVersionCheck check = new SecurityVersionCheck(store);
    SecurityVersionStatus status = check.check(ALICE_KEY, SecurityVersion.INITIAL);

    assertTrue(status.isDrifted());
    assertFalse(status.isCurrent());
    assertEquals(SecurityVersion.INITIAL, status.snapshot());
    assertEquals(new SecurityVersion(2L), status.current());
    SecurityVersionStatus.Drifted drifted =
        assertInstanceOf(SecurityVersionStatus.Drifted.class, status);
    assertEquals(SecurityVersion.INITIAL, drifted.snapshot());
    assertEquals(new SecurityVersion(2L), drifted.current());
  }

  @Test
  @DisplayName("snapshot ahead of current (after reset) is also Drifted")
  void snapshotAheadAfterResetIsDrifted() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    SecurityVersion snapshot = store.increment(ALICE_KEY); // current → 1
    store.reset(ALICE_KEY);                                 // current → 0

    SecurityVersionCheck check = new SecurityVersionCheck(store);
    SecurityVersionStatus status = check.check(ALICE_KEY, snapshot);

    assertTrue(status.isDrifted());
    assertEquals(new SecurityVersion(1L), status.snapshot());
    assertEquals(SecurityVersion.INITIAL, status.current());
  }

  @Test
  @DisplayName("after re-increment to the snapshot value, status flips back to Current")
  void reincrementingToSnapshotFlipsToCurrent() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    store.increment(ALICE_KEY); // current → 1
    SecurityVersionCheck check = new SecurityVersionCheck(store);

    SecurityVersionStatus before = check.check(ALICE_KEY, new SecurityVersion(1L));
    assertTrue(before.isCurrent());

    store.increment(ALICE_KEY); // current → 2
    SecurityVersionStatus drifted = check.check(ALICE_KEY, new SecurityVersion(1L));
    assertTrue(drifted.isDrifted());
  }

  @Test
  @DisplayName("SessionRecord convenience overload builds the key from tenant + subject")
  void sessionRecordOverloadHitsTheRightKey() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    SecurityVersionCheck check = new SecurityVersionCheck(store);

    Instant now = Instant.parse("2026-01-01T00:00:00Z");
    SessionRecord session = new SessionRecord(
        new SessionId("sid-1"), ALICE, TenantId.DEFAULT,
        now, now, SecurityVersion.INITIAL, SessionStatus.ACTIVE);

    assertTrue(check.check(session).isCurrent());
    store.increment(ALICE_KEY);
    assertTrue(check.check(session).isDrifted());
  }

  @Test
  @DisplayName("null arguments are rejected uniformly")
  void rejectNulls() {
    InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();
    SecurityVersionCheck check = new SecurityVersionCheck(store);

    assertThrows(NullPointerException.class, () -> new SecurityVersionCheck(null));
    assertThrows(NullPointerException.class,
        () -> check.check((SecurityVersionKey) null, SecurityVersion.INITIAL));
    assertThrows(NullPointerException.class,
        () -> check.check(ALICE_KEY, null));
    assertThrows(NullPointerException.class,
        () -> check.check((SessionRecord) null));
  }

  @Test
  @DisplayName("Drifted record refuses equal snapshot/current and rejects null components")
  void driftedRecordEnforcesInvariants() {
    assertThrows(IllegalArgumentException.class,
        () -> new SecurityVersionStatus.Drifted(SecurityVersion.INITIAL, SecurityVersion.INITIAL));
    assertThrows(NullPointerException.class,
        () -> new SecurityVersionStatus.Drifted(null, SecurityVersion.INITIAL));
    assertThrows(NullPointerException.class,
        () -> new SecurityVersionStatus.Drifted(SecurityVersion.INITIAL, null));
    assertThrows(NullPointerException.class,
        () -> new SecurityVersionStatus.Current(null));
  }
}
