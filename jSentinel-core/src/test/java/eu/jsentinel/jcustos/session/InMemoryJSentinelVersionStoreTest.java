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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("InMemoryJSentinelVersionStore + JSentinelVersionKey")
class InMemoryJSentinelVersionStoreTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final TenantId ACME = new TenantId("acme");

  private final InMemoryJSentinelVersionStore store = new InMemoryJSentinelVersionStore();

  private static JSentinelVersionKey key(SubjectId subject) {
    return new JSentinelVersionKey(TenantId.DEFAULT, subject);
  }

  // ── Key invariants ──────────────────────────────────────────────

  @Test
  @DisplayName("JSentinelVersionKey rejects null subjectId")
  void rejectsNullSubjectId() {
    assertThrows(NullPointerException.class,
        () -> new JSentinelVersionKey(TenantId.DEFAULT, null));
  }

  @Test
  @DisplayName("JSentinelVersionKey null tenant becomes DEFAULT")
  void nullTenantBecomesDefault() {
    JSentinelVersionKey k = new JSentinelVersionKey(null, ALICE);
    assertEquals(TenantId.DEFAULT, k.tenant());
  }

  // ── current ─────────────────────────────────────────────────────

  @Test
  @DisplayName("current on an unknown key returns INITIAL")
  void unknownKeyReturnsInitial() {
    assertEquals(JSentinelVersion.INITIAL, store.current(key(ALICE)));
  }

  // ── increment ───────────────────────────────────────────────────

  @Test
  @DisplayName("first increment transitions INITIAL → 1")
  void firstIncrementFromInitial() {
    JSentinelVersion v1 = store.increment(key(ALICE));
    assertEquals(new JSentinelVersion(1), v1);
    assertEquals(v1, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("further increments produce monotonic values")
  void incrementsAreMonotonic() {
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    JSentinelVersion v3 = store.increment(key(ALICE));
    assertEquals(new JSentinelVersion(3), v3);
    assertEquals(v3, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("increment returns the post-increment value, not the pre-increment one")
  void incrementReturnsPostValue() {
    JSentinelVersion first = store.increment(key(ALICE));
    JSentinelVersion second = store.increment(key(ALICE));
    assertEquals(new JSentinelVersion(1), first);
    assertEquals(new JSentinelVersion(2), second);
  }

  // ── reset ───────────────────────────────────────────────────────

  @Test
  @DisplayName("reset drops the counter so current returns INITIAL again")
  void resetReturnsToInitial() {
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.reset(key(ALICE));
    assertEquals(JSentinelVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("reset on an unknown key is a no-op")
  void resetUnknownIsNoOp() {
    store.reset(key(ALICE));
    assertEquals(JSentinelVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("reset followed by increment restarts at 1")
  void resetThenIncrement() {
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.reset(key(ALICE));
    assertEquals(new JSentinelVersion(1), store.increment(key(ALICE)));
  }

  // ── keying ──────────────────────────────────────────────────────

  @Test
  @DisplayName("versions are independent across subjects")
  void subjectsIndependent() {
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.increment(key(BOB));
    assertEquals(new JSentinelVersion(2), store.current(key(ALICE)));
    assertEquals(new JSentinelVersion(1), store.current(key(BOB)));
  }

  @Test
  @DisplayName("tenant is part of the key — same subject has independent versions per tenant")
  void tenantParticipatesInKey() {
    JSentinelVersionKey defaultScope = new JSentinelVersionKey(TenantId.DEFAULT, ALICE);
    JSentinelVersionKey acmeScope = new JSentinelVersionKey(ACME, ALICE);
    store.increment(defaultScope);
    store.increment(defaultScope);
    store.increment(acmeScope);
    assertEquals(new JSentinelVersion(2), store.current(defaultScope));
    assertEquals(new JSentinelVersion(1), store.current(acmeScope));
  }

  // ── null arguments ──────────────────────────────────────────────

  @Test
  @DisplayName("all methods reject null key")
  void rejectNulls() {
    assertThrows(NullPointerException.class, () -> store.current(null));
    assertThrows(NullPointerException.class, () -> store.increment(null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
  }
}
