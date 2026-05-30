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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("InMemorySecurityVersionStore + SecurityVersionKey")
class InMemorySecurityVersionStoreTest {

  private static final SubjectId ALICE = new SubjectId("alice");
  private static final SubjectId BOB = new SubjectId("bob");
  private static final TenantId ACME = new TenantId("acme");

  private final InMemorySecurityVersionStore store = new InMemorySecurityVersionStore();

  private static SecurityVersionKey key(SubjectId subject) {
    return new SecurityVersionKey(TenantId.DEFAULT, subject);
  }

  // ── Key invariants ──────────────────────────────────────────────

  @Test
  @DisplayName("SecurityVersionKey rejects null subjectId")
  void rejectsNullSubjectId() {
    assertThrows(NullPointerException.class,
        () -> new SecurityVersionKey(TenantId.DEFAULT, null));
  }

  @Test
  @DisplayName("SecurityVersionKey null tenant becomes DEFAULT")
  void nullTenantBecomesDefault() {
    SecurityVersionKey k = new SecurityVersionKey(null, ALICE);
    assertEquals(TenantId.DEFAULT, k.tenant());
  }

  // ── current ─────────────────────────────────────────────────────

  @Test
  @DisplayName("current on an unknown key returns INITIAL")
  void unknownKeyReturnsInitial() {
    assertEquals(SecurityVersion.INITIAL, store.current(key(ALICE)));
  }

  // ── increment ───────────────────────────────────────────────────

  @Test
  @DisplayName("first increment transitions INITIAL → 1")
  void firstIncrementFromInitial() {
    SecurityVersion v1 = store.increment(key(ALICE));
    assertEquals(new SecurityVersion(1), v1);
    assertEquals(v1, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("further increments produce monotonic values")
  void incrementsAreMonotonic() {
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    SecurityVersion v3 = store.increment(key(ALICE));
    assertEquals(new SecurityVersion(3), v3);
    assertEquals(v3, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("increment returns the post-increment value, not the pre-increment one")
  void incrementReturnsPostValue() {
    SecurityVersion first = store.increment(key(ALICE));
    SecurityVersion second = store.increment(key(ALICE));
    assertEquals(new SecurityVersion(1), first);
    assertEquals(new SecurityVersion(2), second);
  }

  // ── reset ───────────────────────────────────────────────────────

  @Test
  @DisplayName("reset drops the counter so current returns INITIAL again")
  void resetReturnsToInitial() {
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.reset(key(ALICE));
    assertEquals(SecurityVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("reset on an unknown key is a no-op")
  void resetUnknownIsNoOp() {
    store.reset(key(ALICE));
    assertEquals(SecurityVersion.INITIAL, store.current(key(ALICE)));
  }

  @Test
  @DisplayName("reset followed by increment restarts at 1")
  void resetThenIncrement() {
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.reset(key(ALICE));
    assertEquals(new SecurityVersion(1), store.increment(key(ALICE)));
  }

  // ── keying ──────────────────────────────────────────────────────

  @Test
  @DisplayName("versions are independent across subjects")
  void subjectsIndependent() {
    store.increment(key(ALICE));
    store.increment(key(ALICE));
    store.increment(key(BOB));
    assertEquals(new SecurityVersion(2), store.current(key(ALICE)));
    assertEquals(new SecurityVersion(1), store.current(key(BOB)));
  }

  @Test
  @DisplayName("tenant is part of the key — same subject has independent versions per tenant")
  void tenantParticipatesInKey() {
    SecurityVersionKey defaultScope = new SecurityVersionKey(TenantId.DEFAULT, ALICE);
    SecurityVersionKey acmeScope = new SecurityVersionKey(ACME, ALICE);
    store.increment(defaultScope);
    store.increment(defaultScope);
    store.increment(acmeScope);
    assertEquals(new SecurityVersion(2), store.current(defaultScope));
    assertEquals(new SecurityVersion(1), store.current(acmeScope));
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
