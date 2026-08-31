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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.authentication.RememberMeTokenRecord;
import eu.jsentinel.jcustos.authentication.RememberMeTokenStore;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link RememberMeTokenStore} implementation must
 * satisfy.
 */
@DisplayName("RememberMeTokenStore — contract")
public interface RememberMeTokenStoreContract {

  /**
   * @return a fresh, empty {@code RememberMeTokenStore}
   */
  RememberMeTokenStore newStore();

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  Instant EXPIRY = T0.plusSeconds(3600);
  SubjectId ALICE = new SubjectId("alice");
  SubjectId BOB = new SubjectId("bob");

  /**
   * Builds a sample token record.
   *
   * @param hash    token hash
   * @param tenant  tenant scope
   * @param subject subject
   * @return new record
   */
  default RememberMeTokenRecord token(String hash, TenantId tenant, SubjectId subject) {
    return new RememberMeTokenRecord(hash, tenant, subject, T0, EXPIRY);
  }

  @Test
  @DisplayName("save persists; findByHash retrieves; deleteByHash drops")
  default void crudByHash() {
    RememberMeTokenStore store = newStore();
    RememberMeTokenRecord r = token("h1", TenantId.DEFAULT, ALICE);
    store.save(r);
    assertEquals(Optional.of(r), store.findByHash("h1"));
    assertTrue(store.deleteByHash("h1"));
    assertTrue(store.findByHash("h1").isEmpty());
  }

  @Test
  @DisplayName("save upserts on the hash key")
  default void saveUpserts() {
    RememberMeTokenStore store = newStore();
    RememberMeTokenRecord first = token("h1", TenantId.DEFAULT, ALICE);
    store.save(first);
    RememberMeTokenRecord later = new RememberMeTokenRecord(
        "h1", TenantId.DEFAULT, ALICE, T0, EXPIRY.plusSeconds(60));
    store.save(later);
    assertEquals(Optional.of(later), store.findByHash("h1"));
  }

  @Test
  @DisplayName("findByHash / deleteByHash reject blank")
  default void blankHashRejected() {
    RememberMeTokenStore store = newStore();
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(null));
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(IllegalArgumentException.class, () -> store.deleteByHash(""));
  }

  @Test
  @DisplayName("save rejects null; deleteByHash returns false for unknown")
  default void saveDeleteRejections() {
    RememberMeTokenStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertFalse(store.deleteByHash("ghost"));
  }

  @Test
  @DisplayName("deleteBySubject removes every (tenant, subject) token")
  default void deleteBySubjectDrops() {
    RememberMeTokenStore store = newStore();
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    store.save(token("h2", TenantId.DEFAULT, ALICE));
    store.save(token("h3", TenantId.DEFAULT, BOB));

    assertEquals(2, store.deleteBySubject(TenantId.DEFAULT, ALICE));
    assertTrue(store.findByHash("h1").isEmpty());
    assertTrue(store.findByHash("h3").isPresent());
  }

  @Test
  @DisplayName("deleteBySubject is tenant-scoped")
  default void deleteBySubjectTenantScoped() {
    RememberMeTokenStore store = newStore();
    TenantId acme = new TenantId("acme");
    store.save(token("h1", TenantId.DEFAULT, ALICE));
    store.save(token("h2", acme, ALICE));

    assertEquals(1, store.deleteBySubject(acme, ALICE));
    assertTrue(store.findByHash("h1").isPresent());
  }

  @Test
  @DisplayName("deleteBySubject rejects nulls / on unknown returns 0")
  default void deleteBySubjectRejections() {
    RememberMeTokenStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.deleteBySubject(null, ALICE));
    assertThrows(NullPointerException.class,
        () -> store.deleteBySubject(TenantId.DEFAULT, null));
    assertEquals(0, store.deleteBySubject(TenantId.DEFAULT, new SubjectId("ghost")));
  }

  @Test
  @DisplayName("purgeExpired drops every token whose expiresAt is at or before now")
  default void purgeExpiredAtOrBefore() {
    RememberMeTokenStore store = newStore();
    Instant early = T0.plusSeconds(60);
    Instant late = T0.plusSeconds(3600);
    store.save(new RememberMeTokenRecord("early", TenantId.DEFAULT, ALICE, T0, early));
    store.save(new RememberMeTokenRecord("late", TenantId.DEFAULT, ALICE, T0, late));

    assertEquals(1, store.purgeExpired(early));
    assertTrue(store.findByHash("early").isEmpty());
    assertTrue(store.findByHash("late").isPresent());
  }

  @Test
  @DisplayName("purgeExpired rejects null / on empty returns 0")
  default void purgeExpiredRejections() {
    RememberMeTokenStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.purgeExpired(null));
    assertEquals(0, store.purgeExpired(EXPIRY));
  }
}
