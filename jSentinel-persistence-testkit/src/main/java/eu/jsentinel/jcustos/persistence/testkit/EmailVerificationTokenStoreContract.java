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

import eu.jsentinel.jcustos.accountlifecycle.EmailVerificationTokenRecord;
import eu.jsentinel.jcustos.accountlifecycle.EmailVerificationTokenStore;
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
 * Contract every {@link EmailVerificationTokenStore} implementation
 * must satisfy.
 */
@DisplayName("EmailVerificationTokenStore — contract")
public interface EmailVerificationTokenStoreContract {

  /**
   * @return a fresh, empty {@code EmailVerificationTokenStore}
   */
  EmailVerificationTokenStore newStore();

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  Instant EXPIRY = T0.plusSeconds(900);
  SubjectId ALICE = new SubjectId("alice");

  /**
   * Builds a sample pending token record.
   *
   * @param hash  token hash
   * @param email email being verified
   * @return new record
   */
  default EmailVerificationTokenRecord token(String hash, String email) {
    return new EmailVerificationTokenRecord(
        hash, TenantId.DEFAULT, ALICE, email, T0, EXPIRY, Optional.empty());
  }

  @Test
  @DisplayName("save + findByHash round-trip preserves email; markConsumed flips isConsumed")
  default void lifecycle() {
    EmailVerificationTokenStore store = newStore();
    store.save(token("h1", "alice@example.org"));
    assertTrue(store.markConsumed("h1", T0.plusSeconds(30)));
    EmailVerificationTokenRecord found = store.findByHash("h1").orElseThrow();
    assertTrue(found.isConsumed());
    assertEquals("alice@example.org", found.email());
  }

  @Test
  @DisplayName("markConsumed twice on the same hash returns false the second time")
  default void markConsumedIdempotent() {
    EmailVerificationTokenStore store = newStore();
    store.save(token("h1", "alice@example.org"));
    store.markConsumed("h1", T0.plusSeconds(30));
    assertFalse(store.markConsumed("h1", T0.plusSeconds(60)));
  }

  @Test
  @DisplayName("markConsumed on unknown hash returns false")
  default void markConsumedUnknown() {
    EmailVerificationTokenStore store = newStore();
    assertFalse(store.markConsumed("ghost", T0.plusSeconds(30)));
  }

  @Test
  @DisplayName("deleteBySubject drops pending and consumed records")
  default void deleteBySubject() {
    EmailVerificationTokenStore store = newStore();
    store.save(token("h1", "alice@example.org"));
    store.save(token("h2", "alice.alt@example.org"));
    store.markConsumed("h2", T0.plusSeconds(30));
    store.save(new EmailVerificationTokenRecord(
        "h3", TenantId.DEFAULT, new SubjectId("bob"), "bob@example.org",
        T0, EXPIRY, Optional.empty()));

    assertEquals(2, store.deleteBySubject(TenantId.DEFAULT, ALICE));
    assertTrue(store.findByHash("h3").isPresent());
  }

  @Test
  @DisplayName("purgeExpired drops every record at or before now")
  default void purgeExpired() {
    EmailVerificationTokenStore store = newStore();
    store.save(new EmailVerificationTokenRecord(
        "early", TenantId.DEFAULT, ALICE, "a@b", T0, T0.plusSeconds(60), Optional.empty()));
    store.save(new EmailVerificationTokenRecord(
        "late", TenantId.DEFAULT, ALICE, "a@b", T0, T0.plusSeconds(3600), Optional.empty()));

    assertEquals(1, store.purgeExpired(T0.plusSeconds(60)));
    assertTrue(store.findByHash("late").isPresent());
  }

  @Test
  @DisplayName("invalid arguments are rejected uniformly")
  default void invalidArgumentsRejected() {
    EmailVerificationTokenStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(IllegalArgumentException.class, () -> store.findByHash(""));
    assertThrows(IllegalArgumentException.class,
        () -> store.markConsumed("", T0.plusSeconds(30)));
    assertThrows(NullPointerException.class,
        () -> store.markConsumed("h1", null));
  }
}
