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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("StoreBackedLoginAttemptPolicy")
class StoreBackedLoginAttemptPolicyTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final LoginAttemptConfiguration CONFIG =
      new LoginAttemptConfiguration(3, Duration.ofMinutes(15),
          Duration.ofMinutes(15), Duration.ofHours(4));

  private static Clock fixed(Instant at) {
    return Clock.fixed(at, ZoneOffset.UTC);
  }

  private static LoginAttemptContext ctx(String user, String ip, Instant at) {
    return new LoginAttemptContext(user, ip, "sid-" + user, at);
  }

  @Test
  @DisplayName("beforeAttempt allows when failure counter is below threshold")
  void allowedBelowThreshold() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy =
        new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT, fixed(T0));

    policy.recordFailure(ctx("alice", "1.1.1.1", T0));
    policy.recordFailure(ctx("alice", "1.1.1.1", T0));

    assertEquals(LoginAttemptDecision.allowed(),
        policy.beforeAttempt(ctx("alice", "1.1.1.1", T0)));
  }

  @Test
  @DisplayName("beforeAttempt locks out at threshold; reports remaining time")
  void lockedAtThreshold() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    Clock clock = fixed(T0);
    StoreBackedLoginAttemptPolicy policy =
        new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT, clock);

    policy.recordFailure(ctx("alice", "1.1.1.1", T0));
    policy.recordFailure(ctx("alice", "1.1.1.1", T0));
    policy.recordFailure(ctx("alice", "1.1.1.1", T0));

    LoginAttemptDecision decision = policy.beforeAttempt(ctx("alice", "1.1.1.1", T0));
    LoginAttemptDecision.LockedOut locked =
        assertInstanceOf(LoginAttemptDecision.LockedOut.class, decision);
    assertEquals(Duration.ofMinutes(15), locked.remaining());
    assertEquals(3, locked.failedAttempts());
  }

  @Test
  @DisplayName("lockout expires after the configured initial-lockout window")
  void lockoutExpires() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    Clock clock = fixed(T0);
    StoreBackedLoginAttemptPolicy policy =
        new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT, clock);

    policy.recordFailure(ctx("alice", "1.1.1.1", T0));
    policy.recordFailure(ctx("alice", "1.1.1.1", T0));
    policy.recordFailure(ctx("alice", "1.1.1.1", T0));

    // Move clock forward past lockout window.
    StoreBackedLoginAttemptPolicy expiredPolicy = new StoreBackedLoginAttemptPolicy(
        store, CONFIG, TenantId.DEFAULT, fixed(T0.plus(Duration.ofMinutes(16))));
    assertEquals(LoginAttemptDecision.allowed(),
        expiredPolicy.beforeAttempt(ctx("alice", "1.1.1.1", T0)));
  }

  @Test
  @DisplayName("recordSuccess clears the counter")
  void successClearsCounter() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy =
        new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT, fixed(T0));

    policy.recordFailure(ctx("alice", "1.1.1.1", T0));
    policy.recordFailure(ctx("alice", "1.1.1.1", T0));
    policy.recordSuccess(ctx("alice", "1.1.1.1", T0));

    assertEquals(0, store.failureCount(new LoginAttemptKey(
        TenantId.DEFAULT, "alice", "1.1.1.1")));
  }

  @Test
  @DisplayName("username + clientAddress are normalised (lowercase / trim)")
  void keyNormalisation() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    StoreBackedLoginAttemptPolicy policy =
        new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT, fixed(T0));

    policy.recordFailure(ctx("Alice", "  1.1.1.1  ", T0));
    policy.recordFailure(ctx("ALICE", "1.1.1.1", T0));

    assertEquals(2, store.failureCount(new LoginAttemptKey(
        TenantId.DEFAULT, "alice", "1.1.1.1")));
  }

  @Test
  @DisplayName("tenant is part of the key — different tenants accumulate independently")
  void tenantParticipates() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    Clock clock = fixed(T0);
    TenantId acme = new TenantId("acme");
    StoreBackedLoginAttemptPolicy defaultPolicy =
        new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT, clock);
    StoreBackedLoginAttemptPolicy acmePolicy =
        new StoreBackedLoginAttemptPolicy(store, CONFIG, acme, clock);

    defaultPolicy.recordFailure(ctx("alice", "1.1.1.1", T0));
    defaultPolicy.recordFailure(ctx("alice", "1.1.1.1", T0));
    defaultPolicy.recordFailure(ctx("alice", "1.1.1.1", T0));

    // ACME tenant alice is still allowed
    assertEquals(LoginAttemptDecision.allowed(),
        acmePolicy.beforeAttempt(ctx("alice", "1.1.1.1", T0)));
  }

  @Test
  @DisplayName("constructors reject nulls")
  void rejectNulls() {
    InMemoryLoginAttemptStore store = new InMemoryLoginAttemptStore();
    assertThrows(NullPointerException.class,
        () -> new StoreBackedLoginAttemptPolicy(null));
    assertThrows(NullPointerException.class,
        () -> new StoreBackedLoginAttemptPolicy(store, null, TenantId.DEFAULT, fixed(T0)));
    assertThrows(NullPointerException.class,
        () -> new StoreBackedLoginAttemptPolicy(store, CONFIG, TenantId.DEFAULT, null));

    StoreBackedLoginAttemptPolicy policy = new StoreBackedLoginAttemptPolicy(store);
    assertThrows(NullPointerException.class, () -> policy.beforeAttempt(null));
    assertThrows(NullPointerException.class, () -> policy.recordSuccess(null));
    assertThrows(NullPointerException.class, () -> policy.recordFailure(null));
  }
}
