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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * {@link LoginAttemptPolicy} that stores its failure counters in a
 * {@link LoginAttemptStore}.
 * <p>
 * Counter and last-failure timestamp survive a process restart — a
 * lockout earned on Monday is still in effect on Tuesday. Unlike the
 * {@link InMemoryLoginAttemptPolicy} default, this implementation
 * runs a <em>flat</em> lockout: once
 * {@link LoginAttemptConfiguration#failureThreshold()} failures
 * accumulate within the configured
 * {@link LoginAttemptConfiguration#window()}, the key locks for
 * {@link LoginAttemptConfiguration#initialLockout()} starting at the
 * last failure. The progressive backoff that the in-memory policy
 * offers requires per-key history (lockout level, "just locked"
 * flag) that the narrower {@link LoginAttemptStore} contract does
 * not carry — applications that need progressive backoff stay on
 * the in-memory policy or wrap this one with a richer key store.
 *
 * <p><strong>Scope (JS-SEC-012):</strong> the lockout key is the
 * {@code (tenant, username, ip)} tuple, so this policy only locks a
 * <em>single</em> username from a <em>single</em> source address. It does
 * <strong>not</strong> stop password spraying (many usernames, one host) or
 * distributed credential stuffing (one account, many IPs) — those keep every
 * per-tuple counter under the threshold. Anti-automation across those
 * dimensions is the job of the {@code AbuseDetectionService} (CLIENT_ADDRESS /
 * TENANT / GLOBAL volume, per the ASVS L2 map); wire it alongside this policy
 * rather than relying on the lockout alone.
 *
 * <p>Bound to one {@link TenantId} at construction. Multi-tenant
 * deployments instantiate one policy per tenant or wrap with a
 * resolver.
 */
@ExperimentalJCustosApi
public final class StoreBackedLoginAttemptPolicy implements LoginAttemptPolicy {

  private final LoginAttemptStore store;
  private final LoginAttemptConfiguration config;
  private final TenantId tenant;
  private final Clock clock;

  /**
   * Builds a policy with {@link LoginAttemptConfiguration#defaults()}
   * and {@link TenantId#DEFAULT}.
   *
   * @param store backing store; non-null
   */
  public StoreBackedLoginAttemptPolicy(LoginAttemptStore store) {
    this(store, LoginAttemptConfiguration.defaults(), TenantId.DEFAULT, Clock.systemUTC());
  }

  /**
   * Full constructor.
   *
   * @param store  backing store; non-null
   * @param config thresholds; non-null
   * @param tenant tenant scope; {@code null} becomes
   *               {@link TenantId#DEFAULT}
   * @param clock  time source; non-null. Pass a fixed clock to make
   *               tests deterministic.
   */
  public StoreBackedLoginAttemptPolicy(LoginAttemptStore store,
                                       LoginAttemptConfiguration config,
                                       TenantId tenant,
                                       Clock clock) {
    this.store = requireNonNull(store, "store must not be null");
    this.config = requireNonNull(config, "config must not be null");
    this.tenant = tenant == null ? TenantId.DEFAULT : tenant;
    this.clock = requireNonNull(clock, "clock must not be null");
  }

  @Override
  public LoginAttemptDecision beforeAttempt(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    LoginAttemptKey key = key(context);
    int failures = store.failureCount(key);
    if (failures < config.failureThreshold()) {
      return LoginAttemptDecision.allowed();
    }
    Optional<Instant> last = store.lastFailureAt(key);
    if (last.isEmpty()) {
      return LoginAttemptDecision.allowed();
    }
    Instant now = clock.instant();
    Instant unlocksAt = last.get().plus(config.initialLockout());
    if (!now.isBefore(unlocksAt)) {
      return LoginAttemptDecision.allowed();
    }
    Duration remaining = Duration.between(now, unlocksAt);
    return LoginAttemptDecision.lockedOut(remaining, failures);
  }

  @Override
  public void recordSuccess(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    store.reset(key(context));
  }

  @Override
  public void recordFailure(LoginAttemptContext context) {
    requireNonNull(context, "context must not be null");
    store.recordFailure(key(context), clock.instant());
  }

  private LoginAttemptKey key(LoginAttemptContext context) {
    return new LoginAttemptKey(tenant, normalise(context.username()),
        normalise(context.clientAddress()));
  }

  private static String normalise(String value) {
    return value == null || value.isBlank() ? "-" : value.trim().toLowerCase(Locale.ROOT);
  }
}
