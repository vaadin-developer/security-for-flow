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
package com.svenruppert.jsentinel.bruteforce;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.util.CapacityBound;

import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link LoginAttemptStore} backed by a single
 * {@link ConcurrentHashMap}. Suitable for tests, demos, and
 * single-process applications.
 * <p>
 * Counters and last-failure instants are kept in a private
 * package-local {@code Ledger} record, mutated atomically through
 * {@code compute}/{@code merge}-style map operations.
 */
@ExperimentalJSentinelApi
public final class InMemoryLoginAttemptStore implements LoginAttemptStore {

  private final ConcurrentHashMap<LoginAttemptKey, Ledger> ledgers = new ConcurrentHashMap<>();
  private final int maxEntries;

  /** Creates an empty store bounded at {@link CapacityBound#DEFAULT_MAX_ENTRIES}. */
  public InMemoryLoginAttemptStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * JS-SEC-048 (CWE-770): {@code ledgers} is keyed on an attacker-controlled login key, so a spray
   * of distinct keys (each removed only by a valid {@code reset}) would grow the heap without limit.
   * When at capacity a new key evicts the entry with the oldest {@code lastFailureAt} (the least
   * recently active), mirroring the {@code InMemoryJtiStore} soonest-first eviction.
   *
   * @param maxEntries key cap (shared default {@link CapacityBound#DEFAULT_MAX_ENTRIES})
   */
  public InMemoryLoginAttemptStore(int maxEntries) {
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
  }

  /** Package-visible for tests: number of tracked ledger keys (JS-SEC-048 bound). */
  int trackedKeyCount() {
    return ledgers.size();
  }

  @Override
  public void recordFailure(LoginAttemptKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    enforceBound(key);
    ledgers.compute(key, (k, prev) -> prev == null
        ? new Ledger(1, at)
        : new Ledger(prev.count + 1, at));
  }

  private void enforceBound(LoginAttemptKey incomingKey) {
    if (ledgers.size() < maxEntries || ledgers.containsKey(incomingKey)) {
      return;
    }
    ledgers.entrySet().stream()
        .min(Map.Entry.comparingByValue(Comparator.comparing(Ledger::lastFailureAt)))
        .map(Map.Entry::getKey)
        .ifPresent(ledgers::remove);
  }

  @Override
  public int failureCount(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    Ledger ledger = ledgers.get(key);
    return ledger == null ? 0 : ledger.count;
  }

  @Override
  public Optional<Instant> lastFailureAt(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    Ledger ledger = ledgers.get(key);
    return ledger == null ? Optional.empty() : Optional.of(ledger.lastFailureAt);
  }

  @Override
  public void reset(LoginAttemptKey key) {
    requireNonNull(key, "key must not be null");
    ledgers.remove(key);
  }

  private record Ledger(int count, Instant lastFailureAt) {
  }
}
