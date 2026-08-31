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
package eu.jsentinel.jcustos.replay.impl;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.replay.api.NonceStore;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * In-memory {@link NonceStore} (V00.79): per-request-key nonce binding with TTL and
 * single-use consume. For a single JVM only. Thread-safe.
 */
@ExperimentalJCustosApi
public final class InMemoryNonceStore implements NonceStore {

  private record Bound(String nonce, Instant expiresAt) {
  }

  private final Supplier<Instant> clock;
  private final int maxEntries;
  private final Map<String, Bound> bindings = new ConcurrentHashMap<>();

  public InMemoryNonceStore() {
    this(Instant::now);
  }

  public InMemoryNonceStore(Supplier<Instant> clock) {
    this(clock, CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * JS-SEC-051 (CWE-770): additionally bound the bindings map. {@code requestKey} is
   * attacker-controlled and an initiated-but-never-consumed binding persists for the process
   * lifetime, so an attacker repeatedly initiating flows without completing the callback would leak
   * one entry per un-completed flow without limit. On a full map {@link #bind} first purges expired
   * bindings and, if still full, throws — matching the {@code JdkInMemoryStateStore} sibling.
   *
   * @param maxEntries binding cap (shared default {@link CapacityBound#DEFAULT_MAX_ENTRIES})
   */
  public InMemoryNonceStore(Supplier<Instant> clock, int maxEntries) {
    this.clock = Objects.requireNonNull(clock, "clock");
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
  }

  /** Package-visible for tests: number of tracked bindings (JS-SEC-051 bound). */
  int trackedKeyCount() {
    return bindings.size();
  }

  @Override
  public void bind(String requestKey, String nonce, Duration ttl) {
    Objects.requireNonNull(requestKey, "requestKey");
    Objects.requireNonNull(nonce, "nonce");
    Objects.requireNonNull(ttl, "ttl");
    if (bindings.size() >= maxEntries && !bindings.containsKey(requestKey)) {
      purgeExpired();
      if (bindings.size() >= maxEntries) {
        throw new IllegalStateException(
            CapacityBound.capacityExceededCode("replay/nonce-store") + ": " + maxEntries);
      }
    }
    bindings.put(requestKey, new Bound(nonce, clock.get().plus(ttl)));
  }

  private void purgeExpired() {
    Instant now = clock.get();
    bindings.values().removeIf(b -> now.isAfter(b.expiresAt()));
  }

  @Override
  public Optional<String> consume(String requestKey) {
    Objects.requireNonNull(requestKey, "requestKey");
    Bound bound = bindings.remove(requestKey);
    if (bound == null || clock.get().isAfter(bound.expiresAt())) {
      return Optional.empty();
    }
    return Optional.of(bound.nonce());
  }
}
