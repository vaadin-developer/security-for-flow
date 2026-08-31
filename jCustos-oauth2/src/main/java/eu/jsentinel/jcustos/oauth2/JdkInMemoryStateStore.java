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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.oauth2.api.StateEntry;
import eu.jsentinel.jcustos.oauth2.api.StateStore;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

/**
 * In-process {@link StateStore} (V00.77) for stateless REST / Standalone RPs:
 * a {@link ConcurrentHashMap} keyed by the {@code state} value, with per-entry
 * TTL and <strong>single-use</strong> {@link #consume(String)} (the entry is
 * atomically removed, so a replayed callback cannot succeed twice). Expired
 * entries are evicted lazily on access; a hard cap bounds memory.
 *
 * @since 00.77.00
 */
@ExperimentalJCustosApi
public final class JdkInMemoryStateStore implements StateStore {

  /** Default upper bound on retained (unconsumed) entries. */
  public static final int DEFAULT_CAPACITY = 100_000;

  private record Bound(StateEntry entry, Instant expiresAt) {
  }

  private final ConcurrentMap<String, Bound> entries = new ConcurrentHashMap<>();
  private final int capacity;
  private final Supplier<Instant> clock;

  public JdkInMemoryStateStore() {
    this(DEFAULT_CAPACITY, Instant::now);
  }

  public JdkInMemoryStateStore(int capacity, Supplier<Instant> clock) {
    if (capacity < 1) {
      throw new IllegalArgumentException("capacity must be >= 1, was " + capacity);
    }
    this.capacity = capacity;
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public void bind(String stateKey, StateEntry entry, Duration ttl) {
    Objects.requireNonNull(stateKey, "stateKey");
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(ttl, "ttl");
    if (entries.size() >= capacity) {
      purgeExpired();
    }
    if (entries.size() >= capacity) {
      throw new IllegalStateException("oauth2/state-store-capacity-exceeded: " + capacity);
    }
    entries.put(stateKey, new Bound(entry, clock.get().plus(ttl)));
  }

  @Override
  public Optional<StateEntry> consume(String stateKey) {
    Bound bound = entries.remove(Objects.requireNonNull(stateKey, "stateKey"));
    if (bound == null) {
      return Optional.empty();
    }
    if (clock.get().isAfter(bound.expiresAt())) {
      return Optional.empty();
    }
    return Optional.of(bound.entry());
  }

  @Override
  public void clear() {
    entries.clear();
  }

  /** @return the number of retained entries (test/diagnostic aid). */
  public int size() {
    return entries.size();
  }

  private void purgeExpired() {
    Instant now = clock.get();
    entries.values().removeIf(b -> now.isAfter(b.expiresAt()));
  }
}
