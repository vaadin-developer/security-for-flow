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
package com.svenruppert.jsentinel.replay.impl;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.replay.api.NonceStore;

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
@ExperimentalJSentinelApi
public final class InMemoryNonceStore implements NonceStore {

  private record Bound(String nonce, Instant expiresAt) {
  }

  private final Supplier<Instant> clock;
  private final Map<String, Bound> bindings = new ConcurrentHashMap<>();

  public InMemoryNonceStore() {
    this(Instant::now);
  }

  public InMemoryNonceStore(Supplier<Instant> clock) {
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public void bind(String requestKey, String nonce, Duration ttl) {
    Objects.requireNonNull(requestKey, "requestKey");
    Objects.requireNonNull(nonce, "nonce");
    Objects.requireNonNull(ttl, "ttl");
    bindings.put(requestKey, new Bound(nonce, clock.get().plus(ttl)));
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
