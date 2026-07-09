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
package com.svenruppert.jsentinel.oauth2.vaadin;

import com.svenruppert.jsentinel.oauth2.api.StateEntry;
import com.svenruppert.jsentinel.oauth2.api.StateStore;
import com.vaadin.flow.server.VaadinSession;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * The Vaadin {@link StateStore} (Konzept §10.3, V00.77): the OAuth2 {@code state}
 * + PKCE verifier live in the {@link VaadinSession} for the duration between the
 * authorization redirect and the callback, surviving the browser round-trip
 * without a server-side cross-request map. All entries are kept in a single
 * session attribute (a {@link ConcurrentHashMap}), so {@link #clear()} is exact.
 * {@link #consume(String)} is single-use (removes the entry) and TTL-checked
 * against the injected clock.
 */
public final class VaadinSessionStateStore implements StateStore {

  private static final String ATTRIBUTE = VaadinSessionStateStore.class.getName() + ".entries";

  private final Supplier<Instant> clock;

  public VaadinSessionStateStore() {
    this(Instant::now);
  }

  public VaadinSessionStateStore(Supplier<Instant> clock) {
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  private record Stored(StateEntry entry, Instant expiresAt) {
  }

  @Override
  public void bind(String stateKey, StateEntry entry, Duration ttl) {
    Objects.requireNonNull(stateKey, "stateKey");
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(ttl, "ttl");
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      throw new IllegalStateException(
          "No active VaadinSession — bind must run on a Vaadin request thread");
    }
    entries(session).put(stateKey, new Stored(entry, clock.get().plus(ttl)));
  }

  @Override
  public Optional<StateEntry> consume(String stateKey) {
    Objects.requireNonNull(stateKey, "stateKey");
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) {
      return Optional.empty();
    }
    Stored stored = entries(session).remove(stateKey); // single-use
    if (stored == null || clock.get().isAfter(stored.expiresAt())) {
      return Optional.empty();
    }
    return Optional.of(stored.entry());
  }

  @Override
  public void clear() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session != null) {
      session.setAttribute(ATTRIBUTE, null);
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Stored> entries(VaadinSession session) {
    Object existing = session.getAttribute(ATTRIBUTE);
    if (existing instanceof Map<?, ?> map) {
      return (Map<String, Stored>) map;
    }
    Map<String, Stored> created = new ConcurrentHashMap<>();
    session.setAttribute(ATTRIBUTE, created);
    return created;
  }
}
