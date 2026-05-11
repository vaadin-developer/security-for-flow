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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.authorization.api.SubjectId;
import com.svenruppert.vaadin.security.authorization.api.SubjectSessionRegistry;
import com.svenruppert.vaadin.security.demo.rest.domain.DemoUser;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory demo token store. Demo-only — not a production token mechanism.
 * <p>
 * Production systems must use cryptographically signed tokens with expiry,
 * refresh, and revocation policies.
 *
 * <h2>Per-token lifetime metadata</h2>
 *
 * <p>Each issued token also carries a {@link Metadata} record:
 * <ul>
 *   <li>{@code createdAt} — set once on {@link #issue(DemoUser)}.</li>
 *   <li>{@code lastActivityAt} — bumped on {@link #markActivity(String)}
 *       to drive {@code SessionPolicy.evaluate(SessionMetadata)} idle
 *       timeouts.</li>
 * </ul>
 *
 * <p>The store doesn't enforce expiry by itself — the framework's
 * {@code SessionPolicy} does. The store only serves the timestamps.
 */
public final class DemoTokenStore implements SubjectSessionRegistry {

  /** Per-token user + lifetime metadata. */
  public record Metadata(DemoUser user, Instant createdAt, Instant lastActivityAt) {
  }

  private final ConcurrentMap<String, Metadata> tokens = new ConcurrentHashMap<>();
  private final ConcurrentMap<SubjectId, Set<String>> sessionsByUser = new ConcurrentHashMap<>();
  private final SecureRandom random = new SecureRandom();
  private final Clock clock;

  /** Default — uses {@link Clock#systemUTC()}. */
  public DemoTokenStore() {
    this(Clock.systemUTC());
  }

  /** Test seam: inject a fixed clock. */
  public DemoTokenStore(Clock clock) {
    this.clock = clock;
  }

  public String issue(DemoUser user) {
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    String token = HexFormat.of().formatHex(bytes);
    Instant now = Instant.now(clock);
    tokens.put(token, new Metadata(user, now, now));
    sessionsByUser
        .computeIfAbsent(SubjectId.of(user.username()), k -> ConcurrentHashMap.newKeySet())
        .add(token);
    return token;
  }

  public Optional<DemoUser> resolve(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    Metadata metadata = tokens.get(token);
    return metadata == null ? Optional.empty() : Optional.of(metadata.user());
  }

  /**
   * Returns the token's {@link Metadata}, or empty if the token is unknown.
   * Used by the REST adapter to build {@code SessionMetadata} for
   * {@code SessionPolicy.evaluate(...)}.
   */
  public Optional<Metadata> resolveMetadata(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    return Optional.ofNullable(tokens.get(token));
  }

  /**
   * Bumps the {@code lastActivityAt} of a known token to "now" on the
   * configured clock. No-op for unknown tokens. Returns the previous
   * timestamp (or {@link Optional#empty()} if the token wasn't there
   * before) so callers can build {@code SessionMetadata} that reflects
   * the activity *before* this request — the policy's idle check
   * compares the previous activity against the current time.
   */
  public Optional<Instant> markActivity(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    Instant now = Instant.now(clock);
    final Instant[] previous = new Instant[1];
    Metadata updated = tokens.computeIfPresent(token, (k, current) -> {
      previous[0] = current.lastActivityAt();
      return new Metadata(current.user(), current.createdAt(), now);
    });
    return updated == null ? Optional.empty() : Optional.ofNullable(previous[0]);
  }

  public void revoke(String token) {
    if (token == null) {
      return;
    }
    Metadata removed = tokens.remove(token);
    if (removed != null) {
      Set<String> entries = sessionsByUser.get(SubjectId.of(removed.user().username()));
      if (entries != null) {
        entries.remove(token);
      }
    }
  }

  // ── SubjectSessionRegistry ────────────────────────────────────

  @Override
  public void register(SubjectId subjectId, String sessionId) {
    sessionsByUser
        .computeIfAbsent(subjectId, k -> ConcurrentHashMap.newKeySet())
        .add(sessionId);
  }

  @Override
  public void unregister(SubjectId subjectId, String sessionId) {
    Set<String> entries = sessionsByUser.get(subjectId);
    if (entries != null) {
      entries.remove(sessionId);
    }
  }

  @Override
  public Collection<String> sessionsOf(SubjectId subjectId) {
    Set<String> entries = sessionsByUser.get(subjectId);
    return entries == null ? List.of() : List.copyOf(entries);
  }

  @Override
  public Collection<String> clearAll(SubjectId subjectId) {
    Set<String> entries = sessionsByUser.remove(subjectId);
    return entries == null ? List.of() : List.copyOf(entries);
  }
}
