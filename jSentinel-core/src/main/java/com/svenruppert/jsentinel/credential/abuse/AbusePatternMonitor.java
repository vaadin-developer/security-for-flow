/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.jsentinel.credential.abuse;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Higher-level abuse-pattern detector that sits next to the
 * {@link AbuseDetectionService}.
 *
 * <h2>Patterns</h2>
 * <ul>
 *   <li>{@link AbusePattern#PASSWORD_SPRAYING} — same client touches
 *       many distinct usernames inside a window.</li>
 *   <li>{@link AbusePattern#CREDENTIAL_STUFFING} — single username
 *       receives failures from many distinct clients.</li>
 *   <li>{@link AbusePattern#RESET_ABUSE} — single username or client
 *       generates many reset requests.</li>
 * </ul>
 *
 * <p>Each pattern keeps a privacy-minimised sliding-window record of
 * timestamps + the distinct-target set hashed to a string key. When
 * the configured threshold trips, the monitor emits an
 * {@link AbusePatternSignal} through the provided {@code signalSink}
 * — the signal carries aggregates only, never the usernames or
 * client addresses themselves (CWE-359).</p>
 *
 * <p>This is the in-memory reference implementation. Production
 * multi-node deployments must replace the backing maps with a
 * clustered store; see Konzept §13.</p>
 */
public final class AbusePatternMonitor {

  /**
   * Tunables for the three pattern detectors.
   *
   * @param sprayingDistinctUsers   number of distinct usernames per
   *                                client per window that triggers
   *                                SPRAYING; 0 to disable
   * @param sprayingWindow          sliding-window length for SPRAYING
   * @param stuffingDistinctClients number of distinct clients per
   *                                username per window that triggers
   *                                STUFFING; 0 to disable
   * @param stuffingWindow          sliding-window length for STUFFING
   * @param resetAbuseAttempts      number of RESET_REQUEST attempts
   *                                per username per window that
   *                                triggers RESET_ABUSE; 0 to disable
   * @param resetAbuseWindow        sliding-window length for RESET_ABUSE
   */
  public record Config(
      int sprayingDistinctUsers,
      Duration sprayingWindow,
      int stuffingDistinctClients,
      Duration stuffingWindow,
      int resetAbuseAttempts,
      Duration resetAbuseWindow
  ) {
    public Config {
      Objects.requireNonNull(sprayingWindow, "sprayingWindow");
      Objects.requireNonNull(stuffingWindow, "stuffingWindow");
      Objects.requireNonNull(resetAbuseWindow, "resetAbuseWindow");
      if (sprayingDistinctUsers < 0
          || stuffingDistinctClients < 0
          || resetAbuseAttempts < 0) {
        throw new IllegalArgumentException("thresholds must be >= 0");
      }
    }

    /**
     * Sensible default: 8 distinct usernames per client in 5 min →
     * SPRAYING; 5 distinct clients per username in 15 min → STUFFING;
     * 5 reset attempts per username in 1 h → RESET_ABUSE.
     */
    public static Config defaults() {
      return new Config(
          8, Duration.ofMinutes(5),
          5, Duration.ofMinutes(15),
          5, Duration.ofHours(1));
    }
  }

  private final Config config;
  private final Consumer<AbusePatternSignal> signalSink;

  /** client -> deque of (timestamp, username) */
  private final ConcurrentHashMap<String, Deque<TimedTarget>> sprayingByClient =
      new ConcurrentHashMap<>();
  /** username -> deque of (timestamp, client) */
  private final ConcurrentHashMap<String, Deque<TimedTarget>> stuffingByUser =
      new ConcurrentHashMap<>();
  /** username -> deque of timestamps */
  private final ConcurrentHashMap<String, Deque<Instant>> resetByUser =
      new ConcurrentHashMap<>();

  public AbusePatternMonitor(
      Config config, Consumer<AbusePatternSignal> signalSink) {
    this.config = Objects.requireNonNull(config, "config");
    this.signalSink = Objects.requireNonNull(signalSink, "signalSink");
  }

  /**
   * Feed one attempt + outcome into the monitor. Detectors are
   * evaluated independently; each may emit at most one signal per
   * call.
   */
  public List<AbusePatternSignal> observe(
      AbuseAttemptContext context, AttemptOutcome outcome) {
    Objects.requireNonNull(context, "context");
    Objects.requireNonNull(outcome, "outcome");
    List<AbusePatternSignal> emitted = new ArrayList<>();

    if (context.attemptType() == AbuseAttemptType.LOGIN) {
      observeSpraying(context).ifPresent(s -> {
        emitted.add(s);
        signalSink.accept(s);
      });
      if (outcome == AttemptOutcome.FAILURE) {
        observeStuffing(context).ifPresent(s -> {
          emitted.add(s);
          signalSink.accept(s);
        });
      }
    } else if (context.attemptType() == AbuseAttemptType.RESET_REQUEST) {
      observeResetAbuse(context).ifPresent(s -> {
        emitted.add(s);
        signalSink.accept(s);
      });
    }
    return emitted;
  }

  private Optional<AbusePatternSignal> observeSpraying(AbuseAttemptContext context) {
    if (config.sprayingDistinctUsers() <= 0) {
      return Optional.empty();
    }
    if (context.clientAddress().isEmpty() || context.username().isEmpty()) {
      return Optional.empty();
    }
    String client = context.clientAddress().get();
    String username = context.username().get();
    Deque<TimedTarget> deque = sprayingByClient.computeIfAbsent(
        client, k -> new ArrayDeque<>());
    synchronized (deque) {
      pruneByTime(deque, context.at(), config.sprayingWindow());
      deque.addLast(new TimedTarget(context.at(), username));
      Set<String> distinct = new HashSet<>();
      int attempts = 0;
      for (TimedTarget t : deque) {
        distinct.add(t.target);
        attempts++;
      }
      if (distinct.size() >= config.sprayingDistinctUsers()) {
        return Optional.of(new AbusePatternSignal(
            AbusePattern.PASSWORD_SPRAYING,
            context.at(),
            config.sprayingWindow(),
            distinct.size(),
            attempts));
      }
      return Optional.empty();
    }
  }

  private Optional<AbusePatternSignal> observeStuffing(AbuseAttemptContext context) {
    if (config.stuffingDistinctClients() <= 0) {
      return Optional.empty();
    }
    if (context.username().isEmpty() || context.clientAddress().isEmpty()) {
      return Optional.empty();
    }
    String username = context.username().get();
    String client = context.clientAddress().get();
    Deque<TimedTarget> deque = stuffingByUser.computeIfAbsent(
        username, k -> new ArrayDeque<>());
    synchronized (deque) {
      pruneByTime(deque, context.at(), config.stuffingWindow());
      deque.addLast(new TimedTarget(context.at(), client));
      Set<String> distinct = new HashSet<>();
      int attempts = 0;
      for (TimedTarget t : deque) {
        distinct.add(t.target);
        attempts++;
      }
      if (distinct.size() >= config.stuffingDistinctClients()) {
        return Optional.of(new AbusePatternSignal(
            AbusePattern.CREDENTIAL_STUFFING,
            context.at(),
            config.stuffingWindow(),
            distinct.size(),
            attempts));
      }
      return Optional.empty();
    }
  }

  private Optional<AbusePatternSignal> observeResetAbuse(AbuseAttemptContext context) {
    if (config.resetAbuseAttempts() <= 0) {
      return Optional.empty();
    }
    if (context.username().isEmpty()) {
      return Optional.empty();
    }
    String username = context.username().get();
    Deque<Instant> deque = resetByUser.computeIfAbsent(
        username, k -> new ArrayDeque<>());
    synchronized (deque) {
      pruneInstantDeque(deque, context.at(), config.resetAbuseWindow());
      deque.addLast(context.at());
      int attempts = deque.size();
      if (attempts >= config.resetAbuseAttempts()) {
        return Optional.of(new AbusePatternSignal(
            AbusePattern.RESET_ABUSE,
            context.at(),
            config.resetAbuseWindow(),
            1,
            attempts));
      }
      return Optional.empty();
    }
  }

  private static void pruneByTime(
      Deque<TimedTarget> deque, Instant now, Duration window) {
    Instant cutoff = now.minus(window);
    while (!deque.isEmpty() && deque.peekFirst().when.isBefore(cutoff)) {
      deque.pollFirst();
    }
  }

  private static void pruneInstantDeque(
      Deque<Instant> deque, Instant now, Duration window) {
    Instant cutoff = now.minus(window);
    while (!deque.isEmpty() && deque.peekFirst().isBefore(cutoff)) {
      deque.pollFirst();
    }
  }

  /**
   * Counts deduplicated targets in a sliding-window deque. Visible
   * for tests; in production the values inside {@link TimedTarget}
   * are never logged.
   */
  static int distinctTargets(Deque<TimedTarget> deque) {
    Set<String> seen = new HashSet<>();
    for (TimedTarget t : deque) {
      seen.add(t.target);
    }
    return seen.size();
  }

  /**
   * Package-private record so tests can introspect counter state if
   * they need to. Holds a timestamp and an aggregated target id.
   */
  record TimedTarget(Instant when, String target) {
  }

  /**
   * Snapshot of internal state for diagnostics. The returned map is a
   * copy; mutating it does not affect the monitor.
   */
  public Map<AbusePattern, Integer> snapshotCardinalities() {
    Map<AbusePattern, Integer> snapshot = new LinkedHashMap<>();
    snapshot.put(AbusePattern.PASSWORD_SPRAYING, sprayingByClient.size());
    snapshot.put(AbusePattern.CREDENTIAL_STUFFING, stuffingByUser.size());
    snapshot.put(AbusePattern.RESET_ABUSE, resetByUser.size());
    return snapshot;
  }
}
