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

import com.svenruppert.jsentinel.audit.RateLimitExceeded;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory reference implementation of
 * {@link AbuseDetectionService}.
 *
 * <p>Each {@code (AbuseAttemptType, AbuseDimension, dimensionKey)}
 * tuple has its own sliding-window deque of failure timestamps.
 * {@link AbuseDimension#USERNAME} counters track failures only;
 * {@link AbuseDimension#CLIENT_ADDRESS},
 * {@link AbuseDimension#TENANT} and {@link AbuseDimension#GLOBAL}
 * track every attempt regardless of outcome (the volume axes).</p>
 *
 * <p>Auditing is best-effort: every block / step-up / delay decision
 * publishes a {@link RateLimitExceeded} event with the dimension
 * encoded in the {@code scope} field. Sink failures are swallowed
 * (CWE-778).</p>
 */
public final class InMemoryAbuseDetectionService implements AbuseDetectionService {

  /** Dimensions that count every attempt, not just failures. */
  private static final Set<AbuseDimension> VOLUME_DIMENSIONS = EnumSet.of(
      AbuseDimension.CLIENT_ADDRESS,
      AbuseDimension.TENANT,
      AbuseDimension.GLOBAL);

  /** JS-SEC-030 (CWE-770): default upper bound on tracked counter keys. */
  public static final int DEFAULT_MAX_ENTRIES = 100_000;

  private final AbuseLimitsPolicy policy;
  private final JSentinelAuditService auditService;
  private final int maxEntries;
  private final ConcurrentHashMap<String, Deque<Instant>> counters =
      new ConcurrentHashMap<>();

  public InMemoryAbuseDetectionService(
      AbuseLimitsPolicy policy, JSentinelAuditService auditService) {
    this(policy, auditService, DEFAULT_MAX_ENTRIES);
  }

  public InMemoryAbuseDetectionService(
      AbuseLimitsPolicy policy, JSentinelAuditService auditService, int maxEntries) {
    this.policy = Objects.requireNonNull(policy, "policy");
    this.auditService = Objects.requireNonNull(auditService, "auditService");
    if (maxEntries < 1) {
      throw new IllegalArgumentException("maxEntries must be >= 1");
    }
    this.maxEntries = maxEntries;
  }

  /** Package-visible for tests: number of tracked counter keys (JS-SEC-030 bound). */
  int trackedCounterCount() {
    return counters.size();
  }

  @Override
  public AbuseDecision evaluate(AbuseAttemptContext context) {
    Objects.requireNonNull(context, "context");
    AbuseDecision strongest = AbuseDecision.Allow.INSTANCE;
    int strongestRank = 0;
    for (AbuseDimension dimension : AbuseDimension.values()) {
      Optional<AbuseLimitsPolicy.Limit> maybeLimit =
          policy.limit(context.attemptType(), dimension);
      if (maybeLimit.isEmpty()) {
        continue;
      }
      AbuseLimitsPolicy.Limit limit = maybeLimit.get();
      Optional<String> key = keyFor(context, dimension);
      if (key.isEmpty()) {
        continue;
      }
      int count = currentCount(
          composite(context.attemptType(), dimension, key.get()),
          limit.window(),
          context.at());
      AbuseDecision dimensionDecision = mapToDecision(limit, count, dimension);
      int rank = rank(dimensionDecision);
      if (rank > strongestRank) {
        strongest = dimensionDecision;
        strongestRank = rank;
      }
    }
    if (strongestRank > 0) {
      publish(context, strongest);
    }
    return strongest;
  }

  @Override
  public void recordOutcome(
      AbuseAttemptContext context, AttemptOutcome outcome) {
    Objects.requireNonNull(context, "context");
    Objects.requireNonNull(outcome, "outcome");
    for (AbuseDimension dimension : AbuseDimension.values()) {
      Optional<String> key = keyFor(context, dimension);
      if (key.isEmpty()) {
        continue;
      }
      String composite = composite(context.attemptType(), dimension, key.get());
      if (VOLUME_DIMENSIONS.contains(dimension)) {
        // Volume counters tick on every attempt.
        appendEvent(composite, context.at());
      } else {
        // Failure-only counters.
        if (outcome == AttemptOutcome.FAILURE) {
          appendEvent(composite, context.at());
        } else {
          // R014: a success resets the window by clearing the deque IN PLACE.
          // It must NOT remove the mapping: a concurrent appendEvent that already
          // holds this deque reference would otherwise add to an orphaned deque
          // and the failure would be lost — letting attempts slip past blockAt.
          counters.computeIfPresent(composite, (k, deque) -> {
            deque.clear();
            return deque;
          });
        }
      }
    }
  }

  private static Optional<String> keyFor(
      AbuseAttemptContext context, AbuseDimension dimension) {
    return switch (dimension) {
      case USERNAME -> context.username();
      case CLIENT_ADDRESS -> context.clientAddress();
      case TENANT -> Optional.of(tenantKey(context.tenant()));
      case GLOBAL -> Optional.of("*");
    };
  }

  private static String tenantKey(TenantId tenant) {
    return tenant == null ? TenantId.DEFAULT.value() : tenant.value();
  }

  private static String composite(
      AbuseAttemptType attemptType,
      AbuseDimension dimension,
      String key) {
    return attemptType.name() + "/" + dimension.name() + "/" + key;
  }

  private int currentCount(String composite, Duration window, Instant now) {
    Instant cutoff = now.minus(window);
    int[] size = {0};
    // R014: purge expired entries and read the size INSIDE compute, so the deque
    // is only ever touched while the ConcurrentHashMap holds the per-key bin lock
    // — the same discipline as appendEvent and the success-reset. No deque is ever
    // accessed through a reference that a concurrent remove could have orphaned.
    counters.computeIfPresent(composite, (k, deque) -> {
      // R039: the sliding window is the half-open interval (now-window, now] —
      // an event exactly `window` old has expired. Evict timestamps at or
      // before the cutoff (was isBefore, which kept the boundary event and made
      // the effective window one tick wider than "the last <window>").
      while (!deque.isEmpty() && !deque.peekFirst().isAfter(cutoff)) {
        deque.pollFirst();
      }
      size[0] = deque.size();
      // JS-SEC-030 (CWE-770): drop a fully-expired (now-empty) counter so the map is
      // self-reclaiming — the composite key embeds an attacker-controlled username /
      // client address. Safe: appendEvent's add is atomic inside compute, so a
      // concurrent record on this key just recreates the deque.
      return deque.isEmpty() ? null : deque;
    });
    return size[0];
  }

  private void appendEvent(String composite, Instant at) {
    enforceBound(composite);
    // R014: create-or-append in a single atomic compute. The previous
    // computeIfAbsent + synchronized(deque) left a window in which a concurrent
    // success-reset could remove the freshly created deque before the add landed,
    // losing the failure. Doing the add inside compute closes that window.
    counters.compute(composite, (k, deque) -> {
      Deque<Instant> d = (deque == null) ? new ArrayDeque<>() : deque;
      d.addLast(at);
      return d;
    });
  }

  /**
   * JS-SEC-030 (CWE-770): hard cap on the counter map. The composite key embeds an
   * attacker-controlled username / client address, and {@link #currentCount} only
   * reclaims keys that are re-evaluated — a spray of distinct keys each recorded once
   * and never re-evaluated would otherwise grow the map without limit. When a new key
   * would exceed {@code maxEntries}, evict arbitrary existing counters back under the
   * bound via a safe {@code keySet().iterator().remove()}. Soft bound: a concurrent
   * burst may transiently overshoot by a few, but growth stays bounded.
   */
  private void enforceBound(String incomingKey) {
    if (counters.size() < maxEntries || counters.containsKey(incomingKey)) {
      return;
    }
    var it = counters.keySet().iterator();
    while (counters.size() >= maxEntries && it.hasNext()) {
      String victim = it.next();
      if (!victim.equals(incomingKey)) {
        it.remove();
      }
    }
  }

  private static AbuseDecision mapToDecision(
      AbuseLimitsPolicy.Limit limit, int count, AbuseDimension dimension) {
    if (limit.blockAt() > 0 && count >= limit.blockAt()) {
      return new AbuseDecision.Block(limit.blockLen(), dimension);
    }
    if (limit.stepUpAt() > 0 && count >= limit.stepUpAt()) {
      return new AbuseDecision.RequireAdditionalCheck(dimension);
    }
    if (limit.delayAt() > 0 && count >= limit.delayAt()) {
      return new AbuseDecision.Delay(limit.delayLen(), dimension);
    }
    return AbuseDecision.Allow.INSTANCE;
  }

  /**
   * Numeric rank so a decision evaluated across dimensions picks the
   * strongest reaction.
   */
  private static int rank(AbuseDecision decision) {
    if (decision instanceof AbuseDecision.Allow) {
      return 0;
    }
    if (decision instanceof AbuseDecision.Delay) {
      return 1;
    }
    if (decision instanceof AbuseDecision.RequireAdditionalCheck) {
      return 2;
    }
    return 3; // Block
  }

  private void publish(AbuseAttemptContext context, AbuseDecision decision) {
    AbuseDimension dim = dimensionOf(decision);
    if (dim == null) {
      return;
    }
    AbuseLimitsPolicy.Limit limit = policy.limit(context.attemptType(), dim)
        .orElse(null);
    if (limit == null) {
      return;
    }
    String subjectId = context.username().orElse(
        context.clientAddress().orElse("anonymous"));
    int events = currentCount(composite(
        context.attemptType(), dim,
        keyFor(context, dim).orElse("?")), limit.window(), context.at());
    try {
      int threshold = limit.blockAt() > 0 ? limit.blockAt() : limit.delayAt();
      if (threshold <= 0) {
        return;
      }
      auditService.publish(new RateLimitExceeded(
          context.at(),
          context.attemptType().name() + "/" + dim.name(),
          subjectId,
          threshold,
          limit.window(),
          events));
    } catch (RuntimeException ignored) {
      // Audit failure must not block the decision (CWE-778).
    }
  }

  private static AbuseDimension dimensionOf(AbuseDecision decision) {
    if (decision instanceof AbuseDecision.Delay d) {
      return d.dimension();
    }
    if (decision instanceof AbuseDecision.RequireAdditionalCheck r) {
      return r.dimension();
    }
    if (decision instanceof AbuseDecision.Block b) {
      return b.dimension();
    }
    return null;
  }
}
