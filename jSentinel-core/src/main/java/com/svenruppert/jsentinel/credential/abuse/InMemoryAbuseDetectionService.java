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

  private final AbuseLimitsPolicy policy;
  private final JSentinelAuditService auditService;
  private final ConcurrentHashMap<String, Deque<Instant>> counters =
      new ConcurrentHashMap<>();

  public InMemoryAbuseDetectionService(
      AbuseLimitsPolicy policy, JSentinelAuditService auditService) {
    this.policy = Objects.requireNonNull(policy, "policy");
    this.auditService = Objects.requireNonNull(auditService, "auditService");
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
          counters.remove(composite);
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
    Deque<Instant> deque = counters.get(composite);
    if (deque == null) {
      return 0;
    }
    Instant cutoff = now.minus(window);
    synchronized (deque) {
      while (!deque.isEmpty() && deque.peekFirst().isBefore(cutoff)) {
        deque.pollFirst();
      }
      return deque.size();
    }
  }

  private void appendEvent(String composite, Instant at) {
    Deque<Instant> deque = counters.computeIfAbsent(
        composite, k -> new ArrayDeque<>());
    synchronized (deque) {
      deque.addLast(at);
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
