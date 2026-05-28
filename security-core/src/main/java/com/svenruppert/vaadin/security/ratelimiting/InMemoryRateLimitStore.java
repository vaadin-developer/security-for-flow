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
package com.svenruppert.vaadin.security.ratelimiting;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RateLimitStore} backed by a per-key
 * {@link ConcurrentLinkedDeque} of timestamps.
 * <p>
 * {@link #recordEvent(RateLimitKey, Instant)} appends to the tail in
 * amortised O(1). {@link #countSince(RateLimitKey, Instant)} walks the
 * deque tail-to-head and stops once an entry before the cutoff is
 * found — assumes timestamps are recorded in approximately
 * monotonically-increasing order, which is the standard case for
 * sliding-window throttling.
 *
 * <p>Retention is the application's responsibility via
 * {@link #purgeOlderThan(Instant)}; without periodic purges the
 * deques would grow unboundedly under sustained traffic.
 */
@ExperimentalSecurityApi
public final class InMemoryRateLimitStore implements RateLimitStore {

  private final Map<RateLimitKey, ConcurrentLinkedDeque<Instant>> buckets =
      new ConcurrentHashMap<>();

  /** Creates an empty store. */
  public InMemoryRateLimitStore() {
  }

  @Override
  public void recordEvent(RateLimitKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    buckets.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>()).add(at);
  }

  @Override
  public int countSince(RateLimitKey key, Instant since) {
    requireNonNull(key, "key must not be null");
    requireNonNull(since, "since must not be null");
    ConcurrentLinkedDeque<Instant> deque = buckets.get(key);
    if (deque == null) {
      return 0;
    }
    int count = 0;
    Iterator<Instant> it = deque.descendingIterator();
    while (it.hasNext()) {
      Instant event = it.next();
      if (event.isBefore(since)) {
        break;
      }
      count++;
    }
    return count;
  }

  @Override
  public void reset(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    buckets.remove(key);
  }

  @Override
  public int purgeOlderThan(Instant cutoff) {
    requireNonNull(cutoff, "cutoff must not be null");
    int purged = 0;
    Iterator<Map.Entry<RateLimitKey, ConcurrentLinkedDeque<Instant>>> entries =
        buckets.entrySet().iterator();
    while (entries.hasNext()) {
      ConcurrentLinkedDeque<Instant> deque = entries.next().getValue();
      while (true) {
        Instant head = deque.peek();
        if (head == null || !head.isBefore(cutoff)) {
          break;
        }
        if (deque.remove(head)) {
          purged++;
        } else {
          break;
        }
      }
      if (deque.isEmpty()) {
        entries.remove();
      }
    }
    return purged;
  }
}
