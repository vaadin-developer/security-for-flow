package eu.jsentinel.jcustos.events.replay;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryReplayStore")
class InMemoryReplayStoreTest {

  private final Instant future = Instant.parse("2026-06-24T11:00:00Z");

  @Test
  @DisplayName("the same envelope is accepted once, then detected as replay")
  void firstSeenThenReplay() {
    InMemoryReplayStore store = new InMemoryReplayStore();
    EventEnvelopeId id = EventEnvelopeId.of("env-1");
    assertTrue(store.markSeen(id, future));
    assertFalse(store.markSeen(id, future));
    assertTrue(store.hasSeen(id));
  }

  @Test
  @DisplayName("on capacity overflow the soonest-to-expire entry is evicted, not the LRU one (R012)")
  void evictsSoonestExpiryNotLru() {
    InMemoryReplayStore store = new InMemoryReplayStore(2);
    EventEnvelopeId longLived = EventEnvelopeId.of("long");   // inserted first (the LRU-eldest)
    EventEnvelopeId shortLived = EventEnvelopeId.of("short");
    store.markSeen(longLived, Instant.parse("2026-06-24T12:00:00Z"));  // later expiry
    store.markSeen(shortLived, Instant.parse("2026-06-24T10:01:00Z")); // sooner expiry
    // third insert overflows capacity 2 → must evict the soonest-to-expire (short),
    // NOT the eldest/LRU (long, which is still valid for longer).
    store.markSeen(EventEnvelopeId.of("third"), future);

    assertTrue(store.hasSeen(longLived),
        "a still-long-valid id must not be evicted (would open a replay window)");
    assertFalse(store.hasSeen(shortLived), "the soonest-to-expire id is the one evicted");
  }

  @Test
  @DisplayName("R08: ids sharing one expiry instant evict + purge cleanly (no orphaned index entries)")
  void sameExpiryInstantHandledByIndex() {
    // Two ids share the exact same expiry instant — exercises the per-instant
    // Set in the O(log n) expiry index. Eviction must drop exactly one of them
    // and leave the store consistent; purge must clear the rest with no orphans.
    InMemoryReplayStore store = new InMemoryReplayStore(2);
    Instant shared = Instant.parse("2026-06-24T10:01:00Z");
    EventEnvelopeId a = EventEnvelopeId.of("a");
    EventEnvelopeId b = EventEnvelopeId.of("b");
    store.markSeen(a, shared);
    store.markSeen(b, shared);
    // third insert (later expiry) overflows capacity 2 → evict one soonest-to-
    // expire id (a or b, both share the soonest instant), keep the other + third
    store.markSeen(EventEnvelopeId.of("third"), future);
    assertEquals(2, store.size());
    int survivingSharedExpiry = (store.hasSeen(a) ? 1 : 0) + (store.hasSeen(b) ? 1 : 0);
    assertEquals(1, survivingSharedExpiry, "exactly one of the two same-expiry ids must remain");
    assertTrue(store.hasSeen(EventEnvelopeId.of("third")));
    // purge at the shared instant drops the surviving same-expiry id; third stays
    store.purgeExpired(shared);
    assertEquals(1, store.size());
    assertFalse(store.hasSeen(a));
    assertFalse(store.hasSeen(b));
    assertTrue(store.hasSeen(EventEnvelopeId.of("third")));
    // re-inserting an id at the just-purged shared instant must succeed (index
    // entry was not left orphaned)
    assertTrue(store.markSeen(a, shared));
  }

  @Test
  @DisplayName("purgeExpired drops entries at or before now")
  void purgeExpired() {
    InMemoryReplayStore store = new InMemoryReplayStore();
    store.markSeen(EventEnvelopeId.of("old"), Instant.parse("2026-06-24T10:00:00Z"));
    store.markSeen(EventEnvelopeId.of("new"), Instant.parse("2026-06-24T12:00:00Z"));
    store.purgeExpired(Instant.parse("2026-06-24T11:00:00Z"));
    assertFalse(store.hasSeen(EventEnvelopeId.of("old")));
    assertTrue(store.hasSeen(EventEnvelopeId.of("new")));
  }

  @Test
  @DisplayName("the LRU bound caps retained entries")
  void boundedLru() {
    InMemoryReplayStore store = new InMemoryReplayStore(3);
    for (int i = 0; i < 10; i++) {
      store.markSeen(EventEnvelopeId.of("env-" + i), future);
    }
    assertEquals(3, store.size());
  }

  @Test
  @DisplayName("R06: a capacity below 1 is rejected via the shared CapacityBound guard")
  void rejectsNonPositiveCapacity() {
    assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayStore(0));
    assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayStore(-1));
  }

  @Test
  @DisplayName("markSeen is atomic — exactly one of many concurrent callers wins")
  void concurrentMarkSeenHasSingleWinner() throws InterruptedException {
    InMemoryReplayStore store = new InMemoryReplayStore();
    EventEnvelopeId id = EventEnvelopeId.of("contended");
    int threads = 32;
    AtomicInteger winners = new AtomicInteger();
    Thread[] pool = new Thread[threads];
    for (int i = 0; i < threads; i++) {
      pool[i] = new Thread(() -> {
        if (store.markSeen(id, future)) {
          winners.incrementAndGet();
        }
      });
    }
    for (Thread t : pool) {
      t.start();
    }
    for (Thread t : pool) {
      t.join();
    }
    assertEquals(1, winners.get());
  }
}
