package com.svenruppert.jsentinel.events.replay;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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

import com.svenruppert.jsentinel.events.api.EventEnvelopeId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
