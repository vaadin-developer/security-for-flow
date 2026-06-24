package com.svenruppert.jsentinel.events.testkit;

/*-
 * #%L
 * jSentinel Events — Contract testkit
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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.EventSequence;
import com.svenruppert.jsentinel.events.sequence.JSentinelEventSequenceStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link JSentinelEventSequenceStore} implementations.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
@DisplayName("JSentinelEventSequenceStore — contract")
public interface SequenceStoreContract {

  JSentinelEventSequenceStore newSequenceStore();

  EventProducerId PRODUCER_A = EventProducerId.of("producer-a");
  EventProducerId PRODUCER_B = EventProducerId.of("producer-b");

  @Test
  @DisplayName("a fresh scope has no last sequence")
  default void freshScopeEmpty() {
    assertTrue(newSequenceStore().lastSequence(TenantId.DEFAULT, PRODUCER_A).isEmpty());
  }

  @Test
  @DisplayName("updateSequence then lastSequence round-trips")
  default void updateThenRead() {
    JSentinelEventSequenceStore store = newSequenceStore();
    store.updateSequence(TenantId.DEFAULT, PRODUCER_A, EventSequence.of(42));
    assertEquals(42, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value());
  }

  @Test
  @DisplayName("sequences are isolated per tenant + producer")
  default void scopedPerTenantAndProducer() {
    JSentinelEventSequenceStore store = newSequenceStore();
    store.updateSequence(TenantId.DEFAULT, PRODUCER_A, EventSequence.of(10));
    store.updateSequence(TenantId.DEFAULT, PRODUCER_B, EventSequence.of(20));
    store.updateSequence(TenantId.of("other"), PRODUCER_A, EventSequence.of(30));
    assertEquals(10, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value());
    assertEquals(20, store.lastSequence(TenantId.DEFAULT, PRODUCER_B).orElseThrow().value());
    assertEquals(30, store.lastSequence(TenantId.of("other"), PRODUCER_A).orElseThrow().value());
  }

  @Test
  @DisplayName("reserveNext starts at FIRST and advances monotonically")
  default void reserveNextAdvances() {
    JSentinelEventSequenceStore store = newSequenceStore();
    assertEquals(EventSequence.FIRST, store.reserveNext(TenantId.DEFAULT, PRODUCER_A));
    assertEquals(2, store.reserveNext(TenantId.DEFAULT, PRODUCER_A).value());
    assertEquals(2, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value());
    // a different scope is independent
    assertEquals(EventSequence.FIRST, store.reserveNext(TenantId.DEFAULT, PRODUCER_B));
  }

  @Test
  @DisplayName("reserveNext is atomic — N concurrent reservations yield N distinct, gap-free sequences (R011)")
  default void reserveNextIsAtomicUnderContention() throws InterruptedException {
    JSentinelEventSequenceStore store = newSequenceStore();
    int threads = 64;
    ConcurrentHashMap.KeySetView<Long, Boolean> seen = ConcurrentHashMap.newKeySet();
    AtomicInteger duplicates = new AtomicInteger();
    CountDownLatch start = new CountDownLatch(1);
    Thread[] pool = new Thread[threads];
    for (int i = 0; i < threads; i++) {
      pool[i] = new Thread(() -> {
        try {
          start.await();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return;
        }
        EventSequence reserved = store.reserveNext(TenantId.DEFAULT, PRODUCER_A);
        if (!seen.add(reserved.value())) {
          duplicates.incrementAndGet();
        }
      });
    }
    for (Thread t : pool) {
      t.start();
    }
    start.countDown();
    for (Thread t : pool) {
      t.join();
    }
    assertEquals(0, duplicates.get(), "no two reservations may share a sequence");
    assertEquals(threads, seen.size(), "every reservation is distinct");
    assertEquals(threads, store.lastSequence(TenantId.DEFAULT, PRODUCER_A).orElseThrow().value(),
        "the last reserved sequence equals the reservation count (gap-free)");
    long sum = seen.stream().mapToLong(Long::longValue).sum();
    assertEquals((long) threads * (threads + 1) / 2, sum,
        "the reserved sequences are exactly 1..N with no gaps");
  }
}
