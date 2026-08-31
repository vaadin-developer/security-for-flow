package eu.jsentinel.jcustos.audit.integrity.chain;

/*-
 * #%L
 * jSentinel Audit Integrity — tamper-evident audit
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

import eu.jsentinel.jcustos.audit.integrity.api.AuditChainEntry;
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AuditChainAppender — the only writer, CAS retry, contention")
class AuditChainAppenderTest {

  private static final Instant AT = Instant.parse("2026-07-19T10:15:30Z");

  @Test
  @DisplayName("sequential appends build a linkage-valid, recomputable chain")
  void sequentialAppends() {
    InMemoryAuditChainStore store = new InMemoryAuditChainStore();
    AuditChainAppender appender = new AuditChainAppender(store,
        eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm.SHA_256, () -> AT);

    for (int i = 0; i < 5; i++) {
      appender.append("test/v1", ("payload-" + i).getBytes(StandardCharsets.UTF_8));
    }

    assertEquals(5, store.size());
    String previous = AuditChainEntry.GENESIS_PREVIOUS_HASH;
    for (int i = 0; i < 5; i++) {
      AuditChainEntry entry = store.entryAt(i).orElseThrow();
      assertEquals(i, entry.index());
      assertEquals(previous, entry.previousEntryHash());
      assertEquals(AuditChainEntryHasher.computeEntryHash(entry.index(),
              entry.appendedAt(), entry.algorithmId(), entry.previousEntryHash(),
              entry.payloadType(), entry.payload()),
          entry.entryHash(), "every stored hash must recompute");
      previous = entry.entryHash();
    }
  }

  @Test
  @DisplayName("concurrent appenders produce a gap-free, linkage-valid chain (CAS retry)")
  void concurrentAppends() throws Exception {
    InMemoryAuditChainStore store = new InMemoryAuditChainStore();
    AuditChainAppender appender = new AuditChainAppender(store);

    List<Thread> writers = new ArrayList<>();
    for (int t = 0; t < 4; t++) {
      int thread = t;
      writers.add(Thread.ofVirtual().start(() -> {
        for (int i = 0; i < 25; i++) {
          appender.append("test/v1",
              ("t" + thread + "-" + i).getBytes(StandardCharsets.UTF_8));
        }
      }));
    }
    for (Thread writer : writers) {
      writer.join();
    }

    assertEquals(100, store.size());
    String previous = AuditChainEntry.GENESIS_PREVIOUS_HASH;
    for (int i = 0; i < 100; i++) {
      AuditChainEntry entry = store.entryAt(i).orElseThrow();
      assertEquals(i, entry.index(), "indices must be gap-free");
      assertEquals(previous, entry.previousEntryHash(), "linkage must hold at " + i);
      previous = entry.entryHash();
    }
  }

  @Test
  @DisplayName("exhausted contention fails with the stable operator code")
  void contentionExhaustion() {
    AuditChainStore alwaysLosing = new AuditChainStore() {
      @Override
      public Optional<AuditChainEntry> head() {
        return Optional.empty();
      }

      @Override
      public long size() {
        return 0;
      }

      @Override
      public boolean append(AuditChainEntry entry) {
        return false;
      }

      @Override
      public List<AuditChainEntry> read(long fromIndex, int maxCount) {
        return List.of();
      }

      @Override
      public Optional<AuditChainEntry> entryAt(long index) {
        return Optional.empty();
      }
    };

    AuditChainException ex = assertThrows(AuditChainException.class, () ->
        new AuditChainAppender(alwaysLosing)
            .append("test/v1", "p".getBytes(StandardCharsets.UTF_8)));
    assertEquals(AuditChainAppender.CODE_APPEND_CONTENTION, ex.code());
  }

  @Test
  @DisplayName("a full in-memory store throws the CapacityBound code instead of evicting")
  void capacityIsThrowOnFull() {
    InMemoryAuditChainStore tiny = new InMemoryAuditChainStore(2);
    AuditChainAppender appender = new AuditChainAppender(tiny);
    appender.append("test/v1", "a".getBytes(StandardCharsets.UTF_8));
    appender.append("test/v1", "b".getBytes(StandardCharsets.UTF_8));

    AuditChainException ex = assertThrows(AuditChainException.class, () ->
        appender.append("test/v1", "c".getBytes(StandardCharsets.UTF_8)));
    assertEquals(InMemoryAuditChainStore.CODE_CAPACITY_EXCEEDED, ex.code());
    assertEquals(2, tiny.size(), "append-only: nothing may be evicted");
    assertTrue(tiny.entryAt(0).isPresent());
  }
}
