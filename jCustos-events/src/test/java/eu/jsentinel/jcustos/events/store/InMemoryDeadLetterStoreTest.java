package eu.jsentinel.jcustos.events.store;

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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryDeadLetterStore")
class InMemoryDeadLetterStoreTest {

  private static final Instant AT = Instant.parse("2026-06-24T10:15:30Z");

  @Test
  @DisplayName("stored dead letters appear in findOpen, oldest first")
  void storeAndFindOpen() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    store.store(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("a"), RejectionReason.INVALID_SIGNATURE, AT));
    store.store(JCustosEventDeadLetter.of(
        StoreFixtures.envelope("b"), RejectionReason.REPLAY_DETECTED, AT));

    List<JCustosEventDeadLetter> open = store.findOpen(10);
    assertEquals(2, open.size());
    assertEquals(RejectionReason.INVALID_SIGNATURE, open.get(0).reason());
    assertEquals(RejectionReason.REPLAY_DETECTED, open.get(1).reason());
  }

  @Test
  @DisplayName("markResolved removes a record from findOpen")
  void markResolved() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    JCustosEventDeadLetter dl = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("a"), RejectionReason.SEQUENCE_VIOLATION, AT);
    store.store(dl);
    store.markResolved(dl.id());
    assertTrue(store.findOpen(10).isEmpty());
  }

  @Test
  @DisplayName("R07: markResolved drops the heavy record so resolved dead letters do not accumulate")
  void markResolvedDropsRecord() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    JCustosEventDeadLetter a = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("a"), RejectionReason.SEQUENCE_VIOLATION, AT);
    JCustosEventDeadLetter b = JCustosEventDeadLetter.of(
        StoreFixtures.envelope("b"), RejectionReason.REPLAY_DETECTED, AT);
    store.store(a);
    store.store(b);
    assertEquals(2, store.retainedRecordCount());

    store.markResolved(a.id());

    // the record (and its embedded signed envelope) is gone, not parked in a
    // side set — only the still-open dead letter is retained
    assertEquals(1, store.retainedRecordCount(),
        "a resolved dead letter must not be retained");
    List<JCustosEventDeadLetter> open = store.findOpen(10);
    assertEquals(1, open.size());
    assertEquals(RejectionReason.REPLAY_DETECTED, open.get(0).reason());
  }

  @Test
  @DisplayName("findOpen honours the limit")
  void limit() {
    InMemoryDeadLetterStore store = new InMemoryDeadLetterStore();
    for (int i = 0; i < 5; i++) {
      store.store(JCustosEventDeadLetter.of(
          StoreFixtures.envelope("e" + i), RejectionReason.EXPIRED, AT));
    }
    assertEquals(3, store.findOpen(3).size());
  }
}
