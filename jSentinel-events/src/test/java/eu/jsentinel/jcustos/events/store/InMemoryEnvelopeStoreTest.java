package eu.jsentinel.jcustos.events.store;

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

import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryEnvelopeStore")
class InMemoryEnvelopeStoreTest {

  @Test
  @DisplayName("append assigns increasing cursor positions")
  void appendAssignsPositions() {
    InMemoryEnvelopeStore store = new InMemoryEnvelopeStore();
    assertEquals(1, store.append(StoreFixtures.envelope("a")).position());
    assertEquals(2, store.append(StoreFixtures.envelope("b")).position());
    assertEquals(2, store.count());
  }

  @Test
  @DisplayName("findAfter returns a stable-ordered page and supports resume")
  void findAfterResumes() {
    InMemoryEnvelopeStore store = new InMemoryEnvelopeStore();
    for (char c = 'a'; c <= 'e'; c++) {
      store.append(StoreFixtures.envelope(String.valueOf(c)));
    }
    List<StoredEnvelope> firstPage = store.findAfter(JSentinelEventCursor.start(), 2);
    assertEquals(2, firstPage.size());
    assertEquals(EventEnvelopeId.of("a"), firstPage.get(0).envelope().envelopeId());
    assertEquals(EventEnvelopeId.of("b"), firstPage.get(1).envelope().envelopeId());

    JSentinelEventCursor resume = firstPage.get(1).cursor();
    List<StoredEnvelope> secondPage = store.findAfter(resume, 10);
    assertEquals(3, secondPage.size());
    assertEquals(EventEnvelopeId.of("c"), secondPage.get(0).envelope().envelopeId());
    assertEquals(EventEnvelopeId.of("e"), secondPage.get(2).envelope().envelopeId());
  }

  @Test
  @DisplayName("findByEnvelopeId resolves a stored envelope or empty")
  void findByEnvelopeId() {
    InMemoryEnvelopeStore store = new InMemoryEnvelopeStore();
    store.append(StoreFixtures.envelope("x"));
    assertTrue(store.findByEnvelopeId(EventEnvelopeId.of("x")).isPresent());
    assertTrue(store.findByEnvelopeId(EventEnvelopeId.of("missing")).isEmpty());
  }
}
