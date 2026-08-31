package eu.jsentinel.jcustos.events.testkit;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.store.JSentinelEventCursor;
import eu.jsentinel.jcustos.events.store.JSentinelEventEnvelopeStore;
import eu.jsentinel.jcustos.events.store.StoredEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link JSentinelEventEnvelopeStore} implementations,
 * including the stable cursor ordering the SSE resume relies on.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
@DisplayName("JSentinelEventEnvelopeStore — contract")
public interface EnvelopeStoreContract {

  JSentinelEventEnvelopeStore newEnvelopeStore();

  @Test
  @DisplayName("append assigns increasing positions and count tracks them")
  default void appendAssignsPositions() {
    JSentinelEventEnvelopeStore store = newEnvelopeStore();
    assertEquals(1, store.append(TestkitEnvelopes.envelope("a")).position());
    assertEquals(2, store.append(TestkitEnvelopes.envelope("b")).position());
    assertEquals(2, store.count());
  }

  @Test
  @DisplayName("findAfter returns a stable-ordered page and supports resume")
  default void findAfterResumes() {
    JSentinelEventEnvelopeStore store = newEnvelopeStore();
    for (char c = 'a'; c <= 'e'; c++) {
      store.append(TestkitEnvelopes.envelope(String.valueOf(c)));
    }
    List<StoredEnvelope> first = store.findAfter(JSentinelEventCursor.start(), 2);
    assertEquals(2, first.size());
    assertEquals(EventEnvelopeId.of("a"), first.get(0).envelope().envelopeId());

    List<StoredEnvelope> rest = store.findAfter(first.get(1).cursor(), 10);
    assertEquals(3, rest.size());
    assertEquals(EventEnvelopeId.of("c"), rest.get(0).envelope().envelopeId());
    assertEquals(EventEnvelopeId.of("e"), rest.get(2).envelope().envelopeId());
  }

  @Test
  @DisplayName("findByEnvelopeId resolves a stored envelope or empty")
  default void findByEnvelopeId() {
    JSentinelEventEnvelopeStore store = newEnvelopeStore();
    store.append(TestkitEnvelopes.envelope("x"));
    assertTrue(store.findByEnvelopeId(EventEnvelopeId.of("x")).isPresent());
    assertTrue(store.findByEnvelopeId(EventEnvelopeId.of("missing")).isEmpty());
  }

  @Test
  @DisplayName("JS-SEC-058: findAfter with a Long.MAX_VALUE cursor returns an empty page, not an overflow throw")
  default void findAfterOutOfRangeCursorIsEmpty() {
    JSentinelEventEnvelopeStore store = newEnvelopeStore();
    store.append(TestkitEnvelopes.envelope("a"));
    // an at/after-end (here far-out-of-range) cursor must yield "nothing after it" rather than
    // throwing from the position+1 overflow.
    assertTrue(store.findAfter(JSentinelEventCursor.at(Long.MAX_VALUE), 10).isEmpty());
  }
}
