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
import eu.jsentinel.jcustos.events.replay.JSentinelEventReplayStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link JSentinelEventReplayStore} implementations.
 * Implement {@link #newReplayStore()} to bind a concrete store under test.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
@DisplayName("JSentinelEventReplayStore — contract")
public interface ReplayStoreContract {

  JSentinelEventReplayStore newReplayStore();

  @Test
  @DisplayName("markSeen accepts an envelope once, then reports replay")
  default void firstSeenThenReplay() {
    JSentinelEventReplayStore store = newReplayStore();
    EventEnvelopeId id = EventEnvelopeId.of("env-1");
    Instant expires = TestkitEnvelopes.AT.plusSeconds(300);
    assertTrue(store.markSeen(id, expires));
    assertFalse(store.markSeen(id, expires));
    assertTrue(store.hasSeen(id));
  }

  @Test
  @DisplayName("purgeExpired drops entries at or before now")
  default void purgeExpired() {
    JSentinelEventReplayStore store = newReplayStore();
    store.markSeen(EventEnvelopeId.of("old"), TestkitEnvelopes.AT.plusSeconds(10));
    store.markSeen(EventEnvelopeId.of("new"), TestkitEnvelopes.AT.plusSeconds(1000));
    store.purgeExpired(TestkitEnvelopes.AT.plusSeconds(100));
    assertFalse(store.hasSeen(EventEnvelopeId.of("old")));
    assertTrue(store.hasSeen(EventEnvelopeId.of("new")));
  }
}
