package com.svenruppert.jsentinel.events.persistence.eclipsestore;

/*-
 * #%L
 * jSentinel Events — Eclipse-Store persistence
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

import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EclipseStoreReplayStore — JS-SEC-050 capacity bound")
class EclipseStoreReplayStoreBoundTest extends EclipseStoreEventStorageTestBase {

  @Test
  @DisplayName("JS-SEC-050: a distinct-envelope spray keeps the persistent seen-map bounded")
  void sprayBounded() {
    int cap = 20;
    EclipseStoreReplayStore replay = new EclipseStoreReplayStore(storage, cap);
    Instant future = Instant.now().plusSeconds(3600); // all live
    for (int i = 0; i < cap * 3; i++) {
      replay.markSeen(new EventEnvelopeId("env-" + i), future);
    }
    assertTrue(storage.root().seenEnvelopes.size() <= cap,
        "seen map must stay bounded, was " + storage.root().seenEnvelopes.size());
  }
}
