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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventEnvelopeId;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.EventSequence;
import com.svenruppert.jsentinel.events.store.JSentinelEventDeadLetter;
import com.svenruppert.jsentinel.events.store.RejectionReason;
import com.svenruppert.jsentinel.events.testkit.TestkitEnvelopes;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EclipseStoreEventStorage — survives a restart")
class EclipseStoreEventStorageRestartTest {

  private static final EventProducerId PRODUCER = EventProducerId.of("rest-service-primary");

  @Test
  @DisplayName("replay, sequence, envelope and dead-letter state survive close + reopen")
  void stateSurvivesRestart(@TempDir Path dir) {
    EclipseStoreEventStorage first = EclipseStoreEventStorage.openAt(dir);
    first.replayStore().markSeen(EventEnvelopeId.of("env-seen"),
        TestkitEnvelopes.AT.plusSeconds(300));
    first.sequenceStore().updateSequence(TenantId.DEFAULT, PRODUCER, EventSequence.of(99));
    first.envelopeStore().append(TestkitEnvelopes.envelope("env-stored"));
    first.deadLetterStore().store(JSentinelEventDeadLetter.of(
        TestkitEnvelopes.envelope("env-dl"), RejectionReason.INVALID_SIGNATURE,
        TestkitEnvelopes.AT));
    first.close();

    EclipseStoreEventStorage second = EclipseStoreEventStorage.openAt(dir);
    try {
      assertTrue(second.replayStore().hasSeen(EventEnvelopeId.of("env-seen")),
          "replay state survived");
      assertEquals(99, second.sequenceStore()
          .lastSequence(TenantId.DEFAULT, PRODUCER).orElseThrow().value(), "sequence survived");
      assertEquals(1, second.envelopeStore().count(), "envelope survived");
      assertTrue(second.envelopeStore().findByEnvelopeId(EventEnvelopeId.of("env-stored"))
          .isPresent(), "stored envelope is resolvable");
      assertEquals(1, second.deadLetterStore().findOpen(10).size(), "dead letter survived");
    } finally {
      second.close();
    }
  }
}
