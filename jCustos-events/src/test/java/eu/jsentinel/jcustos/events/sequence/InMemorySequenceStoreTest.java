package eu.jsentinel.jcustos.events.sequence;

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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventSequence;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemorySequenceStore")
class InMemorySequenceStoreTest {

  private static final EventProducerId P1 = EventProducerId.of("rest-primary");
  private static final EventProducerId P2 = EventProducerId.of("vaadin-client");

  @Test
  @DisplayName("a fresh scope has no last sequence")
  void freshScopeIsEmpty() {
    InMemorySequenceStore store = new InMemorySequenceStore();
    assertTrue(store.lastSequence(TenantId.DEFAULT, P1).isEmpty());
  }

  @Test
  @DisplayName("updateSequence then lastSequence round-trips")
  void updateThenRead() {
    InMemorySequenceStore store = new InMemorySequenceStore();
    store.updateSequence(TenantId.DEFAULT, P1, EventSequence.of(42));
    assertEquals(EventSequence.of(42), store.lastSequence(TenantId.DEFAULT, P1).orElseThrow());
  }

  @Test
  @DisplayName("sequences are scoped per tenant + producer")
  void scopedPerTenantAndProducer() {
    InMemorySequenceStore store = new InMemorySequenceStore();
    store.updateSequence(TenantId.DEFAULT, P1, EventSequence.of(10));
    store.updateSequence(TenantId.DEFAULT, P2, EventSequence.of(20));
    store.updateSequence(TenantId.of("other"), P1, EventSequence.of(30));

    assertEquals(10, store.lastSequence(TenantId.DEFAULT, P1).orElseThrow().value());
    assertEquals(20, store.lastSequence(TenantId.DEFAULT, P2).orElseThrow().value());
    assertEquals(30, store.lastSequence(TenantId.of("other"), P1).orElseThrow().value());
  }
}
