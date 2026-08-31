package eu.jsentinel.jcustos.events.persistence.eclipsestore;

/*-
 * #%L
 * jCustos Events — Eclipse-Store persistence
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.sequence.JCustosEventSequenceStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * R03: the persisted {@code (tenant, producer)} composite key must be
 * injection-proof — ids containing {@code '|'} may not alias another scope's
 * counter — and legacy raw {@code tenant|producer} keys must be migrated at
 * open (unambiguous ones rewritten, ambiguous ones left in place).
 */
@DisplayName("EclipseStoreSequenceStore — injection-proof composite key (R03)")
class EclipseStoreSequenceStoreCompositeKeyTest extends EclipseStoreEventStorageTestBase {

  private static final TenantId ALIAS_TENANT_A = TenantId.of("a|b");
  private static final EventProducerId ALIAS_PRODUCER_A = EventProducerId.of("c");
  private static final TenantId ALIAS_TENANT_B = TenantId.of("a");
  private static final EventProducerId ALIAS_PRODUCER_B = EventProducerId.of("b|c");

  /** Replicates the pre-R03 raw key building so tests can seed a legacy-format store. */
  private static String legacyKey(String tenant, String producer) {
    return tenant + '|' + producer;
  }

  private void reopen() {
    storage.close();
    storage = EclipseStoreEventStorage.openAt(tempDir);
  }

  @Test
  @DisplayName("alias pair (a|b, c) vs (a, b|c) gets independent counters, also across reopen")
  void aliasPairHasIndependentCounters() {
    JCustosEventSequenceStore store = storage.sequenceStore();
    assertEquals(1, store.reserveNext(ALIAS_TENANT_A, ALIAS_PRODUCER_A).value());
    assertEquals(2, store.reserveNext(ALIAS_TENANT_A, ALIAS_PRODUCER_A).value());
    assertTrue(store.lastSequence(ALIAS_TENANT_B, ALIAS_PRODUCER_B).isEmpty(),
        "the aliased scope must not see the other scope's counter");
    assertEquals(1, store.reserveNext(ALIAS_TENANT_B, ALIAS_PRODUCER_B).value(),
        "fresh scope starts at FIRST, not after the aliased scope's last value");

    reopen();
    store = storage.sequenceStore();
    assertEquals(2, store.lastSequence(ALIAS_TENANT_A, ALIAS_PRODUCER_A)
        .orElseThrow().value(), "scope (a|b, c) survived the restart on its own counter");
    assertEquals(1, store.lastSequence(ALIAS_TENANT_B, ALIAS_PRODUCER_B)
        .orElseThrow().value(), "scope (a, b|c) survived the restart on its own counter");
    assertEquals(3, store.reserveNext(ALIAS_TENANT_A, ALIAS_PRODUCER_A).value());
    assertEquals(2, store.reserveNext(ALIAS_TENANT_B, ALIAS_PRODUCER_B).value());
  }

  @Test
  @DisplayName("legacy tenant|producer key with exactly one '|' is migrated at open")
  void unambiguousLegacyKeyIsMigratedAtOpen() {
    storage.root().sequences.put(legacyKey("tenant-x", "producer-y"), 41L);
    storage.manager().store(storage.root().sequences);

    reopen();
    JCustosEventSequenceStore store = storage.sequenceStore();
    TenantId tenant = TenantId.of("tenant-x");
    EventProducerId producer = EventProducerId.of("producer-y");
    assertEquals(41, store.lastSequence(tenant, producer).orElseThrow().value(),
        "counter continues seamlessly under the framed key");
    assertEquals(42, store.reserveNext(tenant, producer).value());
    assertFalse(storage.root().sequences.containsKey(legacyKey("tenant-x", "producer-y")),
        "legacy key is gone after migration");

    reopen();
    assertEquals(42, storage.sequenceStore().lastSequence(tenant, producer)
        .orElseThrow().value(), "second migration pass (idempotent) keeps the framed counter");
  }

  @Test
  @DisplayName("ambiguous legacy key (two '|') stays untouched across reopens")
  void ambiguousLegacyKeyStaysUntouched() {
    storage.root().sequences.put("a|b|c", 7L);
    storage.manager().store(storage.root().sequences);

    reopen();
    assertEquals(Long.valueOf(7L), storage.root().sequences.get("a|b|c"),
        "genuinely ambiguous legacy key is left in place");

    reopen();
    assertEquals(Long.valueOf(7L), storage.root().sequences.get("a|b|c"),
        "second migration pass leaves the ambiguous key untouched as well");
  }
}
