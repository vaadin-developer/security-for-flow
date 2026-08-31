package eu.jsentinel.jcustos.audit.integrity.testkit;

/*-
 * #%L
 * jSentinel Audit Integrity — contract testkit
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
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Reusable contract for {@link AuditChainStore} implementations, pinning the
 * append-only storage obligations: linkage-checked CAS append, no
 * replacement of existing entries, ascending contiguous paging.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
@DisplayName("AuditChainStore — contract")
public interface AuditChainStoreContract {

  AuditChainStore newChainStore();

  @Test
  @DisplayName("a virgin chain is empty everywhere")
  default void virginChainIsEmpty() {
    AuditChainStore store = newChainStore();
    assertTrue(store.head().isEmpty());
    assertEquals(0, store.size());
    assertTrue(store.read(0, 10).isEmpty());
    assertTrue(store.entryAt(0).isEmpty());
  }

  @Test
  @DisplayName("the genesis append succeeds and becomes the head")
  default void genesisAppend() {
    AuditChainStore store = newChainStore();
    AuditChainEntry genesis = TestkitChainEntries.chain(1).get(0);
    assertTrue(store.append(genesis));
    assertEquals(1, store.size());
    assertEquals(genesis, store.head().orElseThrow());
  }

  @Test
  @DisplayName("a genesis append with a wrong previous hash is refused")
  default void wrongGenesisPreviousRefused() {
    AuditChainStore store = newChainStore();
    AuditChainEntry wrong = TestkitChainEntries.entry(0,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "payload-0".getBytes(StandardCharsets.UTF_8));
    assertFalse(store.append(wrong));
    assertEquals(0, store.size());
  }

  @Test
  @DisplayName("a happy chain of five: head, size, paging and entryAt line up")
  default void happyChainOfFive() {
    AuditChainStore store = newChainStore();
    List<AuditChainEntry> chain = TestkitChainEntries.chain(5);
    chain.forEach(entry -> assertTrue(store.append(entry)));

    assertEquals(5, store.size());
    assertEquals(chain.get(4), store.head().orElseThrow());
    assertEquals(chain, store.read(0, 10));
    assertEquals(chain.subList(1, 4), store.read(1, 3));
    for (int i = 0; i < 5; i++) {
      assertEquals(chain.get(i), store.entryAt(i).orElseThrow());
    }
  }

  @Test
  @DisplayName("a stale-head append (right index, wrong previous hash) is refused")
  default void staleHeadRefused() {
    AuditChainStore store = newChainStore();
    List<AuditChainEntry> chain = TestkitChainEntries.chain(3);
    assertTrue(store.append(chain.get(0)));
    assertTrue(store.append(chain.get(1)));

    AuditChainEntry stale = TestkitChainEntries.entry(2,
        chain.get(0).entryHash(),
        "late".getBytes(StandardCharsets.UTF_8));
    assertFalse(store.append(stale));
    assertEquals(2, store.size());
  }

  @Test
  @DisplayName("an append with the wrong index is refused in both directions")
  default void wrongIndexRefused() {
    AuditChainStore store = newChainStore();
    List<AuditChainEntry> chain = TestkitChainEntries.chain(3);
    assertTrue(store.append(chain.get(0)));

    assertFalse(store.append(chain.get(2)), "an index beyond size must be refused");
    AuditChainEntry duplicateIndex = TestkitChainEntries.entry(0,
        AuditChainEntry.GENESIS_PREVIOUS_HASH,
        "other".getBytes(StandardCharsets.UTF_8));
    assertFalse(store.append(duplicateIndex), "an already-taken index must be refused");
    assertEquals(chain.get(0), store.entryAt(0).orElseThrow(),
        "append-only: the original entry can never be replaced");
  }

  @Test
  @DisplayName("paging is contiguous, ascending and tolerant of out-of-range reads")
  default void pagingSemantics() {
    AuditChainStore store = newChainStore();
    TestkitChainEntries.chain(4).forEach(entry -> assertTrue(store.append(entry)));

    List<AuditChainEntry> page = store.read(1, 2);
    assertEquals(2, page.size());
    assertEquals(1, page.get(0).index());
    assertEquals(2, page.get(1).index());
    assertEquals(page.get(0).entryHash(), page.get(1).previousEntryHash());
    assertTrue(store.read(4, 2).isEmpty());
    assertTrue(store.read(99, 2).isEmpty());
  }

  @Test
  @DisplayName("read validates its bounds")
  default void readValidatesBounds() {
    AuditChainStore store = newChainStore();
    assertThrows(IllegalArgumentException.class, () -> store.read(0, 0));
    assertThrows(IllegalArgumentException.class, () -> store.read(-1, 1));
  }
}
