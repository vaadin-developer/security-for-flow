package eu.jsentinel.jcustos.audit.integrity.verify;

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
import eu.jsentinel.jcustos.audit.integrity.chain.InMemoryAuditChainStore;
import eu.jsentinel.jcustos.audit.integrity.ChainTestFixtures;
import eu.jsentinel.jcustos.audit.integrity.verify.AuditChainVerificationResult.Broken;
import eu.jsentinel.jcustos.audit.integrity.verify.AuditChainVerificationResult.Empty;
import eu.jsentinel.jcustos.audit.integrity.verify.AuditChainVerificationResult.Valid;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@DisplayName("AuditIntegrityVerifier — tamper matrix and paged walks")
class AuditIntegrityVerifierTest {

  private final AuditIntegrityVerifier verifier = new AuditIntegrityVerifier();

  @Test
  @DisplayName("a valid chain verifies with count and head hash — paged and as range")
  void validChain() {
    List<AuditChainEntry> chain = ChainTestFixtures.chain(7);
    InMemoryAuditChainStore store = new InMemoryAuditChainStore();
    chain.forEach(store::append);

    Valid storeResult = assertInstanceOf(Valid.class,
        new AuditIntegrityVerifier(3).verify(store));
    assertEquals(7, storeResult.entryCount());
    assertEquals(chain.get(6).entryHash(), storeResult.headHash());

    Valid rangeResult = assertInstanceOf(Valid.class,
        verifier.verifyEntries(chain, AuditChainEntry.GENESIS_PREVIOUS_HASH));
    assertEquals(7, rangeResult.entryCount());
  }

  @Test
  @DisplayName("a mutated payload breaks at exactly its index (ENTRY_HASH_MISMATCH)")
  void mutatedPayloadDetected() {
    List<AuditChainEntry> chain = new ArrayList<>(ChainTestFixtures.chain(5));
    chain.set(2, ChainTestFixtures.tampered(chain.get(2), payload -> {
      payload[0] ^= 0x01;
      return payload;
    }));

    Broken broken = assertInstanceOf(Broken.class,
        verifier.verifyEntries(chain, AuditChainEntry.GENESIS_PREVIOUS_HASH));
    assertEquals(2, broken.atIndex());
    assertEquals(AuditChainBreakReason.ENTRY_HASH_MISMATCH, broken.reason());
  }

  @Test
  @DisplayName("a spliced (re-hashed) replacement entry breaks its successor's link")
  void splicedEntryDetectedAtSuccessor() {
    List<AuditChainEntry> chain = new ArrayList<>(ChainTestFixtures.chain(5));
    // A forged entry 2 that is self-consistent (correctly hashed) but carries
    // different content — entry 3 still links to the ORIGINAL hash.
    AuditChainEntry forged = ChainTestFixtures.entry(2,
        chain.get(1).entryHash(), "forged".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    chain.set(2, forged);

    Broken broken = assertInstanceOf(Broken.class,
        verifier.verifyEntries(chain, AuditChainEntry.GENESIS_PREVIOUS_HASH));
    assertEquals(3, broken.atIndex());
    assertEquals(AuditChainBreakReason.PREVIOUS_HASH_MISMATCH, broken.reason());
  }

  @Test
  @DisplayName("a removed entry surfaces as INDEX_GAP")
  void removedEntryDetected() {
    List<AuditChainEntry> chain = new ArrayList<>(ChainTestFixtures.chain(5));
    chain.remove(2);

    Broken broken = assertInstanceOf(Broken.class,
        verifier.verifyEntries(chain, AuditChainEntry.GENESIS_PREVIOUS_HASH));
    assertEquals(2, broken.atIndex());
    assertEquals(AuditChainBreakReason.INDEX_GAP, broken.reason());
  }

  @Test
  @DisplayName("a chain not anchored to the expected genesis violates the anchor")
  void genesisViolation() {
    List<AuditChainEntry> chain = List.of(ChainTestFixtures.entry(0,
        "1111111111111111111111111111111111111111111111111111111111111111",
        "p".getBytes(java.nio.charset.StandardCharsets.UTF_8)));

    Broken broken = assertInstanceOf(Broken.class,
        verifier.verifyEntries(chain, AuditChainEntry.GENESIS_PREVIOUS_HASH));
    assertEquals(0, broken.atIndex());
    assertEquals(AuditChainBreakReason.GENESIS_VIOLATION, broken.reason());
  }

  @Test
  @DisplayName("an unavailable digest fails closed as ALGORITHM_UNAVAILABLE")
  void unavailableAlgorithmFailsClosed() {
    AuditChainEntry bogus = new AuditChainEntry(0, ChainTestFixtures.AT,
        PayloadHashAlgorithm.of("NO-SUCH-DIGEST"),
        AuditChainEntry.GENESIS_PREVIOUS_HASH, "deadbeef",
        ChainTestFixtures.PAYLOAD_TYPE,
        "p".getBytes(java.nio.charset.StandardCharsets.UTF_8));

    Broken broken = assertInstanceOf(Broken.class,
        verifier.verifyEntries(List.of(bogus), AuditChainEntry.GENESIS_PREVIOUS_HASH));
    assertEquals(AuditChainBreakReason.ALGORITHM_UNAVAILABLE, broken.reason());
  }

  @Test
  @DisplayName("empty inputs verify as Empty")
  void emptyInputs() {
    assertInstanceOf(Empty.class, verifier.verify(new InMemoryAuditChainStore()));
    assertInstanceOf(Empty.class,
        verifier.verifyEntries(List.of(), AuditChainEntry.GENESIS_PREVIOUS_HASH));
  }

  @Test
  @DisplayName("a mid-chain range verifies against its predecessor's head hash")
  void midChainRange() {
    List<AuditChainEntry> chain = ChainTestFixtures.chain(6);
    Valid result = assertInstanceOf(Valid.class,
        verifier.verifyEntries(chain.subList(2, 5), chain.get(1).entryHash()));
    assertEquals(3, result.entryCount());
  }
}
