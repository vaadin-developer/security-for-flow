package eu.jsentinel.jcustos.audit.integrity.chain;

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
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AuditChainEntryHasher — the hash-base wire format")
class AuditChainEntryHasherTest {

  private static final Instant AT = Instant.parse("2026-07-19T10:15:30Z");
  private static final String GENESIS = AuditChainEntry.GENESIS_PREVIOUS_HASH;
  private static final byte[] HELLO = "hello".getBytes(StandardCharsets.UTF_8);

  @Test
  @DisplayName("golden value — changing this hash is a wire-format break of every stored chain")
  void goldenValue() {
    // Computed once from the documented base layout (length-prefixed
    // key=<len>:value\n fields, domain jsentinel-audit-chain/v1, SHA-256).
    assertEquals("ef47f2f544ebdcafc50875c1bf2c3051d665165a96210dbb90618322850aa992",
        AuditChainEntryHasher.computeEntryHash(
            0, AT, PayloadHashAlgorithm.SHA_256, GENESIS, "test/v1", HELLO));
  }

  @Test
  @DisplayName("every field flips the hash")
  void everyFieldFlipsTheHash() {
    String reference = AuditChainEntryHasher.computeEntryHash(
        0, AT, PayloadHashAlgorithm.SHA_256, GENESIS, "test/v1", HELLO);
    Set<String> variants = new HashSet<>();
    variants.add(AuditChainEntryHasher.computeEntryHash(
        1, AT, PayloadHashAlgorithm.SHA_256, GENESIS, "test/v1", HELLO));
    variants.add(AuditChainEntryHasher.computeEntryHash(
        0, AT.plusSeconds(1), PayloadHashAlgorithm.SHA_256, GENESIS, "test/v1", HELLO));
    variants.add(AuditChainEntryHasher.computeEntryHash(
        0, AT, PayloadHashAlgorithm.of("SHA-512"), GENESIS, "test/v1", HELLO));
    variants.add(AuditChainEntryHasher.computeEntryHash(
        0, AT, PayloadHashAlgorithm.SHA_256, "other-previous", "test/v1", HELLO));
    variants.add(AuditChainEntryHasher.computeEntryHash(
        0, AT, PayloadHashAlgorithm.SHA_256, GENESIS, "test/v2", HELLO));
    variants.add(AuditChainEntryHasher.computeEntryHash(
        0, AT, PayloadHashAlgorithm.SHA_256, GENESIS, "test/v1",
        "hellO".getBytes(StandardCharsets.UTF_8)));

    assertFalse(variants.contains(reference));
    assertEquals(6, variants.size(), "each variation must produce a distinct hash");
  }

  @Test
  @DisplayName("length-prefix framing is injective — shifted field content cannot collide")
  void framingIsInjective() {
    // Without length prefixes both calls would concatenate identically.
    String first = AuditChainEntryHasher.computeEntryHash(
        0, AT, PayloadHashAlgorithm.SHA_256, GENESIS, "a", "b-payload".getBytes(StandardCharsets.UTF_8));
    String second = AuditChainEntryHasher.computeEntryHash(
        0, AT, PayloadHashAlgorithm.SHA_256, GENESIS, "a\npayload=1:b", "-payload".getBytes(StandardCharsets.UTF_8));
    assertNotEquals(first, second);
  }

  @Test
  @DisplayName("the genesis constant can never collide with a real hex digest")
  void genesisIsNotHex() {
    assertFalse(GENESIS.matches("^[0-9a-f]+$"));
  }

  @Test
  @DisplayName("an unavailable digest fails closed")
  void unavailableAlgorithmFailsClosed() {
    PayloadHashAlgorithm bogus = PayloadHashAlgorithm.of("NO-SUCH-DIGEST");
    AuditChainException ex = assertThrows(AuditChainException.class, () ->
        AuditChainEntryHasher.computeEntryHash(
            0, AT, bogus, GENESIS, "test/v1", HELLO));
    assertEquals(AuditChainEntryHasher.CODE_ALGORITHM_UNAVAILABLE, ex.code());
    assertTrue(AuditChainEntryHasher.tryComputeEntryHash(
        0, AT, bogus, GENESIS, "test/v1", HELLO).isEmpty());
  }
}
