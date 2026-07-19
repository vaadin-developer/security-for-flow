package com.svenruppert.jsentinel.audit.integrity.testkit;

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

import com.svenruppert.jsentinel.audit.integrity.api.AuditChainEntry;
import com.svenruppert.jsentinel.audit.integrity.chain.AuditChainEntryHasher;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.PayloadHashAlgorithm;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;

/**
 * Deterministic, correctly-hashed chain fixtures for contract and verifier
 * tests, plus tamper helpers that keep the original {@code entryHash} so a
 * verifier can prove the break.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class TestkitChainEntries {

  /** The reference instant every fixture entry is anchored to. */
  public static final Instant AT = Instant.parse("2026-07-19T10:15:30Z");

  /** Payload type of the fixture entries. */
  public static final String PAYLOAD_TYPE = "testkit/v1";

  private TestkitChainEntries() {
  }

  /**
   * @param index             the entry position
   * @param previousEntryHash the predecessor's hash (or the genesis constant)
   * @param payload           the payload bytes
   * @return a correctly hashed SHA-256 entry anchored to {@link #AT}
   */
  public static AuditChainEntry entry(long index, String previousEntryHash, byte[] payload) {
    String entryHash = AuditChainEntryHasher.computeEntryHash(
        index, AT, PayloadHashAlgorithm.SHA_256, previousEntryHash,
        PAYLOAD_TYPE, payload);
    return new AuditChainEntry(index, AT, PayloadHashAlgorithm.SHA_256,
        previousEntryHash, entryHash, PAYLOAD_TYPE, payload);
  }

  /**
   * @param length the chain length
   * @return a valid genesis-rooted chain with deterministic payloads
   *     ({@code payload-<i>})
   */
  public static List<AuditChainEntry> chain(int length) {
    List<AuditChainEntry> entries = new ArrayList<>(length);
    String previous = AuditChainEntry.GENESIS_PREVIOUS_HASH;
    for (int i = 0; i < length; i++) {
      AuditChainEntry entry = entry(i, previous,
          ("payload-" + i).getBytes(StandardCharsets.UTF_8));
      entries.add(entry);
      previous = entry.entryHash();
    }
    return List.copyOf(entries);
  }

  /**
   * @param original the intact entry
   * @param payloadMutation the tamper applied to the payload bytes
   * @return a copy carrying the mutated payload but the ORIGINAL
   *     {@code entryHash} — the shape a storage-level tamper produces, which
   *     a verifier must detect as an entry-hash mismatch
   */
  public static AuditChainEntry tampered(AuditChainEntry original,
      UnaryOperator<byte[]> payloadMutation) {
    return new AuditChainEntry(original.index(), original.appendedAt(),
        original.algorithmId(), original.previousEntryHash(),
        original.entryHash(), original.payloadType(),
        payloadMutation.apply(original.payload()));
  }

  /**
   * @param original the intact entry
   * @param entryHash the replacement hash
   * @return a copy with the replaced {@code entryHash} (all other components
   *     unchanged)
   */
  public static AuditChainEntry withEntryHash(AuditChainEntry original, String entryHash) {
    return new AuditChainEntry(original.index(), original.appendedAt(),
        original.algorithmId(), original.previousEntryHash(),
        entryHash, original.payloadType(), original.payload());
  }
}
