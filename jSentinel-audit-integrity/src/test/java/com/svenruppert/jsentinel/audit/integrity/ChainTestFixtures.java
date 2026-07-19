package com.svenruppert.jsentinel.audit.integrity;

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

import com.svenruppert.jsentinel.audit.integrity.api.AuditChainEntry;
import com.svenruppert.jsentinel.audit.integrity.chain.AuditChainEntryHasher;
import com.svenruppert.jsentinel.events.api.PayloadHashAlgorithm;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.UnaryOperator;

/**
 * Module-local chain fixtures for the verifier/export tests. Mirrors the
 * published {@code TestkitChainEntries} of the testkit module — the tests
 * live HERE so PIT measures them against this module's mutants, and this
 * module cannot depend on its own testkit (Maven cycle).
 */
public final class ChainTestFixtures {

  public static final Instant AT = Instant.parse("2026-07-19T10:15:30Z");
  public static final String PAYLOAD_TYPE = "testkit/v1";

  private ChainTestFixtures() {
  }

  public static AuditChainEntry entry(long index, String previousEntryHash, byte[] payload) {
    String entryHash = AuditChainEntryHasher.computeEntryHash(
        index, AT, PayloadHashAlgorithm.SHA_256, previousEntryHash,
        PAYLOAD_TYPE, payload);
    return new AuditChainEntry(index, AT, PayloadHashAlgorithm.SHA_256,
        previousEntryHash, entryHash, PAYLOAD_TYPE, payload);
  }

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

  public static AuditChainEntry tampered(AuditChainEntry original,
      UnaryOperator<byte[]> payloadMutation) {
    return new AuditChainEntry(original.index(), original.appendedAt(),
        original.algorithmId(), original.previousEntryHash(),
        original.entryHash(), original.payloadType(),
        payloadMutation.apply(original.payload()));
  }
}
