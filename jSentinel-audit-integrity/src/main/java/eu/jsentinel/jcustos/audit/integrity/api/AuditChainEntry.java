package eu.jsentinel.jcustos.audit.integrity.api;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * One link of the tamper-evident audit hash chain (Konzept goal 7,
 * V00.80.00). The {@code entryHash} is the digest of a length-prefixed
 * canonical base covering every other component — including
 * {@code previousEntryHash}, which gives the {@code H(prev || entry)}
 * chaining property: mutating any stored entry breaks its own hash, and
 * replacing an entry wholesale breaks its successor's
 * {@code previousEntryHash} link.
 * <p>
 * {@code algorithmId} reuses {@link PayloadHashAlgorithm} from the events
 * module as the per-entry algorithm-agility field: a chain may migrate
 * digests mid-chain, and a verifier recomputes each entry with the
 * algorithm recorded <em>in that entry</em>.
 *
 * @param index             0-based, gap-free position in the chain
 * @param appendedAt        the chain clock at append time (part of the base)
 * @param algorithmId       the JCA digest of {@code entryHash}
 * @param previousEntryHash the predecessor's {@code entryHash}, or
 *                          {@link #GENESIS_PREVIOUS_HASH} at index 0
 * @param entryHash         lower-case hex digest of the canonical base
 * @param payloadType       caller-defined payload discriminator
 *                          (e.g. {@code jsentinel-event/canonical-json/v1})
 * @param payload           the canonical payload bytes (defensively copied)
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public record AuditChainEntry(
    long index,
    Instant appendedAt,
    PayloadHashAlgorithm algorithmId,
    String previousEntryHash,
    String entryHash,
    String payloadType,
    byte[] payload) {

  /**
   * The {@code previousEntryHash} of the genesis entry — deliberately not a
   * hex string, so it can never collide with a real digest.
   */
  public static final String GENESIS_PREVIOUS_HASH = "jsentinel-audit-chain:genesis";

  public AuditChainEntry {
    if (index < 0) {
      throw new IllegalArgumentException("index must be >= 0");
    }
    Objects.requireNonNull(appendedAt, "appendedAt");
    Objects.requireNonNull(algorithmId, "algorithmId");
    requireNonBlank(previousEntryHash, "previousEntryHash");
    requireNonBlank(entryHash, "entryHash");
    requireNonBlank(payloadType, "payloadType");
    Objects.requireNonNull(payload, "payload");
    payload = payload.clone();
  }

  /** @return a defensive copy of the canonical payload bytes */
  @Override
  public byte[] payload() {
    return payload.clone();
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof AuditChainEntry that
        && index == that.index
        && appendedAt.equals(that.appendedAt)
        && algorithmId.equals(that.algorithmId)
        && previousEntryHash.equals(that.previousEntryHash)
        && entryHash.equals(that.entryHash)
        && payloadType.equals(that.payloadType)
        && Arrays.equals(payload, that.payload);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(index, appendedAt, algorithmId,
        previousEntryHash, entryHash, payloadType);
    return 31 * result + Arrays.hashCode(payload);
  }

  @Override
  public String toString() {
    // No payload dump — the payload may carry subject data.
    return "AuditChainEntry[index=" + index
        + ", appendedAt=" + appendedAt
        + ", algorithmId=" + algorithmId.value()
        + ", previousEntryHash=" + previousEntryHash
        + ", entryHash=" + entryHash
        + ", payloadType=" + payloadType
        + ", payload=" + payload.length + " bytes]";
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be null or blank");
    }
  }
}
