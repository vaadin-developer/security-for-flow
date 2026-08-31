package eu.jsentinel.jcustos.events.api;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * Signed, transportable wrapper around a single security event (Konzept §296).
 *
 * <p>The envelope carries business metadata, technical producer data,
 * replay-protection identity, sequence information and the signature itself.
 * The signature protects not only the payload but the security-relevant
 * metadata (tenant, event type, expiry, producer, sequence), so none of those
 * can be tampered with without invalidating the signature (Konzept §347).
 *
 * <p>The payload itself is bound through {@link #canonicalPayloadHash()},
 * allowing a verifier to check the payload hash first and the full signature
 * base afterwards.
 *
 * <p>All fields except {@link #causationId()} are mandatory. The two
 * {@code byte[]} components are defensively copied on construction and on
 * access, and {@link #equals(Object)} / {@link #hashCode()} use value
 * semantics over their contents so envelopes compare by content.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record SignedJCustosEventEnvelope(
    EventEnvelopeId envelopeId,
    EventId eventId,
    EventType eventType,
    TenantId tenantId,
    SubjectId subjectId,
    EventProducerId producerId,
    Instant occurredAt,
    Instant issuedAt,
    Instant expiresAt,
    CorrelationId correlationId,
    CausationId causationId,
    EventSequence sequence,
    KeyId keyId,
    SignatureAlgorithmId signatureAlgorithm,
    PayloadContentType payloadContentType,
    PayloadHashAlgorithm payloadHashAlgorithm,
    String canonicalPayloadHash,
    byte[] canonicalPayload,
    byte[] signature
) {

  public SignedJCustosEventEnvelope {
    Objects.requireNonNull(envelopeId, "envelopeId");
    Objects.requireNonNull(eventId, "eventId");
    Objects.requireNonNull(eventType, "eventType");
    Objects.requireNonNull(tenantId, "tenantId");
    Objects.requireNonNull(subjectId, "subjectId");
    Objects.requireNonNull(producerId, "producerId");
    Objects.requireNonNull(occurredAt, "occurredAt");
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(correlationId, "correlationId");
    // causationId is optional (root events have no cause)
    Objects.requireNonNull(sequence, "sequence");
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
    Objects.requireNonNull(payloadContentType, "payloadContentType");
    Objects.requireNonNull(payloadHashAlgorithm, "payloadHashAlgorithm");
    if (canonicalPayloadHash == null || canonicalPayloadHash.isBlank()) {
      throw new IllegalArgumentException("canonicalPayloadHash must not be null or blank");
    }
    Objects.requireNonNull(canonicalPayload, "canonicalPayload");
    Objects.requireNonNull(signature, "signature");
    canonicalPayload = canonicalPayload.clone();
    signature = signature.clone();
  }

  /**
   * @return a defensive copy of the canonical payload bytes
   */
  @Override
  public byte[] canonicalPayload() {
    return canonicalPayload.clone();
  }

  /**
   * @return a defensive copy of the signature bytes
   */
  @Override
  public byte[] signature() {
    return signature.clone();
  }

  /**
   * @return {@code true} if this envelope is past its acceptance window at
   *     {@code now}
   */
  public boolean isExpiredAt(Instant now) {
    return now.isAfter(expiresAt);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof SignedJCustosEventEnvelope other)) {
      return false;
    }
    return Objects.equals(envelopeId, other.envelopeId)
        && Objects.equals(eventId, other.eventId)
        && Objects.equals(eventType, other.eventType)
        && Objects.equals(tenantId, other.tenantId)
        && Objects.equals(subjectId, other.subjectId)
        && Objects.equals(producerId, other.producerId)
        && Objects.equals(occurredAt, other.occurredAt)
        && Objects.equals(issuedAt, other.issuedAt)
        && Objects.equals(expiresAt, other.expiresAt)
        && Objects.equals(correlationId, other.correlationId)
        && Objects.equals(causationId, other.causationId)
        && Objects.equals(sequence, other.sequence)
        && Objects.equals(keyId, other.keyId)
        && Objects.equals(signatureAlgorithm, other.signatureAlgorithm)
        && Objects.equals(payloadContentType, other.payloadContentType)
        && Objects.equals(payloadHashAlgorithm, other.payloadHashAlgorithm)
        && Objects.equals(canonicalPayloadHash, other.canonicalPayloadHash)
        && Arrays.equals(canonicalPayload, other.canonicalPayload)
        && Arrays.equals(signature, other.signature);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(envelopeId, eventId, eventType, tenantId, subjectId,
        producerId, occurredAt, issuedAt, expiresAt, correlationId, causationId,
        sequence, keyId, signatureAlgorithm, payloadContentType, payloadHashAlgorithm,
        canonicalPayloadHash);
    result = 31 * result + Arrays.hashCode(canonicalPayload);
    result = 31 * result + Arrays.hashCode(signature);
    return result;
  }

  @Override
  public String toString() {
    return "SignedJCustosEventEnvelope[envelopeId=" + envelopeId
        + ", eventType=" + eventType
        + ", tenantId=" + tenantId
        + ", producerId=" + producerId
        + ", sequence=" + sequence
        + ", keyId=" + keyId
        + ", signatureAlgorithm=" + signatureAlgorithm
        + ", payloadContentType=" + payloadContentType
        + ", canonicalPayload=" + canonicalPayload.length + "B"
        + ", signature=" + signature.length + "B]";
  }
}
