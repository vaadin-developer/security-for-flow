package com.svenruppert.jsentinel.audit.integrity.export;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.api.SignatureAlgorithmId;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

/**
 * A signed statement over a contiguous audit-chain range (Konzept goal 7).
 * Because the entries are hash-chained, signing the range endpoints plus the
 * head hash binds <em>every</em> entry in the range: any interior tamper
 * breaks the recomputed chain before the signature is even checked.
 * {@code firstPreviousHash} anchors the range into the earlier chain, so a
 * batch that does not start at genesis still verifies against its
 * predecessor's head.
 *
 * @param fromIndex          first included index
 * @param toIndex            last included index
 * @param entryCount         number of included entries
 * @param firstPreviousHash  the {@code previousEntryHash} of the first entry
 * @param batchHeadHash      the {@code entryHash} of the last entry
 * @param signedAt           signing time
 * @param keyId              the signing key id
 * @param signatureAlgorithm the signature algorithm id
 * @param signature          the raw signature bytes (defensively copied)
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public record SignedAuditBatch(
    long fromIndex,
    long toIndex,
    long entryCount,
    String firstPreviousHash,
    String batchHeadHash,
    Instant signedAt,
    KeyId keyId,
    SignatureAlgorithmId signatureAlgorithm,
    byte[] signature) {

  public SignedAuditBatch {
    if (fromIndex < 0 || toIndex < fromIndex) {
      throw new IllegalArgumentException("invalid range [" + fromIndex + ", " + toIndex + "]");
    }
    if (entryCount != toIndex - fromIndex + 1) {
      throw new IllegalArgumentException("entryCount must match the range");
    }
    requireNonBlank(firstPreviousHash, "firstPreviousHash");
    requireNonBlank(batchHeadHash, "batchHeadHash");
    Objects.requireNonNull(signedAt, "signedAt");
    Objects.requireNonNull(keyId, "keyId");
    Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm");
    Objects.requireNonNull(signature, "signature");
    if (signature.length == 0) {
      throw new IllegalArgumentException("signature must not be empty");
    }
    signature = signature.clone();
  }

  /** @return a defensive copy of the signature bytes */
  @Override
  public byte[] signature() {
    return signature.clone();
  }

  @Override
  public boolean equals(Object other) {
    return other instanceof SignedAuditBatch that
        && fromIndex == that.fromIndex
        && toIndex == that.toIndex
        && entryCount == that.entryCount
        && firstPreviousHash.equals(that.firstPreviousHash)
        && batchHeadHash.equals(that.batchHeadHash)
        && signedAt.equals(that.signedAt)
        && keyId.equals(that.keyId)
        && signatureAlgorithm.equals(that.signatureAlgorithm)
        && Arrays.equals(signature, that.signature);
  }

  @Override
  public int hashCode() {
    int result = Objects.hash(fromIndex, toIndex, entryCount, firstPreviousHash,
        batchHeadHash, signedAt, keyId, signatureAlgorithm);
    return 31 * result + Arrays.hashCode(signature);
  }

  @Override
  public String toString() {
    return "SignedAuditBatch[range=[" + fromIndex + ", " + toIndex + "]"
        + ", entryCount=" + entryCount
        + ", batchHeadHash=" + batchHeadHash
        + ", signedAt=" + signedAt
        + ", keyId=" + keyId.value()
        + ", signatureAlgorithm=" + signatureAlgorithm.value()
        + ", signature=" + signature.length + " bytes]";
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be null or blank");
    }
  }
}
