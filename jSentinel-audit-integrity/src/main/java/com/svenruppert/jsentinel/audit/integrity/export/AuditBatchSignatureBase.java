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

import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.api.SignatureAlgorithmId;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

/**
 * The byte base an audit-batch signature covers. Length-prefixed
 * {@code key=<len>:value\n} framing (injective — mirrors the entry hasher's
 * layout with its own domain separator) over every batch component except
 * the signature itself. Field order is part of the wire format.
 */
final class AuditBatchSignatureBase {

  /** Domain separator and version of the batch signature base. */
  static final String BASE_DOMAIN = "jsentinel-audit-batch/v1";

  private AuditBatchSignatureBase() {
  }

  static byte[] compute(long fromIndex, long toIndex, long entryCount,
      String firstPreviousHash, String batchHeadHash, Instant signedAt,
      KeyId keyId, SignatureAlgorithmId signatureAlgorithm) {
    ByteArrayOutputStream base = new ByteArrayOutputStream();
    field(base, "v", BASE_DOMAIN);
    field(base, "fromIndex", Long.toString(fromIndex));
    field(base, "toIndex", Long.toString(toIndex));
    field(base, "entryCount", Long.toString(entryCount));
    field(base, "firstPreviousHash", firstPreviousHash);
    field(base, "batchHeadHash", batchHeadHash);
    field(base, "signedAt", signedAt.toString());
    field(base, "keyId", keyId.value());
    field(base, "signatureAlgorithm", signatureAlgorithm.value());
    return base.toByteArray();
  }

  private static void field(ByteArrayOutputStream base, String key, String value) {
    byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
    byte[] prefix = (key + "=" + valueBytes.length + ":").getBytes(StandardCharsets.UTF_8);
    base.write(prefix, 0, prefix.length);
    base.write(valueBytes, 0, valueBytes.length);
    base.write('\n');
  }
}
