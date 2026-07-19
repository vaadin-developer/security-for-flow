package com.svenruppert.jsentinel.audit.integrity.chain;

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
import com.svenruppert.jsentinel.events.api.PayloadHashAlgorithm;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;

/**
 * The single home of the audit-chain hash-base byte layout. The base is a
 * sequence of length-prefixed fields — {@code key=<len>:value\n} with UTF-8
 * byte lengths (raw byte length for the payload) — mirroring the framing
 * convention of the envelope signature base, which makes the encoding
 * injective: no field content can shift a field boundary. Field order is
 * part of the wire format:
 * <pre>
 * v=&lt;len&gt;:jsentinel-audit-chain/v1
 * index=&lt;len&gt;:&lt;decimal&gt;
 * appendedAt=&lt;len&gt;:&lt;Instant&gt;
 * algorithm=&lt;len&gt;:&lt;JCA name&gt;
 * previousEntryHash=&lt;len&gt;:&lt;value&gt;
 * payloadType=&lt;len&gt;:&lt;value&gt;
 * payload=&lt;byte-len&gt;:&lt;raw payload bytes&gt;
 * </pre>
 * The entry hash is the lower-case hex digest of that base; because
 * {@code previousEntryHash} sits inside the base, the digest chains
 * ({@code H(prev || entry)}).
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class AuditChainEntryHasher {

  /** Domain separator and version of the hash-base layout. */
  public static final String BASE_DOMAIN = "jsentinel-audit-chain/v1";

  static final String CODE_ALGORITHM_UNAVAILABLE = "audit-integrity/algorithm-unavailable";

  private static final String F_VERSION = "v";
  private static final String F_INDEX = "index";
  private static final String F_APPENDED_AT = "appendedAt";
  private static final String F_ALGORITHM = "algorithm";
  private static final String F_PREVIOUS = "previousEntryHash";
  private static final String F_PAYLOAD_TYPE = "payloadType";
  private static final String F_PAYLOAD = "payload";
  private static final HexFormat HEX = HexFormat.of();

  private AuditChainEntryHasher() {
  }

  /**
   * @return the lower-case hex entry hash of the canonical base
   * @throws AuditChainException code {@code audit-integrity/algorithm-unavailable}
   *     when the JCA digest is not available — fail closed, never a silent
   *     substitute digest
   */
  public static String computeEntryHash(long index, Instant appendedAt,
      PayloadHashAlgorithm algorithmId, String previousEntryHash,
      String payloadType, byte[] payload) {
    byte[] base = base(index, appendedAt, algorithmId, previousEntryHash,
        payloadType, payload);
    try {
      return HEX.formatHex(MessageDigest.getInstance(algorithmId.value()).digest(base));
    } catch (NoSuchAlgorithmException e) {
      throw new AuditChainException(CODE_ALGORITHM_UNAVAILABLE,
          "digest '" + algorithmId.value() + "' is not available in this JVM"
              + " — register the provider or migrate the chain to a supported"
              + " algorithm", e);
    }
  }

  /**
   * Soft variant for verification paths: an unavailable digest yields
   * {@link Optional#empty()} so the verifier can fail closed without
   * exception control flow (JS-SEC-054 posture).
   */
  public static Optional<String> tryComputeEntryHash(long index, Instant appendedAt,
      PayloadHashAlgorithm algorithmId, String previousEntryHash,
      String payloadType, byte[] payload) {
    try {
      return Optional.of(computeEntryHash(index, appendedAt, algorithmId,
          previousEntryHash, payloadType, payload));
    } catch (AuditChainException e) {
      return Optional.empty();
    }
  }

  private static byte[] base(long index, Instant appendedAt,
      PayloadHashAlgorithm algorithmId, String previousEntryHash,
      String payloadType, byte[] payload) {
    Objects.requireNonNull(appendedAt, "appendedAt");
    Objects.requireNonNull(algorithmId, "algorithmId");
    Objects.requireNonNull(previousEntryHash, "previousEntryHash");
    Objects.requireNonNull(payloadType, "payloadType");
    Objects.requireNonNull(payload, "payload");
    ByteArrayOutputStream base = new ByteArrayOutputStream();
    field(base, F_VERSION, BASE_DOMAIN.getBytes(StandardCharsets.UTF_8));
    field(base, F_INDEX, Long.toString(index).getBytes(StandardCharsets.UTF_8));
    field(base, F_APPENDED_AT, appendedAt.toString().getBytes(StandardCharsets.UTF_8));
    field(base, F_ALGORITHM, algorithmId.value().getBytes(StandardCharsets.UTF_8));
    field(base, F_PREVIOUS, previousEntryHash.getBytes(StandardCharsets.UTF_8));
    field(base, F_PAYLOAD_TYPE, payloadType.getBytes(StandardCharsets.UTF_8));
    field(base, F_PAYLOAD, payload);
    return base.toByteArray();
  }

  private static void field(ByteArrayOutputStream base, String key, byte[] value) {
    byte[] prefix = (key + "=" + value.length + ":").getBytes(StandardCharsets.UTF_8);
    base.write(prefix, 0, prefix.length);
    base.write(value, 0, value.length);
    base.write('\n');
  }
}
