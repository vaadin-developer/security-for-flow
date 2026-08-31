package eu.jsentinel.jcustos.audit.integrity.export;

/*-
 * #%L
 * jCustos Audit Integrity — tamper-evident audit
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

import com.svenruppert.dependencies.core.net.MediaType;
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainEntry;
import eu.jsentinel.jcustos.audit.integrity.chain.AuditChainException;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.KeyId;
import eu.jsentinel.jcustos.events.api.PayloadHashAlgorithm;
import eu.jsentinel.jcustos.events.api.SignatureAlgorithmId;
import eu.jsentinel.jcustos.events.codec.CanonicalJson;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The NDJSON wire form of a verifiable export ({@code application/x-ndjson}):
 * line 1 is the batch header object, every further line one chain entry —
 * each line a self-contained JSON object with a {@code kind} discriminator
 * and a {@code v} format version. Binary fields travel Base64-encoded.
 * Written and parsed with the hardened canonical-JSON engine of the events
 * module (sorted keys, deterministic escaping, depth cap), so
 * {@code encode} output is byte-deterministic.
 * <p>
 * Independent re-verification = {@link #decode(String)} +
 * {@link AuditBatchVerifier} — nothing but the NDJSON text and public key
 * material is needed.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class AuditExportNdjsonCodec {

  static final String CODE_MALFORMED = "audit-integrity/export-malformed";

  private static final long FORMAT_VERSION = 1L;
  private static final String F_KIND = "kind";
  private static final String F_VERSION = "v";
  private static final String KIND_BATCH = "batch";
  private static final String KIND_ENTRY = "entry";
  private static final String F_FROM_INDEX = "fromIndex";
  private static final String F_TO_INDEX = "toIndex";
  private static final String F_ENTRY_COUNT = "entryCount";
  private static final String F_FIRST_PREVIOUS_HASH = "firstPreviousHash";
  private static final String F_BATCH_HEAD_HASH = "batchHeadHash";
  private static final String F_SIGNED_AT = "signedAt";
  private static final String F_KEY_ID = "keyId";
  private static final String F_SIGNATURE_ALGORITHM = "signatureAlgorithm";
  private static final String F_SIGNATURE = "signature";
  private static final String F_INDEX = "index";
  private static final String F_APPENDED_AT = "appendedAt";
  private static final String F_ALGORITHM = "algorithm";
  private static final String F_PREVIOUS_ENTRY_HASH = "previousEntryHash";
  private static final String F_ENTRY_HASH = "entryHash";
  private static final String F_PAYLOAD_TYPE = "payloadType";
  private static final String F_PAYLOAD = "payload";

  private static final Base64.Encoder ENCODER = Base64.getEncoder();
  private static final Base64.Decoder DECODER = Base64.getDecoder();

  /** @return the export's media type, {@code application/x-ndjson} */
  public MediaType contentType() {
    return MediaType.APPLICATION_NDJSON;
  }

  /**
   * @param export the verifiable export
   * @return its NDJSON form (no trailing newline)
   */
  public String encode(AuditChainExport export) {
    Objects.requireNonNull(export, "export");
    StringBuilder out = new StringBuilder();
    writeLine(out, batchFields(export.batch()));
    for (AuditChainEntry entry : export.entries()) {
      out.append('\n');
      writeLine(out, entryFields(entry));
    }
    return out.toString();
  }

  /**
   * Strict parse of the NDJSON form. One trailing line terminator is
   * tolerated (RF01): POSIX tools and the SIEM exporter terminate text
   * files with a newline, and a file round-trip must decode.
   *
   * @param ndjson the export text
   * @return the reconstructed export
   * @throws AuditChainException code {@code audit-integrity/export-malformed}
   *     on any structural violation
   */
  public AuditChainExport decode(String ndjson) {
    Objects.requireNonNull(ndjson, "ndjson");
    String document = ndjson;
    if (document.endsWith("\n")) {
      document = document.substring(0, document.length() - 1);
    }
    if (document.endsWith("\r")) {
      document = document.substring(0, document.length() - 1);
    }
    String[] lines = document.split("\n", -1);
    if (lines.length < 2) {
      throw malformed("an export needs a batch line and at least one entry line");
    }
    Map<String, Object> batchLine = parseLine(lines[0], KIND_BATCH, 1);
    SignedAuditBatch batch = toBatch(batchLine);
    List<AuditChainEntry> entries = new ArrayList<>(lines.length - 1);
    for (int i = 1; i < lines.length; i++) {
      entries.add(toEntry(parseLine(lines[i], KIND_ENTRY, i + 1)));
    }
    if (entries.size() != batch.entryCount()) {
      throw malformed("the batch declares " + batch.entryCount()
          + " entries but the document carries " + entries.size());
    }
    try {
      return new AuditChainExport(batch, entries);
    } catch (IllegalArgumentException e) {
      throw malformed(e.getMessage());
    }
  }

  private static Map<String, Object> batchFields(SignedAuditBatch batch) {
    Map<String, Object> f = new LinkedHashMap<>();
    f.put(F_KIND, KIND_BATCH);
    f.put(F_VERSION, FORMAT_VERSION);
    f.put(F_FROM_INDEX, batch.fromIndex());
    f.put(F_TO_INDEX, batch.toIndex());
    f.put(F_ENTRY_COUNT, batch.entryCount());
    f.put(F_FIRST_PREVIOUS_HASH, batch.firstPreviousHash());
    f.put(F_BATCH_HEAD_HASH, batch.batchHeadHash());
    f.put(F_SIGNED_AT, batch.signedAt().toString());
    f.put(F_KEY_ID, batch.keyId().value());
    f.put(F_SIGNATURE_ALGORITHM, batch.signatureAlgorithm().value());
    f.put(F_SIGNATURE, ENCODER.encodeToString(batch.signature()));
    return f;
  }

  private static Map<String, Object> entryFields(AuditChainEntry entry) {
    Map<String, Object> f = new LinkedHashMap<>();
    f.put(F_KIND, KIND_ENTRY);
    f.put(F_VERSION, FORMAT_VERSION);
    f.put(F_INDEX, entry.index());
    f.put(F_APPENDED_AT, entry.appendedAt().toString());
    f.put(F_ALGORITHM, entry.algorithmId().value());
    f.put(F_PREVIOUS_ENTRY_HASH, entry.previousEntryHash());
    f.put(F_ENTRY_HASH, entry.entryHash());
    f.put(F_PAYLOAD_TYPE, entry.payloadType());
    f.put(F_PAYLOAD, ENCODER.encodeToString(entry.payload()));
    return f;
  }

  private static void writeLine(StringBuilder out, Map<String, Object> fields) {
    CanonicalJson.write(out, fields);
  }

  private static Map<String, Object> parseLine(String line, String expectedKind,
      int lineNumber) {
    Object parsed;
    try {
      parsed = CanonicalJson.parse(line);
    } catch (RuntimeException e) {
      throw malformed("line " + lineNumber + " is not canonical JSON");
    }
    if (!(parsed instanceof Map<?, ?> map)) {
      throw malformed("line " + lineNumber + " is not a JSON object");
    }
    @SuppressWarnings("unchecked")
    Map<String, Object> fields = (Map<String, Object>) map;
    if (!expectedKind.equals(fields.get(F_KIND))) {
      throw malformed("line " + lineNumber + " must be of kind '" + expectedKind + "'");
    }
    if (!Long.valueOf(FORMAT_VERSION).equals(fields.get(F_VERSION))) {
      throw malformed("line " + lineNumber + " carries an unsupported format version");
    }
    return fields;
  }

  private static SignedAuditBatch toBatch(Map<String, Object> f) {
    try {
      return new SignedAuditBatch(
          longField(f, F_FROM_INDEX),
          longField(f, F_TO_INDEX),
          longField(f, F_ENTRY_COUNT),
          stringField(f, F_FIRST_PREVIOUS_HASH),
          stringField(f, F_BATCH_HEAD_HASH),
          Instant.parse(stringField(f, F_SIGNED_AT)),
          KeyId.of(stringField(f, F_KEY_ID)),
          new SignatureAlgorithmId(stringField(f, F_SIGNATURE_ALGORITHM)),
          DECODER.decode(stringField(f, F_SIGNATURE)));
    } catch (IllegalArgumentException | DateTimeParseException e) {
      throw malformed("invalid batch header: " + e.getMessage());
    }
  }

  private static AuditChainEntry toEntry(Map<String, Object> f) {
    try {
      return new AuditChainEntry(
          longField(f, F_INDEX),
          Instant.parse(stringField(f, F_APPENDED_AT)),
          PayloadHashAlgorithm.of(stringField(f, F_ALGORITHM)),
          stringField(f, F_PREVIOUS_ENTRY_HASH),
          stringField(f, F_ENTRY_HASH),
          stringField(f, F_PAYLOAD_TYPE),
          DECODER.decode(stringField(f, F_PAYLOAD)));
    } catch (IllegalArgumentException | DateTimeParseException e) {
      throw malformed("invalid entry line: " + e.getMessage());
    }
  }

  private static long longField(Map<String, Object> fields, String name) {
    if (fields.get(name) instanceof Long value) {
      return value;
    }
    throw malformed("field '" + name + "' must be an integer");
  }

  private static String stringField(Map<String, Object> fields, String name) {
    if (fields.get(name) instanceof String value) {
      return value;
    }
    throw malformed("field '" + name + "' must be a string");
  }

  private static AuditChainException malformed(String detail) {
    return new AuditChainException(CODE_MALFORMED, detail);
  }
}
