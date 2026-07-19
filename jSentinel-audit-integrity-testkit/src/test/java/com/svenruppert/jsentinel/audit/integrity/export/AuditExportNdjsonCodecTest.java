package com.svenruppert.jsentinel.audit.integrity.export;

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
import com.svenruppert.jsentinel.audit.integrity.chain.AuditChainAppender;
import com.svenruppert.jsentinel.audit.integrity.chain.AuditChainException;
import com.svenruppert.jsentinel.audit.integrity.chain.InMemoryAuditChainStore;
import com.svenruppert.jsentinel.audit.integrity.testkit.TestkitChainEntries;
import com.svenruppert.jsentinel.events.api.KeyId;
import com.svenruppert.jsentinel.events.keys.InMemoryKeyManagement;
import com.svenruppert.jsentinel.events.signature.Ed25519SignatureAlgorithm;
import com.svenruppert.jsentinel.events.signature.SignatureAlgorithms;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AuditExportNdjsonCodec — verifiable NDJSON wire form")
class AuditExportNdjsonCodecTest {

  private final AuditExportNdjsonCodec codec = new AuditExportNdjsonCodec();
  private final InMemoryKeyManagement keys =
      new InMemoryKeyManagement(new Ed25519SignatureAlgorithm(), KeyId.of("audit-key-1"));

  private AuditChainExport export(int length) {
    InMemoryAuditChainStore store = new InMemoryAuditChainStore();
    AuditChainAppender appender = new AuditChainAppender(store);
    for (int i = 0; i < length; i++) {
      appender.append("test/v1", ("payload-" + i).getBytes(StandardCharsets.UTF_8));
    }
    return new AuditExportService(store,
        new AuditBatchSigner(keys, () -> TestkitChainEntries.AT))
        .exportAll().orElseThrow();
  }

  @Test
  @DisplayName("encode -> decode round-trips the export by value")
  void roundTrip() {
    AuditChainExport export = export(4);
    AuditChainExport decoded = codec.decode(codec.encode(export));
    assertEquals(export.batch(), decoded.batch());
    assertEquals(export.entries(), decoded.entries());
  }

  @Test
  @DisplayName("RF01: a single trailing line terminator (file round-trip) is tolerated")
  void trailingNewlineTolerated() {
    AuditChainExport export = export(2);
    assertEquals(export.entries(),
        codec.decode(codec.encode(export) + "\n").entries());
    assertEquals(export.entries(),
        codec.decode(codec.encode(export) + "\r\n").entries());
    assertMalformed(codec.encode(export) + "\n\n");
  }

  @Test
  @DisplayName("a decoded export re-verifies with public material only")
  void decodedExportReVerifies() {
    AuditChainExport decoded = codec.decode(codec.encode(export(3)));
    assertInstanceOf(AuditBatchVerificationResult.Valid.class,
        new AuditBatchVerifier(keys, SignatureAlgorithms.defaults())
            .verify(decoded.batch(), decoded.entries()));
  }

  @Test
  @DisplayName("golden entry line — changing it is a wire-format break")
  void goldenEntryLine() {
    AuditChainEntry entry = TestkitChainEntries.chain(1).get(0);
    AuditChainExport export = new AuditChainExport(
        new AuditBatchSigner(keys, () -> TestkitChainEntries.AT).sign(List.of(entry)),
        List.of(entry));
    String entryLine = codec.encode(export).split("\n")[1];
    assertEquals("{\"algorithm\":\"SHA-256\""
            + ",\"appendedAt\":\"2026-07-19T10:15:30Z\""
            + ",\"entryHash\":\"" + entry.entryHash() + "\""
            + ",\"index\":0"
            + ",\"kind\":\"entry\""
            + ",\"payload\":\"" + Base64.getEncoder().encodeToString(entry.payload()) + "\""
            + ",\"payloadType\":\"testkit/v1\""
            + ",\"previousEntryHash\":\"jsentinel-audit-chain:genesis\""
            + ",\"v\":1}",
        entryLine);
  }

  @Test
  @DisplayName("a tampered payload inside the document decodes but fails verification at its index")
  void tamperedDocumentFailsVerification() {
    AuditChainExport export = export(3);
    String ndjson = codec.encode(export);
    String original = Base64.getEncoder()
        .encodeToString("payload-1".getBytes(StandardCharsets.UTF_8));
    String forged = Base64.getEncoder()
        .encodeToString("payload-X".getBytes(StandardCharsets.UTF_8));
    AuditChainExport tampered = codec.decode(ndjson.replace(original, forged));

    AuditBatchVerificationResult.ChainBroken broken = assertInstanceOf(
        AuditBatchVerificationResult.ChainBroken.class,
        new AuditBatchVerifier(keys, SignatureAlgorithms.defaults())
            .verify(tampered.batch(), tampered.entries()));
    assertEquals(1, broken.cause().atIndex());
  }

  @Test
  @DisplayName("structural violations are rejected with the malformed code")
  void malformedDocuments() {
    AuditChainExport export = export(2);
    String ndjson = codec.encode(export);

    assertMalformed("{}");
    assertMalformed("not json\nstill not json");
    assertMalformed(ndjson.split("\n")[1] + "\n" + ndjson.split("\n")[1]);
    String[] lines = ndjson.split("\n");
    assertMalformed(lines[0] + "\n" + lines[1]);
  }

  private void assertMalformed(String document) {
    AuditChainException ex = assertThrows(AuditChainException.class,
        () -> codec.decode(document));
    assertTrue(ex.getMessage().startsWith("audit-integrity/export-malformed"),
        "unexpected code: " + ex.getMessage());
  }
}
