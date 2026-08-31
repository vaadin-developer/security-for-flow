package eu.jsentinel.jcustos.events.siem;

/*-
 * #%L
 * jSentinel Events — SIEM exporter
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

import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.testkit.TestkitEnvelopes;
import eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SIEM formatters — golden lines, escaping, round-trip")
class SiemFormattersTest {

  private static final long AT_MILLIS = TestkitEnvelopes.AT.toEpochMilli();

  @Test
  @DisplayName("CEF golden line — changing it is a wire-format break")
  void cefGoldenLine() {
    String line = new CefEnvelopeFormatter().format(TestkitEnvelopes.envelope("env-1"));
    assertEquals("CEF:0|" + SiemProduct.VENDOR + "|" + SiemProduct.PRODUCT + "|"
            + SiemProduct.VERSION + "|LoginSucceeded|LoginSucceeded|3|"
            + "rt=" + AT_MILLIS + " end=" + AT_MILLIS
            + " suser=alice cnt=1"
            + " cs1Label=tenantId cs1=default"
            + " cs2Label=correlationId cs2=corr-env-1"
            + " cs3Label=producerId cs3=rest-service-primary"
            + " cs4Label=envelopeId cs4=env-1"
            + " cs5Label=payloadHash cs5=hash-env-1",
        line);
  }

  @Test
  @DisplayName("LEEF golden line — changing it is a wire-format break")
  void leefGoldenLine() {
    String line = new LeefEnvelopeFormatter().format(TestkitEnvelopes.envelope("env-1"));
    assertEquals("LEEF:2.0|" + SiemProduct.VENDOR + "|" + SiemProduct.PRODUCT + "|"
            + SiemProduct.VERSION + "|LoginSucceeded|"
            + "devTime=2026-06-24T10:15:30.000Z"
            + "\tdevTimeFormat=" + LeefEnvelopeFormatter.DEV_TIME_PATTERN
            + "\tsev=3"
            + "\tusrName=alice"
            + "\ttenantId=default"
            + "\tproducerId=rest-service-primary"
            + "\tenvelopeId=env-1"
            + "\teventId=evt-env-1"
            + "\tcorrelationId=corr-env-1"
            + "\tsequence=1"
            + "\tpayloadHash=hash-env-1",
        line);
  }

  @Test
  @DisplayName("JSON-lines metadata golden: codec projection, no payload/signature fields")
  void jsonLinesMetadataGolden() {
    SignedJSentinelEventEnvelope envelope = TestkitEnvelopes.envelope("env-1");
    String line = new JsonLinesEnvelopeFormatter().format(envelope);
    assertEquals(new EnvelopeWireCodec().encodeMetadata(envelope), line,
        "metadata mode must be exactly the codec's projection — one field home");
    assertFalse(line.contains("\"canonicalPayload\":"),
        "the payload field must be absent (the ...Hash field is kept)");
    assertFalse(line.contains("\"signature\":"));
    assertFalse(line.contains("\n"));
  }

  @Test
  @DisplayName("JSON-lines full mode round-trips through the shared wire codec")
  void jsonLinesFullRoundTrip() {
    SignedJSentinelEventEnvelope envelope = TestkitEnvelopes.envelope("env-rt");
    String line = new JsonLinesEnvelopeFormatter(true).format(envelope);
    assertEquals(envelope, new EnvelopeWireCodec().decode(line).getOrThrow());
  }

  @Test
  @DisplayName("CEF escaping: header escapes backslash and pipe; extensions escape backslash, '=' and newlines")
  void cefEscaping() {
    SignedJSentinelEventEnvelope envelope = SiemFixtures.envelopeWith(
        "env-esc", EventType.of("Weird|Type\\x"), "a=b\r\nc\\d");
    String line = new CefEnvelopeFormatter().format(envelope);
    assertTrue(line.contains("|Weird\\|Type\\\\x|"),
        "header escapes | and backslash: " + line);
    assertTrue(line.contains("suser=a\\=b\\nc\\\\d"),
        "extension escapes '=', CRLF (as literal \\n) and backslash: " + line);
    assertFalse(line.contains("\n"), "no raw line break may survive");
    assertFalse(line.contains("\r"));
  }

  @Test
  @DisplayName("LEEF escaping: header escapes pipe; attribute values replace tab/CR/LF with a space")
  void leefEscaping() {
    SignedJSentinelEventEnvelope envelope = SiemFixtures.envelopeWith(
        "env-esc", EventType.of("Weird|Type"), "a\tb\r\nc");
    String line = new LeefEnvelopeFormatter().format(envelope);
    assertTrue(line.contains("|Weird\\|Type|"), "header escapes |: " + line);
    assertTrue(line.contains("usrName=a b  c"),
        "tab and CR/LF each become a space: " + line);
    assertFalse(line.contains("\n"));
    assertFalse(line.contains("\r"));
  }

  @Test
  @DisplayName("CEF/LEEF mini-parse: header fields and key values are recoverable")
  void parseablePlainRecord() {
    SignedJSentinelEventEnvelope envelope = TestkitEnvelopes.envelope("env-parse");
    String[] cefHeader = new CefEnvelopeFormatter().format(envelope).split("\\|", 8);
    assertEquals("CEF:0", cefHeader[0]);
    assertEquals(SiemProduct.VENDOR, cefHeader[1]);
    assertEquals("LoginSucceeded", cefHeader[4]);
    assertEquals("3", cefHeader[6]);
    assertTrue(cefHeader[7].contains("cs4=env-parse"));

    String[] leefParts = new LeefEnvelopeFormatter().format(envelope).split("\\|", 6);
    assertEquals("LEEF:2.0", leefParts[0]);
    assertEquals("LoginSucceeded", leefParts[4]);
    String[] attributes = leefParts[5].split("\t");
    assertTrue(java.util.Arrays.asList(attributes).contains("envelopeId=env-parse"));
    assertTrue(java.util.Arrays.asList(attributes).contains("sequence=1"));
  }

  @Test
  @DisplayName("no formatter output carries payload bytes for the metadata modes")
  void metadataModesArePayloadFree() {
    SignedJSentinelEventEnvelope envelope = TestkitEnvelopes.envelope("env-free");
    String payload = new String(envelope.canonicalPayload(),
        java.nio.charset.StandardCharsets.UTF_8);
    assertFalse(new CefEnvelopeFormatter().format(envelope).contains(payload));
    assertFalse(new LeefEnvelopeFormatter().format(envelope).contains(payload));
    assertFalse(new JsonLinesEnvelopeFormatter().format(envelope)
        .contains(java.util.Base64.getEncoder().encodeToString(envelope.canonicalPayload())));
  }
}
