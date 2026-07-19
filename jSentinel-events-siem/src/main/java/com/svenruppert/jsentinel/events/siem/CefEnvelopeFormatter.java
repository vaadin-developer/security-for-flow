package com.svenruppert.jsentinel.events.siem;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;

/**
 * Formats an envelope as one ArcSight CEF version 0 record:
 * {@code CEF:0|vendor|product|version|signatureId|name|severity|extensions}.
 * Signature id and name both carry the event type; the severity comes from
 * {@link SiemSeverity}. Header fields escape {@code \} and {@code |} and
 * replace CR/LF with a space; extension values escape {@code \} and
 * {@code =} and encode CR/LF as the literal two characters {@code \n}, per
 * the CEF escaping rules.
 * <p>
 * Extensions carry envelope <em>metadata only</em> — never the payload,
 * never the signature; the payload hash is the verifiable reference.
 * {@code LogFieldScrubber} is deliberately not used here: it replaces
 * spaces, which are legal inside CEF extension values.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class CefEnvelopeFormatter implements SiemEnvelopeFormatter {

  private static final String CEF_HEADER = "CEF:0";
  private static final char HEADER_SEPARATOR = '|';
  private static final char EXTENSION_SEPARATOR = ' ';

  static final String EXT_RECEIPT_TIME = "rt";
  static final String EXT_END_TIME = "end";
  static final String EXT_SOURCE_USER = "suser";
  static final String EXT_COUNT = "cnt";
  static final String EXT_TENANT_LABEL = "cs1Label";
  static final String EXT_TENANT = "cs1";
  static final String EXT_CORRELATION_LABEL = "cs2Label";
  static final String EXT_CORRELATION = "cs2";
  static final String EXT_PRODUCER_LABEL = "cs3Label";
  static final String EXT_PRODUCER = "cs3";
  static final String EXT_ENVELOPE_LABEL = "cs4Label";
  static final String EXT_ENVELOPE = "cs4";
  static final String EXT_PAYLOAD_HASH_LABEL = "cs5Label";
  static final String EXT_PAYLOAD_HASH = "cs5";

  static final String LABEL_TENANT = "tenantId";
  static final String LABEL_CORRELATION = "correlationId";
  static final String LABEL_PRODUCER = "producerId";
  static final String LABEL_ENVELOPE = "envelopeId";
  static final String LABEL_PAYLOAD_HASH = "payloadHash";

  @Override
  public String format(SignedJSentinelEventEnvelope e) {
    String type = headerEscape(e.eventType().value());
    StringBuilder sb = new StringBuilder(CEF_HEADER)
        .append(HEADER_SEPARATOR).append(headerEscape(SiemProduct.VENDOR))
        .append(HEADER_SEPARATOR).append(headerEscape(SiemProduct.PRODUCT))
        .append(HEADER_SEPARATOR).append(headerEscape(SiemProduct.VERSION))
        .append(HEADER_SEPARATOR).append(type)
        .append(HEADER_SEPARATOR).append(type)
        .append(HEADER_SEPARATOR).append(SiemSeverity.severityFor(e.eventType()))
        .append(HEADER_SEPARATOR);
    extension(sb, true, EXT_RECEIPT_TIME, String.valueOf(e.occurredAt().toEpochMilli()));
    extension(sb, false, EXT_END_TIME, String.valueOf(e.issuedAt().toEpochMilli()));
    extension(sb, false, EXT_SOURCE_USER, e.subjectId().value());
    extension(sb, false, EXT_COUNT, String.valueOf(e.sequence().value()));
    extension(sb, false, EXT_TENANT_LABEL, LABEL_TENANT);
    extension(sb, false, EXT_TENANT, e.tenantId().value());
    extension(sb, false, EXT_CORRELATION_LABEL, LABEL_CORRELATION);
    extension(sb, false, EXT_CORRELATION, e.correlationId().value());
    extension(sb, false, EXT_PRODUCER_LABEL, LABEL_PRODUCER);
    extension(sb, false, EXT_PRODUCER, e.producerId().value());
    extension(sb, false, EXT_ENVELOPE_LABEL, LABEL_ENVELOPE);
    extension(sb, false, EXT_ENVELOPE, e.envelopeId().value());
    extension(sb, false, EXT_PAYLOAD_HASH_LABEL, LABEL_PAYLOAD_HASH);
    extension(sb, false, EXT_PAYLOAD_HASH, e.canonicalPayloadHash());
    return sb.toString();
  }

  private static void extension(StringBuilder sb, boolean first, String key, String value) {
    if (!first) {
      sb.append(EXTENSION_SEPARATOR);
    }
    sb.append(key).append('=').append(extensionEscape(value));
  }

  private static String headerEscape(String value) {
    StringBuilder sb = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '\\' -> sb.append("\\\\");
        case '|' -> sb.append("\\|");
        case '\r', '\n' -> sb.append(' ');
        default -> sb.append(c);
      }
    }
    return sb.toString();
  }

  private static String extensionEscape(String value) {
    StringBuilder sb = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
        case '\\' -> sb.append("\\\\");
        case '=' -> sb.append("\\=");
        case '\n' -> sb.append("\\n");
        case '\r' -> {
          sb.append("\\n");
          // collapse a CRLF pair into one encoded newline
          if (i + 1 < value.length() && value.charAt(i + 1) == '\n') {
            i++;
          }
        }
        default -> sb.append(c);
      }
    }
    return sb.toString();
  }
}
