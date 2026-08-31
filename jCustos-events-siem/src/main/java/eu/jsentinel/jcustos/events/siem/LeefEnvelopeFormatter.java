package eu.jsentinel.jcustos.events.siem;

/*-
 * #%L
 * jCustos Events — SIEM exporter
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
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Formats an envelope as one IBM QRadar LEEF 2.0 record:
 * {@code LEEF:2.0|vendor|product|version|eventId|} followed by
 * tab-separated {@code key=value} attributes (the delimiter header field is
 * omitted, so the LEEF default — tab — applies). Header fields escape
 * {@code \} and {@code |} and replace CR/LF with a space; attribute values
 * replace tab/CR/LF with a space (no raw delimiter or line break may appear
 * inside a value — spaces stay legal, which is why
 * {@code LogFieldScrubber} is not used here).
 * <p>
 * {@code devTime} is {@code occurredAt} rendered in UTC with the pattern
 * announced by the {@code devTimeFormat} attribute, keeping the pair
 * self-consistent. Attributes carry envelope metadata only — never payload
 * or signature bytes.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class LeefEnvelopeFormatter implements SiemEnvelopeFormatter {

  private static final String LEEF_HEADER = "LEEF:2.0";
  private static final char HEADER_SEPARATOR = '|';
  private static final char ATTRIBUTE_SEPARATOR = '\t';

  /** Java pattern of {@link #ATTR_DEV_TIME}; announced via {@link #ATTR_DEV_TIME_FORMAT}. */
  static final String DEV_TIME_PATTERN = "yyyy-MM-dd'T'HH:mm:ss.SSSX";
  private static final DateTimeFormatter DEV_TIME =
      DateTimeFormatter.ofPattern(DEV_TIME_PATTERN).withZone(ZoneOffset.UTC);

  static final String ATTR_DEV_TIME = "devTime";
  static final String ATTR_DEV_TIME_FORMAT = "devTimeFormat";
  static final String ATTR_SEVERITY = "sev";
  static final String ATTR_USER = "usrName";
  static final String ATTR_TENANT = "tenantId";
  static final String ATTR_PRODUCER = "producerId";
  static final String ATTR_ENVELOPE = "envelopeId";
  static final String ATTR_EVENT = "eventId";
  static final String ATTR_CORRELATION = "correlationId";
  static final String ATTR_SEQUENCE = "sequence";
  static final String ATTR_PAYLOAD_HASH = "payloadHash";

  @Override
  public String format(SignedJCustosEventEnvelope e) {
    StringBuilder sb = new StringBuilder(LEEF_HEADER)
        .append(HEADER_SEPARATOR).append(headerEscape(SiemProduct.VENDOR))
        .append(HEADER_SEPARATOR).append(headerEscape(SiemProduct.PRODUCT))
        .append(HEADER_SEPARATOR).append(headerEscape(SiemProduct.VERSION))
        .append(HEADER_SEPARATOR).append(headerEscape(e.eventType().value()))
        .append(HEADER_SEPARATOR);
    attribute(sb, true, ATTR_DEV_TIME, DEV_TIME.format(e.occurredAt()));
    attribute(sb, false, ATTR_DEV_TIME_FORMAT, DEV_TIME_PATTERN);
    attribute(sb, false, ATTR_SEVERITY,
        String.valueOf(SiemSeverity.severityFor(e.eventType())));
    attribute(sb, false, ATTR_USER, e.subjectId().value());
    attribute(sb, false, ATTR_TENANT, e.tenantId().value());
    attribute(sb, false, ATTR_PRODUCER, e.producerId().value());
    attribute(sb, false, ATTR_ENVELOPE, e.envelopeId().value());
    attribute(sb, false, ATTR_EVENT, e.eventId().value());
    attribute(sb, false, ATTR_CORRELATION, e.correlationId().value());
    attribute(sb, false, ATTR_SEQUENCE, String.valueOf(e.sequence().value()));
    attribute(sb, false, ATTR_PAYLOAD_HASH, e.canonicalPayloadHash());
    return sb.toString();
  }

  private static void attribute(StringBuilder sb, boolean first, String key, String value) {
    if (!first) {
      sb.append(ATTRIBUTE_SEPARATOR);
    }
    sb.append(key).append('=').append(attributeEscape(value));
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

  private static String attributeEscape(String value) {
    StringBuilder sb = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c == '\t' || c == '\r' || c == '\n') {
        sb.append(' ');
      } else {
        sb.append(c);
      }
    }
    return sb.toString();
  }
}
