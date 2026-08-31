package eu.jsentinel.jcustos.events.api;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Media type of the canonical payload bytes carried by an envelope
 * (Konzept §543). Identifies which {@code PayloadCodec} produced the bytes,
 * so the consumer can pick the matching decoder.
 *
 * @param value non-blank media-type string
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record PayloadContentType(String value) {

  /** Interoperable default codec (Konzept §546). */
  public static final PayloadContentType CANONICAL_JSON =
      new PayloadContentType("application/vnd.security-event.canonical-json");

  /** Java-native binary codec (Konzept §547). */
  public static final PayloadContentType ECLIPSE_SERIALIZER =
      new PayloadContentType("application/vnd.security-event.eclipse-serializer");

  public PayloadContentType {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("PayloadContentType value must not be null or blank");
    }
  }

  public static PayloadContentType of(String value) {
    return new PayloadContentType(value);
  }
}
