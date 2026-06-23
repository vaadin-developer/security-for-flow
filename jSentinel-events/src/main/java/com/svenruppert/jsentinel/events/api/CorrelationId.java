package com.svenruppert.jsentinel.events.api;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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

import java.util.UUID;

/**
 * Correlation identity tying an envelope to a request, session or process
 * chain (Konzept §337). Always present on an envelope; system-generated when
 * the caller does not supply one.
 *
 * @param value non-blank correlation identifier
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record CorrelationId(String value) {

  public CorrelationId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("CorrelationId value must not be null or blank");
    }
  }

  public static CorrelationId of(String value) {
    return new CorrelationId(value);
  }

  public static CorrelationId random() {
    return new CorrelationId(UUID.randomUUID().toString());
  }
}
