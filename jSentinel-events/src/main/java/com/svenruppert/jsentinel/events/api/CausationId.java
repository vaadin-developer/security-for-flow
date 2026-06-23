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

/**
 * Optional reference to the envelope that caused this one (Konzept §338).
 *
 * <p>Unlike most envelope fields, the causation reference is optional: a
 * root event in a chain has no cause. The envelope models its absence with a
 * {@code null} {@code CausationId}; when present it must be non-blank.
 *
 * @param value non-blank causation identifier
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record CausationId(String value) {

  public CausationId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("CausationId value must not be null or blank");
    }
  }

  public static CausationId of(String value) {
    return new CausationId(value);
  }
}
