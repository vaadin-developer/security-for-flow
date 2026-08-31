package eu.jsentinel.jcustos.events.api;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

import java.util.UUID;

/**
 * Unique identity of a single transported envelope, used for deduplication
 * and replay protection (Konzept §328).
 *
 * <p>Distinct from {@link EventId}: re-wrapping the same logical event yields
 * a new {@code EventEnvelopeId} but the same {@code EventId}.
 *
 * @param value non-blank identifier, typically a {@link UUID} string
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record EventEnvelopeId(String value) {

  public EventEnvelopeId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("EventEnvelopeId value must not be null or blank");
    }
  }

  public static EventEnvelopeId of(String value) {
    return new EventEnvelopeId(value);
  }

  public static EventEnvelopeId random() {
    return new EventEnvelopeId(UUID.randomUUID().toString());
  }
}
