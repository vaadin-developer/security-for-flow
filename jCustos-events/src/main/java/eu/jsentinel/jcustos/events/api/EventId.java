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

import java.util.UUID;

/**
 * Business identifier of a single {@link JCustosEvent}.
 *
 * <p>The {@code EventId} is the <em>logical</em> identity of the event itself,
 * independent of how often it is wrapped, transported or re-delivered. It is
 * stable across re-encoding: two envelopes carrying the same logical event
 * share the same {@code EventId} but get distinct
 * {@link EventEnvelopeId envelope ids}.
 *
 * @param value non-blank identifier, typically a {@link UUID} string
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public record EventId(String value) {

  public EventId {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("EventId value must not be null or blank");
    }
  }

  /**
   * Wraps an existing identifier string.
   *
   * @param value the non-blank identifier
   * @return a new {@code EventId}
   */
  public static EventId of(String value) {
    return new EventId(value);
  }

  /**
   * Generates a fresh random {@code EventId} backed by a {@link UUID}.
   *
   * @return a new random {@code EventId}
   */
  public static EventId random() {
    return new EventId(UUID.randomUUID().toString());
  }
}
