package eu.jsentinel.jcustos.events.api;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

/**
 * Typed kind of a {@link JSentinelEvent}, e.g. {@code "LoginSucceeded"}.
 *
 * <p>The {@code EventType} is part of the signed envelope metadata
 * (Konzept §326) and is consulted by the {@code ProducerPolicy} to decide
 * whether a given producer may emit this kind of event. It must be a stable,
 * non-blank wire identifier — typically the simple name of the concrete
 * event record.
 *
 * @param value non-blank type identifier
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record EventType(String value) {

  public EventType {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("EventType value must not be null or blank");
    }
  }

  /**
   * Wraps a type identifier string.
   *
   * @param value the non-blank identifier
   * @return a new {@code EventType}
   */
  public static EventType of(String value) {
    return new EventType(value);
  }
}
