package eu.jsentinel.jcustos.events.wire;

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

/**
 * Thrown when an envelope cannot be (de)serialized for the wire. Moved
 * unchanged from {@code eu.jsentinel.jcustos.events.rest} (present
 * since 00.75.00).
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class EventWireException extends RuntimeException {

  public EventWireException(String message) {
    super(message);
  }

  /**
   * @param message the detail message
   * @param cause   the underlying parser failure (e.g. a JDK
   *                {@code NumberFormatException}) being wrapped
   */
  public EventWireException(String message, Throwable cause) {
    super(message, cause);
  }
}
