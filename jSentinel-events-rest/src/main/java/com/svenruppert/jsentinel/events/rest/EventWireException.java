package com.svenruppert.jsentinel.events.rest;

/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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
 * Thrown when an envelope cannot be (de)serialized for the wire.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class EventWireException extends RuntimeException {

  public EventWireException(String message) {
    super(message);
  }

  /**
   * @param message the detail message
   * @param cause   the underlying parser failure (e.g. a JDK
   *                {@code NumberFormatException}) being wrapped
   * @since 00.75.10
   */
  public EventWireException(String message, Throwable cause) {
    super(message, cause);
  }
}
