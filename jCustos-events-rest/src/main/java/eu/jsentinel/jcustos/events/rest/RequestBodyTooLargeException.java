package eu.jsentinel.jcustos.events.rest;

/*-
 * #%L
 * jCustos Events — REST / SSE bridge
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

/**
 * Signals that an incoming request body exceeded the configured size cap before
 * it was fully buffered. Thrown by {@link HttpExchangeRestRequest#read} so the
 * publish handler can answer {@code 413 Content Too Large} instead of buffering
 * an unbounded body that is read <em>before</em> authorization — closing the
 * pre-auth OOM vector (V00.76 entry-review R01).
 */
final class RequestBodyTooLargeException extends RuntimeException {

  RequestBodyTooLargeException(int maxBodyBytes) {
    super("request body exceeds the " + maxBodyBytes + "-byte limit");
  }
}
