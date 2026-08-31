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

import com.svenruppert.dependencies.core.net.MediaType;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Default route constants for the REST/SSE bridge (Konzept §929-§976).
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class EventsRestRoutes {

  private EventsRestRoutes() {
  }

  /** Base prefix for all bridge endpoints. */
  public static final String PREFIX = "/api/events";

  /** SSE stream endpoint (GET). */
  public static final String STREAM = PREFIX + "/stream";

  /** Signed-envelope publish endpoint (POST). */
  public static final String PUBLISH = PREFIX;

  /** Permission required to publish envelopes via the bridge. */
  public static final String PUBLISH_PERMISSION = "events:publish";

  /** JS-SEC-032 (CWE-306): permission required to subscribe to the SSE event stream. */
  public static final String STREAM_PERMISSION = "events:subscribe";

  /** SSE event name for security-event frames. */
  public static final String EVENT_NAME = "security-event";

  /** SSE event name for error frames. */
  public static final String ERROR_EVENT_NAME = "security-event-error";

  /** HTTP media type for the SSE stream ({@code text/event-stream}). */
  public static final String EVENT_STREAM_MEDIA_TYPE = MediaType.TEXT_EVENT_STREAM.mime();
}
