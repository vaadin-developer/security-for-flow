package eu.jsentinel.jcustos.events.rest;

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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

/**
 * Formats Server-Sent-Events frames for the bridge (Konzept §939-§952).
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class SseFrames {

  private SseFrames() {
  }

  /**
   * A {@code security-event} frame carrying a serialized envelope, tagged with
   * the resume cursor position as its SSE id.
   *
   * @param cursorPosition the envelope store position (SSE {@code id})
   * @param envelopeJson the serialized envelope
   * @return the SSE frame text
   */
  public static String securityEvent(long cursorPosition, String envelopeJson) {
    return "event: " + EventsRestRoutes.EVENT_NAME + "\n"
        + "id: " + cursorPosition + "\n"
        + "data: " + envelopeJson + "\n\n";
  }

  /**
   * A {@code security-event-error} frame.
   *
   * @param message a structured error message
   * @return the SSE frame text
   */
  public static String error(String message) {
    return "event: " + EventsRestRoutes.ERROR_EVENT_NAME + "\n"
        + "data: " + message + "\n\n";
  }

  /**
   * @return an SSE keep-alive comment frame
   */
  public static String keepAlive() {
    return ": keep-alive\n\n";
  }
}
