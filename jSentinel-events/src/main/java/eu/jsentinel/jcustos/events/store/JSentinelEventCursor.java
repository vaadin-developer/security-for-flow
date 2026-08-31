package eu.jsentinel.jcustos.events.store;

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
 * Opaque, monotone position into the envelope store's stable append order
 * (Konzept §967 — "globaler Store-Cursor"). Used by the SSE bridge for
 * resume: a reconnecting client passes its last position and the server
 * replays everything after it.
 *
 * @param position append-order position; {@code 0} means "from the beginning"
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record JSentinelEventCursor(long position) {

  public JSentinelEventCursor {
    if (position < 0) {
      throw new IllegalArgumentException("cursor position must be >= 0, was " + position);
    }
  }

  /**
   * @return a cursor positioned before the first stored envelope
   */
  public static JSentinelEventCursor start() {
    return new JSentinelEventCursor(0);
  }

  /**
   * @param position the append-order position
   * @return a cursor at the given position
   */
  public static JSentinelEventCursor at(long position) {
    return new JSentinelEventCursor(position);
  }
}
