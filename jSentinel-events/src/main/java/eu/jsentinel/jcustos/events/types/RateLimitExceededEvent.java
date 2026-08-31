package eu.jsentinel.jcustos.events.types;

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
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.api.JSentinelEvent;
import eu.jsentinel.jcustos.events.api.JSentinelEventCategory;

import java.util.Objects;

/**
 * A rate limit was exceeded (Konzept §279).
 *
 * @param metadata variable per-instance metadata
 * @param limitName the limit that was exceeded
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record RateLimitExceededEvent(EventMetadata metadata, String limitName)
    implements JSentinelEvent {

  public static final EventType TYPE = EventType.of("RateLimitExceeded");

  public RateLimitExceededEvent {
    Objects.requireNonNull(metadata, "metadata");
  }

  @Override
  public EventType eventType() {
    return TYPE;
  }

  @Override
  public JSentinelEventCategory category() {
    return JSentinelEventCategory.RATE_LIMIT;
  }
}
