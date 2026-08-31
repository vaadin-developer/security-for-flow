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
 * A device-authorization grant completed — the user authorized and the RP
 * obtained tokens (RFC 8628, V00.77). No token material in the payload.
 *
 * @param metadata variable per-instance metadata
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public record DeviceAuthorizationCompletedEvent(EventMetadata metadata) implements JSentinelEvent {

  public static final EventType TYPE = EventType.of("DeviceAuthorizationCompleted");

  public DeviceAuthorizationCompletedEvent {
    Objects.requireNonNull(metadata, "metadata");
  }

  @Override
  public EventType eventType() {
    return TYPE;
  }

  @Override
  public JSentinelEventCategory category() {
    return JSentinelEventCategory.DEVICE;
  }
}
