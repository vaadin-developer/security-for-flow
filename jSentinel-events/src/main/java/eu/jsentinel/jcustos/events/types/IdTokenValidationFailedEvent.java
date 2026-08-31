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
 * An OIDC ID-token validation failed (V00.78). Carries only the stable
 * {@code IdTokenValidationError} code (e.g. {@code oidc/nonce-mismatch}) — never
 * the token or the offending claim value. A security signal (replay / substitution).
 *
 * @param metadata  variable per-instance metadata
 * @param errorCode the stable kebab-case validation error code
 * @since 00.78.00
 */
@ExperimentalJSentinelApi
public record IdTokenValidationFailedEvent(EventMetadata metadata, String errorCode)
    implements JSentinelEvent {

  public static final EventType TYPE = EventType.of("IdTokenValidationFailed");

  public IdTokenValidationFailedEvent {
    Objects.requireNonNull(metadata, "metadata");
    Objects.requireNonNull(errorCode, "errorCode");
  }

  @Override
  public EventType eventType() {
    return TYPE;
  }

  @Override
  public JSentinelEventCategory category() {
    return JSentinelEventCategory.TOKEN;
  }
}
