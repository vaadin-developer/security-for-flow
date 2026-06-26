package com.svenruppert.jsentinel.events.types;

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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.EventMetadata;
import com.svenruppert.jsentinel.events.api.EventType;
import com.svenruppert.jsentinel.events.api.JSentinelEvent;
import com.svenruppert.jsentinel.events.api.JSentinelEventCategory;

import java.util.Objects;

/**
 * An OAuth2 token was obtained from the token endpoint (V00.77). The payload is
 * non-secret: the grant type and a hash of the audience — never the token.
 *
 * @param metadata      variable per-instance metadata
 * @param grantType     the OAuth2 grant type (e.g. {@code authorization_code})
 * @param audienceHash  a hash of the token-endpoint audience (never the token)
 * @since 00.77.00
 */
@ExperimentalJSentinelApi
public record OAuth2TokenObtainedEvent(EventMetadata metadata, String grantType, String audienceHash)
    implements JSentinelEvent {

  public static final EventType TYPE = EventType.of("OAuth2TokenObtained");

  public OAuth2TokenObtainedEvent {
    Objects.requireNonNull(metadata, "metadata");
    Objects.requireNonNull(grantType, "grantType");
    Objects.requireNonNull(audienceHash, "audienceHash");
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
