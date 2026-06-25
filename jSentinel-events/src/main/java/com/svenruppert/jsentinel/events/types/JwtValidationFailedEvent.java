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
 * A JWT failed validation (Konzept-V00.76.00 §3.1). Carries only the stable
 * machine-readable failure code (e.g. {@code jwt/signature-invalid}) — never the
 * raw token and never a human-readable message that might echo input (R03
 * guardrail).
 *
 * @param metadata    per-instance metadata
 * @param failureCode the {@code JwtValidationError.code()}
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public record JwtValidationFailedEvent(EventMetadata metadata, String failureCode)
    implements JSentinelEvent {

  public static final EventType TYPE = EventType.of("JwtValidationFailed");

  public JwtValidationFailedEvent {
    Objects.requireNonNull(metadata, "metadata");
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
