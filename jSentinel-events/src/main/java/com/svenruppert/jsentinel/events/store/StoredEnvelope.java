package com.svenruppert.jsentinel.events.store;

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
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;

import java.util.Objects;

/**
 * An envelope together with its stable store position, returned by
 * {@link JSentinelEventEnvelopeStore#findAfter(JSentinelEventCursor, int)} so a
 * consumer can advance its {@link JSentinelEventCursor} for the next page.
 *
 * @param cursor the position of this envelope in the store's append order
 * @param envelope the stored envelope
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record StoredEnvelope(JSentinelEventCursor cursor, SignedJSentinelEventEnvelope envelope) {

  public StoredEnvelope {
    Objects.requireNonNull(cursor, "cursor");
    Objects.requireNonNull(envelope, "envelope");
  }
}
