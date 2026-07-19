package com.svenruppert.jsentinel.events.rest;

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

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;

/**
 * Thin delegator kept for one release so V00.75 callers of the REST-side
 * codec keep compiling. The codec itself moved to
 * {@link com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec} in
 * V00.80.00 (jSentinel-events) so transport-independent consumers can encode
 * without a REST dependency — switch imports to the new home.
 *
 * @deprecated use {@link com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec}
 *     from {@code jSentinel-events} instead
 * @since 00.75.00
 */
@Deprecated(forRemoval = true, since = "00.80.00")
@ExperimentalJSentinelApi
public final class EnvelopeWireCodec {

  private final com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec delegate =
      new com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec();

  /**
   * @param envelope the envelope
   * @return its JSON wire form
   * @see com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec#encode
   */
  public String encode(SignedJSentinelEventEnvelope envelope) {
    return delegate.encode(envelope);
  }

  /**
   * @param json the JSON wire form
   * @return the decoded envelope on success, or a short error description on
   *     malformed / incomplete input
   * @see com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec#decode
   */
  public Result<SignedJSentinelEventEnvelope, String> decode(String json) {
    return delegate.decode(json);
  }
}
