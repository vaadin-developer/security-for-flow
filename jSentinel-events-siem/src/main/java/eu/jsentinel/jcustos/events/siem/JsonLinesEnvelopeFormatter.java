package eu.jsentinel.jcustos.events.siem;

/*-
 * #%L
 * jCustos Events — SIEM exporter
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec;

/**
 * Formats an envelope as one JSON line (media type
 * {@code application/x-ndjson}), delegating to the {@link EnvelopeWireCodec}
 * so the field names share the codec's single home — zero drift with the
 * REST/SSE/webhook wire form.
 * <p>
 * Two modes: the default emits the codec's <em>metadata projection</em>
 * (no payload, no signature — the payload hash stays); with
 * {@code includePayload} the full wire form is emitted, giving the SIEM the
 * complete verifiable signed record. The payload may contain user data —
 * choosing the full mode is the operator's data-classification call.
 * <p>
 * The codec emits a flat single-line JSON object (its writer produces no
 * raw line breaks — JSON string escaping encodes them), so the formatter
 * contract holds by construction.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class JsonLinesEnvelopeFormatter implements SiemEnvelopeFormatter {

  private final EnvelopeWireCodec codec = new EnvelopeWireCodec();
  private final boolean includePayload;

  /** Metadata-only mode — the secret-free default. */
  public JsonLinesEnvelopeFormatter() {
    this(false);
  }

  /**
   * @param includePayload {@code true} emits the full wire form including
   *     payload and signature (independently verifiable);
   *     {@code false} emits the metadata projection
   */
  public JsonLinesEnvelopeFormatter(boolean includePayload) {
    this.includePayload = includePayload;
  }

  @Override
  public String format(SignedJCustosEventEnvelope envelope) {
    return includePayload
        ? codec.encode(envelope)
        : codec.encodeMetadata(envelope);
  }
}
