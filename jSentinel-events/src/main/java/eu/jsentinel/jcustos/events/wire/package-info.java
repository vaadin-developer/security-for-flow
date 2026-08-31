/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

/**
 * Wire codec for signed envelopes: {@link
 * eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec} serializes a
 * {@link eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope}
 * to and from a flat JSON object (Base64 binaries, no Jackson) and offers a
 * secret-free {@code encodeMetadata} projection for logging / SIEM-style
 * consumers. Moved here from {@code jCustos-events-rest} in V00.80.00 so
 * transport-independent consumers (log publishers, monitoring) can encode
 * without a REST dependency; the REST module keeps a deprecated delegator
 * for one release.
 *
 * @since 00.80.00
 */
package eu.jsentinel.jcustos.events.wire;
