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
 * V00.75 payload-codec SPI (Konzept §405-§566): the controlled
 * {@link eu.jsentinel.jcustos.events.codec.CanonicalJCustosEventPayload}
 * model, the {@link
 * eu.jsentinel.jcustos.events.codec.JCustosEventCanonicalizer} that
 * maps a typed event to it, the {@link
 * eu.jsentinel.jcustos.events.codec.PayloadCodec} SPI, and the
 * interoperable in-tree {@link
 * eu.jsentinel.jcustos.events.codec.CanonicalJsonPayloadCodec}.
 *
 * <p>Codecs serialize the canonical payload, never an arbitrary event, so the
 * signed bytes stay deterministic and versionable. Jackson / Gson / org.json
 * are Maven-Enforcer-banned on this module; the codec uses the in-tree
 * {@link eu.jsentinel.jcustos.events.codec.CanonicalJson} engine. The
 * Java-native Eclipse-Serializer codec (Konzept §468) lives in
 * {@code jCustos-events-persistence-eclipsestore} so the core stays
 * storage-free.
 *
 * @since 00.75.00
 */
package eu.jsentinel.jcustos.events.codec;
