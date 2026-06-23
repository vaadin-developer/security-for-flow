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

/**
 * V00.75 signature SPI (Konzept §346-§403): the {@link
 * com.svenruppert.jsentinel.events.signature.SignatureAlgorithm} contract,
 * its {@link
 * com.svenruppert.jsentinel.events.signature.SignatureAlgorithms} registry,
 * and the two built-in JCA providers — {@code Ed25519} (default) and
 * {@code SHA256withECDSA} (optional fallback).
 *
 * <p>The built-ins register through {@link java.util.ServiceLoader} (see
 * {@code META-INF/services}) and are also wired directly into
 * {@code SignatureAlgorithms.defaults()}, so the module stays dependency-free
 * (only {@code jSentinel-core}). All cryptographic primitives go through JCA;
 * the global provider order is never modified.
 *
 * @since 00.75.00
 */
package com.svenruppert.jsentinel.events.signature;
