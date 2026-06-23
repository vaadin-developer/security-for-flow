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
 * V00.75 key-management SPI (Konzept §567-§615): the signer-side
 * {@link com.svenruppert.jsentinel.events.keys.JSentinelEventSigningKeyProvider}
 * and verifier-side {@link
 * com.svenruppert.jsentinel.events.keys.JSentinelEventVerificationKeyResolver},
 * the {@link com.svenruppert.jsentinel.events.keys.KeyStatus} lifecycle enum,
 * and two implementations: {@link
 * com.svenruppert.jsentinel.events.keys.InMemoryKeyManagement} (default /
 * tests, with rotation + revocation) and {@link
 * com.svenruppert.jsentinel.events.keys.JdkKeyStoreKeyManagement} (PKCS12
 * reference). HSM / Cloud-KMS can follow later behind the same SPI.
 *
 * @since 00.75.00
 */
package com.svenruppert.jsentinel.events.keys;
