/*-
 * #%L
 * jSentinel JWT — standardized JWT validation
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
 * V00.76 Nimbus JOSE+JWT-backed implementations of the jSentinel-core JWT
 * SPIs (Konzept-V00.76.00 §6/§7/§9): {@code NimbusJwtValidator},
 * {@code HttpJwksClient} and the {@code NimbusJwtValidatorFactory} that the
 * {@code .jwt(...)} bootstrap discovers via {@link java.util.ServiceLoader}.
 *
 * <p>This is the only module on the reactor where a JOSE library is on the
 * classpath; the JOSE-free SPI contracts and sealed result types live in
 * {@code com.svenruppert.jsentinel.jwt.api} inside {@code jSentinel-core}.
 *
 * @since 00.76.00
 */
package com.svenruppert.jsentinel.jwt.impl;
