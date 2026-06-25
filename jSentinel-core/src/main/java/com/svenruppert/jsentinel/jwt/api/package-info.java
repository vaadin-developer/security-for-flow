/*-
 * #%L
 * jSentinel Core
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
 * V00.76 JOSE-free JWT validation SPI (Konzept-V00.76.00 §3/§6/§7/§8/§9).
 *
 * <p>This package holds only interfaces, records and sealed result types — no
 * {@code com.nimbusds.*}, no JOSE library. Consumers that do not need JWT pull
 * neither Nimbus nor BouncyCastle. The Nimbus-backed default implementation of
 * {@link com.svenruppert.jsentinel.jwt.api.JwtValidator},
 * {@link com.svenruppert.jsentinel.jwt.api.JwksClient} and
 * {@link com.svenruppert.jsentinel.jwt.api.JwtValidatorFactory} lives in the
 * opt-in {@code jSentinel-jwt} module.
 *
 * <p>Validation is {@code Result}-based ({@code Result<ValidatedJwt,
 * JwtValidationError>}): expected failures travel in the return value, not as
 * thrown exceptions. The algorithm surface is asymmetric-only in V00.76
 * (RS/PS/ES/EdDSA — no HMAC, no {@code alg:none}); symmetric JWT is deferred.
 *
 * @since 00.76.00
 */
package com.svenruppert.jsentinel.jwt.api;
