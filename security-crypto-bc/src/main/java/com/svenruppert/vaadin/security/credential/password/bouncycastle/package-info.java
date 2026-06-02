/*-
 * #%L
 * Security Crypto — BouncyCastle
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
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
 * Phase-1b BouncyCastle-backed password hash providers.
 *
 * <h2>Opt-in</h2>
 * <p>This module is strictly opt-in. Applications that need memory-hard
 * password hashing (Argon2id, scrypt) or bcrypt add the
 * {@code security-crypto-bc} artifact to their classpath; everyone else
 * keeps the {@code security-core} default of PBKDF2-HMAC-SHA-256.</p>
 *
 * <h2>No global JCA changes</h2>
 * <p>Providers in this package use BouncyCastle's low-level crypto APIs
 * directly and never call {@code Security.addProvider} or
 * {@code Security.insertProviderAt}. The global JCA provider order is
 * therefore identical with or without this module on the classpath.</p>
 *
 * <h2>Fail-fast wiring</h2>
 * <p>If an application configures the {@code modern} profile (preferred
 * algorithm {@code Argon2id}, {@code bcrypt} or {@code scrypt}) without
 * the corresponding provider on the classpath, the
 * {@code DefaultPasswordHashingService} constructor throws because the
 * preferred provider cannot be resolved. There is no silent downgrade
 * to PBKDF2 (CWE-693).</p>
 */
package com.svenruppert.vaadin.security.credential.password.bouncycastle;
