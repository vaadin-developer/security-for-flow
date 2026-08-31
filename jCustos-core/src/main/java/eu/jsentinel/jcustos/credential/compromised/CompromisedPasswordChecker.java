/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package eu.jsentinel.jcustos.credential.compromised;

import eu.jsentinel.jcustos.credential.secret.SecretValue;

/**
 * SPI for compromised-password lookups.
 *
 * <p>Implementations must not log, persist or transmit the candidate
 * password (CWE-359, CWE-532). Network-backed implementations are
 * required to use a privacy-preserving protocol such as k-anonymity
 * range queries — the plain candidate must never leave the process.</p>
 *
 * <p>The check is invoked from the credential set / change / reset
 * pipeline only. {@link CompromisedPasswordPolicy#checkOnLogin()}
 * defaults to {@code false} to keep the login hot path constant-time
 * and avoid burning external rate-limit budget on every attempt
 * (CWE-203, CWE-307).</p>
 */
@FunctionalInterface
public interface CompromisedPasswordChecker {

  /**
   * Evaluates the candidate password.
   *
   * @param password caller-owned secret. The implementation must not
   *                 modify it, log it, or hold a reference past the
   *                 call.
   * @return {@link CompromisedPasswordResult.Clean} when the password
   *         is not known to be breached, {@link CompromisedPasswordResult.Pwned}
   *         when it matches a known entry, or
   *         {@link CompromisedPasswordResult.CheckFailed} when no
   *         verdict could be produced.
   */
  CompromisedPasswordResult check(SecretValue password);
}
