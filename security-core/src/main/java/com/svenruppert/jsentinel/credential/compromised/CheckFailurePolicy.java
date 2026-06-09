/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.jsentinel.credential.compromised;

/**
 * Operator-configured behaviour when a
 * {@link CompromisedPasswordChecker} returns
 * {@link CompromisedPasswordResult.CheckFailed}.
 *
 * <p>Mirrors the language used in NIST SP 800-63B §5.1.1 and
 * OWASP ASVS V2.1: a compromised-password check is a *control*,
 * and the failure mode of that control must be a *deliberate*
 * choice.</p>
 */
public enum CheckFailurePolicy {

  /**
   * Treat a failed check as {@code Clean} — the change proceeds.
   * Default for online checkers where availability would otherwise
   * cause an outage in the credential pipeline.
   */
  ALLOW,

  /**
   * Treat a failed check as {@code Clean} but raise a structured
   * audit event so operators can review later.
   */
  WARN,

  /**
   * Treat a failed check as a definitive negative outcome — the
   * change is rejected. Suited for high-assurance deployments
   * where a missing check is worse than a denied change.
   */
  BLOCK
}
