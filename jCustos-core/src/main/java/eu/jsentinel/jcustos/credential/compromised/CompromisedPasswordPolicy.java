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
package eu.jsentinel.jcustos.credential.compromised;

import java.util.Objects;

/**
 * Operator-controlled policy that governs when the compromised
 * password check runs and how a failed check is interpreted.
 *
 * <p>Defaults:</p>
 * <ul>
 *   <li>{@code checkOnSetOrChange} = true — NIST SP 800-63B §5.1.1</li>
 *   <li>{@code checkOnLogin} = false — checking on every login would
 *       leak timing information and rate-limit budget (CWE-203 /
 *       CWE-307)</li>
 *   <li>{@code onFailure} = {@link CheckFailurePolicy#ALLOW} for
 *       online checkers; deployments that prefer fail-closed should
 *       set this to {@link CheckFailurePolicy#BLOCK} explicitly.</li>
 * </ul>
 */
public record CompromisedPasswordPolicy(
    boolean checkOnSetOrChange,
    boolean checkOnLogin,
    CheckFailurePolicy onFailure) {

  public CompromisedPasswordPolicy {
    Objects.requireNonNull(onFailure, "onFailure");
  }

  /**
   * Defaults: check on set / change only, allow on check failure.
   */
  public static CompromisedPasswordPolicy defaults() {
    return new CompromisedPasswordPolicy(true, false, CheckFailurePolicy.ALLOW);
  }

  /**
   * Fail-closed variant: any check failure rejects the change.
   */
  public static CompromisedPasswordPolicy failClosed() {
    return new CompromisedPasswordPolicy(true, false, CheckFailurePolicy.BLOCK);
  }

  /**
   * Disabled variant: no check is ever invoked. Callers can use
   * this to short-circuit the compromised-password pipeline
   * without removing the SPI binding.
   */
  public static CompromisedPasswordPolicy disabled() {
    return new CompromisedPasswordPolicy(false, false, CheckFailurePolicy.ALLOW);
  }
}
