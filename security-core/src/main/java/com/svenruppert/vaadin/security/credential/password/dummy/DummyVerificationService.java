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
package com.svenruppert.vaadin.security.credential.password.dummy;

/**
 * Performs a comparable KDF run when the verification pipeline cannot
 * proceed against the supplied envelope (unknown user, malformed
 * envelope, missing provider, unknown pepper key).
 *
 * <p>The dummy path serves three goals simultaneously:</p>
 * <ul>
 *   <li>flatten the observable timing between &quot;user exists&quot;
 *       and &quot;user does not exist&quot; (CWE-208);</li>
 *   <li>flatten the observable behaviour between healthy and corrupted
 *       envelopes (CWE-203);</li>
 *   <li>consume the same {@code KdfExecutionLimiter} permit class that
 *       a real verification would have consumed, so a flood of unknown
 *       users still pressures the limiter equally (CWE-307).</li>
 * </ul>
 */
public interface DummyVerificationService {

  /**
   * Executes a single dummy KDF against a stored dummy envelope built
   * under the active policy. Returns nothing meaningful; the caller
   * already knows the verification failed.
   *
   * <p>Implementations must not throw on missing providers &mdash; they
   * must fall back to the policy's default dummy provider so the dummy
   * path remains uniform across failure types.</p>
   */
  void runDummyKdf(char[] password, DummyVerificationContext context);
}
