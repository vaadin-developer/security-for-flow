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
package eu.jsentinel.jcustos.credential.reset;

/**
 * Outcome of {@link PasswordResetService#consume}.
 *
 * <p>Sealed but deliberately small: every failure cause collapses to
 * the single {@link Failed} variant so the perimeter never reveals
 * whether the selector was unknown, the verifier wrong, the token
 * expired, the new password rejected or a CAS race lost (CWE-203 /
 * CWE-209 / CWE-640).</p>
 */
public sealed interface PasswordResetConsumeResult
    permits PasswordResetConsumeResult.Succeeded,
            PasswordResetConsumeResult.Failed {

  record Succeeded() implements PasswordResetConsumeResult {
    public static final Succeeded INSTANCE = new Succeeded();
  }

  record Failed() implements PasswordResetConsumeResult {
    public static final Failed INSTANCE = new Failed();
  }
}
