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
package com.svenruppert.jsentinel.credential.reset;

/**
 * Lifecycle of a stored password-reset token.
 *
 * <ul>
 *   <li>{@link #ISSUED} — usable until expiry</li>
 *   <li>{@link #CONSUMED} — single-use; verifier already redeemed</li>
 *   <li>{@link #EXPIRED} — terminal state set on first access past
 *       {@code expiresAt}</li>
 *   <li>{@link #REVOKED} — operator-driven cancellation</li>
 * </ul>
 *
 * <p>Only {@link #ISSUED} → {@link #CONSUMED} (single-use, CWE-640) and
 * {@link #ISSUED} → {@link #EXPIRED} / {@link #REVOKED} are valid
 * transitions; the reset service enforces them via CAS on the store.</p>
 */
public enum ResetTokenStatus {
  ISSUED,
  CONSUMED,
  EXPIRED,
  REVOKED
}
