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
package com.svenruppert.jsentinel.credential.store;

/**
 * Lifecycle state of a stored credential.
 *
 * <p>The set matches Konzept §10. Each state is operator-driven and
 * <em>not</em> set by the verification pipeline; the lifecycle service
 * introduced in Prompt 021 owns the transition rules.</p>
 *
 * <ul>
 *   <li>{@link #ACTIVE} — normal use</li>
 *   <li>{@link #MUST_CHANGE} — user must change password on next login</li>
 *   <li>{@link #RESET_PENDING} — reset token issued, awaiting consumption</li>
 *   <li>{@link #COMPROMISED} — known-bad credential, no further login</li>
 *   <li>{@link #LOCKED} — temporary lockout (brute-force, admin)</li>
 *   <li>{@link #DISABLED} — account explicitly disabled</li>
 *   <li>{@link #REHASH_REQUIRED} — verification still allowed, rehash pending</li>
 *   <li>{@link #DEPRECATED_ALGORITHM} — algorithm deprecated; rehash will fix it</li>
 * </ul>
 */
public enum CredentialStatus {
  ACTIVE,
  MUST_CHANGE,
  RESET_PENDING,
  COMPROMISED,
  LOCKED,
  DISABLED,
  REHASH_REQUIRED,
  DEPRECATED_ALGORITHM
}
