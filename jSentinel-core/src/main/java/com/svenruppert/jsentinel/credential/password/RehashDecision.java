/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
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

package com.svenruppert.jsentinel.credential.password;


import java.util.Objects;

/**
 * Whether a successfully verified credential should be transparently
 * rehashed under the currently active policy. Sealed so the calling
 * service can pattern-match exhaustively.
 *
 * <p>Decisions are produced by the verification pipeline after a
 * successful verification, never on failure. A {@link Required} decision
 * does <strong>not</strong> imply that the verification failed; it only
 * means the stored envelope is below the desired profile.</p>
 */
public sealed interface RehashDecision
    permits RehashDecision.NotRequired, RehashDecision.Required {

  record NotRequired() implements RehashDecision {
    public static final NotRequired INSTANCE = new NotRequired();
  }

  /**
   * @param reason         dominant reason for the rehash; deterministic
   *                       so multiple verifications of the same envelope
   *                       under the same policy yield the same reason
   * @param targetPolicyVersion policy version the rehash should target;
   *                            usually the active policy version
   */
  record Required(
      RehashReason reason,
      int targetPolicyVersion
  ) implements RehashDecision {

    public Required {
      Objects.requireNonNull(reason, "reason");
      if (targetPolicyVersion < 1) {
        throw new IllegalArgumentException("targetPolicyVersion must be >= 1");
      }
    }
  }
}
