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
package eu.jsentinel.jcustos.credential.emergency;

import java.time.Instant;
import java.util.Objects;

/**
 * Operator-declared, time-bounded credential emergency override.
 *
 * <p>An override is the explicit container for an out-of-band
 * decision: "we are temporarily acting outside the standard
 * policy because of incident {@code reason}". The record is
 * passed to operations that may be invoked during incident
 * response (mass status change, pepper rotation, algorithm
 * deprecation) so the audit trail carries every dimension
 * needed for review (CWE-778, CWE-693, CWE-284).</p>
 *
 * <p>The override is non-executable: instantiating it does not
 * change runtime behaviour. It is consumed by the operations
 * that explicitly require it.</p>
 *
 * @param incidentId    short stable identifier of the incident
 *                      (e.g. {@code "INC-2026-04-pepper-leak"})
 * @param reason        structured reason code
 * @param effectiveFrom start of the override window
 * @param effectiveTo   end of the override window — must be after
 *                      {@code effectiveFrom}; the framework does
 *                      not enforce expiry, callers do
 * @param authorisedBy  operator subject id that authorised the
 *                      override; never the operator's password
 *                      or any other secret
 */
public record EmergencyPolicyOverride(
    String incidentId,
    Reason reason,
    Instant effectiveFrom,
    Instant effectiveTo,
    String authorisedBy) {

  public EmergencyPolicyOverride {
    Objects.requireNonNull(incidentId, "incidentId");
    Objects.requireNonNull(reason, "reason");
    Objects.requireNonNull(effectiveFrom, "effectiveFrom");
    Objects.requireNonNull(effectiveTo, "effectiveTo");
    Objects.requireNonNull(authorisedBy, "authorisedBy");
    if (incidentId.isBlank()) {
      throw new IllegalArgumentException("incidentId must not be blank");
    }
    if (authorisedBy.isBlank()) {
      throw new IllegalArgumentException("authorisedBy must not be blank");
    }
    if (!effectiveTo.isAfter(effectiveFrom)) {
      throw new IllegalArgumentException(
          "effectiveTo must be after effectiveFrom");
    }
  }

  /**
   * Structured incident category. Free-form descriptions live in
   * the playbook documents under
   * {@code docs/security/credentials/playbooks/}.
   */
  public enum Reason {
    /** Pepper key material is suspected or confirmed compromised. */
    PEPPER_COMPROMISE,
    /** A hashing algorithm has lost its acceptable status. */
    ALGORITHM_COMPROMISE,
    /** A cryptographic provider has been revoked or recalled. */
    PROVIDER_COMPROMISE,
    /** Mass forced credential rotation requested. */
    MASS_ROTATION,
    /** Sustained credential reset abuse. */
    RESET_ABUSE,
    /** Other; details live in the incident record, not in this enum. */
    OTHER
  }
}
