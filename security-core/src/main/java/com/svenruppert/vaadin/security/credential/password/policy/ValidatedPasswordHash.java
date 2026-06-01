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
package com.svenruppert.vaadin.security.credential.password.policy;

import com.svenruppert.vaadin.security.credential.password.envelope.PasswordHashEnvelope;

import java.util.Objects;

/**
 * Successful output of {@link PasswordHashValidator#validate}.
 *
 * <p>Pairs the parsed envelope with the policy it was checked against.
 * Downstream stages (provider resolution, verification, rehash decision)
 * consume only validated envelopes; the type acts as a compile-time
 * marker that policy checks have already run.</p>
 */
public record ValidatedPasswordHash(
    PasswordHashEnvelope envelope,
    PasswordHashPolicy validatedAgainst
) {

  public ValidatedPasswordHash {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(validatedAgainst, "validatedAgainst");
  }

  @Override
  public String toString() {
    return "ValidatedPasswordHash["
        + "envelope=" + envelope
        + ", policyVersion=" + validatedAgainst.policyVersion()
        + "]";
  }
}
