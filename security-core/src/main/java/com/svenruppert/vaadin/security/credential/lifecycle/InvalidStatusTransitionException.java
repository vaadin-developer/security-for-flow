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
package com.svenruppert.vaadin.security.credential.lifecycle;

import com.svenruppert.vaadin.security.credential.store.CredentialStatus;

import java.util.Objects;

/**
 * Thrown by {@link CredentialLifecycleService#transition} when the
 * requested transition is not part of the configured state machine.
 * Messages describe only the states involved; they never carry the
 * username or credential payload (CWE-209).
 */
public final class InvalidStatusTransitionException extends RuntimeException {

  private final CredentialStatus from;
  private final CredentialStatus to;

  public InvalidStatusTransitionException(
      CredentialStatus from, CredentialStatus to) {
    super("transition " + Objects.requireNonNull(from)
        + " -> " + Objects.requireNonNull(to) + " is not allowed");
    this.from = from;
    this.to = to;
  }

  public CredentialStatus from() {
    return from;
  }

  public CredentialStatus to() {
    return to;
  }
}
