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
package com.svenruppert.vaadin.security.credential.input;

import java.util.Objects;

/**
 * Structured outcome of {@link PasswordInputValidator#validate}.
 *
 * <p>Sealed so callers can pattern-match exhaustively. The
 * {@link Rejected} variant carries the structural violation reason; it
 * never carries the input itself.</p>
 */
public sealed interface PasswordInputValidationResult
    permits PasswordInputValidationResult.Accepted,
            PasswordInputValidationResult.Rejected {

  record Accepted() implements PasswordInputValidationResult {
    public static final Accepted INSTANCE = new Accepted();
  }

  record Rejected(PasswordInputViolation violation)
      implements PasswordInputValidationResult {

    public Rejected {
      Objects.requireNonNull(violation, "violation");
    }
  }
}
