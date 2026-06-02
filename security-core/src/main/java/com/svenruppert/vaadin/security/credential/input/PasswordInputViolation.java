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

/**
 * Reason that input was rejected by the {@link PasswordInputValidator}.
 *
 * <p>The enum values are deliberately structural so audit sinks and
 * registration-form messages can specialise without ever embedding the
 * supplied password material (CWE-209 / CWE-522).</p>
 */
public enum PasswordInputViolation {
  TOO_SHORT,
  TOO_LONG,
  CONTAINS_CONTROL_CHARACTER
}
