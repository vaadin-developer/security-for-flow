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
package com.svenruppert.jsentinel.credential.abuse;

/**
 * Named patterns detectable by the
 * {@link AbusePatternMonitor}. The vocabulary is fixed so audit sinks
 * and metrics use the same labels everywhere.
 */
public enum AbusePattern {
  /**
   * One client (or a narrow set) trying a single password against
   * many usernames in a short window — see Konzept §13.
   */
  PASSWORD_SPRAYING,
  /**
   * Many distinct clients hammering the same username — a stuffing
   * attack with a leaked credential.
   */
  CREDENTIAL_STUFFING,
  /**
   * A burst of password-reset requests for the same identity or from
   * the same client — automated reset abuse.
   */
  RESET_ABUSE
}
