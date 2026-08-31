package eu.jsentinel.jcustos.events.keys;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Lifecycle status of a verification key (Konzept §590).
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public enum KeyStatus {

  /** Current signing key; also valid for verification. */
  ACTIVE,

  /** No longer used for signing but still accepted for verification (rotation grace). */
  ACCEPTED_FOR_VERIFICATION,

  /** Explicitly revoked; signatures under this key must be rejected. */
  REVOKED,

  /** Past its validity window. */
  EXPIRED,

  /** No key is known for the given id. */
  UNKNOWN
}
