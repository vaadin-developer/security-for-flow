/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
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

package eu.jsentinel.jcustos.credential;


/**
 * Generic, public-facing failure classification used by UI- and API-near
 * layers to react to a denied credential verification.
 *
 * <p>This enum must never leak whether a username is known, whether a hash
 * format is corrupt, whether a provider is missing, or whether a pepper
 * key is unknown. All such situations collapse onto
 * {@link #INVALID_CREDENTIALS}. Differentiated information is carried by
 * {@link InternalAuditEventType} and stays inside audit sinks.</p>
 *
 * <p>{@link #TEMPORARILY_UNAVAILABLE} is reserved for situations where
 * the verification could not be carried out because the system intentionally
 * shed load (KDF execution limit, downstream outage). It must not change
 * with the validity of the supplied credential.</p>
 */
public enum PublicFailureType {
  INVALID_CREDENTIALS,
  TEMPORARILY_UNAVAILABLE
}
