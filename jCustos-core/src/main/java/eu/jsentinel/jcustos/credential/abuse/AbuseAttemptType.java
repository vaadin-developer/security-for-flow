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
package eu.jsentinel.jcustos.credential.abuse;

/**
 * Categories of credential-sensitive operations the
 * {@link AbuseDetectionService} tracks independently.
 *
 * <p>Each attempt type gets its own counters per dimension — a wave of
 * reset requests must not exhaust the login budget and vice versa
 * (CWE-307 / CWE-770).</p>
 */
public enum AbuseAttemptType {
  LOGIN,
  PASSWORD_CHANGE,
  RESET_REQUEST,
  RESET_CONSUME
}
