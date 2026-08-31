/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.dx.runtime;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

/**
 * Aggregate health classification of a {@link JSentinelRuntime} snapshot.
 * <p>
 * Semantics:
 * <ul>
 *   <li>{@link #FAILED} — at least one {@link Severity#ERROR} finding.
 *   <li>{@link #DEGRADED} — at least one {@link Severity#WARNING}, no errors.
 *   <li>{@link #HEALTHY} — no errors and no warnings. {@link Severity#INFO}
 *       findings do <strong>not</strong> degrade — they are informational
 *       only.
 * </ul>
 *
 * @since 00.74.10
 */
@ExperimentalJSentinelApi
public enum Health {
  HEALTHY,
  DEGRADED,
  FAILED
}
