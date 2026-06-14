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
package com.svenruppert.jsentinel.dx.runtime;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * One observation in a {@link HealthStatus} report — typically a
 * {@link JSentinelBootstrapWarning} mapped into the health surface.
 * <p>
 * The {@code code} string is the stable diagnostic identifier shared with
 * {@code JSentinelBootstrapWarning#code()} (e.g.
 * {@code "audit/missing-service"}, {@code "credentials/modern-without-bc"}).
 * Consumers route on the code, not on the human-readable {@code message}.
 *
 * @since 00.74.10
 */
@ExperimentalJSentinelApi
public record HealthFinding(Severity severity, String code, String message) {

  public HealthFinding {
    Objects.requireNonNull(severity, "severity");
    Objects.requireNonNull(code, "code");
    Objects.requireNonNull(message, "message");
  }
}
