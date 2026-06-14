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

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Structured health classification of a {@link JSentinelRuntime} snapshot —
 * the canonical {@code /health}-endpoint body type. Pure function of the
 * runtime warnings list, plus a wall-clock {@code inspectedAt} stamp.
 * <p>
 * Severity → overall classification:
 * <ul>
 *   <li>Any {@link Severity#ERROR} finding ⇒ {@link Health#FAILED}.
 *   <li>Any {@link Severity#WARNING} finding (no errors) ⇒ {@link Health#DEGRADED}.
 *   <li>Only {@link Severity#INFO} findings (or none) ⇒ {@link Health#HEALTHY}.
 * </ul>
 *
 * @since 00.74.10
 */
@ExperimentalJSentinelApi
public record HealthStatus(
    Health overall,
    List<HealthFinding> findings,
    int registeredServices,
    Instant inspectedAt) {

  public HealthStatus {
    Objects.requireNonNull(overall, "overall");
    Objects.requireNonNull(findings, "findings");
    Objects.requireNonNull(inspectedAt, "inspectedAt");
    if (registeredServices < 0) {
      throw new IllegalArgumentException("registeredServices must be >= 0");
    }
    findings = List.copyOf(findings);
  }

  /**
   * Returns the findings whose {@link Severity} equals {@code severity}.
   * The returned list is unmodifiable.
   */
  public List<HealthFinding> findingsBySeverity(Severity severity) {
    Objects.requireNonNull(severity, "severity");
    return findings.stream()
        .filter(f -> f.severity() == severity)
        .toList();
  }

  /** True when {@link #overall()} is {@link Health#FAILED}. */
  public boolean hasErrors() {
    return overall == Health.FAILED;
  }

  /** True when {@link #overall()} is {@link Health#DEGRADED}. */
  public boolean isDegraded() {
    return overall == Health.DEGRADED;
  }
}
