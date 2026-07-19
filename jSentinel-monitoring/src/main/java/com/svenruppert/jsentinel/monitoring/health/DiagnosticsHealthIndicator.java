package com.svenruppert.jsentinel.monitoring.health;

/*-
 * #%L
 * jSentinel Monitoring — metrics, health and diagnostics export points
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.dx.diagnostics.DuplicateService;
import com.svenruppert.jsentinel.dx.diagnostics.JSentinelDiagnostics;
import com.svenruppert.jsentinel.dx.diagnostics.JSentinelServiceReport;
import com.svenruppert.jsentinel.dx.diagnostics.MissingRecommendedService;
import com.svenruppert.jsentinel.dx.diagnostics.ServiceWarning;
import com.svenruppert.jsentinel.dx.runtime.HealthFinding;
import com.svenruppert.jsentinel.dx.runtime.Severity;

import java.util.ArrayList;
import java.util.List;

/**
 * Health indicator over the dx diagnostics sweep: runs
 * {@link JSentinelDiagnostics#inspect()} and maps the resulting
 * {@link JSentinelServiceReport} into {@link HealthFinding}s.
 *
 * <p>Mapping:</p>
 * <ul>
 *   <li>{@link JSentinelServiceReport#missing()} ⇒
 *       {@link Severity#ERROR} finding with code
 *       {@link #MISSING_SERVICE_CODE} — a missing critical SPI means
 *       the security stack cannot work.</li>
 *   <li>{@link JSentinelServiceReport#duplicates()} ⇒
 *       {@link Severity#WARNING} finding with code
 *       {@link #DUPLICATE_SERVICE_CODE}.</li>
 *   <li>{@link JSentinelServiceReport#warnings()} ⇒
 *       {@link Severity#WARNING} finding carrying the warning's own
 *       code — consumers route on codes, so the diagnostic code passes
 *       through unchanged.</li>
 * </ul>
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class DiagnosticsHealthIndicator implements JSentinelHealthIndicator {

  /** Stable indicator id. */
  public static final String ID = "diagnostics";

  /** Finding code for a missing recommended SPI implementation. */
  public static final String MISSING_SERVICE_CODE = "diagnostics/missing-service";

  /** Finding code for an SPI with multiple registered implementations. */
  public static final String DUPLICATE_SERVICE_CODE = "diagnostics/duplicate-service";

  /** ServiceLoader requires a public no-arg constructor. */
  public DiagnosticsHealthIndicator() {
  }

  @Override
  public String id() {
    return ID;
  }

  @Override
  public List<HealthFinding> check() {
    JSentinelServiceReport report = JSentinelDiagnostics.inspect();
    List<HealthFinding> findings = new ArrayList<>();
    for (MissingRecommendedService missing : report.missing()) {
      findings.add(new HealthFinding(Severity.ERROR, MISSING_SERVICE_CODE,
          withFix(missing.spi().getSimpleName() + ": " + missing.reason(),
              missing.suggestedFix())));
    }
    for (DuplicateService duplicate : report.duplicates()) {
      findings.add(new HealthFinding(Severity.WARNING, DUPLICATE_SERVICE_CODE,
          duplicate.spi().getSimpleName()
              + ": multiple implementations registered: "
              + implNames(duplicate.impls())));
    }
    for (ServiceWarning warning : report.warnings()) {
      findings.add(new HealthFinding(Severity.WARNING, warning.code(),
          withFix(warning.message(), warning.suggestedFix())));
    }
    return findings;
  }

  private static String withFix(String message, String suggestedFix) {
    if (suggestedFix.isBlank()) {
      return message;
    }
    return message + " Suggested fix: " + suggestedFix;
  }

  private static String implNames(List<Class<?>> impls) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < impls.size(); i++) {
      if (i > 0) {
        sb.append(", ");
      }
      sb.append(impls.get(i).getName());
    }
    return sb.toString();
  }
}
