package eu.jsentinel.jcustos.monitoring.health;

/*-
 * #%L
 * jCustos Monitoring — metrics, health and diagnostics export points
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.dx.diagnostics.DuplicateService;
import eu.jsentinel.jcustos.dx.diagnostics.JCustosDiagnostics;
import eu.jsentinel.jcustos.dx.diagnostics.JCustosServiceReport;
import eu.jsentinel.jcustos.dx.diagnostics.MissingRecommendedService;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;
import eu.jsentinel.jcustos.dx.runtime.HealthFinding;
import eu.jsentinel.jcustos.dx.runtime.Severity;

import java.util.ArrayList;
import java.util.List;

/**
 * Health indicator over the dx diagnostics sweep: runs
 * {@link JCustosDiagnostics#inspect()} and maps the resulting
 * {@link JCustosServiceReport} into {@link HealthFinding}s.
 *
 * <p>Mapping:</p>
 * <ul>
 *   <li>{@link JCustosServiceReport#missing()} ⇒
 *       {@link Severity#ERROR} finding with code
 *       {@link #MISSING_SERVICE_CODE} — a missing critical SPI means
 *       the security stack cannot work.</li>
 *   <li>{@link JCustosServiceReport#duplicates()} ⇒
 *       {@link Severity#WARNING} finding with code
 *       {@link #DUPLICATE_SERVICE_CODE}.</li>
 *   <li>{@link JCustosServiceReport#warnings()} ⇒
 *       {@link Severity#WARNING} finding carrying the warning's own
 *       code — consumers route on codes, so the diagnostic code passes
 *       through unchanged.</li>
 * </ul>
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class DiagnosticsHealthIndicator implements JCustosHealthIndicator {

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
    JCustosServiceReport report = JCustosDiagnostics.inspect();
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
