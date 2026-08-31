package eu.jsentinel.jcustos.jwt.diagnostics;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticContributor;
import eu.jsentinel.jcustos.dx.diagnostics.DiagnosticReportBuilder;
import eu.jsentinel.jcustos.dx.diagnostics.ServiceWarning;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;

import java.util.Optional;

/**
 * V00.76 JWT diagnostics. Surfaces a warning when {@code .jwt(...)} was never
 * wired (no {@link JwtValidator} registered). Reads only the core resolver SPI —
 * no JOSE types — so it stays side-effect-free and JOSE-agnostic.
 *
 * @since 00.76.00
 */
@JCustosAutoService(DiagnosticContributor.class)
public final class JwtDiagnosticContributor implements DiagnosticContributor {

  /** ServiceLoader requires a public no-arg constructor. */
  public JwtDiagnosticContributor() {
  }

  @Override
  public String id() {
    return "jwt";
  }

  @Override
  public void contribute(DiagnosticReportBuilder builder) {
    try {
      Optional<JwtValidator> validator = JCustosServiceResolver.findJwtValidator();
      if (validator.isEmpty()) {
        builder.addWarning(new ServiceWarning(
            "jwt/no-validator",
            "No JwtValidator is registered.",
            "Configure one via .jwt(j -> j.jwksUri(...).algorithmProfile(...)) "
                + "or .jwt(j -> j.validator(...))."));
      }
    } catch (RuntimeException e) {
      builder.addWarning(new ServiceWarning(
          "jwt/rule-failed",
          "JWT diagnostic failed: " + e.getClass().getSimpleName(),
          "Inspect JCustosServiceResolver state."));
    }
  }
}
