package eu.jsentinel.jcustos.jwt.impl;

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

import eu.jsentinel.jcustos.autoservice.api.JCustosAutoService;
import eu.jsentinel.jcustos.jwt.api.JwtValidator;
import eu.jsentinel.jcustos.jwt.api.JwtValidatorFactory;
import eu.jsentinel.jcustos.jwt.api.JwtValidatorSpec;

import java.util.Objects;

/**
 * Nimbus-backed {@link JwtValidatorFactory}. Registered via
 * {@code @JCustosAutoService} so {@code jCustos-dx} can discover it through
 * {@link java.util.ServiceLoader} and assemble a validator from a
 * {@link JwtValidatorSpec} without ever compiling against a JOSE type.
 *
 * @since 00.76.00
 */
@JCustosAutoService(JwtValidatorFactory.class)
public final class NimbusJwtValidatorFactory implements JwtValidatorFactory {

  /** ServiceLoader requires a public no-arg constructor. */
  public NimbusJwtValidatorFactory() {
  }

  @Override
  public JwtValidator create(JwtValidatorSpec spec) {
    Objects.requireNonNull(spec, "spec");
    return new NimbusJwtValidator(
        spec.allowList(), new HttpJwksClient(spec.jwksUri()), spec.expectations());
  }
}
