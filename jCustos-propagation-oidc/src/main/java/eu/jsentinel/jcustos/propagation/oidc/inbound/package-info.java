/*-
 * #%L
 * jCustos propagation — OIDC strategies
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

/**
 * V00.76 inbound JWT validation for the OIDC propagation module. Consumes the
 * core {@code JwtValidator} SPI via {@code JCustosServiceResolver} at runtime —
 * <strong>no</strong> compile dependency on {@code jCustos-jwt} and no JOSE
 * library on this module's classpath, so the module's JOSE enforcer ban stays
 * intact.
 *
 * @since 00.76.00
 */
package eu.jsentinel.jcustos.propagation.oidc.inbound;
