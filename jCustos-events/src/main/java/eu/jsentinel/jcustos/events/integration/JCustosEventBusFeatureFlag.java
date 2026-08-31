package eu.jsentinel.jcustos.events.integration;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * The feature flag that gates event-bus emission from existing services
 * (Konzept §1029, plan P034). Legacy direct-audit deployments keep working with
 * the bus disabled.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class JCustosEventBusFeatureFlag {

  private JCustosEventBusFeatureFlag() {
  }

  /** System property controlling bus emission. */
  public static final String PROPERTY = "jcustos.events.bus.enabled";

  /**
   * @return {@code true} if bus emission is enabled (default {@code false})
   */
  public static boolean enabled() {
    return Boolean.parseBoolean(System.getProperty(PROPERTY, "false"));
  }
}
