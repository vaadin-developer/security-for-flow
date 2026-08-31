package eu.jsentinel.jcustos.events.publisher;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
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

/**
 * Pluggable alert target — a pager, ticket system, chat webhook, or the
 * in-tree {@link LoggingAlertSink}. Implementations should not throw; a
 * {@link RuntimeException} is isolated by the {@link JCustosAlertPublisher}
 * (logged, never propagated), so a failing sink cannot break event dispatch.
 *
 * @since 00.80.00
 */
@FunctionalInterface
@ExperimentalJCustosApi
public interface JCustosAlertSink {

  /**
   * Delivers one alert.
   *
   * @param alert the alert
   */
  void accept(JCustosAlert alert);
}
