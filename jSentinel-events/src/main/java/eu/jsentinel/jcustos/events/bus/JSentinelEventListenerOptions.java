package eu.jsentinel.jcustos.events.bus;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

/**
 * Per-subscription options (Konzept §785). A <em>critical</em> listener can
 * trigger fail-closed behaviour when it throws; a non-critical listener's
 * failure is isolated and reported as a {@code ListenerFailed} event.
 *
 * @param critical whether the listener is critical
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public record JSentinelEventListenerOptions(boolean critical) {

  /**
   * @return non-critical options (the default)
   */
  public static JSentinelEventListenerOptions defaults() {
    return new JSentinelEventListenerOptions(false);
  }

  /**
   * @return critical options
   */
  public static JSentinelEventListenerOptions criticalListener() {
    return new JSentinelEventListenerOptions(true);
  }
}
