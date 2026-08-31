package eu.jsentinel.jcustos.monitoring.metrics;

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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

/**
 * {@link ServiceLoader}-backed discovery for
 * {@link JCustosMetricsPublisher} implementations.
 *
 * <p>Resolution rules: no registered implementation → the
 * {@link NoOpJCustosMetricsPublisher#INSTANCE no-op publisher}
 * (logged as INFO {@code monitoring/no-metrics-publisher-discovered});
 * exactly one → that implementation; multiple → the deterministic
 * winner by implementation class name, logged as WARN
 * {@code monitoring/multiple-metrics-publishers}. Discovery never
 * throws — a broken service registration degrades to the no-op
 * publisher with a WARN.</p>
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class JCustosMetricsPublishers {

  private JCustosMetricsPublishers() {
  }

  /**
   * Discovers the effective {@link JCustosMetricsPublisher} via
   * {@link ServiceLoader}. Never throws.
   *
   * @return the discovered publisher, or
   *     {@link NoOpJCustosMetricsPublisher#INSTANCE} when none is
   *     registered or discovery fails
   */
  public static JCustosMetricsPublisher discover() {
    List<JCustosMetricsPublisher> providers = new ArrayList<>();
    try {
      for (JCustosMetricsPublisher provider : ServiceLoader.load(JCustosMetricsPublisher.class)) {
        providers.add(provider);
      }
    } catch (ServiceConfigurationError error) {
      HasLogger.staticLogger().warn(
          "monitoring/metrics-publisher-discovery-failed: "
              + "broken service registration — falling back to the no-op publisher", error);
      return NoOpJCustosMetricsPublisher.INSTANCE;
    }
    return select(providers);
  }

  /**
   * Selection seam for {@link #discover()}: applies the
   * none / one / multiple resolution rules to an already-collected
   * provider list. Package-private for direct unit testing.
   */
  static JCustosMetricsPublisher select(List<JCustosMetricsPublisher> providers) {
    if (providers.isEmpty()) {
      HasLogger.staticLogger().info(
          "monitoring/no-metrics-publisher-discovered: using the no-op publisher");
      return NoOpJCustosMetricsPublisher.INSTANCE;
    }
    if (providers.size() == 1) {
      return providers.get(0);
    }
    List<JCustosMetricsPublisher> sorted = new ArrayList<>(providers);
    sorted.sort(Comparator.comparing(provider -> provider.getClass().getName()));
    List<String> classNames = sorted.stream()
        .map(provider -> provider.getClass().getName())
        .toList();
    JCustosMetricsPublisher winner = sorted.get(0);
    HasLogger.staticLogger().warn(
        "monitoring/multiple-metrics-publishers: {} publishers registered {} — using {}",
        sorted.size(), classNames, winner.getClass().getName());
    return winner;
  }
}
