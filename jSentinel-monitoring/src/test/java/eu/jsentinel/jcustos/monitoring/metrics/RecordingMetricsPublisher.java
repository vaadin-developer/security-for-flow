package eu.jsentinel.jcustos.monitoring.metrics;

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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Module-local test double: records every counter increment and gauge
 * push into thread-safe maps for assertion. Not a mock — a real,
 * fully functional {@link JSentinelMetricsPublisher} implementation.
 */
public final class RecordingMetricsPublisher implements JSentinelMetricsPublisher {

  private final ConcurrentHashMap<String, Long> counters = new ConcurrentHashMap<>();
  private final ConcurrentHashMap<String, Long> gauges = new ConcurrentHashMap<>();

  public RecordingMetricsPublisher() {
  }

  @Override
  public void increment(String counterName, long delta) {
    counters.merge(counterName, delta, Long::sum);
  }

  @Override
  public void gauge(String gaugeName, long value) {
    gauges.put(gaugeName, value);
  }

  /** Current value of the named counter; {@code 0} if never incremented. */
  public long counter(String counterName) {
    return counters.getOrDefault(counterName, 0L);
  }

  /** Snapshot of all recorded counters. */
  public Map<String, Long> counters() {
    return Map.copyOf(counters);
  }

  /** Last pushed value of the named gauge; {@code 0} if never pushed. */
  public long gauge(String gaugeName) {
    return gauges.getOrDefault(gaugeName, 0L);
  }

  /** Snapshot of all recorded gauges. */
  public Map<String, Long> gauges() {
    return Map.copyOf(gauges);
  }

  /** Drops all recorded counters and gauges. */
  public void clear() {
    counters.clear();
    gauges.clear();
  }
}
