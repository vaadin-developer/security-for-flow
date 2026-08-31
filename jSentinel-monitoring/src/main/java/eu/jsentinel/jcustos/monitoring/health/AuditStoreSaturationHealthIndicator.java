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

import eu.jsentinel.jcustos.audit.RingBufferAuditSink;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.dx.runtime.HealthFinding;
import eu.jsentinel.jcustos.dx.runtime.Severity;

import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Health indicator for the {@link RingBufferAuditSink} fill level —
 * the health-side anchor of the Konzept-V00.80.00 Audit-Store-Lag
 * signal. When the retained-event count reaches the configured warn
 * ratio of the capacity, a {@link Severity#WARNING} finding with code
 * {@link #SATURATION_CODE} is reported; a saturated ring buffer is
 * about to drop its oldest events, i.e. audit history is being lost.
 *
 * <p>The corresponding gauge
 * ({@link eu.jsentinel.jcustos.monitoring.metrics.JCustosMetricNames#AUDIT_STORE_LAG
 * security.audit.store.lag}) stays application-wired via the metrics
 * SPI — this indicator covers the pull-style {@code /health} view of
 * the same signal.</p>
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class AuditStoreSaturationHealthIndicator implements JCustosHealthIndicator {

  /** Stable indicator id. */
  public static final String ID = "audit-store";

  /** Finding code reported when the warn ratio is reached. */
  public static final String SATURATION_CODE = "monitoring/audit-store-saturation";

  /** Default warn ratio when none is configured explicitly. */
  public static final double DEFAULT_WARN_RATIO = 0.9d;

  private final RingBufferAuditSink sink;
  private final double warnRatio;

  /**
   * Builds an indicator with the {@link #DEFAULT_WARN_RATIO}.
   *
   * @param sink the observed audit ring buffer, never {@code null}
   */
  public AuditStoreSaturationHealthIndicator(RingBufferAuditSink sink) {
    this(sink, DEFAULT_WARN_RATIO);
  }

  /**
   * @param sink      the observed audit ring buffer, never {@code null}
   * @param warnRatio saturation threshold in {@code (0, 1]}; a finding
   *                  is reported when
   *                  {@code size / capacity >= warnRatio}
   */
  public AuditStoreSaturationHealthIndicator(RingBufferAuditSink sink, double warnRatio) {
    this.sink = Objects.requireNonNull(sink, "sink");
    if (!(warnRatio > 0.0d && warnRatio <= 1.0d)) {
      throw new IllegalArgumentException(
          "warnRatio must be in (0, 1], but was " + warnRatio);
    }
    this.warnRatio = warnRatio;
  }

  @Override
  public String id() {
    return ID;
  }

  @Override
  public List<HealthFinding> check() {
    int size = sink.size();
    int capacity = sink.capacity();
    double saturation = (double) size / capacity;
    if (saturation < warnRatio) {
      return List.of();
    }
    return List.of(new HealthFinding(Severity.WARNING, SATURATION_CODE,
        String.format(Locale.ROOT,
            "Audit ring buffer holds %d of %d events (saturation %.2f >= warn ratio %.2f)"
                + " — the oldest events are about to be dropped.",
            size, capacity, saturation, warnRatio)));
  }
}
