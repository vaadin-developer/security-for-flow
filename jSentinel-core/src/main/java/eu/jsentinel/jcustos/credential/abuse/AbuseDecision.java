/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.abuse;

import java.time.Duration;
import java.util.Objects;

/**
 * Progressive reaction returned by
 * {@link AbuseDetectionService#evaluate}.
 *
 * <p>Adapter-neutral, sealed. The adapter (Vaadin / REST / Standalone)
 * maps these decisions to concrete responses, but the perimeter
 * message must stay generic — exact counters / per-dimension
 * specifics never leak (CWE-203).</p>
 */
public sealed interface AbuseDecision
    permits AbuseDecision.Allow,
            AbuseDecision.Delay,
            AbuseDecision.Block,
            AbuseDecision.RequireAdditionalCheck {

  /**
   * The attempt may proceed unconditionally.
   */
  record Allow() implements AbuseDecision {
    public static final Allow INSTANCE = new Allow();
  }

  /**
   * Honour the attempt but pause for {@code delay} first — a soft
   * brake that slows automated scanners without locking the user
   * out.
   */
  record Delay(Duration delay, AbuseDimension dimension)
      implements AbuseDecision {

    public Delay {
      Objects.requireNonNull(delay, "delay");
      Objects.requireNonNull(dimension, "dimension");
      if (delay.isNegative() || delay.isZero()) {
        throw new IllegalArgumentException("delay must be positive");
      }
    }
  }

  /**
   * Refuse the attempt. The caller surfaces a generic public failure;
   * {@code retryAfter} is internal metadata for the audit trail.
   */
  record Block(Duration retryAfter, AbuseDimension dimension)
      implements AbuseDecision {

    public Block {
      Objects.requireNonNull(retryAfter, "retryAfter");
      Objects.requireNonNull(dimension, "dimension");
      if (retryAfter.isNegative() || retryAfter.isZero()) {
        throw new IllegalArgumentException("retryAfter must be positive");
      }
    }
  }

  /**
   * Require step-up authentication / captcha / additional check
   * before the attempt may proceed.
   */
  record RequireAdditionalCheck(AbuseDimension dimension)
      implements AbuseDecision {

    public RequireAdditionalCheck {
      Objects.requireNonNull(dimension, "dimension");
    }
  }
}
