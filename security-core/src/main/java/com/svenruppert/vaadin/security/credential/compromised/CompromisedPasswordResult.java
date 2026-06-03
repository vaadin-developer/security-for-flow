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
package com.svenruppert.vaadin.security.credential.compromised;

import java.util.Objects;

/**
 * Sealed result of a {@link CompromisedPasswordChecker} call.
 *
 * <p>The result is intentionally not a {@code boolean} — the
 * "compromised vs unknown vs check-failed" trichotomy carries the
 * information that callers need to apply the operator-configured
 * failure policy (CWE-203, CWE-209).</p>
 */
public sealed interface CompromisedPasswordResult
    permits CompromisedPasswordResult.Clean,
            CompromisedPasswordResult.Pwned,
            CompromisedPasswordResult.CheckFailed {

  /**
   * The candidate password is not present in the checker's data
   * source. Note: this is "not found" — the absence of evidence,
   * not evidence of safety.
   */
  record Clean() implements CompromisedPasswordResult {
    public static final Clean INSTANCE = new Clean();
  }

  /**
   * The candidate password matched a known compromised entry.
   *
   * @param occurrences number of times the password is known to have
   *                    appeared in breach data; sources that do not
   *                    report a count must use {@code 1}
   */
  record Pwned(long occurrences) implements CompromisedPasswordResult {
    public Pwned {
      if (occurrences < 1L) {
        throw new IllegalArgumentException("occurrences must be >= 1");
      }
    }
  }

  /**
   * The checker could not produce a verdict — network outage,
   * malformed response, timeout, etc. The caller applies
   * {@link CompromisedPasswordPolicy#onFailure()} to decide
   * whether to allow, warn or block the change.
   *
   * <p>The reason is a structural identifier (not free-form text)
   * so audit sinks can summarise without leaking secrets.</p>
   */
  record CheckFailed(FailureReason reason)
      implements CompromisedPasswordResult {
    public CheckFailed {
      Objects.requireNonNull(reason, "reason");
    }
  }

  /**
   * Structured failure reason — never carries password material,
   * URLs or response bodies.
   */
  enum FailureReason {
    NETWORK,
    TIMEOUT,
    MALFORMED_RESPONSE,
    RATE_LIMITED,
    DISABLED,
    UNKNOWN
  }
}
