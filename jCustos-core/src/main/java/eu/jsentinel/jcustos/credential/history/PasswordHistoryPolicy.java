/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.history;

/**
 * Opt-in password-history policy.
 *
 * <h2>Trade-off</h2>
 * <p>Password history rejects reuse of the last N passwords, which can
 * reduce easy rotation cycles. The trade-off is real, however: every
 * stored verifier is an additional attack surface (CWE-522). The
 * Konzept §15 explicitly recommends keeping password history
 * <em>off</em> by default and never enabling it together with forced
 * periodic rotation — that combination drives users toward the
 * weakest possible incremental passwords.</p>
 *
 * @param enabled     whether the history check runs at all
 * @param retainLast  how many historical verifiers to keep per user;
 *                    only consulted when {@code enabled} is true
 */
public record PasswordHistoryPolicy(boolean enabled, int retainLast) {

  public PasswordHistoryPolicy {
    if (retainLast < 0) {
      throw new IllegalArgumentException("retainLast must be >= 0");
    }
    if (enabled && retainLast == 0) {
      throw new IllegalArgumentException(
          "history enabled but retainLast is 0");
    }
  }

  /**
   * History disabled — the production default.
   */
  public static PasswordHistoryPolicy disabled() {
    return new PasswordHistoryPolicy(false, 0);
  }

  /**
   * History enabled with {@code retainLast} verifiers per user.
   */
  public static PasswordHistoryPolicy retain(int retainLast) {
    return new PasswordHistoryPolicy(true, retainLast);
  }
}
