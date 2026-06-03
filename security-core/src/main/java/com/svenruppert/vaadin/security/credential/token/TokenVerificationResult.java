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
package com.svenruppert.vaadin.security.credential.token;

/**
 * Outcome of {@link TokenDigestService#verifyVerifier}. Sealed so
 * adapters pattern-match exhaustively. The two failure variants must
 * collapse to the same generic public response at the perimeter
 * (CWE-203 / CWE-208).
 */
public sealed interface TokenVerificationResult
    permits TokenVerificationResult.Verified,
            TokenVerificationResult.NotMatched,
            TokenVerificationResult.SelectorMismatch {

  record Verified() implements TokenVerificationResult {
    public static final Verified INSTANCE = new Verified();
  }

  record NotMatched() implements TokenVerificationResult {
    public static final NotMatched INSTANCE = new NotMatched();
  }

  /**
   * The supplied token's selector does not match the stored digest's
   * selector. Treated identically to {@link NotMatched} at the
   * perimeter but kept distinct for internal audit.
   */
  record SelectorMismatch() implements TokenVerificationResult {
    public static final SelectorMismatch INSTANCE = new SelectorMismatch();
  }
}
