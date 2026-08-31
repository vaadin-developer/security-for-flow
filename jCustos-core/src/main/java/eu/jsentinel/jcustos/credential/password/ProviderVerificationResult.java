/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
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

package eu.jsentinel.jcustos.credential.password;


import eu.jsentinel.jcustos.credential.InternalAuditEventType;

import java.util.Objects;

/**
 * Provider-level outcome of running a KDF and comparing the derived
 * material against the stored inner hash.
 *
 * <p>This type is sealed so the verification pipeline can pattern-match
 * exhaustively. Provider implementations must not throw exceptions for
 * the normal mismatch case; they return {@link NotMatched} instead. They
 * may return {@link ProviderError} when the KDF cannot be executed at all
 * (e.g. unavailable JCA service); in that case the pipeline collapses
 * the response onto a generic public failure and records the supplied
 * {@link InternalAuditEventType} internally.</p>
 *
 * <p>The {@code message} of {@link ProviderError} is intended for audit
 * sinks; it must not contain secrets, salts, derived key material or
 * encoded envelopes.</p>
 */
public sealed interface ProviderVerificationResult
    permits ProviderVerificationResult.Matched,
            ProviderVerificationResult.NotMatched,
            ProviderVerificationResult.ProviderError {

  record Matched() implements ProviderVerificationResult {
    public static final Matched INSTANCE = new Matched();
  }

  record NotMatched() implements ProviderVerificationResult {
    public static final NotMatched INSTANCE = new NotMatched();
  }

  record ProviderError(
      InternalAuditEventType internalAuditEventType,
      String message
  ) implements ProviderVerificationResult {

    public ProviderError {
      Objects.requireNonNull(internalAuditEventType, "internalAuditEventType");
      Objects.requireNonNull(message, "message");
    }
  }
}
