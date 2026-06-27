/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.dpop;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

/**
 * Validates an inbound DPoP proof (RFC 9449 §4.3), V00.79. An implementation parses
 * the {@code dpop+jwt} JWS, verifies its signature against the embedded public key,
 * checks {@code htm} / {@code htu} / {@code iat} / {@code ath}, enforces single-use of
 * {@code jti}, and returns the proof's key thumbprint so the caller can bind it to a
 * DPoP-confirmed access token ({@code cnf.jkt}). Failures are returned as a sealed
 * {@link DpopValidationError}, never thrown, and never echo the offending proof.
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public interface DpopProofValidator {

  Result<ValidatedDpopProof, DpopValidationError> validate(DpopValidationRequest request);
}
