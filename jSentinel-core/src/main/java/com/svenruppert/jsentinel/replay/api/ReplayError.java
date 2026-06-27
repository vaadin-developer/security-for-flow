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
package com.svenruppert.jsentinel.replay.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;

/**
 * A non-secret replay-protection failure (V00.79). Returned by {@link JtiStore}
 * when a one-time identifier ({@code jti}) has already been seen within its
 * validity window — the signal that a DPoP proof / JWT is being replayed.
 *
 * @param code    a stable kebab-case code
 * @param message a short non-secret description
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public record ReplayError(String code, String message) {

  public ReplayError {
    Objects.requireNonNull(code, "code");
    Objects.requireNonNull(message, "message");
  }

  /** The {@code jti} was already recorded — a replay. */
  public static ReplayError replayDetected() {
    return new ReplayError("replay/jti-already-seen", "the one-time identifier was already used");
  }
}
