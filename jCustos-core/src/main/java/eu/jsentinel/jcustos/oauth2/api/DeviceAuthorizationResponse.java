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
package eu.jsentinel.jcustos.oauth2.api;

import java.net.URI;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The device-authorization response (RFC 8628 §3.2, V00.77). Carries the opaque
 * {@code device_code} the RP polls with, the {@code user_code} + verification URI
 * the human enters on a second device, the absolute expiry and the minimum poll
 * interval. The {@code device_code} is a credential — masked in {@link #toString()}.
 *
 * @since 00.77.00
 */
public record DeviceAuthorizationResponse(
    String deviceCode,
    String userCode,
    URI verificationUri,
    Optional<URI> verificationUriComplete,
    Instant expiresAt,
    long intervalSeconds) {

  /** RFC 8628 §3.2: the default poll interval when the server omits {@code interval}. */
  public static final long DEFAULT_INTERVAL_SECONDS = 5L;

  public DeviceAuthorizationResponse {
    Objects.requireNonNull(deviceCode, "deviceCode");
    Objects.requireNonNull(userCode, "userCode");
    Objects.requireNonNull(verificationUri, "verificationUri");
    Objects.requireNonNull(verificationUriComplete, "verificationUriComplete");
    Objects.requireNonNull(expiresAt, "expiresAt");
    if (intervalSeconds < 0) {
      throw new IllegalArgumentException("intervalSeconds must be >= 0");
    }
  }

  /** @return a string that masks the device_code (the user_code is shown — it is user-facing). */
  @Override
  public String toString() {
    return "DeviceAuthorizationResponse[deviceCode=***, userCode=" + userCode
        + ", verificationUri=" + verificationUri + ", expiresAt=" + expiresAt
        + ", intervalSeconds=" + intervalSeconds + "]";
  }
}
