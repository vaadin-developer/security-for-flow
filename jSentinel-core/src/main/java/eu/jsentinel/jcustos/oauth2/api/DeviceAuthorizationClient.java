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

import com.svenruppert.functional.result.Result;

import java.util.Set;

/**
 * The device-authorization endpoint (RFC 8628 §3.1, V00.77) — the first leg of
 * the device grant: the RP asks for a {@code device_code} + {@code user_code},
 * then polls the token endpoint while the human authorizes on a second device.
 * JOSE-free; the HTTP implementation lives in {@code jCustos-oauth2}.
 *
 * @since 00.77.00
 */
public interface DeviceAuthorizationClient {

  /**
   * Requests a device + user code for the given scopes.
   *
   * @param scopes the requested scopes (may be empty)
   * @return the device-authorization response, or a non-secret {@link OAuth2Error}
   */
  Result<DeviceAuthorizationResponse, OAuth2Error> requestDeviceCode(Set<String> scopes);
}
