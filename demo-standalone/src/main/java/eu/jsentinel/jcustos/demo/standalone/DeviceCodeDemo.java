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
package eu.jsentinel.jcustos.demo.standalone;

import com.svenruppert.functional.result.Result;
import eu.jsentinel.jcustos.oauth2.DeviceTokenPoller;
import eu.jsentinel.jcustos.oauth2.HttpDeviceAuthorizationClient;
import eu.jsentinel.jcustos.oauth2.HttpTokenEndpointClient;
import eu.jsentinel.jcustos.oauth2.api.ClientAuthentication;
import eu.jsentinel.jcustos.oauth2.api.DeviceAuthorizationResponse;
import eu.jsentinel.jcustos.oauth2.api.OAuth2Error;
import eu.jsentinel.jcustos.oauth2.api.TokenResponse;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * V00.77 reference: how a CLI / standalone tool — which has no browser — logs in
 * with the OAuth2 Device Authorization Grant (RFC 8628). The tool requests a
 * device + user code, shows the user where to authorize on a second device, then
 * polls the token endpoint until the grant resolves. This class is transport-only
 * (the {@code instructions} consumer renders the user prompt); the
 * {@code DeviceCodeDemoTest} drives it end-to-end against a real {@code HttpServer}.
 */
public final class DeviceCodeDemo {

  private final HttpDeviceAuthorizationClient deviceClient;
  private final DeviceTokenPoller poller;
  private final Consumer<String> instructions;
  private final Set<String> scopes;

  public DeviceCodeDemo(URI deviceAuthorizationEndpoint, URI tokenEndpoint, String clientId,
      Set<String> scopes, Consumer<String> instructions) {
    ClientAuthentication auth = new ClientAuthentication.NoneAuthentication(
        Objects.requireNonNull(clientId, "clientId"));
    HttpClient http = HttpClient.newHttpClient();
    this.deviceClient = new HttpDeviceAuthorizationClient(http, deviceAuthorizationEndpoint, auth);
    this.poller = new DeviceTokenPoller(
        new HttpTokenEndpointClient(tokenEndpoint, auth, http));
    this.scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
    this.instructions = Objects.requireNonNull(instructions, "instructions");
  }

  /**
   * Runs the full device-grant login: request the code, prompt the user, poll
   * for tokens.
   *
   * @return the obtained tokens, or a non-secret {@link OAuth2Error}
   */
  public Result<TokenResponse, OAuth2Error> login() {
    Result<DeviceAuthorizationResponse, OAuth2Error> started =
        deviceClient.requestDeviceCode(scopes);
    if (started.isFailure()) {
      return started.map(d -> (TokenResponse) null);
    }
    DeviceAuthorizationResponse device = started.toOptional().orElseThrow();
    instructions.accept("To sign in, visit " + device.verificationUri()
        + " and enter code: " + device.userCode());
    return poller.poll(device);
  }
}
