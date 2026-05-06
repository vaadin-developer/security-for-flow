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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.bootstrap.BootstrapStateService;
import com.svenruppert.vaadin.security.bootstrap.BootstrapStatus;
import com.svenruppert.vaadin.security.bootstrap.CreateInitialAdminCommand;
import com.svenruppert.vaadin.security.bootstrap.InitialAdminBootstrapService;
import com.svenruppert.vaadin.security.bootstrap.InitialAdminCreationResult;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoJson;
import com.svenruppert.vaadin.security.rest.BodyRestRequest;
import com.svenruppert.vaadin.security.rest.BootstrapRestStatusMapper;
import com.svenruppert.vaadin.security.rest.RestRequest;
import com.svenruppert.vaadin.security.rest.RestResponse;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST handlers for {@code /api/bootstrap/*}.
 * <p>
 * The handlers never log the bootstrap token, never echo it in responses,
 * and never put it in error messages. The security decision lives in
 * {@link InitialAdminBootstrapService}; the handlers translate the result
 * to an HTTP status via {@link BootstrapRestStatusMapper}.
 */
public final class DemoBootstrapHandlers {

  private static final BootstrapRestStatusMapper STATUS_MAPPER = new BootstrapRestStatusMapper();

  private final BootstrapStateService stateService;
  private final InitialAdminBootstrapService bootstrapService;

  public DemoBootstrapHandlers(
      BootstrapStateService stateService,
      InitialAdminBootstrapService bootstrapService) {
    this.stateService = stateService;
    this.bootstrapService = bootstrapService;
  }

  public void status(RestRequest request, RestResponse response) {
    BootstrapStatus snapshot = BootstrapStatus.from(stateService);
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("bootstrapRequired", snapshot.bootstrapRequired());
    payload.put("mode", snapshot.mode().name());
    response.status(200);
    response.body(DemoJson.encode(payload));
  }

  public void createInitialAdmin(RestRequest request, RestResponse response) {
    if (!(request instanceof BodyRestRequest bodyRequest)) {
      writeJson(response, 400, Map.of("error", "bad_request"));
      return;
    }
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(bodyRequest.bodyAsUtf8());
    } catch (RuntimeException e) {
      writeJson(response, 400, Map.of("error", "bad_request"));
      return;
    }
    String token = string(body, "bootstrapToken");
    String username = string(body, "username");
    String password = string(body, "password");
    String displayName = string(body, "displayName");
    String email = string(body, "email");
    if (token == null || username == null || password == null) {
      writeJson(response, 400, Map.of("error", "bad_request"));
      return;
    }
    char[] pwd = password.toCharArray();
    InitialAdminCreationResult result = bootstrapService.createInitialAdmin(
        new CreateInitialAdminCommand(token, username, pwd, displayName, email));

    int status = STATUS_MAPPER.statusFor(result);
    String code = STATUS_MAPPER.errorCodeFor(result);
    Map<String, Object> payload = new LinkedHashMap<>();
    if (result instanceof InitialAdminCreationResult.Created) {
      payload.put("status", code);
    } else {
      payload.put("error", code);
      if (result instanceof InitialAdminCreationResult.PasswordPolicyViolation policy) {
        payload.put("reason", policy.reason() == null ? "" : policy.reason());
      } else if (result instanceof InitialAdminCreationResult.InvalidUsername invalid) {
        payload.put("reason", invalid.reason() == null ? "" : invalid.reason());
      }
    }
    writeJson(response, status, payload);
  }

  private static String string(Map<String, Object> body, String key) {
    Object value = body.get(key);
    return value instanceof String s ? s : null;
  }

  private static void writeJson(RestResponse response, int status, Map<String, Object> payload) {
    response.status(status);
    response.body(DemoJson.encode(payload));
  }
}
