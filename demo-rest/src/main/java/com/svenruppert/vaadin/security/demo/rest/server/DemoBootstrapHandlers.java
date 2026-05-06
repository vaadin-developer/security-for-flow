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
import com.svenruppert.vaadin.security.bootstrap.CreateInitialAdminCommand;
import com.svenruppert.vaadin.security.bootstrap.InitialAdminBootstrapService;
import com.svenruppert.vaadin.security.bootstrap.InitialAdminCreationResult;
import com.svenruppert.vaadin.security.demo.rest.shared.DemoJson;
import com.svenruppert.vaadin.security.rest.RestRequest;
import com.svenruppert.vaadin.security.rest.RestResponse;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST handlers for {@code /api/bootstrap/*}.
 * <p>
 * The handlers do not log the bootstrap token, never echo it in responses,
 * and never put it in error messages. The actual security decision happens
 * inside {@link InitialAdminBootstrapService}; the handlers only translate
 * the result to an HTTP status code.
 */
public final class DemoBootstrapHandlers {

  private final BootstrapStateService stateService;
  private final InitialAdminBootstrapService bootstrapService;

  public DemoBootstrapHandlers(
      BootstrapStateService stateService,
      InitialAdminBootstrapService bootstrapService) {
    this.stateService = stateService;
    this.bootstrapService = bootstrapService;
  }

  public void status(RestRequest request, RestResponse response) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("bootstrapRequired", stateService.bootstrapRequired());
    payload.put("mode", stateService.mode().name());
    response.status(200);
    response.body(DemoJson.encode(payload));
  }

  public void createInitialAdmin(RestRequest request, RestResponse response) {
    Map<String, Object> body;
    try {
      body = DemoJson.decodeObject(((DemoHttpRequest) request).body());
    } catch (RuntimeException e) {
      writeError(response, 400, "bad_request");
      return;
    }
    String token = string(body, "bootstrapToken");
    String username = string(body, "username");
    String password = string(body, "password");
    String displayName = string(body, "displayName");
    String email = string(body, "email");
    if (token == null || username == null || password == null) {
      writeError(response, 400, "bad_request");
      return;
    }
    char[] pwd = password.toCharArray();
    InitialAdminCreationResult result = bootstrapService.createInitialAdmin(
        new CreateInitialAdminCommand(token, username, pwd, displayName, email));
    switch (result) {
      case InitialAdminCreationResult.Created created -> {
        response.status(201);
        response.body(DemoJson.encode(Map.of("status", "created")));
      }
      case InitialAdminCreationResult.AlreadyInitialized ignored ->
          writeError(response, 409, "system_already_initialized");
      case InitialAdminCreationResult.InvalidBootstrapToken ignored ->
          writeError(response, 403, "invalid_bootstrap_token");
      case InitialAdminCreationResult.PasswordPolicyViolation policy -> {
        response.status(400);
        response.body(DemoJson.encode(Map.of(
            "error", "password_policy_violation",
            "reason", policy.reason() == null ? "" : policy.reason())));
      }
      case InitialAdminCreationResult.InvalidUsername invalid -> {
        response.status(400);
        response.body(DemoJson.encode(Map.of(
            "error", "invalid_username",
            "reason", invalid.reason() == null ? "" : invalid.reason())));
      }
      case InitialAdminCreationResult.InternalError internal ->
          writeError(response, 500, "internal_error");
    }
  }

  private static String string(Map<String, Object> body, String key) {
    Object value = body.get(key);
    return value instanceof String s ? s : null;
  }

  private static void writeError(RestResponse response, int status, String error) {
    response.status(status);
    response.body(DemoJson.encode(Map.of("error", error)));
  }
}
