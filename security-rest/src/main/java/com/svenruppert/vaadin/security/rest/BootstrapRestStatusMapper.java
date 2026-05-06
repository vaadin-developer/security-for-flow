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
package com.svenruppert.vaadin.security.rest;

import com.svenruppert.vaadin.security.bootstrap.InitialAdminCreationResult;

/**
 * Maps an {@link InitialAdminCreationResult} to an HTTP status code and a
 * stable error code suitable for inclusion in a JSON response body. Does
 * not serialize the body itself — that stays with the application so this
 * module remains framework-light.
 */
public final class BootstrapRestStatusMapper {

  public int statusFor(InitialAdminCreationResult result) {
    return switch (result) {
      case InitialAdminCreationResult.Created ignored -> 201;
      case InitialAdminCreationResult.AlreadyInitialized ignored -> 409;
      case InitialAdminCreationResult.InvalidBootstrapToken ignored -> 403;
      case InitialAdminCreationResult.PasswordPolicyViolation ignored -> 400;
      case InitialAdminCreationResult.InvalidUsername ignored -> 400;
      case InitialAdminCreationResult.InternalError ignored -> 500;
    };
  }

  public String errorCodeFor(InitialAdminCreationResult result) {
    return switch (result) {
      case InitialAdminCreationResult.Created ignored -> "created";
      case InitialAdminCreationResult.AlreadyInitialized ignored -> "system_already_initialized";
      case InitialAdminCreationResult.InvalidBootstrapToken ignored -> "invalid_bootstrap_token";
      case InitialAdminCreationResult.PasswordPolicyViolation ignored -> "password_policy_violation";
      case InitialAdminCreationResult.InvalidUsername ignored -> "invalid_username";
      case InitialAdminCreationResult.InternalError ignored -> "internal_error";
    };
  }
}
