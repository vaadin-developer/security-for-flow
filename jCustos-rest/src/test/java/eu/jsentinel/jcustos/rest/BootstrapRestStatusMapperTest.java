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
package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.bootstrap.InitialAdminCreationResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("BootstrapRestStatusMapper")
class BootstrapRestStatusMapperTest {

  private final BootstrapRestStatusMapper mapper = new BootstrapRestStatusMapper();

  @Test
  @DisplayName("status codes for all variants")
  void statusCodes() {
    assertEquals(201, mapper.statusFor(new InitialAdminCreationResult.Created("root")));
    assertEquals(409, mapper.statusFor(new InitialAdminCreationResult.AlreadyInitialized()));
    assertEquals(403, mapper.statusFor(new InitialAdminCreationResult.InvalidBootstrapToken()));
    assertEquals(400, mapper.statusFor(new InitialAdminCreationResult.PasswordPolicyViolation("too short")));
    assertEquals(400, mapper.statusFor(new InitialAdminCreationResult.InvalidUsername("bad")));
    assertEquals(500, mapper.statusFor(new InitialAdminCreationResult.InternalError("boom", null)));
  }

  @Test
  @DisplayName("error codes are stable strings")
  void errorCodes() {
    assertEquals("created", mapper.errorCodeFor(new InitialAdminCreationResult.Created("root")));
    assertEquals("system_already_initialized",
        mapper.errorCodeFor(new InitialAdminCreationResult.AlreadyInitialized()));
    assertEquals("invalid_bootstrap_token",
        mapper.errorCodeFor(new InitialAdminCreationResult.InvalidBootstrapToken()));
    assertEquals("password_policy_violation",
        mapper.errorCodeFor(new InitialAdminCreationResult.PasswordPolicyViolation("x")));
    assertEquals("invalid_username",
        mapper.errorCodeFor(new InitialAdminCreationResult.InvalidUsername("x")));
    assertEquals("internal_error",
        mapper.errorCodeFor(new InitialAdminCreationResult.InternalError("x", null)));
  }
}
