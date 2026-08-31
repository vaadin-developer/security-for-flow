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
package eu.jsentinel.jcustos.demo.restclient.backend;

/**
 * Outcome of {@link DemoBackendClient#createInitialAdmin(BootstrapAdminRequest)}.
 * Mirrors the server-side {@code InitialAdminCreationResult} variants
 * relevant to the UI.
 */
public sealed interface BootstrapResult
    permits BootstrapResult.Created,
            BootstrapResult.AlreadyInitialized,
            BootstrapResult.InvalidToken,
            BootstrapResult.PolicyViolation,
            BootstrapResult.InvalidUsername,
            BootstrapResult.TransportError,
            BootstrapResult.InternalError {

  record Created(String username) implements BootstrapResult {
  }

  record AlreadyInitialized() implements BootstrapResult {
  }

  record InvalidToken() implements BootstrapResult {
  }

  record PolicyViolation(String reason) implements BootstrapResult {
  }

  record InvalidUsername(String reason) implements BootstrapResult {
  }

  record TransportError(String message) implements BootstrapResult {
  }

  record InternalError(String message) implements BootstrapResult {
  }
}
