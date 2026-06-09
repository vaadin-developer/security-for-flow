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
package com.svenruppert.jsentinel.demo.restclient.backend;

import java.util.Objects;

/**
 * Domain-shaped failure surface for {@link DemoBackendClient}.
 * <p>
 * UI code matches on {@link #kind()}, never on raw HTTP status codes.
 * Error messages must never carry tokens or sensitive payloads.
 */
public final class BackendException extends RuntimeException {

  /** Semantic categories the UI can map to UX. */
  public enum Kind {
    /** No / invalid token — UI should reroute to the login view. */
    Unauthenticated,
    /** Authenticated but missing the required permission — UX denial. */
    Forbidden,
    /** Resource not found. */
    NotFound,
    /** Malformed request / validation failure. */
    BadRequest,
    /** Conflict, e.g. setup attempted after first-run completed. */
    Conflict,
    /** Backend reported a 5xx server-side problem. */
    ServerError,
    /** Network / I/O / timeout — backend is unreachable. */
    Transport
  }

  private final Kind kind;

  public BackendException(Kind kind, String message) {
    super(message);
    this.kind = Objects.requireNonNull(kind, "kind");
  }

  public BackendException(Kind kind, String message, Throwable cause) {
    super(message, cause);
    this.kind = Objects.requireNonNull(kind, "kind");
  }

  public Kind kind() {
    return kind;
  }
}
