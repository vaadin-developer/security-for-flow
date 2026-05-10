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
package com.svenruppert.vaadin.security.audit;

/**
 * Closed set of security-relevant event categories produced by the framework
 * and by application code.
 * <p>
 * The enum is intentionally flat — finer-grained semantics belong in
 * {@link SecurityAuditEvent#attributes()}.
 */
public enum SecurityAuditEventType {

  /** A login attempt succeeded — credentials accepted. */
  LOGIN_SUCCESS,

  /** A login attempt failed — credentials rejected. */
  LOGIN_FAILURE,

  /** A subject explicitly logged out. */
  LOGOUT,

  /** Access to a protected resource (route, REST endpoint, action) was granted. */
  ACCESS_GRANTED,

  /** Access to a protected resource was denied (no subject or insufficient roles/permissions). */
  ACCESS_DENIED,

  /** A new session was created for a subject. */
  SESSION_CREATED,

  /** A session expired due to inactivity or absolute lifetime. */
  SESSION_EXPIRED,

  /** A session was invalidated by application or framework code. */
  SESSION_INVALIDATED,

  /** A role was assigned to a subject. */
  ROLE_ASSIGNED,

  /** A role was revoked from a subject. */
  ROLE_REVOKED,

  /** A login-attempt policy throttled or locked a subject / address. */
  BRUTE_FORCE_LIMIT_REACHED,

  /** A guarded action call was denied via {@code requireAllowed(...)}. */
  ACTION_DENIED
}
