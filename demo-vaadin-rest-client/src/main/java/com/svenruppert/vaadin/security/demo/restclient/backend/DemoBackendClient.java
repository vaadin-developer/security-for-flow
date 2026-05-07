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
package com.svenruppert.vaadin.security.demo.restclient.backend;

import com.svenruppert.vaadin.security.bootstrap.BootstrapStatus;

import java.util.List;

/**
 * Encapsulated, domain-shaped contract for talking to the {@code demo-rest}
 * backend. The Vaadin UI sees only this interface — no
 * {@code java.net.http}, no JSON, no HTTP status codes, no endpoint paths.
 * <p>
 * Outcomes are split between sealed result types (login, bootstrap setup —
 * legitimate multi-pathway outcomes) and {@link BackendException} (read /
 * mutate operations — failure is exceptional and pattern-matched on the
 * semantic {@code Kind}).
 */
public interface DemoBackendClient {

  // ── Bootstrap ────────────────────────────────────────────────

  BootstrapStatus bootstrapStatus();

  BootstrapResult createInitialAdmin(BootstrapAdminRequest request);

  // ── Authentication ───────────────────────────────────────────

  LoginResult login(Credentials credentials);

  /** @throws BackendException with {@link BackendException.Kind#Unauthenticated} if the token is invalid */
  RemoteUser currentUser(String token);

  void logout(String token);

  // ── Operations ───────────────────────────────────────────────

  /** Operations the authenticated subject is allowed to invoke. */
  List<RemoteOperation> visibleOperations(String token);

  // ── Documents ────────────────────────────────────────────────

  List<RemoteDocument> listDocuments(String token);

  RemoteDocument createDocument(String token, String title);

  void deleteDocument(String token, long id);

  // ── Admin ────────────────────────────────────────────────────

  RemoteAdminStatus adminStatus(String token);
}
