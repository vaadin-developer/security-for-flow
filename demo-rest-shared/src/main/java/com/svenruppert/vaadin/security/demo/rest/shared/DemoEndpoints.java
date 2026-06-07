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
package com.svenruppert.vaadin.security.demo.rest.shared;

/** Demo endpoint path constants shared between server and CLI. */
public final class DemoEndpoints {

  public static final String API_PREFIX = "/api";
  public static final String LOGIN = "/api/login";
  public static final String LOGOUT = "/api/logout";
  public static final String ME = "/api/me";
  public static final String OPERATIONS = "/api/operations";
  public static final String DOCUMENTS = "/api/documents";
  public static final String DOCUMENT_BY_ID = "/api/documents/";
  /**
   * Documents inspector — accessible by any subject with either
   * {@code document:read} <em>or</em> {@code document:create}.
   * Demonstrates the {@code @RequiresAnyPermission} OR-semantics
   * evaluator.
   */
  public static final String DOCUMENTS_INSPECT = "/api/documents/inspect";
  public static final String ADMIN_STATUS = "/api/admin/status";
  public static final String ADMIN_USERS = "/api/admin/users";
  /** Single-user resource: {@code /api/admin/users/{username}}. PUT body {"role":"…"}. */
  public static final String ADMIN_USER_BY_NAME = "/api/admin/users/";
  public static final String AUDIT = "/api/audit";
  public static final String BOOTSTRAP_STATUS = "/api/bootstrap/status";
  public static final String BOOTSTRAP_ADMIN = "/api/bootstrap/admin";

  private DemoEndpoints() {
  }
}
