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
package com.svenruppert.jsentinel.demo.rest.shared;

/** Demo endpoint path constants shared between server and CLI. */
public final class DemoEndpoints {

  public static final String API_PREFIX = "/api";
  /** V00.76: validate an inbound JWT bearer token against the configured JwtValidator. */
  public static final String JWT_DEMO = "/api/jwt/demo";
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
  /**
   * Owned-document inspector — GET
   * {@code /api/owned-documents/{id}} returns the document if the
   * subject is admin OR the document's owner; 403 otherwise.
   * Protected by the V00.70 Policy-DSL example
   * {@code @RequiresPolicy("document.owner-or-admin")}.
   */
  public static final String OWNED_DOCUMENT_BY_ID = "/api/owned-documents/";
  public static final String ADMIN_STATUS = "/api/admin/status";
  public static final String ADMIN_USERS = "/api/admin/users";
  /** Single-user resource: {@code /api/admin/users/{username}}. PUT body {"role":"…"}. */
  public static final String ADMIN_USER_BY_NAME = "/api/admin/users/";
  public static final String AUDIT = "/api/audit";
  public static final String BOOTSTRAP_STATUS = "/api/bootstrap/status";
  public static final String BOOTSTRAP_ADMIN = "/api/bootstrap/admin";
  /**
   * Password-reset request endpoint — POST {"subjectId":"…"}, returns 200
   * with the issued plain token (demo-only; production never echoes the
   * token, the {@code JSentinelNotificationSender} delivers it instead).
   */
  public static final String PASSWORD_RESET_REQUEST = "/api/password-reset/request";
  /**
   * Password-reset consume endpoint — POST {"token":"…"}, returns 200 on
   * success / 404 on unknown / 410 on already-consumed or expired.
   */
  public static final String PASSWORD_RESET_CONSUME = "/api/password-reset/consume";
  /**
   * Admin endpoint to mint a long-lived API key — POST
   * {"name":"…","subjectId":"…","scopes":["document:read", …]} returns
   * {"plainKey":"…","keyHash":"…"} once. Requires {@code admin:roles}.
   * Plain key is shown only here; clients pass it via the
   * {@code X-Api-Key} header on subsequent requests.
   */
  public static final String ADMIN_API_KEYS = "/api/admin/api-keys";
  /**
   * Admin endpoint to revoke an API key — POST {"keyHash":"…"}. Requires
   * {@code admin:roles}. Idempotent: revoking an already-revoked key
   * returns the same 200 response.
   */
  public static final String ADMIN_API_KEYS_REVOKE = "/api/admin/api-keys/revoke";
  /**
   * Rotating refresh-token issue endpoint — POST {"subjectId":"…"}
   * returns {@code {"accessToken":"…","accessExpiresAt":"…",
   * "refreshToken":"…","refreshExpiresAt":"…"}}. Demo-only:
   * unauthenticated; production deployments would couple this to a
   * username/password or API-key authentication step first.
   */
  public static final String AUTH_TOKEN_ISSUE = "/api/auth/token/issue";
  /**
   * Refresh-token rotation endpoint — POST {"refreshToken":"…"}
   * consumes the supplied refresh token and returns a fresh
   * {@code TokenPair}. Replaying a consumed refresh token returns
   * 401 with {@code WWW-Authenticate: TokenRotated}.
   */
  public static final String AUTH_TOKEN_REFRESH = "/api/auth/token/refresh";
  /**
   * Refresh-token revoke endpoint — POST {"refreshToken":"…"}.
   * Idempotent: revoking an unknown/already-revoked token still
   * returns 200.
   */
  public static final String AUTH_TOKEN_REVOKE = "/api/auth/token/revoke";

  private DemoEndpoints() {
  }
}
