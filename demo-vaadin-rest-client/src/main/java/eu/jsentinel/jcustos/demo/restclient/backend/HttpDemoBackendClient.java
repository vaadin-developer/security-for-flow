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

import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;
import eu.jsentinel.jcustos.bootstrap.BootstrapStatus;
import eu.jsentinel.jcustos.demo.rest.shared.DemoEndpoints;
import eu.jsentinel.jcustos.demo.rest.shared.DemoJson;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The single class in this module that knows about HTTP, JSON and
 * endpoint paths. Maps domain calls onto {@code demo-rest} endpoints and
 * translates responses into {@link DemoBackendClient} domain types.
 */
public final class HttpDemoBackendClient implements DemoBackendClient {

  private static final String AUTH_HEADER = "Authorization";
  private static final String CONTENT_TYPE = "Content-Type";
  private static final String JSON_CONTENT = "application/json";

  private final BackendConfig config;
  private final HttpClient http;

  public HttpDemoBackendClient(BackendConfig config) {
    this(config, HttpClient.newBuilder()
        .connectTimeout(config.connectTimeout())
        .build());
  }

  HttpDemoBackendClient(BackendConfig config, HttpClient http) {
    this.config = config;
    this.http = http;
  }

  // ── Bootstrap ────────────────────────────────────────────────

  @Override
  public BootstrapStatus bootstrapStatus() {
    HttpResponse<String> response = sendOrTransport("GET",
        DemoEndpoints.BOOTSTRAP_STATUS, null, null);
    if (response.statusCode() != 200) throw fromStatus(response);
    Map<String, Object> body = DemoJson.decodeObject(response.body());
    boolean required = Boolean.TRUE.equals(body.get("bootstrapRequired"));
    String modeRaw = body.get("mode") == null ? "DISABLED" : body.get("mode").toString();
    BootstrapMode mode;
    try {
      mode = BootstrapMode.valueOf(modeRaw);
    } catch (IllegalArgumentException e) {
      mode = BootstrapMode.DISABLED;
    }
    return new BootstrapStatus(required, mode);
  }

  @Override
  public BootstrapResult createInitialAdmin(BootstrapAdminRequest request) {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("bootstrapToken", request.bootstrapToken());
    payload.put("username", request.username());
    payload.put("password", new String(request.password()));
    if (request.displayName() != null && !request.displayName().isBlank()) {
      payload.put("displayName", request.displayName());
    }
    if (request.email() != null && !request.email().isBlank()) {
      payload.put("email", request.email());
    }
    String body = DemoJson.encode(payload);
    Arrays.fill(request.password(), '\0');

    HttpResponse<String> response;
    try {
      response = send("POST", DemoEndpoints.BOOTSTRAP_ADMIN, null, body);
    } catch (BackendException ex) {
      if (ex.kind() == BackendException.Kind.Transport) {
        return new BootstrapResult.TransportError(ex.getMessage());
      }
      // unexpected — surface as internal
      return new BootstrapResult.InternalError(ex.getMessage());
    }

    int status = response.statusCode();
    if (status == 201) {
      return new BootstrapResult.Created(request.username());
    }
    Map<String, Object> error = safeDecode(response.body());
    String code = stringOf(error.get("error"));
    String reason = stringOf(error.get("reason"));
    return switch (status) {
      case 409 -> new BootstrapResult.AlreadyInitialized();
      case 403 -> new BootstrapResult.InvalidToken();
      case 400 -> {
        if ("password_policy_violation".equals(code)) {
          yield new BootstrapResult.PolicyViolation(reason == null ? "" : reason);
        }
        if ("invalid_username".equals(code)) {
          yield new BootstrapResult.InvalidUsername(reason == null ? "" : reason);
        }
        yield new BootstrapResult.InternalError(code == null ? "bad_request" : code);
      }
      case 500 -> new BootstrapResult.InternalError(code == null ? "internal_error" : code);
      default -> new BootstrapResult.InternalError("unexpected_status_" + status);
    };
  }

  // ── Authentication ───────────────────────────────────────────

  @Override
  public LoginResult login(Credentials credentials) {
    String body = DemoJson.encode(Map.of(
        "username", credentials.username(),
        "password", credentials.password()));
    HttpResponse<String> response;
    try {
      response = send("POST", DemoEndpoints.LOGIN, null, body);
    } catch (BackendException ex) {
      if (ex.kind() == BackendException.Kind.Transport) {
        return new LoginResult.TransportError(ex.getMessage());
      }
      return new LoginResult.TransportError(ex.getMessage());
    }
    if (response.statusCode() == 401) return new LoginResult.InvalidCredentials();
    if (response.statusCode() != 200) {
      return new LoginResult.TransportError("unexpected_status_" + response.statusCode());
    }
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    String token = stringOf(payload.get("token"));
    if (token == null) return new LoginResult.TransportError("missing_token");
    RemoteUser user = remoteUserFrom(stringOf(payload.get("displayName")),
        credentials.username(), payload);
    return new LoginResult.Authenticated(token, user);
  }

  @Override
  public RemoteUser currentUser(String token) {
    HttpResponse<String> response = send("GET", DemoEndpoints.ME, token, null);
    if (response.statusCode() != 200) throw fromStatus(response);
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    String subjectId = stringOf(payload.get("subjectId"));
    String displayName = stringOf(payload.get("displayName"));
    return remoteUserFrom(displayName, subjectId == null ? "?" : subjectId, payload);
  }

  @Override
  public void logout(String token) {
    HttpResponse<String> response = sendOrTransport("POST",
        DemoEndpoints.LOGOUT, token, "");
    int status = response.statusCode();
    if (status == 200 || status == 401) return;
    throw fromStatus(response);
  }

  // ── Operations ───────────────────────────────────────────────

  @Override
  public List<RemoteOperation> visibleOperations(String token) {
    HttpResponse<String> response = send("GET", DemoEndpoints.OPERATIONS, token, null);
    if (response.statusCode() != 200) throw fromStatus(response);
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    Object value = payload.get("operations");
    if (!(value instanceof List<?> list)) return List.of();
    return list.stream()
        .filter(Map.class::isInstance)
        .map(o -> {
          @SuppressWarnings("unchecked")
          Map<String, Object> entry = (Map<String, Object>) o;
          return new RemoteOperation(
              stringOf(entry.get("id")),
              stringOf(entry.get("label")),
              stringOf(entry.get("description")),
              stringOf(entry.get("method")),
              stringOf(entry.get("path")));
        })
        .toList();
  }

  // ── Documents ────────────────────────────────────────────────

  @Override
  public List<RemoteDocument> listDocuments(String token) {
    HttpResponse<String> response = send("GET", DemoEndpoints.DOCUMENTS, token, null);
    if (response.statusCode() != 200) throw fromStatus(response);
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    Object value = payload.get("documents");
    if (!(value instanceof List<?> list)) return List.of();
    return list.stream()
        .filter(Map.class::isInstance)
        .map(o -> {
          @SuppressWarnings("unchecked")
          Map<String, Object> entry = (Map<String, Object>) o;
          return new RemoteDocument(longOf(entry.get("id")), stringOf(entry.get("title")));
        })
        .toList();
  }

  @Override
  public RemoteDocument createDocument(String token, String title) {
    String body = DemoJson.encode(Map.of("title", title));
    HttpResponse<String> response = send("POST", DemoEndpoints.DOCUMENTS, token, body);
    if (response.statusCode() != 201) throw fromStatus(response);
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    return new RemoteDocument(longOf(payload.get("id")), stringOf(payload.get("title")));
  }

  @Override
  public void deleteDocument(String token, long id) {
    HttpResponse<String> response = send("DELETE",
        DemoEndpoints.DOCUMENT_BY_ID + id, token, null);
    if (response.statusCode() != 204) throw fromStatus(response);
  }

  // ── Admin ────────────────────────────────────────────────────

  @Override
  public RemoteAdminStatus adminStatus(String token) {
    HttpResponse<String> response = send("GET", DemoEndpoints.ADMIN_STATUS, token, null);
    if (response.statusCode() != 200) throw fromStatus(response);
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    return new RemoteAdminStatus(
        stringOf(payload.get("status")),
        stringOf(payload.get("message")));
  }

  @Override
  public List<RemoteUserEntry> listUsers(String token) {
    HttpResponse<String> response = send("GET", DemoEndpoints.ADMIN_USERS, token, null);
    if (response.statusCode() != 200) throw fromStatus(response);
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    Object value = payload.get("users");
    if (!(value instanceof List<?> list)) return List.of();
    return list.stream()
        .filter(Map.class::isInstance)
        .map(o -> {
          @SuppressWarnings("unchecked")
          Map<String, Object> entry = (Map<String, Object>) o;
          return new RemoteUserEntry(
              stringOf(entry.get("username")),
              stringOf(entry.get("displayName")),
              stringOf(entry.get("role")));
        })
        .toList();
  }

  @Override
  public RemoteUserEntry setUserRole(String token, String username, String role) {
    String body = DemoJson.encode(Map.of("role", role));
    HttpResponse<String> response = send("PUT",
        DemoEndpoints.ADMIN_USER_BY_NAME + username, token, body);
    if (response.statusCode() != 200) throw fromStatus(response);
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    return new RemoteUserEntry(
        stringOf(payload.get("username")),
        stringOf(payload.get("displayName")),
        stringOf(payload.get("role")));
  }

  @Override
  public RemoteUserEntry createUser(
      String token, String username, String password, String displayName, String role) {
    Map<String, Object> bodyPayload = new LinkedHashMap<>();
    bodyPayload.put("username", username);
    bodyPayload.put("password", password);
    if (displayName != null && !displayName.isBlank()) {
      bodyPayload.put("displayName", displayName);
    }
    bodyPayload.put("role", role);
    String body = DemoJson.encode(bodyPayload);
    HttpResponse<String> response = send("POST",
        DemoEndpoints.ADMIN_USERS, token, body);
    if (response.statusCode() != 201) throw fromStatus(response);
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    return new RemoteUserEntry(
        stringOf(payload.get("username")),
        stringOf(payload.get("displayName")),
        stringOf(payload.get("role")));
  }

  @Override
  public void deleteUser(String token, String username) {
    HttpResponse<String> response = send("DELETE",
        DemoEndpoints.ADMIN_USER_BY_NAME + username, token, null);
    if (response.statusCode() != 204) throw fromStatus(response);
  }

  // ── Helpers ──────────────────────────────────────────────────

  private HttpResponse<String> send(String method, String path, String token, String body) {
    HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(config.baseUrl() + path))
        .timeout(config.requestTimeout());
    if (token != null) builder.header(AUTH_HEADER, "Bearer " + token);
    HttpRequest.BodyPublisher publisher = body == null
        ? HttpRequest.BodyPublishers.noBody()
        : HttpRequest.BodyPublishers.ofString(body);
    if (body != null) builder.header(CONTENT_TYPE, JSON_CONTENT);
    builder.method(method, publisher);
    try {
      return http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    } catch (IOException e) {
      throw new BackendException(BackendException.Kind.Transport, "I/O failure", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new BackendException(BackendException.Kind.Transport, "interrupted", e);
    }
  }

  private HttpResponse<String> sendOrTransport(String method, String path, String token, String body) {
    return send(method, path, token, body);
  }

  private static BackendException fromStatus(HttpResponse<String> response) {
    int status = response.statusCode();
    BackendException.Kind kind = switch (status) {
      case 401 -> BackendException.Kind.Unauthenticated;
      case 403 -> BackendException.Kind.Forbidden;
      case 404 -> BackendException.Kind.NotFound;
      case 400, 405 -> BackendException.Kind.BadRequest;
      case 409 -> BackendException.Kind.Conflict;
      default -> status >= 500
          ? BackendException.Kind.ServerError
          : BackendException.Kind.Transport;
    };
    return new BackendException(kind, "backend_status_" + status);
  }

  private static RemoteUser remoteUserFrom(String displayName, String subjectId, Map<String, Object> payload) {
    Set<RoleName> roles = stringList(payload.get("roles")).stream()
        .map(RoleName::new)
        .collect(Collectors.toUnmodifiableSet());
    Set<PermissionName> perms = stringList(payload.get("permissions")).stream()
        .map(PermissionName::new)
        .collect(Collectors.toUnmodifiableSet());
    return new RemoteUser(
        subjectId == null || subjectId.isBlank() ? "user" : subjectId,
        displayName == null ? subjectId : displayName,
        roles, perms);
  }

  private static List<String> stringList(Object value) {
    if (!(value instanceof List<?> list)) return List.of();
    return list.stream()
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .toList();
  }

  private static String stringOf(Object value) {
    return value == null ? null : value.toString();
  }

  private static long longOf(Object value) {
    if (value instanceof Number n) return n.longValue();
    if (value instanceof String s) return Long.parseLong(s);
    throw new IllegalArgumentException("not a number: " + value);
  }

  private static Map<String, Object> safeDecode(String body) {
    if (body == null || body.isBlank()) return Map.of();
    try {
      return DemoJson.decodeObject(body);
    } catch (RuntimeException e) {
      return Map.of();
    }
  }
}
