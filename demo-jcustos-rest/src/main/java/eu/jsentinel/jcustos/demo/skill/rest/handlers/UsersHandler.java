package eu.jsentinel.jcustos.demo.skill.rest.handlers;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import com.sun.net.httpserver.HttpExchange;
import eu.jsentinel.jcustos.demo.skill.rest.Json;
import eu.jsentinel.jcustos.demo.skill.rest.Router;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectory;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;
import eu.jsentinel.jcustos.demo.skill.rest.security.roles.AuthorizationRole;

import java.io.IOException;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code GET /api/users}                      — list users
 * {@code POST /api/users}                     — create
 *     body {@code {"username":"...","password":"...","name":"...","role":"USER"}}
 * {@code DELETE /api/users/{id}}              — delete
 * {@code POST /api/users/{id}/roles/{role}}   — assign role
 * {@code DELETE /api/users/{id}/roles/{role}} — revoke role
 *
 * <p>Requires permission {@code admin:roles}.
 */
public final class UsersHandler {

  private UsersHandler() {
  }

  public static void list(HttpExchange exchange, JCustosSubject subject) throws IOException {
    UserDirectory dir = UserDirectoryProvider.directory();
    List<Map<String, Object>> body = dir.all()
        .map(UsersHandler::project)
        .toList();
    Router.respondJson(exchange, 200, Json.encode(body));
  }

  public static void create(HttpExchange exchange, JCustosSubject subject) throws IOException {
    Map<String, String> body = Json.parseFlat(Router.readBody(exchange));
    String username = body.get("username");
    String password = body.get("password");
    String name = body.getOrDefault("name", username);
    String roleName = body.getOrDefault("role", "USER");
    if (username == null || password == null) {
      Router.respondJson(exchange, 400, Json.encode(Map.of("error", "username and password required")));
      return;
    }
    AuthorizationRole role;
    try {
      role = AuthorizationRole.valueOf(roleName);
    } catch (IllegalArgumentException e) {
      Router.respondJson(exchange, 400, Json.encode(Map.of("error", "unknown role")));
      return;
    }
    Long id = nextId();
    User user = new User(id, name, EnumSet.of(AuthorizationRole.USER, role));
    UserDirectoryProvider.directory().addUser(username, password, user);
    Router.respondJson(exchange, 201, Json.encode(project(user)));
  }

  public static void delete(HttpExchange exchange, JCustosSubject subject) throws IOException {
    Long id = idFromPath(exchange, "/api/users/");
    if (id == null) {
      Router.respond(exchange, 400, "Bad Request");
      return;
    }
    UserDirectoryProvider.directory().deleteUser(id);
    Router.respondJson(exchange, 200, "{\"ok\":true}");
  }

  public static void assignRole(HttpExchange exchange, JCustosSubject subject) throws IOException {
    RoleTarget t = roleTargetFromPath(exchange);
    if (t == null) {
      Router.respond(exchange, 400, "Bad Request");
      return;
    }
    UserDirectoryProvider.directory().assignRole(t.id, t.role);
    Router.respondJson(exchange, 200, "{\"ok\":true}");
  }

  public static void revokeRole(HttpExchange exchange, JCustosSubject subject) throws IOException {
    RoleTarget t = roleTargetFromPath(exchange);
    if (t == null) {
      Router.respond(exchange, 400, "Bad Request");
      return;
    }
    UserDirectoryProvider.directory().revokeRole(t.id, t.role);
    Router.respondJson(exchange, 200, "{\"ok\":true}");
  }

  private static Long nextId() {
    return UserDirectoryProvider.directory().all()
        .mapToLong(User::id)
        .max()
        .orElse(0L) + 1L;
  }

  private static Map<String, Object> project(User user) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("id", user.id());
    out.put("name", user.name());
    out.put("roles", user.roles().stream().map(Enum::name).toList());
    return out;
  }

  private static Long idFromPath(HttpExchange exchange, String prefix) {
    String path = exchange.getRequestURI().getPath();
    if (!path.startsWith(prefix)) return null;
    String tail = path.substring(prefix.length());
    int slash = tail.indexOf('/');
    String idStr = slash < 0 ? tail : tail.substring(0, slash);
    try {
      return Long.parseLong(idStr);
    } catch (NumberFormatException e) {
      return null;
    }
  }

  private static RoleTarget roleTargetFromPath(HttpExchange exchange) {
    // /api/users/{id}/roles/{role}
    String path = exchange.getRequestURI().getPath();
    String prefix = "/api/users/";
    if (!path.startsWith(prefix)) return null;
    String tail = path.substring(prefix.length());
    String[] parts = tail.split("/");
    if (parts.length != 3 || !"roles".equals(parts[1])) return null;
    try {
      return new RoleTarget(Long.parseLong(parts[0]), AuthorizationRole.valueOf(parts[2]));
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private record RoleTarget(Long id, AuthorizationRole role) {
  }
}
