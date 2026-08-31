package eu.jsentinel.jcustos.demo.skill.rest.handlers;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import com.sun.net.httpserver.HttpExchange;
import eu.jsentinel.jcustos.demo.skill.rest.Json;
import eu.jsentinel.jcustos.demo.skill.rest.Router;
import eu.jsentinel.jcustos.demo.skill.rest.security.TokenStore;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.User;
import eu.jsentinel.jcustos.demo.skill.rest.security.model.UserDirectoryProvider;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Auth endpoints:
 * <ul>
 *   <li>{@code POST /api/auth/login} — body
 *       {@code {"username":"...","password":"..."}} returns
 *       {@code {"token":"<uuid>"}}.</li>
 *   <li>{@code POST /api/auth/logout} — Bearer token revoked.</li>
 *   <li>{@code GET  /api/whoami} — subject summary as JSON.</li>
 * </ul>
 */
public final class AuthHandler {

  private AuthHandler() {
  }

  @SuppressWarnings("unchecked")
  public static void login(HttpExchange exchange, JCustosSubject ignored) throws IOException {
    Map<String, String> body = Json.parseFlat(Router.readBody(exchange));
    String username = body.get("username");
    String password = body.get("password");
    Credentials credentials = new Credentials(username, password);
    AuthenticationService<Credentials, User> authn =
        JCustosServiceResolver.authenticationService();
    if (!authn.checkCredentials(credentials)) {
      Router.respondJson(exchange, 401, Json.encode(Map.of("error", "invalid credentials")));
      return;
    }
    Optional<User> user = UserDirectoryProvider.directory().findByCredentials(credentials);
    if (user.isEmpty()) {
      Router.respondJson(exchange, 401, Json.encode(Map.of("error", "user not loadable")));
      return;
    }
    String token = TokenStore.INSTANCE.issue(user.get());
    Router.respondJson(exchange, 200, Json.encode(Map.of(
        "token", token,
        "user", user.get().name())));
  }

  public static void logout(HttpExchange exchange, JCustosSubject subject) throws IOException {
    String auth = exchange.getRequestHeaders().getFirst("Authorization");
    if (auth != null && auth.startsWith("Bearer ")) {
      TokenStore.INSTANCE.revoke(auth.substring("Bearer ".length()).trim());
    }
    Router.respondJson(exchange, 200, "{\"ok\":true}");
  }

  public static void whoami(HttpExchange exchange, JCustosSubject subject) throws IOException {
    if (subject == null) {
      Router.respondJson(exchange, 401, Json.encode(Map.of("error", "unauthorized")));
      return;
    }
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("id", subject.subjectId());
    body.put("displayName", subject.displayName());
    body.put("roles", subject.roles().stream().map(Object::toString).toList());
    body.put("permissions", subject.permissions().stream().map(Object::toString).toList());
    Router.respondJson(exchange, 200, Json.encode(body));
  }
}
