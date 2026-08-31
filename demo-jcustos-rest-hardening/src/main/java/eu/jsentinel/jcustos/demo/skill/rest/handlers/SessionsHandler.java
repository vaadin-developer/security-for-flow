package eu.jsentinel.jcustos.demo.skill.rest.handlers;

import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import com.sun.net.httpserver.HttpExchange;
import eu.jsentinel.jcustos.demo.skill.rest.Json;
import eu.jsentinel.jcustos.demo.skill.rest.Router;
import eu.jsentinel.jcustos.demo.skill.rest.security.TokenStore;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code GET /api/sessions} — lists active Bearer tokens.
 * {@code DELETE /api/sessions/{token}} — revokes one.
 *
 * <p>Requires permission {@code admin:sessions}.
 */
public final class SessionsHandler {

  private SessionsHandler() {
  }

  public static void list(HttpExchange exchange, JCustosSubject subject) throws IOException {
    List<Map<String, Object>> body = TokenStore.INSTANCE.all()
        .map(SessionsHandler::project)
        .toList();
    Router.respondJson(exchange, 200, Json.encode(body));
  }

  public static void revoke(HttpExchange exchange, JCustosSubject subject) throws IOException {
    String path = exchange.getRequestURI().getPath();
    String prefix = "/api/sessions/";
    if (!path.startsWith(prefix)) {
      Router.respond(exchange, 400, "Bad Request");
      return;
    }
    String token = path.substring(prefix.length());
    TokenStore.INSTANCE.revoke(token);
    Router.respondJson(exchange, 200, "{\"ok\":true}");
  }

  private static Map<String, Object> project(TokenStore.TokenInfo info) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("token", info.token());
    out.put("user", info.user().name());
    out.put("userId", info.user().id());
    out.put("createdAt", info.createdAt().toString());
    return out;
  }
}
