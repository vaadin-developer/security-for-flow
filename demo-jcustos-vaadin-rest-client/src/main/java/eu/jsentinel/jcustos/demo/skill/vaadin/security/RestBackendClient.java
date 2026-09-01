package eu.jsentinel.jcustos.demo.skill.vaadin.security;

import com.vaadin.flow.server.VaadinSession;

import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.propagation.proxy.PropagatingProxy;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Thin HTTP client wrapping the {@code jcustos-rest} backend. Used
 * by {@code AuthenticationService} (login → token) and
 * {@code AuthorizationService} (whoami → roles + permissions).
 *
 * <p>{@code login} talks to the backend directly — it has no token to
 * carry yet. Every call that <em>does</em> carry the caller's token
 * goes through {@link BackendGateway}, a {@code @PropagateToken}
 * interface wrapped in a {@code PropagatingProxy}. The token therefore
 * never appears as a method parameter and no call site spells out an
 * {@code Authorization} header.
 */
public final class RestBackendClient {

  public static final String BASE_URL = "http://localhost:8081";
  public static final String TOKEN_SESSION_KEY = "jcustos.token";

  private static final BackendGateway GATEWAY =
      PropagatingProxy.wrap(BackendGateway.class, new HttpBackendGateway());

  private static final HttpClient CLIENT = HttpClient.newBuilder()
      .connectTimeout(Duration.ofSeconds(5))
      .build();

  private static final Pattern KV = Pattern.compile(
      "\"([^\"]+)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

  private RestBackendClient() {
  }

  /** Logs in and returns the token, or empty on rejection. */
  public static Optional<String> login(String username, String password) {
    String body = String.format(
        "{\"username\":\"%s\",\"password\":\"%s\"}",
        escape(username), escape(password));
    try {
      HttpResponse<String> response = CLIENT.send(HttpRequest.newBuilder()
          .uri(URI.create(BASE_URL + "/api/auth/login"))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
          .timeout(Duration.ofSeconds(10))
          .build(), HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) return Optional.empty();
      Map<String, String> parsed = parseFlat(response.body());
      String token = parsed.get("token");
      if (token == null) return Optional.empty();
      VaadinSession.getCurrent().setAttribute(TOKEN_SESSION_KEY, token);
      credentialStore().bind(new BearerToken(token));
      return Optional.of(token);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  /** Returns the whoami JSON body, or empty when the token is absent / expired. */
  public static Optional<String> whoami() {
    return GATEWAY.whoami();
  }

  /** Revokes the current token. Best-effort. */
  public static void logout() {
    GATEWAY.logout();
    credentialStore().clear();
    VaadinSession session = VaadinSession.getCurrent();
    if (session != null) {
      session.setAttribute(TOKEN_SESSION_KEY, null);
    }
  }

  private static TokenCredentialStore credentialStore() {
    return JCustosServiceResolver.tokenCredentialStore();
  }

  public static String currentToken() {
    VaadinSession session = VaadinSession.getCurrent();
    if (session == null) return null;
    Object value = session.getAttribute(TOKEN_SESSION_KEY);
    return value instanceof String s ? s : null;
  }

  // ── Minimal JSON helpers (avoid Jackson dep for the demo) ──────

  public static Map<String, String> parseFlat(String body) {
    Map<String, String> out = new LinkedHashMap<>();
    if (body == null) return out;
    Matcher m = KV.matcher(body);
    while (m.find()) {
      out.put(m.group(1), unescape(m.group(2)));
    }
    return out;
  }

  private static String escape(String s) {
    return s.replace("\\", "\\\\").replace("\"", "\\\"");
  }

  private static String unescape(String s) {
    return s.replace("\\\"", "\"").replace("\\\\", "\\");
  }
}
