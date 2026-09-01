package eu.jsentinel.jcustos.demo.skill.vaadin.security;

import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.OutboundHeaderContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

/**
 * {@link BackendGateway} over {@link HttpClient}.
 *
 * <p>Note what this class does <em>not</em> do: it never touches the
 * Vaadin session and never spells out {@code "Bearer " + token}. The
 * outbound header arrives through {@link OutboundHeaderContext}, bound
 * by the propagation strategy that the bootstrap configured. Swapping
 * pass-through for token exchange is therefore a bootstrap change, not
 * a change here.
 */
final class HttpBackendGateway implements BackendGateway {

  private static final HttpClient CLIENT = HttpClient.newBuilder()
      .connectTimeout(Duration.ofSeconds(5))
      .build();

  @Override
  public Optional<String> whoami() {
    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(URI.create(RestBackendClient.BASE_URL + "/api/whoami"))
        .GET()
        .timeout(Duration.ofSeconds(10));
    if (!applyPropagatedHeader(builder)) {
      return Optional.empty();
    }
    try {
      HttpResponse<String> response =
          CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        return Optional.empty();
      }
      return Optional.of(response.body());
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  @Override
  public void logout() {
    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(URI.create(RestBackendClient.BASE_URL + "/api/auth/logout"))
        .POST(HttpRequest.BodyPublishers.noBody())
        .timeout(Duration.ofSeconds(5));
    if (!applyPropagatedHeader(builder)) {
      return;
    }
    try {
      CLIENT.send(builder.build(), HttpResponse.BodyHandlers.discarding());
    } catch (Exception ignored) {
      // Best-effort: a failed revocation must not block the local logout.
    }
  }

  /**
   * Copies the header the strategy bound for this call onto the request.
   *
   * @return {@code false} when no header was bound, meaning there is no
   *         usable credential and the call should be skipped
   */
  private static boolean applyPropagatedHeader(HttpRequest.Builder builder) {
    Optional<HeaderValue> header = OutboundHeaderContext.current();
    if (header.isEmpty()) {
      return false;
    }
    builder.header(header.get().name(), header.get().value());
    return true;
  }
}
