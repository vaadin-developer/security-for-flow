package eu.jsentinel.jcustos.rest;

import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * JS-SEC-026: proves a configured decision mapper reaches the enforcement
 * path.
 *
 * <p>Before V00.83 {@code RestJCustosBootstrap.decisionMapper(...)} and
 * {@code .errorBodies(...)} were recorded for diagnostics while the filter
 * hard-wired its own mapper. No test caught it, because the existing
 * bootstrap tests asserted against {@code runtime.services()} rather than
 * against what actually went on the wire. These tests assert the response.
 *
 * <p>No mocking framework: the mappers are real implementations of the real
 * interface and the response is the same recording fixture the other filter
 * tests use.
 */
@DisplayName("JS-SEC-026 — configured decision mapping reaches the filter")
class RestDecisionMappingWiringTest {

  @AfterEach
  void clearPublishedMapper() {
    RestDecisionContext.reset();
  }

  /** Renders denials as RFC 7807 problem+json, standing in for a real strategy. */
  private static final RestErrorBodies PROBLEM_JSON = decision -> switch (decision) {
    case AuthorizationDecision.Forbidden(String ignored) ->
        "{\"type\":\"about:blank\",\"title\":\"Forbidden\",\"status\":403}";
    default ->
        "{\"type\":\"about:blank\",\"title\":\"Unauthorized\",\"status\":401}";
  };

  @Test
  @DisplayName("a published mapper renders the denial instead of the default")
  void publishedMapperRendersTheDenial() throws NoSuchMethodException {
    RestDecisionContext.publish(new HttpStatusDecisionMapper(PROBLEM_JSON));
    RecordingResponse response = new RecordingResponse();

    new RestAuthorizationFilter(request -> Optional.empty())
        .authorizeAndHandle(request(), response, (rq, rs) -> { }, securedMethod());

    assertEquals(401, response.status);
    assertTrue(response.body.contains("\"status\":401"),
        "the published strategy must render the body, was: " + response.body);
  }

  @Test
  @DisplayName("an explicit constructor mapper wins over the published one")
  void explicitMapperWinsOverPublished() throws NoSuchMethodException {
    RestDecisionContext.publish(new HttpStatusDecisionMapper(PROBLEM_JSON));
    RecordingResponse response = new RecordingResponse();
    RestDecisionMapping explicit = (decision, target) -> {
      target.status(418);
      target.body("explicit");
      return false;
    };

    new RestAuthorizationFilter(request -> Optional.empty(), explicit)
        .authorizeAndHandle(request(), response, (rq, rs) -> { }, securedMethod());

    assertEquals(418, response.status);
    assertEquals("explicit", response.body);
  }

  @Test
  @DisplayName("without configuration the conservative default still applies")
  void withoutConfigurationTheDefaultApplies() throws NoSuchMethodException {
    RecordingResponse response = new RecordingResponse();

    new RestAuthorizationFilter(request -> Optional.empty())
        .authorizeAndHandle(request(), response, (rq, rs) -> { }, securedMethod());

    assertEquals(401, response.status);
    assertEquals("Unauthorized", response.body);
  }

  @Test
  @DisplayName("the mapper is read per request, so publishing after construction works")
  void mapperIsReadPerRequestNotAtConstruction() throws NoSuchMethodException {
    // The filter is built first — DemoHttpRouter holds it in a constructor
    // field, so this is the real ordering, not a contrived one.
    RestAuthorizationFilter filter = new RestAuthorizationFilter(request -> Optional.empty());
    RestDecisionContext.publish(new HttpStatusDecisionMapper(PROBLEM_JSON));
    RecordingResponse response = new RecordingResponse();

    filter.authorizeAndHandle(request(), response, (rq, rs) -> { }, securedMethod());

    assertTrue(response.body.contains("\"status\":401"),
        "a mapper published after construction must still take effect");
  }

  @Test
  @DisplayName("a forbidden decision renders through the same strategy")
  void forbiddenRendersThroughTheSameStrategy() throws NoSuchMethodException {
    RestDecisionContext.publish(new HttpStatusDecisionMapper(PROBLEM_JSON));
    RecordingResponse response = new RecordingResponse();
    JCustosSubject subject =
        new JCustosSubject("u1", "User", Set.of(), Set.of(new PermissionName("document:read")));

    new RestAuthorizationFilter(request -> Optional.of(subject))
        .authorizeAndHandle(request(), response, (rq, rs) -> { }, securedMethod());

    assertEquals(403, response.status);
    assertTrue(response.body.contains("\"status\":403"),
        "denial paths must share one strategy, was: " + response.body);
  }

  private static Method securedMethod() throws NoSuchMethodException {
    return HandlerFixture.class.getDeclaredMethod("delete");
  }

  private static RestRequest request() {
    return new SimpleRestRequest("DELETE", "/api/documents/42", Map.of(), Map.of());
  }

  static final class HandlerFixture {
    @RequiresPermission("document:delete")
    void delete() {
    }
  }

  record SimpleRestRequest(
      String method,
      String path,
      Map<String, String> headers,
      Map<String, String> queryParameters
  ) implements RestRequest {
  }

  static final class RecordingResponse implements RestResponse {
    int status = 200;
    String body;

    @Override
    public void status(int statusCode) {
      this.status = statusCode;
    }

    @Override
    public void body(String body) {
      this.body = body;
    }
  }
}
