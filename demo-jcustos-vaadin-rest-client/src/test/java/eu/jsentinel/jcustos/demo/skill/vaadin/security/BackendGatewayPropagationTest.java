package eu.jsentinel.jcustos.demo.skill.vaadin.security;

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.InMemoryTokenCredentialStore;
import eu.jsentinel.jcustos.credential.propagation.OutboundHeaderContext;
import eu.jsentinel.jcustos.credential.propagation.PassThroughStrategy;
import eu.jsentinel.jcustos.propagation.proxy.PropagatingProxy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves that the V00.83 demo adoption actually propagates: the
 * {@code @PropagateToken} annotation on {@link BackendGateway} makes the
 * proxy resolve the configured strategy and bind the outbound header
 * before the call runs.
 *
 * <p>This is the check the framework lacked — {@code @PropagateToken}
 * was covered inside {@code jCustos-propagation} but never exercised
 * from a consuming application, which is exactly the "real demo
 * adoption" the stable-API promotion was waiting for.
 *
 * <p>No mocking framework: the gateway under test is a real
 * implementation of the real interface, and the credential store is the
 * shipped {@code InMemoryTokenCredentialStore}.
 */
@DisplayName("V00.83 demo adoption — @PropagateToken on BackendGateway")
class BackendGatewayPropagationTest {

  private InMemoryTokenCredentialStore store;

  /** Records what the proxy bound, standing in for the HTTP call. */
  private static final class RecordingGateway implements BackendGateway {

    private final AtomicReference<Optional<HeaderValue>> seen =
        new AtomicReference<>(Optional.empty());

    @Override
    public Optional<String> whoami() {
      seen.set(OutboundHeaderContext.current());
      return Optional.of("{\"user\":\"demo\"}");
    }

    @Override
    public void logout() {
      seen.set(OutboundHeaderContext.current());
    }
  }

  @BeforeEach
  void setUp() {
    store = new InMemoryTokenCredentialStore();
    JCustosServiceResolver.setTokenCredentialStore(store);
    JCustosServiceResolver.registerOutboundTokenStrategy(
        PassThroughStrategy.NAME, PassThroughStrategy.INSTANCE);
    OutboundHeaderContext.clear();
  }

  @AfterEach
  void tearDown() {
    OutboundHeaderContext.clear();
    store.clear();
  }

  @Test
  @DisplayName("bound credential becomes an Authorization header on whoami()")
  void boundCredentialBecomesOutboundHeader() {
    store.bind(new BearerToken("token-abc"));
    RecordingGateway impl = new RecordingGateway();
    BackendGateway gateway = PropagatingProxy.wrap(BackendGateway.class, impl);

    gateway.whoami();

    Optional<HeaderValue> header = impl.seen.get();
    assertTrue(header.isPresent(),
        "@PropagateToken must bind an outbound header when a credential is present");
    assertEquals("Authorization", header.get().name());
    assertEquals("Bearer token-abc", header.get().value());
  }

  @Test
  @DisplayName("logout() propagates too — the annotation is class-level")
  void logoutPropagatesAsWell() {
    store.bind(new BearerToken("token-xyz"));
    RecordingGateway impl = new RecordingGateway();

    PropagatingProxy.wrap(BackendGateway.class, impl).logout();

    assertEquals("Bearer token-xyz", impl.seen.get().orElseThrow().value());
  }

  @Test
  @DisplayName("no credential — no header, so the gateway can skip the call")
  void withoutCredentialNoHeaderIsBound() {
    RecordingGateway impl = new RecordingGateway();

    PropagatingProxy.wrap(BackendGateway.class, impl).whoami();

    assertTrue(impl.seen.get().isEmpty(),
        "without a credential the strategy must bind nothing");
  }

  @Test
  @DisplayName("context is cleared after the call — no leak into the next one")
  void contextIsClearedAfterTheCall() {
    store.bind(new BearerToken("token-abc"));

    PropagatingProxy.wrap(BackendGateway.class, new RecordingGateway()).whoami();

    assertTrue(OutboundHeaderContext.current().isEmpty(),
        "the proxy must clear the context so the header cannot leak");
  }
}
