package eu.jsentinel.jcustos.demo.skill.vaadin.security;

import eu.jsentinel.jcustos.annotations.PropagateToken;

import java.util.Optional;

/**
 * Outbound contract for the calls that carry the caller's token to the
 * {@code jcustos-rest} backend.
 *
 * <p>The interface is annotated with {@link PropagateToken}, so a
 * {@code PropagatingProxy}-wrapped instance resolves the outbound
 * header from the configured {@code TokenCredentialStore} before each
 * call. The implementation never reads the session or builds an
 * {@code Authorization} header itself — it only applies whatever the
 * strategy bound for this call.
 *
 * <p>{@code login} is deliberately absent: it establishes the token
 * rather than carrying one, so it stays on
 * {@link RestBackendClient} as a plain unannotated call.
 */
@PropagateToken(service = "jcustos-rest-demo")
public interface BackendGateway {

  /** @return the whoami JSON body, or empty when the call is rejected. */
  Optional<String> whoami();

  /** Revokes the current token. Best-effort — failures are swallowed. */
  void logout();
}
