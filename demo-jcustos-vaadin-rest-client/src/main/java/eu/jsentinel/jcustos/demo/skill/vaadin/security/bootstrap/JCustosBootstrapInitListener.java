package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.credential.password.PasswordHashingServices;
import eu.jsentinel.jcustos.credential.propagation.vaadin.VaadinSessionTokenCredentialStore;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the V00.73 fluent {@link VaadinSecurity#bootstrap()} chain once
 * per JVM at Vaadin service init, then prints
 * {@link JCustosRuntime#log()} to stdout so the operator sees which
 * services activated.
 *
 * <p>Registered via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 *
 * <p>The chain pulls {@code @JCustosAutoService}-annotated services
 * through {@link ServiceLoader} so this listener doesn't need to know
 * the application's concrete implementations.
 */
public class JCustosBootstrapInitListener implements VaadinServiceInitListener {

  private static final AtomicBoolean DONE = new AtomicBoolean();

  @Override
  public void serviceInit(ServiceInitEvent event) {
    if (!DONE.compareAndSet(false, true)) {
      return;
    }
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElse(null);
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElse(null);
    if (authn == null || authz == null) {
      // No registered SPIs — let the framework fall back to its
      // legacy ServiceLoader path. The fluent bootstrap is additive.
      return;
    }
    JCustosRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinJCustosStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        .stepUpRoute("step-up")
        .audit(a -> a.ringBuffer(256).logging())
        .credentials(c -> c.hashing(PasswordHashingServices.defaults()))
        // Token propagation: the session-backed store holds the token the
        // login established, and pass-through forwards it as a Bearer header
        // on every @PropagateToken call. Switching to token exchange would
        // be a change here, not in the calling code.
        .propagation(p -> p
            .credentialStore(new VaadinSessionTokenCredentialStore())
            .passThrough())
        .install();
    System.out.println(runtime.log());
  }
}
