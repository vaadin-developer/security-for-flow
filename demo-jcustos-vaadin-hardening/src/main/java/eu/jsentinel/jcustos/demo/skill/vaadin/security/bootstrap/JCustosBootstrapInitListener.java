package eu.jsentinel.jcustos.demo.skill.vaadin.security.bootstrap;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinSecurity;
import eu.jsentinel.jcustos.starter.profile.VaadinJCustosStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the V00.73 fluent {@link VaadinSecurity#bootstrap()} chain
 * once per JVM at Vaadin service init.
 *
 * <p>This listener is layer-1 — it stays untouched when persistence,
 * hardening or any other layer is applied later. Sub-aspect
 * configuration (audit, sessions, credentials) flows through
 * {@link BootstrapBuilder#apply(eu.jsentinel.jcustos.dx.vaadin.bootstrap.VaadinJCustosBootstrap)},
 * which loads every registered {@link BootstrapExtension} via
 * {@link ServiceLoader}. New layers add a new extension; the entry
 * point here never has to change.
 */
public class JCustosBootstrapInitListener implements VaadinServiceInitListener {

  private static final AtomicBoolean DONE = new AtomicBoolean();
  private static volatile JCustosRuntime runtime;

  /**
   * Returns the {@link JCustosRuntime} captured at the most recent
   * successful {@code serviceInit(...)}, or {@code null} if the
   * bootstrap has not yet run (e.g. the first Vaadin request is still
   * in flight). The {@code HealthView} reads this on every render so a
   * runtime swap during V00.75-style hot-reload remains observable.
   *
   * @return the active runtime snapshot, or {@code null}
   */
  public static JCustosRuntime currentRuntime() {
    return runtime;
  }

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
      return;
    }
    JCustosRuntime bootstrapped = BootstrapBuilder.apply(
        VaadinSecurity.bootstrap()
            .use(VaadinJCustosStarter.developmentDefaults())
            .authentication(authn)
            .authorization(authz)
            .loginRoute("login")
            .stepUpRoute("step-up")
    ).install();
    runtime = bootstrapped;
    System.out.println(bootstrapped.log());
  }
}
