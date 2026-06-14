package com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.credential.password.PasswordHashingServices;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.vaadin.bootstrap.VaadinSecurity;
import com.svenruppert.jsentinel.starter.profile.VaadinJSentinelStarter;
import com.vaadin.flow.server.ServiceInitEvent;
import com.vaadin.flow.server.VaadinServiceInitListener;

import java.util.ServiceLoader;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the V00.73 fluent {@link VaadinSecurity#bootstrap()} chain once
 * per JVM at Vaadin service init, then prints
 * {@link JSentinelRuntime#log()} to stdout so the operator sees which
 * services activated.
 *
 * <p>Registered via
 * {@code META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener}.
 *
 * <p>The chain pulls {@code @JSentinelAutoService}-annotated services
 * through {@link ServiceLoader} so this listener doesn't need to know
 * the application's concrete implementations.
 */
public class JSentinelBootstrapInitListener implements VaadinServiceInitListener {

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
    JSentinelRuntime runtime = VaadinSecurity.bootstrap()
        .use(VaadinJSentinelStarter.developmentDefaults())
        .authentication(authn)
        .authorization(authz)
        .loginRoute("login")
        .stepUpRoute("step-up")
        .audit(a -> a.ringBuffer(256).logging())
        .credentials(c -> c.hashing(PasswordHashingServices.defaults()))
        .install();
    System.out.println(runtime.log());
  }
}
