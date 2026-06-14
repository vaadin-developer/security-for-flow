package com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.vaadin.bootstrap.VaadinSecurity;
import com.svenruppert.jsentinel.starter.profile.VaadinJSentinelStarter;
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
 * {@link BootstrapBuilder#apply(com.svenruppert.jsentinel.dx.vaadin.bootstrap.VaadinJSentinelBootstrap)},
 * which loads every registered {@link BootstrapExtension} via
 * {@link ServiceLoader}. New layers add a new extension; the entry
 * point here never has to change.
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
      return;
    }
    JSentinelRuntime runtime = BootstrapBuilder.apply(
        VaadinSecurity.bootstrap()
            .use(VaadinJSentinelStarter.developmentDefaults())
            .authentication(authn)
            .authorization(authz)
            .loginRoute("login")
            .stepUpRoute("step-up")
    ).install();
    System.out.println(runtime.log());
  }
}
