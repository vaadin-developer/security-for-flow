package com.svenruppert.jsentinel.demo.skill.rest;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.dx.rest.bootstrap.RestSecurity;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.sun.net.httpserver.HttpServer;
import com.svenruppert.jsentinel.demo.skill.rest.handlers.AuditHandler;
import com.svenruppert.jsentinel.demo.skill.rest.handlers.AuthHandler;
import com.svenruppert.jsentinel.demo.skill.rest.handlers.BootstrapHandler;
import com.svenruppert.jsentinel.demo.skill.rest.handlers.SessionsHandler;
import com.svenruppert.jsentinel.demo.skill.rest.handlers.UsersHandler;
import com.svenruppert.jsentinel.demo.skill.rest.security.bootstrap.BootstrapBuilder;
import com.svenruppert.jsentinel.demo.skill.rest.security.bootstrap.BootstrapWiring;
import com.svenruppert.jsentinel.demo.skill.rest.security.MyRestSubjectResolver;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * Persistence-layer REST server — same bootstrap-chain mechanism as
 * layer 1 (delegates audit / sessions / credentials to
 * {@link BootstrapBuilder#apply(com.svenruppert.jsentinel.dx.rest.bootstrap.RestJSentinelBootstrap)}),
 * but adds the {@code /api/setup} route + a bootstrap-required guard
 * that returns 503 on every other endpoint until the first admin is
 * provisioned.
 *
 * <p>Bootstrap-chain configuration is contributed by
 * {@code PersistenceBootstrapExtension} (Eclipse-Store storeBacked
 * for audit + sessions). Hardening, if applied, adds a separate
 * {@code HardeningBootstrapExtension} that stacks alongside this
 * one — both contribute to the same {@code .audit / .sessions /
 * .credentials} sub-builders, no conflict.
 */
public final class RestServer implements HasLogger {

  public static final int DEFAULT_PORT = 8083;

  private final HttpServer http;
  private final int port;

  private RestServer(HttpServer http, int port) {
    this.http = http;
    this.port = port;
  }

  public static RestServer start(int port) throws IOException {
    MyRestSubjectResolver resolver = new MyRestSubjectResolver();

    JSentinelRuntime runtime = BootstrapBuilder.apply(
        RestSecurity.bootstrap()
            .mode(JSentinelBootstrapMode.DEVELOPMENT)
            .subjectResolver(resolver)
    ).install();
    System.out.println(runtime.log());

    List<Router.Route> routes = new Router.Builder()
        .addPublic("POST", "/api/setup", BootstrapHandler::setup)
        .addPublic("POST", "/api/auth/login", AuthHandler::login)
        .addPublic("POST", "/api/auth/logout", AuthHandler::logout)
        .add("GET", "/api/whoami", "api:view", AuthHandler::whoami)
        .add("GET", "/api/audit", "audit:read", AuditHandler::list)
        .add("GET", "/api/sessions", "admin:sessions", SessionsHandler::list)
        .add("DELETE", "/api/sessions", "admin:sessions", SessionsHandler::revoke)
        .add("GET", "/api/users", "admin:roles", UsersHandler::list)
        .add("POST", "/api/users", "admin:roles", UsersHandler::create)
        .add("DELETE", "/api/users", "admin:roles", UsersHandler::delete)
        .add("POST", "/api/users", "admin:roles", UsersHandler::assignRole)
        .add("DELETE", "/api/users", "admin:roles", UsersHandler::revokeRole)
        .build();
    Router router = new Router(resolver, routes);
    com.sun.net.httpserver.HttpHandler guarded = exchange -> {
      String path = exchange.getRequestURI().getPath();
      if (BootstrapWiring.instance().stateService().bootstrapRequired()
          && !path.equals("/api/setup")) {
        Router.respondJson(exchange, 503, Json.encode(java.util.Map.of(
            "error", "bootstrap required",
            "setupEndpoint", "POST /api/setup")));
        return;
      }
      router.handle(exchange);
    };

    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/api", guarded);
    server.start();
    return new RestServer(server, server.getAddress().getPort());
  }

  public int port() {
    return port;
  }

  public void stop() {
    http.stop(0);
  }

  public static void main(String[] args) throws IOException {
    int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
    RestServer server = start(port);
    System.out.println("REST server listening on http://localhost:" + server.port());
    System.out.println("First start? Look on stdout for the bootstrap token,");
    System.out.println("then POST it to /api/setup with the admin's chosen username/password.");
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
  }
}
