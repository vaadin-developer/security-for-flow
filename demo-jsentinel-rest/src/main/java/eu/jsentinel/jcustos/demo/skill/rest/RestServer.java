package eu.jsentinel.jcustos.demo.skill.rest;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.dx.rest.bootstrap.RestSecurity;
import eu.jsentinel.jcustos.dx.runtime.JCustosBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JCustosRuntime;
import com.sun.net.httpserver.HttpServer;
import eu.jsentinel.jcustos.demo.skill.rest.security.bootstrap.BootstrapBuilder;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuditHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.AuthHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.SessionsHandler;
import eu.jsentinel.jcustos.demo.skill.rest.handlers.UsersHandler;
import eu.jsentinel.jcustos.demo.skill.rest.security.MyRestSubjectResolver;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;

/**
 * Standalone REST server (JDK {@link HttpServer}, no servlet
 * container). Layer-1 minimum: in-memory users + tokens.
 *
 * <p>Start with {@code mvn exec:java} or {@code java -cp ... RestServer}.
 */
public final class RestServer implements HasLogger {

  public static final int DEFAULT_PORT = 8081;

  private final HttpServer http;
  private final int port;

  private RestServer(HttpServer http, int port) {
    this.http = http;
    this.port = port;
  }

  public static RestServer start(int port) throws IOException {
    MyRestSubjectResolver resolver = new MyRestSubjectResolver();

    JCustosRuntime runtime = BootstrapBuilder.apply(
        RestSecurity.bootstrap()
            .mode(JCustosBootstrapMode.DEVELOPMENT)
            .subjectResolver(resolver)
    ).install();
    System.out.println(runtime.log());

    List<Router.Route> routes = new Router.Builder()
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

    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/api", router);
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
    System.out.println("Try: curl -X POST -H 'Content-Type: application/json' \\");
    System.out.println("       -d '{\"username\":\"admin\",\"password\":\"admin\"}' \\");
    System.out.println("       http://localhost:" + server.port() + "/api/auth/login");
    System.out.println("Press Ctrl+C to stop.");
    Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
  }
}
