package eu.jsentinel.jcustos.demo.skill.standalone;

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.AuditEvent;
import eu.jsentinel.jcustos.audit.AuditQuery;
import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AccessDeniedException;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.bootstrap.CreateInitialAdminCommand;
import eu.jsentinel.jcustos.bootstrap.InitialAdminCreationResult;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JSentinelRuntime;
import eu.jsentinel.jcustos.dx.standalone.bootstrap.StandaloneSecurity;
import eu.jsentinel.jcustos.standalone.SecuredProxy;
import eu.jsentinel.jcustos.standalone.StandaloneLoginFlow;
import eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap.BootstrapWiring;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.Credentials;
import eu.jsentinel.jcustos.demo.skill.standalone.security.model.User;
import eu.jsentinel.jcustos.demo.skill.standalone.services.DocumentService;
import eu.jsentinel.jcustos.demo.skill.standalone.services.InMemoryDocumentService;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ServiceLoader;

/**
 * Persistence-layer replacement for the standalone CLI. Opens the
 * Eclipse-Store backend before login, wires the audit + session
 * stores into the bootstrap chain, and routes the user through the
 * setup-token flow on first start.
 */
public final class Main implements HasLogger {

  private final BufferedReader in;
  private final PrintStream out;
  private final StandaloneLoginFlow<Credentials, User> loginFlow;
  private final DocumentService documents;

  public Main(BufferedReader in, PrintStream out) {
    this.in = in;
    this.out = out;
    this.loginFlow = new StandaloneLoginFlow<>();
    this.documents = SecuredProxy.wrap(DocumentService.class, new InMemoryDocumentService());
  }

  public static void main(String[] args) throws Exception {
    AuthenticationService<?, ?> authn = ServiceLoader.load(AuthenticationService.class)
        .findFirst().orElseThrow();
    AuthorizationService<?> authz = ServiceLoader.load(AuthorizationService.class)
        .findFirst().orElseThrow();
    JSentinelRuntime runtime = eu.jsentinel.jcustos.demo.skill.standalone.security.bootstrap.BootstrapBuilder.apply(
        StandaloneSecurity.bootstrap()
            .mode(JSentinelBootstrapMode.DEVELOPMENT)
            .authentication(authn)
            .authorization(authz)
    ).install();
    HasLogger.staticLogger().info("{}", runtime.log());

    BufferedReader reader = new BufferedReader(
        new InputStreamReader(System.in, StandardCharsets.UTF_8));
    new Main(reader, System.out).run();
  }

  void run() throws IOException {
    out.println("=== jSentinel Standalone Demo (persistence) ===");
    if (BootstrapWiring.instance().stateService().bootstrapRequired()) {
      out.println("System uninitialised — running setup.");
      if (!runSetup()) {
        out.println("Setup failed. Bye.");
        return;
      }
    }
    User subject = promptLogin();
    if (subject == null) {
      out.println("Login failed. Bye.");
      return;
    }
    out.println("Welcome, " + subject.name() + " — roles=" + subject.roles());
    printHelp();
    loop(subject);
    loginFlow.logout();
    out.println("Bye.");
  }

  /** Returns true iff the bootstrap succeeded. */
  private boolean runSetup() throws IOException {
    out.println("Bootstrap token (look at " + BootstrapWiring.DEFAULT_TOKEN_FILE
        + " or the startup log):");
    out.print("Token: ");
    out.flush();
    String token = in.readLine();
    out.print("Admin username: ");
    out.flush();
    String username = in.readLine();
    out.print("Admin password: ");
    out.flush();
    String password = in.readLine();
    if (token == null || username == null || password == null) return false;
    InitialAdminCreationResult result = BootstrapWiring.instance().bootstrapService()
        .createInitialAdmin(new CreateInitialAdminCommand(
            token, username, password.toCharArray(), null, null));
    return switch (result) {
      case InitialAdminCreationResult.Created created -> {
        out.println("Created admin " + created.username() + ".");
        yield true;
      }
      case InitialAdminCreationResult.AlreadyInitialized ignored -> true;
      case InitialAdminCreationResult.InvalidBootstrapToken ignored -> {
        out.println("Invalid token.");
        yield false;
      }
      case InitialAdminCreationResult.PasswordPolicyViolation policy -> {
        out.println("Password policy: " + policy.reason());
        yield false;
      }
      case InitialAdminCreationResult.InvalidUsername invalid -> {
        out.println("Invalid username: " + invalid.reason());
        yield false;
      }
      case InitialAdminCreationResult.InternalError ignored -> {
        out.println("Internal error.");
        yield false;
      }
    };
  }

  private User promptLogin() throws IOException {
    out.print("Username: ");
    out.flush();
    String username = in.readLine();
    if (username == null) return null;
    out.print("Password: ");
    out.flush();
    String password = in.readLine();
    if (password == null) return null;
    StandaloneLoginFlow.LoginResult<User> result =
        loginFlow.login(new Credentials(username, password), username);
    return switch (result) {
      case StandaloneLoginFlow.LoginResult.Success<User> s -> s.subject();
      case StandaloneLoginFlow.LoginResult.Rejected<User> ignored -> null;
      case StandaloneLoginFlow.LoginResult.LockedOut<User> l -> {
        out.println("Locked.");
        yield null;
      }
    };
  }

  private void printHelp() {
    out.println("Commands: list, create <title>, delete <title>, audit, whoami, help, quit");
  }

  private void loop(User subject) throws IOException {
    String line;
    while (true) {
      out.print("> ");
      out.flush();
      line = in.readLine();
      if (line == null || line.equalsIgnoreCase("quit")) return;
      line = line.trim();
      if (line.isEmpty()) continue;
      String[] parts = line.split("\\s+", 2);
      String cmd = parts[0].toLowerCase();
      String arg = parts.length > 1 ? parts[1] : "";
      try {
        dispatch(subject, cmd, arg);
      } catch (AccessDeniedException denied) {
        out.println("DENIED — " + denied.getMessage());
      } catch (RuntimeException failure) {
        out.println("ERROR — " + failure.getMessage());
      }
    }
  }

  private void dispatch(User subject, String cmd, String arg) {
    switch (cmd) {
      case "list" -> documents.list().forEach(d -> out.println("  - " + d));
      case "create" -> {
        documents.create(arg);
        out.println("OK");
      }
      case "delete" -> {
        documents.delete(arg);
        out.println("OK");
      }
      case "audit" -> {
        if (subject.roles().stream().noneMatch(r -> r.name().equals("ADMIN"))) {
          out.println("DENIED");
          return;
        }
        for (AuditEvent event : JSentinelServiceResolver.securityAuditService().query(AuditQuery.all())) {
          out.println("  " + event.timestamp() + " " + event.getClass().getSimpleName());
        }
      }
      case "whoami" -> out.println("id=" + subject.id() + " name=" + subject.name()
          + " roles=" + subject.roles());
      case "help" -> printHelp();
      default -> out.println("Unknown.");
    }
  }
}
