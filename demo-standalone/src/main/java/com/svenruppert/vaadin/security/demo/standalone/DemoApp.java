/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.demo.standalone;

import com.svenruppert.vaadin.security.authorization.api.AccessDeniedException;
import com.svenruppert.vaadin.security.standalone.Secured;
import com.svenruppert.vaadin.security.standalone.StandaloneLoginFlow;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * Minimal interactive CLI demonstrating the standalone security adapter.
 * <p>
 * Flow:
 * <ol>
 *   <li>Prompt for username + password.</li>
 *   <li>Authenticate via the SPI-resolved
 *       {@code AuthenticationService}; on success the
 *       {@code StandaloneLoginFlow} binds the subject into the
 *       thread-local {@code SubjectStore}.</li>
 *   <li>Wrap {@code InMemoryLibraryService} with
 *       {@code Secured.wrap(...)} so every method call enforces its
 *       {@code @RequiresPermission} / {@code @RequiresRole} annotation
 *       through the framework's evaluators.</li>
 *   <li>Read CLI commands. The reflection proxy throws
 *       {@link AccessDeniedException} when an action is not allowed —
 *       the loop catches it and prints a denial message.</li>
 * </ol>
 *
 * <p>Run with: {@code mvn -pl demo-standalone exec:java -Dexec.mainClass=...}
 * or just from your IDE.
 */
public final class DemoApp {

  private final BufferedReader in;
  private final java.io.PrintStream out;
  private final StandaloneLoginFlow<Credentials, User> loginFlow;
  private final LibraryService library;

  public DemoApp(BufferedReader in, java.io.PrintStream out) {
    this.in = in;
    this.out = out;
    this.loginFlow = new StandaloneLoginFlow<>();
    this.library = Secured.wrap(LibraryService.class, new InMemoryLibraryService());
  }

  public static void main(String[] args) throws Exception {
    BufferedReader reader = new BufferedReader(
        new InputStreamReader(System.in, StandardCharsets.UTF_8));
    new DemoApp(reader, System.out).run();
  }

  void run() throws Exception {
    out.println("=== Library CLI ===");
    out.println("Seeded users: admin/admin, librarian/librarian, alice/alice");
    User user = promptLogin();
    if (user == null) {
      out.println("Login failed. Goodbye.");
      return;
    }
    out.println("Welcome, " + user.displayName() + ". Roles: " + user.roles());
    printHelp();
    loop();
    loginFlow.logout();
    out.println("Logged out. Bye.");
  }

  private User promptLogin() throws java.io.IOException {
    out.print("Username: "); out.flush();
    String username = in.readLine();
    if (username == null) return null;
    out.print("Password: "); out.flush();
    String password = in.readLine();
    if (password == null) return null;
    StandaloneLoginFlow.LoginResult<User> result =
        loginFlow.login(new Credentials(username, password), username);
    return switch (result) {
      case StandaloneLoginFlow.LoginResult.Success<User> s -> s.subject();
      case StandaloneLoginFlow.LoginResult.Rejected<User> ignored -> null;
      case StandaloneLoginFlow.LoginResult.LockedOut<User> l -> {
        out.println("Account locked. Try again in "
            + l.decision().remaining().toSeconds() + " s.");
        yield null;
      }
    };
  }

  private void printHelp() {
    out.println("""
        Commands:
          list                 -- list books
          borrow <title>       -- borrow a book
          return <title>       -- return a book
          add <title>          -- add a book to the catalog (LIBRARIAN+)
          remove <title>       -- remove a book from the catalog (ADMIN)
          help                 -- this help
          quit                 -- exit
        """);
  }

  private void loop() throws java.io.IOException {
    String line;
    while (true) {
      out.print("> "); out.flush();
      line = in.readLine();
      if (line == null || line.equalsIgnoreCase("quit")) return;
      line = line.trim();
      if (line.isEmpty()) continue;
      String[] parts = line.split("\\s+", 2);
      String cmd = parts[0].toLowerCase();
      String arg = parts.length > 1 ? parts[1] : "";
      try {
        dispatch(cmd, arg);
      } catch (AccessDeniedException denied) {
        out.println("DENIED — " + denied.getMessage());
      } catch (RuntimeException failure) {
        out.println("ERROR — " + failure.getMessage());
      }
    }
  }

  private void dispatch(String cmd, String arg) {
    switch (cmd) {
      case "list" -> library.listBooks().forEach(b -> out.println("  - " + b));
      case "borrow" -> {
        library.borrowBook(arg);
        out.println("OK — borrowed " + arg);
      }
      case "return" -> {
        library.returnBook(arg);
        out.println("OK — returned " + arg);
      }
      case "add" -> {
        library.addBook(arg);
        out.println("OK — added " + arg);
      }
      case "remove" -> {
        library.removeBook(arg);
        out.println("OK — removed " + arg);
      }
      case "help" -> printHelp();
      default -> out.println("Unknown command. Try 'help'.");
    }
  }
}
