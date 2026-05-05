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
package com.svenruppert.vaadin.security.demo.rest.cli;

import com.svenruppert.vaadin.security.demo.rest.shared.DemoJson;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

/**
 * Interactive command loop for the demo CLI. The loop reads single-line
 * commands, dispatches them to the demo server, and prints HTTP responses.
 * <p>
 * Important: this CLI never makes local authorization decisions. The list of
 * allowed operations always comes from the server.
 */
public final class CliCommandLoop {

  private final BufferedReader reader;
  private final PrintStream out;
  private final CliOperationClient client;
  private final CliSession session = new CliSession();

  public CliCommandLoop(BufferedReader reader, PrintStream out, CliOperationClient client) {
    this.reader = reader;
    this.out = out;
    this.client = client;
  }

  public void run() throws IOException {
    out.println("Demo REST CLI. Type 'help' for available commands.");
    while (true) {
      out.print("> ");
      out.flush();
      String line = reader.readLine();
      if (line == null) return;
      String trimmed = line.trim();
      if (trimmed.isEmpty()) continue;
      String[] parts = trimmed.split("\\s+");
      try {
        boolean keepRunning = handleCommand(parts);
        if (!keepRunning) return;
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      } catch (Exception e) {
        out.println("Error: " + e.getMessage());
      }
    }
  }

  private boolean handleCommand(String[] parts) throws IOException, InterruptedException {
    String command = parts[0];
    return switch (command) {
      case "help" -> {
        printHelp();
        yield true;
      }
      case "login" -> {
        login(parts);
        yield true;
      }
      case "me" -> {
        me();
        yield true;
      }
      case "operations" -> {
        operations();
        yield true;
      }
      case "call" -> {
        call(parts);
        yield true;
      }
      case "logout" -> {
        logout();
        yield true;
      }
      case "exit", "quit" -> false;
      default -> {
        out.println("Unknown command: " + command + ". Type 'help'.");
        yield true;
      }
    };
  }

  private void printHelp() {
    out.println("Commands:");
    out.println("  login <username> <password>");
    out.println("  me");
    out.println("  operations");
    out.println("  call <operation-id> [argument]");
    out.println("  logout");
    out.println("  help");
    out.println("  exit");
  }

  private void login(String[] parts) throws IOException, InterruptedException {
    if (parts.length != 3) {
      out.println("Usage: login <username> <password>");
      return;
    }
    HttpResponse<String> response = client.login(parts[1], parts[2]);
    if (response.statusCode() != 200) {
      out.println(response.statusCode() + " " + response.body());
      return;
    }
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    session.setLogin(
        String.valueOf(payload.get("token")),
        String.valueOf(payload.get("displayName")));
    out.println("Login successful. Current user: " + session.displayName());
  }

  private void me() throws IOException, InterruptedException {
    if (requireLogin()) return;
    HttpResponse<String> response = client.me(session.token());
    out.println(response.statusCode() + " " + response.body());
  }

  private void operations() throws IOException, InterruptedException {
    if (requireLogin()) return;
    HttpResponse<String> response = client.operations(session.token());
    if (response.statusCode() != 200) {
      out.println(response.statusCode() + " " + response.body());
      return;
    }
    Map<String, Object> payload = DemoJson.decodeObject(response.body());
    Object opsValue = payload.get("operations");
    session.clearOperations();
    if (!(opsValue instanceof List<?> ops) || ops.isEmpty()) {
      out.println("No operations available.");
      return;
    }
    out.println("Available operations:");
    for (Object o : ops) {
      if (o instanceof Map<?, ?> m) {
        String id = String.valueOf(m.get("id"));
        String label = String.valueOf(m.get("label"));
        String method = String.valueOf(m.get("method"));
        String path = String.valueOf(m.get("path"));
        session.rememberOperation(id, label, method, path);
        out.printf("- %-18s %-6s %s (%s)%n", id, method, path, label);
      }
    }
  }

  private void call(String[] parts) throws IOException, InterruptedException {
    if (requireLogin()) return;
    if (parts.length < 2) {
      out.println("Usage: call <operation-id> [argument]");
      return;
    }
    String id = parts[1];
    CliSession.OperationEntry entry = session.operation(id);
    if (entry == null) {
      out.println("Unknown operation. Run 'operations' first to refresh the server-provided list.");
      return;
    }
    String path = entry.path();
    if (path.contains("{id}")) {
      if (parts.length < 3) {
        out.println("Operation '" + id + "' requires an argument: call " + id + " <id>");
        return;
      }
      path = path.replace("{id}", parts[2]);
    }
    String body = "POST".equals(entry.method())
        ? DemoJson.encode(Map.of("title", parts.length >= 3 ? parts[2] : "New document"))
        : null;
    HttpResponse<String> response = client.call(entry.method(), path, session.token(), body);
    out.println(response.statusCode() + " " + statusText(response.statusCode()));
    if (!response.body().isEmpty()) out.println(response.body());
  }

  private void logout() throws IOException, InterruptedException {
    if (!session.isLoggedIn()) {
      out.println("Not logged in.");
      return;
    }
    HttpResponse<String> response = client.logout(session.token());
    session.clear();
    out.println(response.statusCode() == 200 ? "Logged out." : "Logout failed: " + response.statusCode());
  }

  private boolean requireLogin() {
    if (!session.isLoggedIn()) {
      out.println("Not logged in. Use 'login <username> <password>'.");
      return true;
    }
    return false;
  }

  private static String statusText(int status) {
    return switch (status) {
      case 200 -> "OK";
      case 201 -> "Created";
      case 204 -> "No Content";
      case 400 -> "Bad Request";
      case 401 -> "Unauthorized";
      case 403 -> "Forbidden";
      case 404 -> "Not Found";
      case 405 -> "Method Not Allowed";
      default -> "";
    };
  }
}
