package com.svenruppert.jsentinel.demo.skill.rest.handlers;

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.AuditQuery;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.sun.net.httpserver.HttpExchange;
import com.svenruppert.jsentinel.demo.skill.rest.Json;
import com.svenruppert.jsentinel.demo.skill.rest.Router;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code GET /api/audit} — returns the audit ring buffer as a JSON
 * array (newest first).
 *
 * <p>Requires permission {@code audit:read} (enforced by the router).
 */
public final class AuditHandler {

  private AuditHandler() {
  }

  public static void list(HttpExchange exchange, JSentinelSubject subject) throws IOException {
    JSentinelAuditService audit = JSentinelServiceResolver.securityAuditService();
    List<AuditEvent> events = audit.query(AuditQuery.all());
    List<Map<String, Object>> body = events.stream()
        .map(AuditHandler::project)
        .toList()
        .reversed();
    Router.respondJson(exchange, 200, Json.encode(body));
  }

  private static Map<String, Object> project(AuditEvent event) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("timestamp", event.timestamp().toString());
    out.put("type", event.getClass().getSimpleName());
    out.put("detail", event.toString());
    return out;
  }
}
