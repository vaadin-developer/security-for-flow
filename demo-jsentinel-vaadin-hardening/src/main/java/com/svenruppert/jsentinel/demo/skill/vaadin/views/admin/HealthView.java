package com.svenruppert.jsentinel.demo.skill.vaadin.views.admin;

import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;
import com.svenruppert.jsentinel.demo.skill.vaadin.security.bootstrap.JSentinelBootstrapInitListener;
import com.svenruppert.jsentinel.demo.skill.vaadin.views.MainLayout;
import com.svenruppert.jsentinel.dx.runtime.Health;
import com.svenruppert.jsentinel.dx.runtime.HealthFinding;
import com.svenruppert.jsentinel.dx.runtime.HealthStatus;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.vaadin.flow.component.Composite;
import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.button.ButtonVariant;
import com.vaadin.flow.component.grid.Grid;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H3;
import com.vaadin.flow.component.html.Paragraph;
import com.vaadin.flow.component.html.Pre;
import com.vaadin.flow.component.icon.VaadinIcon;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;

import java.time.format.DateTimeFormatter;
import java.util.List;

/**
 * V00.74.10 cleanup demo view: exposes the structured tooling
 * surface ({@code runtime.summary()}, {@code runtime.healthCheck()},
 * {@code runtime.toJson()}) over an admin-only Vaadin page. Useful as
 * a copy-paste reference for consumers wiring a {@code /admin/health}
 * dashboard.
 *
 * <p>The route lives under {@code admin/health} and reuses the
 * existing admin permission {@code admin:roles} — no new permission
 * is introduced. Every render re-reads
 * {@link JSentinelBootstrapInitListener#currentRuntime()} so a future
 * runtime swap is visible without a page reload.
 */
@Route(value = "admin/health", layout = MainLayout.class)
@RequiresPermission("admin:roles")
public final class HealthView extends Composite<VerticalLayout> {

  private static final DateTimeFormatter INSTANT = DateTimeFormatter.ISO_INSTANT;

  private final Paragraph summaryBanner = new Paragraph();
  private final Paragraph overallBadge  = new Paragraph();
  private final Paragraph servicesBadge = new Paragraph();
  private final Paragraph inspectedAt   = new Paragraph();
  private final Grid<HealthFinding> findingsGrid = new Grid<>(HealthFinding.class, false);
  private final Pre jsonBlock = new Pre();

  public HealthView() {
    VerticalLayout root = getContent();
    root.setPadding(true);
    root.setSpacing(true);
    root.add(new H1("Runtime Health"));
    root.add(buildHeaderRow());

    root.add(new H3("Summary banner"));
    summaryBanner.getStyle().set("font-family", "monospace");
    root.add(summaryBanner);

    root.add(new H3("Health snapshot"));
    HorizontalLayout badges = new HorizontalLayout(overallBadge, servicesBadge, inspectedAt);
    badges.setSpacing(true);
    root.add(badges);

    root.add(new H3("Findings"));
    findingsGrid.addColumn(HealthFinding::severity).setHeader("Severity").setAutoWidth(true);
    findingsGrid.addColumn(HealthFinding::code).setHeader("Code").setAutoWidth(true);
    findingsGrid.addColumn(HealthFinding::message).setHeader("Message").setFlexGrow(1);
    findingsGrid.setAllRowsVisible(true);
    root.add(findingsGrid);

    root.add(new H3("toJson()"));
    jsonBlock.getStyle()
        .set("background", "var(--lumo-shade-5pct)")
        .set("padding", "var(--lumo-space-s)")
        .set("border-radius", "var(--lumo-border-radius-m)")
        .set("white-space", "pre-wrap")
        .set("word-break", "break-all");
    root.add(jsonBlock);

    refresh();
  }

  private HorizontalLayout buildHeaderRow() {
    Button refresh = new Button("Refresh", VaadinIcon.REFRESH.create(), e -> refresh());
    refresh.addThemeVariants(ButtonVariant.LUMO_PRIMARY);
    HorizontalLayout row = new HorizontalLayout(refresh);
    row.setSpacing(true);
    return row;
  }

  private void refresh() {
    JSentinelRuntime runtime = JSentinelBootstrapInitListener.currentRuntime();
    if (runtime == null) {
      summaryBanner.setText("(runtime not yet initialised)");
      overallBadge.setText("—");
      servicesBadge.setText("");
      inspectedAt.setText("");
      findingsGrid.setItems(List.of());
      jsonBlock.setText("");
      Notification.show("Runtime not yet initialised");
      return;
    }
    summaryBanner.setText(runtime.summary());

    HealthStatus health = runtime.healthCheck();
    overallBadge.setText("Overall: " + renderOverall(health.overall()));
    servicesBadge.setText("Registered services: " + health.registeredServices());
    inspectedAt.setText("Inspected at: " + INSTANT.format(health.inspectedAt()));
    findingsGrid.setItems(health.findings());

    jsonBlock.setText(prettify(runtime.toJson()));
  }

  private static String renderOverall(Health overall) {
    return switch (overall) {
      case HEALTHY  -> "HEALTHY";
      case DEGRADED -> "DEGRADED";
      case FAILED   -> "FAILED";
      default       -> overall.name();
    };
  }

  /**
   * Minimal in-page JSON pretty-printer. The framework's own
   * {@code JsonEncoder} (jSentinel-dx) is intentionally compact-only
   * — pretty-printing belongs to the consumer, so we keep the policy
   * here in the demo.
   */
  private static String prettify(String compact) {
    StringBuilder out = new StringBuilder(compact.length() + 64);
    int indent = 0;
    boolean inString = false;
    for (int i = 0; i < compact.length(); i++) {
      char c = compact.charAt(i);
      if (inString) {
        out.append(c);
        if (c == '\\' && i + 1 < compact.length()) {
          out.append(compact.charAt(++i));
        } else if (c == '"') {
          inString = false;
        }
        continue;
      }
      switch (c) {
        case '"' -> {
          inString = true;
          out.append(c);
        }
        case '{', '[' -> {
          out.append(c);
          out.append('\n');
          indent++;
          appendIndent(out, indent);
        }
        case '}', ']' -> {
          out.append('\n');
          indent--;
          appendIndent(out, indent);
          out.append(c);
        }
        case ',' -> {
          out.append(c);
          out.append('\n');
          appendIndent(out, indent);
        }
        case ':' -> out.append(": ");
        default  -> out.append(c);
      }
    }
    return out.toString();
  }

  private static void appendIndent(StringBuilder out, int indent) {
    for (int i = 0; i < indent; i++) {
      out.append("  ");
    }
  }
}
