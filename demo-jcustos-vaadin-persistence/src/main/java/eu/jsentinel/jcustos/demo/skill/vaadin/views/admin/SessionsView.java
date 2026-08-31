package eu.jsentinel.jcustos.demo.skill.vaadin.views.admin;

import eu.jsentinel.jcustos.authorization.annotations.RequiresPermission;
import eu.jsentinel.jcustos.components.SessionManagementView;
import eu.jsentinel.jcustos.session.SessionRecord;
import eu.jsentinel.jcustos.session.SessionStatus;
import com.vaadin.flow.router.Route;
import eu.jsentinel.jcustos.demo.skill.vaadin.security.services.SessionStoreProvider;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.HomeButton;
import eu.jsentinel.jcustos.demo.skill.vaadin.views.MainLayout;

/**
 * Admin-only session inventory + revoke. Re-uses the framework's
 * {@link SessionManagementView} composite — the only project-specific
 * glue is wiring it to {@link SessionStoreProvider} and to a revoke
 * callback.
 *
 * <p>The constructor adds a Home button at the top of the content
 * layout via {@link HomeButton#forStandalone(Class)}: the button only
 * renders when this view is registered as a top-level {@code @Route}.
 * Once embedded in an {@code AppLayout} the helper returns empty and
 * the layout's drawer takes over navigation.
 */
@Route(value = SessionsView.NAV, layout = MainLayout.class)
@RequiresPermission("admin:sessions")
public class SessionsView extends SessionManagementView {

  public static final String NAV = "admin/sessions";

  public SessionsView() {
    super(SessionStoreProvider.sessionStore(), SessionsView::revoke);
    HomeButton.forStandalone(getClass())
        .ifPresent(home -> getContent().addComponentAsFirst(home));
  }

  private static void revoke(SessionRecord record) {
    SessionStoreProvider.sessionStore()
        .save(record.withStatus(SessionStatus.REVOKED));
  }
}
