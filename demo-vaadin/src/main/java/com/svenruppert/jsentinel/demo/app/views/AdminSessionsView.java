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
package com.svenruppert.jsentinel.demo.app.views;

import com.svenruppert.jsentinel.authorization.annotations.RequiresPermission;
import com.svenruppert.jsentinel.components.SessionManagementView;
import com.svenruppert.jsentinel.demo.app.security.services.DemoSessionStoreProvider;
import com.svenruppert.jsentinel.session.SessionRecord;
import com.svenruppert.jsentinel.session.SessionStatus;
import com.vaadin.flow.router.Route;

/**
 * Admin-only Phase-8a session inventory. Re-uses the framework's
 * {@link SessionManagementView} composite — the only demo-specific
 * code is wiring it to {@link DemoSessionStoreProvider} and to a
 * revoke callback that updates the same store. Demonstrates how a
 * downstream app integrates Phase-8a with two lines of glue.
 */
@Route(AdminSessionsView.NAV)
@RequiresPermission("admin:sessions")
public class AdminSessionsView extends SessionManagementView {

  public static final String NAV = "admin/sessions";

  public AdminSessionsView() {
    super(DemoSessionStoreProvider.sessionStore(), AdminSessionsView::revoke);
  }

  /**
   * Revoke callback: marks the supplied record as
   * {@link SessionStatus#REVOKED} via {@code SessionStore.save(record.withStatus(REVOKED))}.
   * Demo-only — a production wiring would call
   * {@code LogoutService.logout(subjectId, CurrentSession)} so the
   * full Vaadin session is invalidated too.
   */
  private static void revoke(SessionRecord record) {
    DemoSessionStoreProvider.sessionStore()
        .save(record.withStatus(SessionStatus.REVOKED));
  }
}
