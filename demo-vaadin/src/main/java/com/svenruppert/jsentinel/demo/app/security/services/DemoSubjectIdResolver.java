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
package com.svenruppert.jsentinel.demo.app.security.services;

import com.svenruppert.jsentinel.authorization.api.SubjectIdResolver;
import com.svenruppert.jsentinel.demo.app.security.model.MyUser;
import com.svenruppert.jsentinel.logout.SubjectId;

/**
 * Demo {@link SubjectIdResolver} for the Vaadin demo. Maps a
 * {@link MyUser} to its stable id-as-string — matches the subject
 * identifier already used in {@code RoleAssigned} /
 * {@code RoleRevoked} audit events, so {@code SessionStale}
 * events emitted by the {@code JSentinelVersionEnforcerListener}
 * correlate cleanly in the {@code /audit} grid.
 * <p>
 * Registered via
 * {@code META-INF/services/com.svenruppert.jsentinel.authorization.api.SubjectIdResolver}.
 * Without this resolver the Phase 4c snapshot capture in
 * {@code LoginView} is a silent no-op (see
 * {@code LoginView.captureJSentinelVersionSnapshot}).
 */
public final class DemoSubjectIdResolver implements SubjectIdResolver<MyUser> {

  @Override
  public SubjectId resolve(MyUser subject) {
    return SubjectId.of(subject.id().toString());
  }
}
