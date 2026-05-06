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
package com.svenruppert.vaadin.security.authorization.api;

/**
 * Bundles the logout flow so callers do not have to manually orchestrate
 * subject removal, session invalidation and navigation.
 * <p>
 * The core implementation
 * ({@link SubjectClearingLogoutService}) only drops the subject from the
 * {@link SubjectStore}. Adapter modules add session invalidation and
 * navigation — see {@code VaadinLogoutService} in {@code security-vaadin}.
 */
public interface LogoutService {

  void logout(LogoutContext context);
}
