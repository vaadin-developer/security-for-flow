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
package com.svenruppert.vaadin.security.bootstrap;

/**
 * Operating mode of the first-run bootstrap mechanism.
 *
 * <ul>
 *   <li>{@link #DISABLED} — bootstrap is turned off entirely. No token is
 *       generated. The setup endpoint is not active.</li>
 *   <li>{@link #PERSISTENT_FILE} — the bootstrap token is written to a local
 *       file with restrictive permissions. Survives server restarts until
 *       the initial administrator has been created.</li>
 *   <li>{@link #TRANSIENT_CONSOLE} — the bootstrap token is generated fresh
 *       on every start and printed to the server console only. Lives only
 *       for the current process.</li>
 * </ul>
 */
public enum BootstrapMode {
  DISABLED,
  PERSISTENT_FILE,
  TRANSIENT_CONSOLE
}
