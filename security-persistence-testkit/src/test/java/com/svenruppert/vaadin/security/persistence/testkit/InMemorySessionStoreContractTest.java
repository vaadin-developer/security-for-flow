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
package com.svenruppert.vaadin.security.persistence.testkit;

import com.svenruppert.vaadin.security.session.InMemorySessionStore;
import com.svenruppert.vaadin.security.session.SessionStore;

/**
 * Runs every default test in {@link SessionStoreContract} against the
 * {@link InMemorySessionStore} default.
 */
class InMemorySessionStoreContractTest implements SessionStoreContract {

  @Override
  public SessionStore newStore() {
    return new InMemorySessionStore();
  }
}
