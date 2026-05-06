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
package com.svenruppert.vaadin.security.demo.app.security.services;

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.vaadin.security.authorization.api.AuthenticationService;
import com.svenruppert.vaadin.security.demo.app.security.model.Credentials;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectory;
import com.svenruppert.vaadin.security.demo.app.security.model.DemoUserDirectoryProvider;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;

public class MyAuthenticationService
    implements AuthenticationService<Credentials, MyUser>, HasLogger {

  @Override
  public boolean checkCredentials(Credentials credentials) {
    if (credentials == null) return false;
    return directory().checkCredentials(credentials);
  }

  @Override
  public MyUser loadSubject(Credentials credentials) {
    return directory().findByCredentials(credentials).orElse(null);
  }

  @Override
  public Class<MyUser> subjectType() {
    return MyUser.class;
  }

  private static DemoUserDirectory directory() {
    return DemoUserDirectoryProvider.directory();
  }
}
