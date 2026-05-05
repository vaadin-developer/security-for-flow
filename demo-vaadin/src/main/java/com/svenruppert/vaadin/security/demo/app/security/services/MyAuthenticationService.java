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
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;
import com.svenruppert.vaadin.security.demo.app.security.model.UserStorage;
import com.svenruppert.vaadin.security.authorization.api.AuthenticationService;

public class MyAuthenticationService
    implements AuthenticationService<UserStorage.Credentials, MyUser>, HasLogger {

  @Override
  public boolean checkCredentials(UserStorage.Credentials credentials) {
    if (credentials == null) return false;
    return UserStorage.checkCredentials(credentials);
  }

  @Override
  public MyUser loadSubject(UserStorage.Credentials credentials) {
    return UserStorage.userByCredentials(credentials);
  }

  @Override
  public Class<MyUser> subjectType() {
    return MyUser.class;
  }



}
