/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package demo.app.security.services;

import demo.app.security.model.MyUser;
import demo.app.security.model.UserStorage;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.vaadin.security.authorization.api.AuthenticationService;

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
