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
