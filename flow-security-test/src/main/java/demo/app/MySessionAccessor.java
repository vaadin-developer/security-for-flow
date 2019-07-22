package demo.app;

import demo.app.security.model.MyUser;
import demo.app.security.roles.AuthorizationRole;
import org.rapidpm.frp.model.Result;
import org.rapidpm.vaadin.security.authorization.api.*;
import org.rapidpm.vaadin.security.authorization.api.roles.RoleName;

import java.util.List;

import static java.util.Arrays.asList;

public interface MySessionAccessor
    extends SessionAccessor {


  public static boolean isCurrentUserAuthorizedFor(AuthorizationRole... authorizationRoles) {
    if (authorizationRoles == null) return true;
    if (authorizationRoles.length == 0) return true;
    final List<AuthorizationRole>      roles                = asList(authorizationRoles);
    final Result<MyUser>               currentSubject       = SessionAccessor.currentSubject();
    final AuthorizationService<MyUser> authorizationService = new AuthorizationServiceProvider<MyUser>().load();
    return (currentSubject.isPresent()) && authorizationService.rolesFor(currentSubject.get())
                                                               .roleNames()
                                                               .map(RoleName::roleName)
                                                               .anyMatch(subjectRole -> roles.contains(
                                                                   AuthorizationRole.valueOf(subjectRole)));
  }


}
