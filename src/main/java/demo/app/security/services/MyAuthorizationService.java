package demo.app.security.services;

import demo.app.security.model.MyUser;
import org.rapidpm.vaadin.security.authorization.api.AuthorizationService;
import org.rapidpm.vaadin.security.authorization.api.permissions.HasPermissions;
import org.rapidpm.vaadin.security.authorization.api.roles.HasRoles;
import org.rapidpm.vaadin.security.authorization.api.roles.RoleName;

import java.util.Objects;
import java.util.stream.Stream;

public class MyAuthorizationService
    implements AuthorizationService<MyUser> {

  @Override
  public HasRoles rolesFor(MyUser subject) {
    Objects.requireNonNull(subject);
    return () -> subject.roles()
                        .stream()
                        .map(Enum::name)
                        .map(RoleName::new);
  }

  @Override
  public HasPermissions permissionsFor(MyUser subject) {
    Objects.requireNonNull(subject);
    return Stream::empty;
  }
}
