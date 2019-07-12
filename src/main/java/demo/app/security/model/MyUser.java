package demo.app.security.model;

import demo.app.security.roles.AuthorizationRole;
import org.rapidpm.dependencies.core.logger.HasLogger;
import org.rapidpm.frp.model.Triple;

import java.util.HashSet;
import java.util.Set;

import static java.util.Arrays.asList;

public class MyUser
    extends Triple<Long, String, Set<AuthorizationRole>>
    implements HasLogger {

  public MyUser(Long id, String name, Set<AuthorizationRole> roles) {
    super(id, name, roles);
  }

  public MyUser(Long id, String name, AuthorizationRole... roles) {
    super(id, name, new HashSet<>(asList(roles)));
  }

  public Long id() {
    return getT1();
  }

  public String name() {
    return getT2();
  }

  public Set<AuthorizationRole> roles() {
    return getT3();
  }
}
