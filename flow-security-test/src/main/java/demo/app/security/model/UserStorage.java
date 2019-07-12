package demo.app.security.model;

import demo.app.security.roles.AuthorizationRole;
import org.rapidpm.frp.model.serial.Pair;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

public class UserStorage {

  private static Map<Credentials, MyUser> storage  = new ConcurrentHashMap<>();
  private static Map<Long, MyUser>        idToUser = new ConcurrentHashMap<>();

  static {
    storage.put(new Credentials("admin", "admin"), createMyUser(1L, "Herr Admin", AuthorizationRole.ADMIN));
    storage.put(new Credentials("user", "user"), createMyUser(2L, "Herr User", AuthorizationRole.USER));
    storage.put(new Credentials("demo", "demo"), createMyUser(3L, "Herr Demo", AuthorizationRole.NERD));
  }

  static {
    storage.values()
           .forEach(v -> idToUser.put(v.id(), v));
  }

  private UserStorage() {
  }

  static MyUser createMyUser(Long id, String name, AuthorizationRole... roles) {
    Objects.requireNonNull(id);
    Objects.requireNonNull(name);
    Objects.requireNonNull(roles);

    final HashSet<AuthorizationRole> roleHashSet = new HashSet<>();
    Collections.addAll(roleHashSet, roles);
    roleHashSet.add(AuthorizationRole.USER);

    return new MyUser(id, name, roleHashSet);
  }

  public static void deleteUser(Long id) {
    final MyUser myUser = idToUser.remove(id);
    storage.values()
           .removeIf(myUser::equals);
  }

  public static void addUser(Credentials credentials, MyUser myUser) {
    storage.put(credentials, myUser);
    idToUser.put(myUser.id(), myUser);
  }

  public static boolean checkCredentials(Credentials credentials) {
    return storage.containsKey(credentials);
  }

  public static MyUser userByCredentials(Credentials credentials) {
    return storage.get(credentials);
  }

  public static MyUser userByID(Long id) {
    return idToUser.get(id);
  }

  public static Stream<MyUser> allUsers() {
    return storage.values()
                  .stream();
  }


  public static class Credentials
      extends Pair<String, String> {

    public Credentials(String s, String s2) {
      super(s, s2);
    }

    public String username() {
      return getT1();
    }

    public String password() {
      return getT2();
    }
  }
}
