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
package com.svenruppert.vaadin.security.demo.app.security.model;

import com.svenruppert.vaadin.security.demo.app.security.roles.AuthorizationRole;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

public class UserStorage {

  private static final Map<Credentials, MyUser> STORAGE = new ConcurrentHashMap<>();
  private static final Map<Long, MyUser> ID_TO_USER = new ConcurrentHashMap<>();

  static {
    STORAGE.put(new Credentials("admin", "admin"), createMyUser(1L, "Herr Admin", AuthorizationRole.ADMIN));
    STORAGE.put(new Credentials("user", "user"), createMyUser(2L, "Herr User", AuthorizationRole.USER));
    STORAGE.put(new Credentials("demo", "demo"), createMyUser(3L, "Herr Demo", AuthorizationRole.NERD));
  }

  static {
    STORAGE.values()
        .forEach(v -> ID_TO_USER.put(v.id(), v));
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
    final MyUser myUser = ID_TO_USER.remove(id);
    STORAGE.values()
        .removeIf(myUser::equals);
  }

  public static void addUser(Credentials credentials, MyUser myUser) {
    STORAGE.put(credentials, myUser);
    ID_TO_USER.put(myUser.id(), myUser);
  }

  public static boolean checkCredentials(Credentials credentials) {
    return STORAGE.containsKey(credentials);
  }

  public static MyUser userByCredentials(Credentials credentials) {
    return STORAGE.get(credentials);
  }

  public static MyUser userByID(Long id) {
    return ID_TO_USER.get(id);
  }

  public static Stream<MyUser> allUsers() {
    return STORAGE.values()
        .stream();
  }


  public record Credentials(String username, String password) { }
}
