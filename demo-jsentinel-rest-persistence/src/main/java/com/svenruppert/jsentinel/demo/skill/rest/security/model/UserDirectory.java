package com.svenruppert.jsentinel.demo.skill.rest.security.model;

import com.svenruppert.jsentinel.authentication.PasswordHasher;
import com.svenruppert.jsentinel.demo.skill.rest.security.roles.AuthorizationRole;

import java.util.Optional;
import java.util.stream.Stream;

/**
 * Application user store. Decoupled from the concrete in-memory
 * implementation so a future backend swap (DB, LDAP, IAM) does not
 * touch consumers.
 */
public interface UserDirectory {

  Optional<User> findByCredentials(Credentials credentials);

  default boolean checkCredentials(Credentials credentials) {
    return findByCredentials(credentials).isPresent();
  }

  Optional<User> findById(Long id);

  Stream<User> all();

  void addUser(String username, String plaintextPassword, User user);

  /**
   * Adds a user whose password was already hashed elsewhere (typically
   * the bootstrap flow's {@code InitialAdminBootstrapService}). Bypasses
   * the directory's own hasher.
   */
  void registerWithHashedPassword(String username, String passwordHash, User user);

  void deleteUser(Long id);

  /** @return {@code true} if at least one user has the {@code ADMIN} role */
  boolean hasAnyAdministrator();

  void assignRole(Long id, AuthorizationRole role);

  void revokeRole(Long id, AuthorizationRole role);

  PasswordHasher passwordHasher();
}
