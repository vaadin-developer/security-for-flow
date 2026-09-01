/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.credential.propagation;


import java.util.Objects;
import java.util.Optional;

/**
 * Single-slot in-memory store. Not thread-safe — intended for unit
 * tests and reference tooling. Production code uses the adapter
 * defaults ({@code VaadinSessionTokenCredentialStore},
 * {@code ThreadLocalTokenCredentialStore}).
 *
 * @since 00.74.00
 */
public final class InMemoryTokenCredentialStore implements TokenCredentialStore {

  private TokenCredential current;

  public InMemoryTokenCredentialStore() {
  }

  @Override
  public void bind(TokenCredential credential) {
    this.current = Objects.requireNonNull(credential, "credential");
  }

  @Override
  public Optional<TokenCredential> current() {
    return Optional.ofNullable(current);
  }

  @Override
  public void clear() {
    this.current = null;
  }
}
