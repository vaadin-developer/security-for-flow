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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * In-memory {@link RememberMeTokenStore} backed by a
 * {@link ConcurrentHashMap} keyed on the token hash.
 */
@ExperimentalJSentinelApi
public final class InMemoryRememberMeTokenStore implements RememberMeTokenStore {

  private final ConcurrentHashMap<String, RememberMeTokenRecord> tokens = new ConcurrentHashMap<>();

  /** Creates an empty store. */
  public InMemoryRememberMeTokenStore() {
  }

  @Override
  public Optional<RememberMeTokenRecord> findByHash(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return Optional.ofNullable(tokens.get(tokenHash));
  }

  @Override
  public void save(RememberMeTokenRecord record) {
    requireNonNull(record, "record must not be null");
    tokens.put(record.tokenHash(), record);
  }

  @Override
  public boolean deleteByHash(String tokenHash) {
    requireNonBlank(tokenHash, "tokenHash");
    return tokens.remove(tokenHash) != null;
  }

  @Override
  public int deleteBySubject(TenantId tenant, SubjectId subjectId) {
    requireNonNull(tenant, "tenant must not be null");
    requireNonNull(subjectId, "subjectId must not be null");
    int before = tokens.size();
    tokens.values().removeIf(record ->
        record.tenant().equals(tenant) && record.subjectId().equals(subjectId));
    return before - tokens.size();
  }

  @Override
  public int purgeExpired(Instant now) {
    requireNonNull(now, "now must not be null");
    int before = tokens.size();
    tokens.values().removeIf(record -> record.isExpired(now));
    return before - tokens.size();
  }

  private static void requireNonBlank(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
  }
}
