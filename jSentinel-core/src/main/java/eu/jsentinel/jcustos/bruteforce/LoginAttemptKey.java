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
package eu.jsentinel.jcustos.bruteforce;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;

/**
 * Composite key under which {@link LoginAttemptStore} tracks
 * failed-attempt counters and the last failure instant.
 * <p>
 * Both dimensions are recorded independently: {@code userId} catches
 * an attacker hopping IPs against the same account, {@code ip}
 * catches one cycling usernames from the same source. Brute-force
 * policies typically consult both keys per attempt and back off as
 * soon as either counter trips.
 *
 * @param tenant tenant scope; {@code null} becomes {@link TenantId#DEFAULT}
 * @param userId username dimension; non-blank
 * @param ip     client-address dimension; non-blank
 */
@ExperimentalJSentinelApi
public record LoginAttemptKey(TenantId tenant, String userId, String ip) {

  /**
   * Validates the record components and normalises a {@code null}
   * tenant to {@link TenantId#DEFAULT}.
   *
   * @param tenant tenant scope; {@code null} becomes DEFAULT
   * @param userId non-blank username
   * @param ip     non-blank client address
   */
  public LoginAttemptKey {
    tenant = tenant == null ? TenantId.DEFAULT : tenant;
    if (userId == null || userId.isBlank()) {
      throw new IllegalArgumentException("userId must not be blank");
    }
    if (ip == null || ip.isBlank()) {
      throw new IllegalArgumentException("ip must not be blank");
    }
  }
}
