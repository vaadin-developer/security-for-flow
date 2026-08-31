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
package eu.jsentinel.jcustos.identity.oidc;

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * http://ec.europa.eu/idabc/eupl5
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.oidc.api.ClaimsToTenantMapper;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;

import java.util.Optional;

/** The spec-clean default: no tenant (V00.78). Multi-tenant apps supply their own. */
public final class EmptyTenantMapper implements ClaimsToTenantMapper {

  public static final EmptyTenantMapper INSTANCE = new EmptyTenantMapper();

  public EmptyTenantMapper() {
  }

  @Override
  public Optional<TenantId> mapTenant(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo) {
    return Optional.empty();
  }
}
