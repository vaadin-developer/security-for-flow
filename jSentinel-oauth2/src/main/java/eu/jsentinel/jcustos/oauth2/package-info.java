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
/**
 * V00.77 OAuth2 Relying-Party HTTP-flow implementations: the JDK-HttpClient
 * token-endpoint client, authorization-code + PKCE flow, refresh-token rotation
 * with reuse-detection, revocation, introspection and the device-authorization
 * grant. The JOSE-free SPI contracts live in
 * {@code eu.jsentinel.jcustos.oauth2.api} (jSentinel-core); this module is
 * the opt-in HTTP implementation.
 *
 * @since 00.77.00
 */
package eu.jsentinel.jcustos.oauth2;

