/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.ddf.security.handler.oidc;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

import java.util.HashMap;
import java.util.Map;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class OidcHandlerConfigurationImplTest {
  private static Map<String, Object> emptyProperties;
  private static Map<String, Object> validProperties;
  private static Map<String, Object> invalidProperties;

  private OidcHandlerConfigurationImpl handlerConfiguration;

  @BeforeClass
  public static void setupClass() {
    emptyProperties = new HashMap<>();

    validProperties = new HashMap<>();
    validProperties.put(OidcHandlerConfigurationImpl.IDP_TYPE, "generic");
    validProperties.put(OidcHandlerConfigurationImpl.CLIENT_ID, "generic-client");
    validProperties.put(OidcHandlerConfigurationImpl.REALM, "master");
    validProperties.put(OidcHandlerConfigurationImpl.SECRET, "changeit");
    validProperties.put(OidcHandlerConfigurationImpl.DISCOVERY_URI, "https://discovery/uri");
    validProperties.put(OidcHandlerConfigurationImpl.BASE_URI, "https://base/uri");
    validProperties.put(OidcHandlerConfigurationImpl.SCOPE, "openid profile email");
    validProperties.put(OidcHandlerConfigurationImpl.USE_NONCE, false);
    validProperties.put(OidcHandlerConfigurationImpl.RESPONSE_TYPE, "code");
    validProperties.put(OidcHandlerConfigurationImpl.RESPONSE_MODE, "form_post");
    validProperties.put(OidcHandlerConfigurationImpl.LOGOUT_URI, "https://logout/uri");

    invalidProperties = new HashMap<>();
    invalidProperties.put(OidcHandlerConfigurationImpl.IDP_TYPE, "invalid idpType");
    invalidProperties.put(OidcHandlerConfigurationImpl.CLIENT_ID, "invalid clientId");
    invalidProperties.put(OidcHandlerConfigurationImpl.REALM, "invalid realm");
    invalidProperties.put(OidcHandlerConfigurationImpl.SECRET, "invalid secret");
    invalidProperties.put(OidcHandlerConfigurationImpl.DISCOVERY_URI, "invalid discoveryUri");
    invalidProperties.put(OidcHandlerConfigurationImpl.BASE_URI, "invalid baseUri");
    invalidProperties.put(OidcHandlerConfigurationImpl.SCOPE, "invalid scope");
    invalidProperties.put(OidcHandlerConfigurationImpl.USE_NONCE, "invalid useNonce");
    invalidProperties.put(OidcHandlerConfigurationImpl.RESPONSE_TYPE, "invalid responseType");
    invalidProperties.put(OidcHandlerConfigurationImpl.RESPONSE_MODE, "invalid responseMode");
    invalidProperties.put(OidcHandlerConfigurationImpl.LOGOUT_URI, "invalid logoutUri");
  }

  @Test
  public void constructWithNull() {
    handlerConfiguration = new OidcHandlerConfigurationImpl(null);

    assertThat(handlerConfiguration.isInitialized(), is(false));
  }

  @Test
  public void constructWithEmptyProperties() {
    handlerConfiguration = new OidcHandlerConfigurationImpl(emptyProperties);

    assertThat(handlerConfiguration.isInitialized(), is(false));
  }

  @Test(expected = ClassCastException.class)
  public void constructWithInvalidProperties() {
    handlerConfiguration = new OidcHandlerConfigurationImpl(invalidProperties);

    assertThat(handlerConfiguration.isInitialized(), is(false));
  }

  /* currently does not initialize due to a backend http call to the DiscoveryUri failing */
  @Test
  public void constructWithValidProperties() {
    handlerConfiguration = new OidcHandlerConfigurationImpl(validProperties);

    assertThat(handlerConfiguration.isInitialized(), is(false));
  }
}
