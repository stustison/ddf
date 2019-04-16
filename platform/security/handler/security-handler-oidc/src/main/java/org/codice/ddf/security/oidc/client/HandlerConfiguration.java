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
package org.codice.ddf.security.oidc.client;

import java.util.Map;
import org.pac4j.oidc.client.AzureAdClient;
import org.pac4j.oidc.client.GoogleOidcClient;
import org.pac4j.oidc.client.KeycloakOidcClient;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.AzureAdOidcConfiguration;
import org.pac4j.oidc.config.KeycloakOidcConfiguration;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.logout.OidcLogoutActionBuilder;
import org.pac4j.oidc.profile.azuread.AzureAdProfile;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.pac4j.oidc.profile.google.GoogleOidcProfile;
import org.pac4j.oidc.profile.keycloak.KeycloakOidcProfile;

public class HandlerConfiguration {

  private OidcClient oidcClient;

  private OidcConfiguration oidcConfiguration;

  private static final String IDP_TYPE = "idpType";

  private static final String CLIENT_ID = "clientId";

  private static final String SECRET = "secret";

  private static final String DISCOVERY_URI = "discoveryURI";

  private static final String SCOPE = "scope";

  private static final String USE_NONCE = "useNonce";

  private static final String RESPONSE_TYPE = "responseType";

  private static final String RESPONSE_MODE = "responseMode";

  private static final String REALM = "realm";

  private static final String BASE_URI = "baseUri";

  private static final String LOGOUT_URI = "logoutUri";

  private Map<String, Object> properties;

  private OidcLogoutActionBuilder logoutActionBuilder;

  private OidcProfileCreator oidcProfileCreator;

  public void init() {
    if (properties == null) {
      return;
    }
    if (properties.get(IDP_TYPE).equals("Keycloak")) {
      oidcConfiguration = new KeycloakOidcConfiguration();
      ((KeycloakOidcConfiguration) oidcConfiguration).setRealm((String) properties.get(REALM));
      ((KeycloakOidcConfiguration) oidcConfiguration).setBaseUri((String) properties.get(BASE_URI));
    } else if (properties.get(IDP_TYPE).equals("Azure")) {
      oidcConfiguration = new AzureAdOidcConfiguration();
      ((AzureAdOidcConfiguration) oidcConfiguration).setTenant((String) properties.get(REALM));
    } else {
      oidcConfiguration = new OidcConfiguration();
    }

    oidcConfiguration.setClientId((String) properties.get(CLIENT_ID));
    oidcConfiguration.setDiscoveryURI((String) properties.get(DISCOVERY_URI));
    oidcConfiguration.setSecret((String) properties.get(SECRET));
    oidcConfiguration.setScope((String) properties.get(SCOPE));
    oidcConfiguration.setResponseType((String) properties.get(RESPONSE_TYPE));
    oidcConfiguration.setResponseMode((String) properties.get(RESPONSE_MODE));
    oidcConfiguration.setUseNonce((Boolean) properties.get(USE_NONCE));
    oidcConfiguration.setLogoutUrl((String) properties.get(LOGOUT_URI));

    if (properties.get(IDP_TYPE).equals("Keycloak")) {
      oidcClient = new KeycloakOidcClient((KeycloakOidcConfiguration) oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<KeycloakOidcProfile>(oidcConfiguration);
    } else if (properties.get(IDP_TYPE).equals("Azure")) {
      oidcClient = new AzureAdClient((AzureAdOidcConfiguration) oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<AzureAdProfile>(oidcConfiguration);
    } else if (properties.get(IDP_TYPE).equals("Google")) {
      oidcClient = new GoogleOidcClient(oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<GoogleOidcProfile>(oidcConfiguration);
    } else {
      oidcClient = new OidcClient(oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<>(oidcConfiguration);
    }

    logoutActionBuilder = new OidcLogoutActionBuilder(oidcConfiguration);
  }

  public void init(Map<String, Object> properties) {
    this.properties = properties;
    init();
  }

  public OidcClient getOidcClient() {
    return oidcClient;
  }

  public OidcLogoutActionBuilder getLogoutActionBuilder() {
    return logoutActionBuilder;
  }

  public OidcProfileCreator getOidcProfileCreator() {
    return oidcProfileCreator;
  }

  public String getLogoutUri() {
    return (String) properties.get(LOGOUT_URI);
  }

  public OidcConfiguration getOidcConfiguration() {
    return oidcConfiguration;
  }
}
