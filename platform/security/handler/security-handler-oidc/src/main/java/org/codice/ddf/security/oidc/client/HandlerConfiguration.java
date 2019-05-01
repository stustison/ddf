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
import java.util.Map.Entry;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HandlerConfiguration {
  private static final String IDP_TYPE = "idpType";
  private static final String CLIENT_ID = "clientId";
  private static final String REALM = "realm";
  private static final String SECRET = "secret";
  private static final String DISCOVERY_URI = "discoveryUri";
  private static final String BASE_URI = "baseUri";
  private static final String SCOPE = "scope";
  private static final String USE_NONCE = "useNonce";
  private static final String RESPONSE_TYPE = "responseType";
  private static final String RESPONSE_MODE = "responseMode";
  private static final String LOGOUT_URI = "logoutUri";

  private static final Logger LOGGER = LoggerFactory.getLogger(HandlerConfiguration.class);

  private OidcClient oidcClient;
  private OidcConfiguration oidcConfiguration;

  private String idpType;
  private String clientId;
  private String realm;
  private String secret;
  private String discoveryUri;
  private String baseUri;
  private String scope;
  private boolean useNonce;
  private String responseType;
  private String responseMode;
  private String logoutUri;

  private OidcLogoutActionBuilder logoutActionBuilder;

  private OidcProfileCreator oidcProfileCreator;

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
    return logoutUri;
  }

  public OidcConfiguration getOidcConfiguration() {
    return oidcConfiguration;
  }

  public void update(Map<String, Object> properties) {
    for (Entry entry : properties.entrySet()) {
      String key = (String) entry.getKey();
      Object value = entry.getValue();

      switch (key) {
        case IDP_TYPE:
          idpType = (String) value;
          break;
        case REALM:
          realm = (String) value;
          break;
        case CLIENT_ID:
          clientId = (String) value;
          break;
        case SECRET:
          secret = (String) value;
          break;
        case DISCOVERY_URI:
          discoveryUri = (String) value;
          break;
        case BASE_URI:
          baseUri = (String) value;
          break;
        case SCOPE:
          scope = (String) value;
          break;
        case USE_NONCE:
          useNonce = (boolean) value;
          break;
        case RESPONSE_TYPE:
          responseType = (String) value;
          break;
        case RESPONSE_MODE:
          responseMode = (String) value;
          break;
        case LOGOUT_URI:
          logoutUri = (String) value;
          break;
      }
    }
    generateOidcClient();
  }

  private void generateOidcClient() {
    if ("Keycloak".equals(idpType)) {
      oidcConfiguration = new KeycloakOidcConfiguration();
      ((KeycloakOidcConfiguration) oidcConfiguration).setRealm(realm);
      ((KeycloakOidcConfiguration) oidcConfiguration).setBaseUri(baseUri);
    } else if ("Azure".equals(idpType)) {
      oidcConfiguration = new AzureAdOidcConfiguration();
      ((AzureAdOidcConfiguration) oidcConfiguration).setTenant(realm);
    } else {
      oidcConfiguration = new OidcConfiguration();
    }

    oidcConfiguration.setClientId(clientId);
    oidcConfiguration.setDiscoveryURI(discoveryUri);
    oidcConfiguration.setSecret(secret);
    oidcConfiguration.setScope(scope);
    oidcConfiguration.setResponseType(responseType);
    oidcConfiguration.setResponseMode(responseMode);
    oidcConfiguration.setUseNonce(useNonce);
    oidcConfiguration.setLogoutUrl(logoutUri);

    if ("Keycloak".equals(idpType)) {
      oidcClient = new KeycloakOidcClient((KeycloakOidcConfiguration) oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<KeycloakOidcProfile>(oidcConfiguration);
    } else if ("Azure".equals(idpType)) {
      oidcClient = new AzureAdClient((AzureAdOidcConfiguration) oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<AzureAdProfile>(oidcConfiguration);
    } else if ("Google".equals(idpType)) {
      oidcClient = new GoogleOidcClient(oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<GoogleOidcProfile>(oidcConfiguration);
    } else {
      oidcClient = new OidcClient(oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<>(oidcConfiguration);
    }

    logoutActionBuilder = new OidcLogoutActionBuilder(oidcConfiguration);
  }
}
