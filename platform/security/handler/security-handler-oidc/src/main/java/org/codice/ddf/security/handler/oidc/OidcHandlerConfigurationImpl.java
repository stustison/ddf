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

import static org.apache.commons.lang.StringUtils.isBlank;

import java.util.Map;
import org.codice.ddf.security.handler.api.OidcHandlerConfiguration;
import org.pac4j.core.exception.TechnicalException;
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

public class OidcHandlerConfigurationImpl implements OidcHandlerConfiguration {
  private static final Logger LOGGER = LoggerFactory.getLogger(OidcHandlerConfigurationImpl.class);

  public static final String IDP_TYPE = "idpType";
  public static final String CLIENT_ID = "clientId";
  public static final String REALM = "realm";
  public static final String SECRET = "secret";
  public static final String DISCOVERY_URI = "discoveryUri";
  public static final String BASE_URI = "baseUri";
  public static final String SCOPE = "scope";
  public static final String USE_NONCE = "useNonce";
  public static final String RESPONSE_TYPE = "responseType";
  public static final String RESPONSE_MODE = "responseMode";
  public static final String LOGOUT_URI = "logoutUri";

  public static final String DEFAULT_CALLBACK_URL = "https://localhost:8993/admin";

  private OidcConfiguration oidcConfiguration;
  private OidcClient oidcClient;
  private OidcProfileCreator oidcProfileCreator;
  private OidcLogoutActionBuilder logoutActionBuilder;

  private boolean initialized = false;
  private Map<String, Object> properties;

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

  @Override
  public OidcClient getOidcClient() {
    return oidcClient;
  }

  @Override
  public OidcConfiguration getOidcConfiguration() {
    return oidcConfiguration;
  }

  @Override
  public OidcLogoutActionBuilder getLogoutActionBuilder() {
    return logoutActionBuilder;
  }

  @Override
  public OidcProfileCreator getOidcProfileCreator() {
    return oidcProfileCreator;
  }

  @Override
  public boolean isInitialized() {
    return initialized;
  }

  public void update(Map<String, Object> properties) {
    if (properties == null || properties.isEmpty()) {
      LOGGER.warn("Received null or empty properties. Can not update.");
      return;
    }

    this.properties = properties;

    try {
      updateOidcConfiguration();
      initOidcConfiguration();
      updateOidcClient();
      updateOidcLogoutAction();
      initialized = true;

    } catch (TechnicalException e) {
      LOGGER.error("Problem initializing Oidc configuration.", e);
      initialized = false;
    }
  }

  private void updateOidcConfiguration() {
    for (Map.Entry entry : properties.entrySet()) {
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
  }

  private void initOidcConfiguration() {
    if ("Keycloak".equals(idpType)) {
      KeycloakOidcConfiguration keycloakOidcConfiguration = new KeycloakOidcConfiguration();
      keycloakOidcConfiguration.setRealm(realm);
      keycloakOidcConfiguration.setBaseUri(baseUri);
      oidcConfiguration = keycloakOidcConfiguration;

    } else if ("Azure".equals(properties.get(IDP_TYPE))) {
      AzureAdOidcConfiguration azureAdOidcConfiguration = new AzureAdOidcConfiguration();
      azureAdOidcConfiguration.setTenant(realm);
      oidcConfiguration = azureAdOidcConfiguration;
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
    oidcConfiguration.setWithState(true);
    oidcConfiguration.init();
  }

  private void updateOidcClient() {
    if ("Keycloak".equals(properties.get(IDP_TYPE))) {
      oidcClient = new KeycloakOidcClient((KeycloakOidcConfiguration) oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<KeycloakOidcProfile>(oidcConfiguration);

    } else if ("Azure".equals(properties.get(IDP_TYPE))) {
      oidcClient = new AzureAdClient((AzureAdOidcConfiguration) oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<AzureAdProfile>(oidcConfiguration);

    } else if ("Google".equals(properties.get(IDP_TYPE))) {
      oidcClient = new GoogleOidcClient(oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<GoogleOidcProfile>(oidcConfiguration);
    } else {
      oidcClient = new OidcClient(oidcConfiguration);
      oidcProfileCreator = new OidcProfileCreator<>(oidcConfiguration);
    }
    oidcClient.setName(oidcConfiguration.getClientId());

    if (isBlank(oidcClient.getCallbackUrl())) {
      oidcClient.setCallbackUrl(DEFAULT_CALLBACK_URL);
    }

    oidcClient.init();
  }

  private void updateOidcLogoutAction() {
    logoutActionBuilder = new OidcLogoutActionBuilder(oidcConfiguration);
  }

  public void setProperties(Map<String, Object> properties) {
    this.properties = properties;
    updateOidcConfiguration();
  }
}
