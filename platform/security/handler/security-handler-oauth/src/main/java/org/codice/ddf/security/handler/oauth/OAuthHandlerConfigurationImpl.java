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
package org.codice.ddf.security.handler.oauth;

import static org.apache.commons.lang.StringUtils.isBlank;

import java.util.Map;
import org.codice.ddf.security.handler.api.OAuthHandlerConfiguration;
import org.pac4j.oauth.client.OAuth20Client;
import org.pac4j.oauth.config.OAuth20Configuration;
import org.pac4j.oauth.profile.generic.GenericOAuth20ProfileDefinition;
import org.pac4j.scribe.builder.api.GenericApi20;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthHandlerConfigurationImpl implements OAuthHandlerConfiguration {
  private static final Logger LOGGER = LoggerFactory.getLogger(OAuthHandlerConfigurationImpl.class);

  private static final String CLIENT_ID = "clientId";
  private static final String SECRET = "secret";
  private static final String BASE_URI = "baseUri";
  private static final String SCOPE = "scope";

  private static final String DEFAULT_RESPONSE_TYPE = "token";
  private static final String DEFAULT_CALLBACK_URL = "https://localhost:8993/admin";

  private OAuth20Configuration oAuthConfiguration;
  private OAuth20Client oAuthClient;

  private Map<String, Object> properties;
  private boolean initialized = false;

  public OAuthHandlerConfigurationImpl(Map<String, Object> properties) {
    update(properties);
  }

  @Override
  public OAuth20Client getOAuthClient() {
    return oAuthClient;
  }

  @Override
  public OAuth20Configuration getOAuthConfiguration() {
    return oAuthConfiguration;
  }

  @Override
  public boolean isInitialized() {
    return initialized;
  }

  private void update(Map<String, Object> properties) {
    if (properties == null || properties.isEmpty()) {
      LOGGER.warn("Received null or empty properties. Can not update OAuthHandlerConfiguration.");
      return;
    }

    this.properties = properties;

    generateOAuthConfiguration();
    generateOAuthClient();

    initialized = true;
  }

  private void generateOAuthConfiguration() {
    oAuthConfiguration = new OAuth20Configuration();
    oAuthConfiguration.setKey((String) properties.get(CLIENT_ID));
    oAuthConfiguration.setSecret((String) properties.get(SECRET));
    oAuthConfiguration.setTokenAsHeader(false);
    oAuthConfiguration.setWithState(true);
    oAuthConfiguration.setScope((String) properties.get(SCOPE));
    oAuthConfiguration.setApi(
        new GenericApi20((String) properties.get(BASE_URI), (String) properties.get(BASE_URI)));
    oAuthConfiguration.setProfileDefinition(new GenericOAuth20ProfileDefinition());
    oAuthConfiguration.setResponseType(DEFAULT_RESPONSE_TYPE);

    oAuthConfiguration.init();
  }

  private void generateOAuthClient() {
    oAuthClient = new OAuth20Client();
    oAuthClient.setConfiguration(oAuthConfiguration);

    if (isBlank(oAuthClient.getCallbackUrl())) {
      oAuthClient.setCallbackUrl(DEFAULT_CALLBACK_URL);
    }

    oAuthClient.init();
  }
}
