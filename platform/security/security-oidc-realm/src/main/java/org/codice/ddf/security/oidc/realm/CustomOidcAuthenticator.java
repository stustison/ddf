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
package org.codice.ddf.security.oidc.realm;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPRequest.Method;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import javax.naming.AuthenticationException;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.credentials.authenticator.OidcAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomOidcAuthenticator extends OidcAuthenticator {

  private static final Logger LOGGER = LoggerFactory.getLogger(CustomOidcAuthenticator.class);

  private OidcTokenValidator oidcTokenValidator;

  public CustomOidcAuthenticator(OidcConfiguration configuration, OidcClient client) {
    super(configuration, client);
    oidcTokenValidator = new OidcTokenValidator(configuration);
  }

  /* This methods job is to try and get an id token from a
  1. refresh token
  2. authorization code
  3. access token
  */
  @Override
  public void validate(OidcCredentials credentials, WebContext webContext) {
    final RefreshToken refreshToken = credentials.getRefreshToken();
    final AuthorizationCode authorizationCode = credentials.getCode();

    final List<AuthorizationGrant> grantList = new ArrayList<>();

    if (refreshToken != null) {
      grantList.add(new RefreshTokenGrant(refreshToken));
    }

    if (authorizationCode != null) {
      try {
        final URI callbackUri = new URI(client.computeFinalCallbackUrl(webContext));
        grantList.add(new AuthorizationCodeGrant(authorizationCode, callbackUri));
      } catch (URISyntaxException e) {
        LOGGER.debug("Problem computing callback url. Cannot add authorization code grant.");
      }
    }

    // try to get credentials using refresh token and authorization code
    for (AuthorizationGrant grant : grantList) {
      try {
        trySendingGrantAndPopulatingCredentials(grant, credentials, webContext);

        if (credentials.getIdToken() != null) {
          break;
        }
      } catch (IOException | ParseException e) {
        LOGGER.debug("Problem sending grant ({}).", grant, e);
      }
    }

    // try to get credentials using access token
    final AccessToken accessToken = credentials.getAccessToken();
    if (credentials.getIdToken() == null && accessToken != null) {
      oidcTokenValidator.validateAccessToken(credentials.getAccessToken(), null);

      final UserInfoRequest userInfoRequest =
          new UserInfoRequest(
              configuration.findProviderMetadata().getUserInfoEndpointURI(),
              Method.GET,
              new BearerAccessToken(accessToken.toString()));
      final HTTPRequest userInfoHttpRequest = userInfoRequest.toHTTPRequest();

      try {
        final HTTPResponse httpResponse = userInfoHttpRequest.send();
        final UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);
        if (userInfoResponse instanceof UserInfoSuccessResponse) {
          final UserInfoSuccessResponse userInfoSuccessResponse =
              (UserInfoSuccessResponse) userInfoResponse;

          JWT idToken = userInfoSuccessResponse.getUserInfoJWT();
          if (idToken == null && userInfoSuccessResponse.getUserInfo().toJWTClaimsSet() != null) {
            idToken = new PlainJWT(userInfoSuccessResponse.getUserInfo().toJWTClaimsSet());
          }

          oidcTokenValidator.validateUserInfoIdToken(idToken);
          credentials.setIdToken(idToken);
        } else {
          throw new AuthenticationException("Received a non-successful UserInfoResponse.");
        }
      } catch (IOException | ParseException | AuthenticationException e) {
        LOGGER.debug("Problem retrieving id token using access token.", e);
      }
    }
  }

  private void trySendingGrantAndPopulatingCredentials(
      AuthorizationGrant grant, OidcCredentials credentials, WebContext webContext)
      throws IOException, ParseException {
    final TokenRequest request =
        new TokenRequest(
            configuration.findProviderMetadata().getTokenEndpointURI(),
            getClientAuthentication(),
            grant);
    HTTPRequest tokenHttpRequest = request.toHTTPRequest();
    tokenHttpRequest.setConnectTimeout(configuration.getConnectTimeout());
    tokenHttpRequest.setReadTimeout(configuration.getReadTimeout());

    final HTTPResponse httpResponse = tokenHttpRequest.send();
    LOGGER.debug(
        "Token response: status={}, content={}",
        httpResponse.getStatusCode(),
        httpResponse.getContent());

    final TokenResponse response = OIDCTokenResponseParser.parse(httpResponse);
    if (response instanceof TokenErrorResponse) {
      throw new TechnicalException(
          "Bad token response, error=" + ((TokenErrorResponse) response).getErrorObject());
    }
    LOGGER.debug("Token response successful");
    final OIDCTokenResponse tokenSuccessResponse = (OIDCTokenResponse) response;
    final OIDCTokens oidcTokens = tokenSuccessResponse.getOIDCTokens();

    JWT idToken = oidcTokens.getIDToken();
    AccessToken accessToken = oidcTokens.getAccessToken();
    if (accessToken != null) {
      oidcTokenValidator.validateAccessToken(accessToken, idToken);
    }

    // save tokens to credentials
    credentials.setAccessToken(oidcTokens.getAccessToken());
    credentials.setRefreshToken(oidcTokens.getRefreshToken());
    credentials.setIdToken(oidcTokens.getIDToken());
  }
}
