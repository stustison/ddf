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

import static org.pac4j.core.profile.AttributeLocation.PROFILE_ATTRIBUTE;
import static org.pac4j.core.util.CommonHelper.assertNotNull;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.UserInfoErrorResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.io.IOException;
import java.util.Map;
import org.apache.shiro.authc.AuthenticationException;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.profile.ProfileHelper;
import org.pac4j.core.profile.jwt.JwtClaims;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.profile.OidcProfile;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CustomOidcProfileCreator<U extends OidcProfile> extends OidcProfileCreator<U> {

  private static final Logger LOGGER = LoggerFactory.getLogger(CustomOidcProfileCreator.class);

  private OIDCProviderMetadata metadata;

  public CustomOidcProfileCreator(
      OidcConfiguration configuration, OIDCProviderMetadata oidcProviderMetadata) {
    super(configuration);
    metadata = oidcProviderMetadata;
  }

  @Override
  public U create(OidcCredentials credentials, WebContext context) {
    init();

    final AccessToken accessToken = credentials.getAccessToken();
    final JWT idToken = credentials.getIdToken();

    final U profile = getProfileDefinition().newProfile();
    profile.setAccessToken(accessToken);
    profile.setIdTokenString(idToken.getParsedString());

    try {
      IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(idToken.getJWTClaimsSet());
      assertNotNull("claimsSet", claimsSet);
      profile.setId(ProfileHelper.sanitizeIdentifier(profile, claimsSet.getSubject()));
    } catch (java.text.ParseException | ParseException e) {
      LOGGER.warn("Unable to extract ID token claim set.", e);
    }

    final RefreshToken refreshToken = credentials.getRefreshToken();
    if (refreshToken != null && !refreshToken.getValue().isEmpty()) {
      profile.setRefreshToken(refreshToken);
      LOGGER.debug("Refresh Token successful retrieved");
    }

    try {
      if (metadata.getUserInfoEndpointURI() != null && accessToken != null) {

        final UserInfoRequest userInfoRequest =
            new UserInfoRequest(metadata.getUserInfoEndpointURI(), (BearerAccessToken) accessToken);
        final HTTPRequest userInfoHttpRequest = userInfoRequest.toHTTPRequest();
        userInfoHttpRequest.setConnectTimeout(configuration.getConnectTimeout());
        userInfoHttpRequest.setReadTimeout(configuration.getReadTimeout());
        final HTTPResponse httpResponse = userInfoHttpRequest.send();
        LOGGER.debug(
            "Token response: status={}, content={}",
            httpResponse.getStatusCode(),
            httpResponse.getContent());

        final UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);
        if (userInfoResponse instanceof UserInfoErrorResponse) {
          LOGGER.error(
              "Bad User Info response, error={}",
              ((UserInfoErrorResponse) userInfoResponse).getErrorObject());
        } else {
          final JWTClaimsSet userInfoClaimsSet;
          final UserInfoSuccessResponse userInfoSuccessResponse =
              (UserInfoSuccessResponse) userInfoResponse;
          if (userInfoSuccessResponse.getUserInfo() != null) {
            userInfoClaimsSet = userInfoSuccessResponse.getUserInfo().toJWTClaimsSet();
          } else {
            userInfoClaimsSet = userInfoSuccessResponse.getUserInfoJWT().getJWTClaimsSet();
          }

          getProfileDefinition().convertAndAdd(profile, userInfoClaimsSet.getClaims(), null);
        }
      }

      for (final Map.Entry<String, Object> entry :
          idToken.getJWTClaimsSet().getClaims().entrySet()) {
        if (!JwtClaims.SUBJECT.equals(entry.getKey())
            && profile.getAttribute(entry.getKey()) == null) {
          getProfileDefinition()
              .convertAndAdd(profile, PROFILE_ATTRIBUTE, entry.getKey(), entry.getValue());
        }
      }

      profile.setTokenExpirationAdvance(configuration.getTokenExpirationAdvance());
      return profile;

    } catch (final IOException | ParseException | java.text.ParseException e) {
      throw new AuthenticationException(e);
    }
  }
}
