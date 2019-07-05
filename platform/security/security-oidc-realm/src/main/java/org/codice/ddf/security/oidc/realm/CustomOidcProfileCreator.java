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

  private OidcTokenValidator validator;

  public CustomOidcProfileCreator(OidcConfiguration configuration) {
    super(configuration);
    validator = new OidcTokenValidator(configuration);
  }

  @Override
  public U create(OidcCredentials credentials, WebContext context) {
    init();

    final AccessToken accessToken = credentials.getAccessToken();
    final JWT idToken = credentials.getIdToken();

    final U profile = getProfileDefinition().newProfile();
    profile.setAccessToken(accessToken);
    profile.setIdTokenString(idToken.getParsedString());

    IDTokenClaimsSet claimsSet = validator.validateIdTokens(idToken, context);
    assertNotNull("claimsSet", claimsSet);
    profile.setId(ProfileHelper.sanitizeIdentifier(profile, claimsSet.getSubject()));

    final RefreshToken refreshToken = credentials.getRefreshToken();
    if (refreshToken != null && !refreshToken.getValue().isEmpty()) {
      profile.setRefreshToken(refreshToken);
      LOGGER.debug("Refresh Token successful retrieved");
    }

    try {
      if (configuration.findProviderMetadata().getUserInfoEndpointURI() != null
          && accessToken != null) {

        final UserInfoRequest userInfoRequest =
            new UserInfoRequest(
                configuration.findProviderMetadata().getUserInfoEndpointURI(),
                (BearerAccessToken) accessToken);
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
