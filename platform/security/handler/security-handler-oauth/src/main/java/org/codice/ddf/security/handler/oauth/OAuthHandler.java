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

import static org.apache.commons.lang.StringUtils.isNotBlank;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.jwt.impl.SecurityAssertionJwt;
import ddf.security.common.SecurityTokenHolder;
import ddf.security.http.SessionFactory;
import java.io.IOException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.shiro.subject.PrincipalCollection;
import org.codice.ddf.platform.filter.AuthenticationFailureException;
import org.codice.ddf.platform.filter.FilterChain;
import org.codice.ddf.security.handler.api.AuthenticationHandler;
import org.codice.ddf.security.handler.api.HandlerResult;
import org.codice.ddf.security.handler.api.HandlerResult.Status;
import org.codice.ddf.security.handler.api.OidcAuthenticationToken;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.context.session.J2ESessionStore;
import org.pac4j.oauth.credentials.OAuth20Credentials;
import org.pac4j.oauth.credentials.extractor.OAuth20CredentialsExtractor;
import org.pac4j.oauth.exception.OAuthCredentialsException;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthHandler implements AuthenticationHandler {
  private static final Logger LOGGER = LoggerFactory.getLogger(OAuthHandler.class);

  private static final String SOURCE = "OAuthHandler";
  private static final String AUTH_TYPE = "OAUTH";

  private static HandlerResult noActionResult;

  static {
    noActionResult = new HandlerResult(Status.NO_ACTION, null);
    noActionResult.setSource(SOURCE);
  }

  private OAuthHandlerConfigurationImpl configuration;
  private SessionFactory sessionFactory;

  public OAuthHandler(OAuthHandlerConfigurationImpl configuration) {
    this.configuration = configuration;
  }

  @Override
  public String getAuthenticationType() {
    return AUTH_TYPE;
  }

  @Override
  public HandlerResult getNormalizedToken(
      ServletRequest request, ServletResponse response, FilterChain chain, boolean resolve)
      throws AuthenticationFailureException {

    HttpServletRequest httpRequest = (HttpServletRequest) request;
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    if (httpRequest.getMethod().equals("HEAD")) {
      return processHeadRequest(httpResponse);
    }

    HttpSession session = getOrCreateSessionOnRequest(httpRequest);
    if (session == null) {
      LOGGER.error("Unable to get/create session off of incoming request. Cannot continue.");
      return noActionResult;
    }
    SecurityTokenHolder tokenHolder = getOrCreateTokenHolderOnSession(session);
    if (tokenHolder == null) {
      LOGGER.error("Unable to get/create token holder off of session. Cannot continue.");
      return noActionResult;
    }

    J2ESessionStore sessionStore = new J2ESessionStore();
    J2EContext j2EContext = new J2EContext(httpRequest, httpResponse, sessionStore);

    // credentials exist on session
    if (tokenHolder.getPrincipals() != null
        && tokenHolder.getPrincipals() instanceof PrincipalCollection) {
      return getCredentialsFromTokenHolder(tokenHolder, session, j2EContext);
    }

    // at this point, the OAuth Handler must be configured
    if (!configuration.isInitialized()) {
      LOGGER.error(
          "The OAuth Handler's configuration has not been initialized. "
              + "Configure \"OAuth Handler Configuration\" in the admin console to initialize.");
      return noActionResult;
    }

    // time to try and pull credentials off of the request
    LOGGER.debug(
        "Doing OAuth authentication and authorization for path {}.", httpRequest.getContextPath());

    OidcCredentials credentials;

    StringBuffer requestUrlBuffer = httpRequest.getRequestURL();
    requestUrlBuffer.append(
        httpRequest.getQueryString() == null ? "" : "?" + httpRequest.getQueryString());
    String requestUrl = requestUrlBuffer.toString();
    String ipAddress = httpRequest.getRemoteAddr();

    configuration.getOAuthClient().setCallbackUrl(requestUrl);

    boolean isMachine = userAgentIsNotBrowser(httpRequest);

    // machine to machine, check for Client Credentials Flow credentials
    if (isMachine) {
      try {
        credentials = getCredentialFlowCredentials(j2EContext);
      } catch (IllegalArgumentException e) {
        LOGGER.error(
            "Problem with the OAuth Handler's OAuthHandlerConfiguration. "
                + "Check the OAuth Handler Configuration in the admin console.",
            e);
        return noActionResult;
      } catch (OAuthCredentialsException e) {
        LOGGER.error(
            "Problem extracting credentials from machine to machine request. "
                + "See OAuth2's \"Client Credential Flow\" for more information.",
            e);
        return noActionResult;
      }
    } else {
      LOGGER.info(
          "The OAuth Handler does not handle user agent requests. Continuing to other handlers.");
      return noActionResult;
    }

    // if the request has credentials, process it
    if (credentials.getCode() != null
        || credentials.getAccessToken() != null
        || credentials.getIdToken() != null) {
      LOGGER.info(
          "Oidc credentials found/retrieved. Saving to session and continuing filter chain.");

      OidcAuthenticationToken token =
          new OidcAuthenticationToken(credentials, j2EContext, ipAddress);

      HandlerResult handlerResult = new HandlerResult(Status.COMPLETED, token);
      handlerResult.setSource(SOURCE);
      return handlerResult;
    } else {
      LOGGER.info(
          "No credentials found on user-agent request. "
              + "This handler does not support the acquisition of user agent credentials. Continuing to other handlers.");
      return noActionResult;
    }
  }

  @Override
  public HandlerResult handleError(
      ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) {
    LOGGER.debug("In error handler for OAuth - no action taken.");
    return noActionResult;
  }

  private HandlerResult processHeadRequest(HttpServletResponse httpResponse)
      throws AuthenticationFailureException {
    httpResponse.setStatus(HttpServletResponse.SC_OK);
    try {
      httpResponse.flushBuffer();
    } catch (IOException e) {
      throw new AuthenticationFailureException(
          "Unable to send response to HEAD message from OAUTH client.");
    }
    return noActionResult;
  }

  private HandlerResult getCredentialsFromTokenHolder(
      SecurityTokenHolder tokenHolder, HttpSession session, J2EContext j2EContext) {
    // guaranteed non null PrincipalCollection by calling code
    PrincipalCollection principals = (PrincipalCollection) tokenHolder.getPrincipals();

    OidcCredentials credentials =
        (OidcCredentials)
            principals
                .byType(SecurityAssertion.class)
                .stream()
                .filter(sa -> SecurityAssertionJwt.JWT_TOKEN_TYPE.equals(sa.getTokenType()))
                .map(SecurityAssertion::getToken)
                .findFirst()
                .orElse(null);

    if (credentials == null) {
      LOGGER.debug(
          "No Oidc Credentials found in token holder principals. Continuing to other handlers.");
      return noActionResult;
    }

    if ((credentials.getCode() == null
        && credentials.getAccessToken() == null
        && credentials.getIdToken() == null)) {
      LOGGER.error(
          "Invalid Oidc Credentials found in token holder principals, invalidating session and continuing to other handlers.",
          credentials);
      session.invalidate();
      return noActionResult;
    }

    OidcAuthenticationToken token =
        new OidcAuthenticationToken(credentials, j2EContext, j2EContext.getRemoteAddr());

    HandlerResult handlerResult = new HandlerResult(Status.COMPLETED, token);
    handlerResult.setSource(SOURCE);
    return handlerResult;
  }

  private boolean userAgentIsNotBrowser(HttpServletRequest httpRequest) {
    String userAgentHeader = httpRequest.getHeader("User-Agent");
    // basically all browsers support the "Mozilla" way of operating, so they all have "Mozilla"
    // in the string. I just added the rest in case that ever changes for existing browsers.
    // New browsers should contain "Mozilla" as well, though.
    return userAgentHeader == null
        || !(userAgentHeader.contains("Mozilla")
            || userAgentHeader.contains("Safari")
            || userAgentHeader.contains("OPR")
            || userAgentHeader.contains("MSIE")
            || userAgentHeader.contains("Edge")
            || userAgentHeader.contains("Chrome"));
  }

  private OidcCredentials getCredentialFlowCredentials(J2EContext j2EContext)
      throws IllegalArgumentException, OAuthCredentialsException {
    OAuth20CredentialsExtractor credentialsExtractor =
        new CustomOAuthCredentialsExtractor(
            configuration.getOAuthConfiguration(), configuration.getOAuthClient());

    OAuth20Credentials oAuthCredentials = credentialsExtractor.extract(j2EContext);

    OidcCredentials oidcCredentials = new OidcCredentials();

    if (oAuthCredentials.getAccessToken() != null
        && isNotBlank(oAuthCredentials.getAccessToken().getAccessToken())) {
      oidcCredentials.setAccessToken(
          new BearerAccessToken(oAuthCredentials.getAccessToken().getAccessToken()));
    }
    if (isNotBlank(oAuthCredentials.getCode())) {
      oidcCredentials.setCode(new AuthorizationCode(oAuthCredentials.getCode()));
    }

    return oidcCredentials;
  }

  private HttpSession getOrCreateSessionOnRequest(HttpServletRequest httpRequest) {
    HttpSession session = httpRequest.getSession(false);
    if (session == null) {
      session = sessionFactory.getOrCreateSession(httpRequest);
    }
    return session;
  }

  private SecurityTokenHolder getOrCreateTokenHolderOnSession(HttpSession session) {
    SecurityTokenHolder tokenHolder =
        ((SecurityTokenHolder)
            session.getAttribute(ddf.security.SecurityConstants.SECURITY_TOKEN_KEY));
    if (tokenHolder == null) {
      tokenHolder = new SecurityTokenHolder();
      session.setAttribute(ddf.security.SecurityConstants.SECURITY_TOKEN_KEY, tokenHolder);
    }
    return tokenHolder;
  }

  // hack

  public void setSessionFactory(SessionFactory sessionFactory) {
    this.sessionFactory = sessionFactory;
  }
}
