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

import ddf.security.assertion.SecurityAssertion;
import ddf.security.assertion.jwt.impl.SecurityAssertionJwt;
import java.security.Principal;
import java.util.List;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.codice.ddf.security.handler.api.OidcAuthenticationToken;
import org.codice.ddf.security.handler.api.OidcHandlerConfiguration;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.exception.TechnicalException;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.credentials.authenticator.OidcAuthenticator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidcRealm extends AuthenticatingRealm {

  private static final Logger LOGGER = LoggerFactory.getLogger(OidcRealm.class);

  private List<String> usernameAttributeList;
  private OidcHandlerConfiguration oidcHandlerConfiguration;

  /** Determine if the supplied token is supported by this realm. */
  @Override
  public boolean supports(AuthenticationToken authenticationToken) {
    if (!(authenticationToken instanceof OidcAuthenticationToken)) {
      LOGGER.debug("The supplied authentication token is null. Sending back not supported.");
      return false;
    }

    OidcAuthenticationToken oidcAuthenticationToken = (OidcAuthenticationToken) authenticationToken;
    PrincipalCollection principals = (PrincipalCollection) oidcAuthenticationToken.getCredentials();

    if (principals == null) {
      LOGGER.warn(
          "The supplied authentication token has null principal collection."
              + " Sending back not supported.");
      return false;
    }

    OidcCredentials credentials =
        (OidcCredentials)
            principals
                .byType(SecurityAssertion.class)
                .stream()
                .filter(sa -> SecurityAssertionJwt.JWT_TOKEN_TYPE.equals(sa.getTokenType()))
                .map(SecurityAssertion::getToken)
                .findFirst()
                .orElse(null);

    if (credentials == null
        || (credentials.getCode() == null
            && credentials.getAccessToken() == null
            && credentials.getIdToken() == null)) {
      LOGGER.warn(
          "The supplied authentication token has null/empty credentials. Sending back no supported.");
      return false;
    }

    WebContext webContext = oidcAuthenticationToken.getWebContext();
    if (webContext == null) {
      LOGGER.warn(
          "The supplied authentication token has null web context. Sending back not supported.");
      return false;
    }

    LOGGER.debug(
        "Token {} is supported by {}.", authenticationToken.getClass(), OidcRealm.class.getName());
    return true;
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
      throws AuthenticationException {
    // the following variables are guaranteed to be non-null by the supports() method.
    OidcAuthenticationToken oidcAuthenticationToken = (OidcAuthenticationToken) authenticationToken;
    PrincipalCollection principals = (PrincipalCollection) oidcAuthenticationToken.getCredentials();
    OidcCredentials credentials =
        (OidcCredentials)
            principals
                .byType(SecurityAssertion.class)
                .stream()
                .filter(sa -> SecurityAssertionJwt.JWT_TOKEN_TYPE.equals(sa.getTokenType()))
                .map(SecurityAssertion::getToken)
                .findFirst()
                .orElse(null);
    WebContext webContext = oidcAuthenticationToken.getWebContext();

    if (credentials.getIdToken() == null) {
      try {
        OidcAuthenticator authenticator =
            new CustomOidcAuthenticator(
                oidcHandlerConfiguration.getOidcConfiguration(),
                oidcHandlerConfiguration.getOidcClient());
        authenticator.validate(credentials, webContext);
      } catch (TechnicalException e) {
        LOGGER.debug(
            "Problem fetching id token with credentials ({}) and web context ({}).",
            credentials,
            webContext);
      }
    }

    // problem getting id token, invalidate credentials
    if (credentials.getIdToken() == null) {
      webContext.getSessionStore().destroySession(webContext);

      String msg =
          String.format(
              "Could not fetch id token with Oidc credentials (%s). "
                  + "This may be due to the credentials expiring. "
                  + "Invalidating session in order to acquire valid credentials.",
              credentials);

      LOGGER.warn(msg);
      throw new AuthenticationException(msg);
    }

    SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo();
    SimplePrincipalCollection principalCollection = createPrincipalCollectionFromJwt(credentials);
    simpleAuthenticationInfo.setPrincipals(principals);
    simpleAuthenticationInfo.setCredentials(credentials);

    return simpleAuthenticationInfo;
  }

  private SimplePrincipalCollection createPrincipalCollectionFromJwt(OidcCredentials credentials) {
    SimplePrincipalCollection principals = new SimplePrincipalCollection();
    SecurityAssertion securityAssertion = null;
    try {
      securityAssertion = new SecurityAssertionJwt(credentials, usernameAttributeList);
      Principal principal = securityAssertion.getPrincipal();
      if (principal != null) {
        principals.add(principal.getName(), getName());
      }
    } catch (Exception e) {
      LOGGER.warn(
          "Encountered error while trying to get the Principal for the SecurityToken. Security functions may not work properly.",
          e);
    }
    if (securityAssertion != null) {
      principals.add(securityAssertion, getName());
    }
    return principals;
  }

  public List<String> getUsernameAttributeList() {
    return usernameAttributeList;
  }

  public void setUsernameAttributeList(List<String> usernameAttributeList) {
    this.usernameAttributeList = usernameAttributeList;
  }

  public void setOidcHandlerConfiguration(OidcHandlerConfiguration oidcHandlerConfiguration) {
    this.oidcHandlerConfiguration = oidcHandlerConfiguration;
  }
}
