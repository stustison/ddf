/**
 * Copyright (c) Codice Foundation
 *
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 *
 **/

/* global define */
define([
  'backbone.marionette',
  'underscore',
  'js/wreqr.js',
  'jquery',
  'templates/installer/idpConfiguration.handlebars',
  'templates/installer/idpConfigurationTable.handlebars',
  'views/installer/IdpConfigurationEntrySimple.view.js',
  'views/installer/IdpConfigurationEntryBoolean.view.js',
  'views/installer/IdpConfigurationEntryOptions.view.js',
  'views/installer/IdpConfigurationEntryMultiple.view.js',
], function(
  Marionette,
  _,
  wreqr,
  $,
  viewTemplate,
  tableTemplate,
  IdpConfigurationEntrySimple,
  IdpConfigurationEntryBoolean,
  IdpConfigurationEntryOptions,
  IdpConfigurationEntryMultiple
) {
  var IDP_CLIENT_METATYPE_ID = 'org.codice.ddf.security.idp.client.IdpMetadata'
  var IDP_SERVER_METATYPE_ID = 'org.codice.ddf.security.idp.server.IdpEndpoint'
  var OIDC_HANDLER_METATYPE_ID =
    'org.codice.ddf.security.oidc.client.HandlerConfiguration'
  var OIDC_REALM_METATYPE_ID = 'org.codice.ddf.security.oidc.realm.OidcRealm'

  var STRING_TYPE = 1
  var INTEGER_TYPE = 3
  var BOOLEAN_TYPE = 11

  function getTypeNameFromType(type) {
    switch (type) {
      case STRING_TYPE:
        return 'String'
      case INTEGER_TYPE:
        return 'Integer'
      case BOOLEAN_TYPE:
        return 'Boolean'
    }
  }

  /* Displays different metatypes as IdpConfigurationTables */
  var IdpConfigurationView = Marionette.Layout.extend({
    template: viewTemplate,
    className: 'full-height idp-config-view',
    regions: {
      idpClientConfig: '#idp-client-config',
      idpServerConfig: '#idp-server-config',
      oidcHandlerConfig: '#oidc-handler-config',
      oidcRealmConfig: '#oidc-realm-config',
    },
    initialize: function(options) {
      this.idpMetatypes = options.idpMetatypes
      this.navigationModel = options.navigationModel
      this.navigationModel.set('hidePrevious', true)
      this.modified = false
      this.listenTo(this.navigationModel, 'next', this.next)
      this.listenTo(wreqr.vent, 'idpConfigModified', this.setModified)
    },
    onRender: function() {
      this.initConfigs()
    },
    initConfigs: function() {
      var self = this

      _.each(self.idpMetatypes, function(metatype) {
        switch (metatype.get('id')) {
          case IDP_CLIENT_METATYPE_ID:
            self.showRegion(self.idpClientConfig, metatype)
            break
          case IDP_SERVER_METATYPE_ID:
            self.showRegion(self.idpServerConfig, metatype)
            break
          case OIDC_HANDLER_METATYPE_ID:
            self.showRegion(self.oidcHandlerConfig, metatype)
            break
          case OIDC_REALM_METATYPE_ID:
            self.showRegion(self.oidcRealmConfig, metatype)
            break
          default:
            break
        }
      })
    },
    showRegion: function(region, metatype) {
      if (region.currentView) {
        region.show()
      } else {
        region.show(
          new IdpConfigurationTable({
            metatype: metatype,
          })
        )
      }
    },
    setModified: function() {
      this.modified = true
    },
    next: function(event) {
      if (this.hasErrors()) {
        this.navigationModel.nextStep(
          'There is an error in one or more field(s). Please correct and try again.',
          0
        )
        return
      }

      if (this.modified) {
        this.persistConfig()
      }

      this.navigationModel.set('modified', this.modified)
      this.navigationModel.nextStep('', 100)
    },
    persistConfig: function() {
      var config = this.getConfig()

      var data = {
        type: 'WRITE',
        mbean:
          'org.codice.ddf.ui.admin.api.ConfigurationAdmin:service=ui,version=2.3.0',
        attribute: 'IdpConfigurations',
        value: config,
      }

      $.ajax({
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(data),
        url:
          './jolokia/exec/org.codice.ddf.ui.admin.api.ConfigurationAdmin:service=ui,version=2.3.0',
        success: function() {
          wreqr.vent.trigger('idpConfigPersisted')
        },
      })
    },
    getConfig: function() {
      return [
        this.idpClientConfig.currentView.getConfig(),
        this.idpServerConfig.currentView.getConfig(),
        this.oidcHandlerConfig.currentView.getConfig(),
        this.oidcRealmConfig.currentView.getConfig(),
      ]
    },
    hasErrors: function() {
      return (
        this.idpClientConfig.currentView.hasErrors() ||
        this.idpServerConfig.currentView.hasErrors() ||
        this.oidcHandlerConfig.currentView.hasErrors() ||
        this.oidcRealmConfig.currentView.hasErrors()
      )
    },
    onClose: function() {
      this.stopListening(this.navigationModel)
    },
  })

  /* Displays all the different metatype entries (Simple, Boolean, Options, Multiple) in a metatype */
  var IdpConfigurationTable = Marionette.Layout.extend({
    template: tableTemplate,
    tagName: 'table',
    className: 'idp-config-table',
    initialize: function(options) {
      this.metatype = options.metatype
      this.metatypeName = this.metatype.get('name')
      this.metatypeId = this.metatype.get('id')

      this.idpConfigurationEntries = []
    },
    serializeData: function() {
      return {
        metatypeName: this.metatypeName,
        metatypeId: this.metatypeId,
      }
    },
    onRender: function() {
      this.tableBody = this.$el.find('.table-body')

      this.populateTable()
    },
    populateTable: function() {
      // gathers the values for the metatype entries
      var metatypeValues =
        (
          (
            (
              ((this.metatype.attributes.configurations || {}).models ||
                [])[0] || {}
            ).attributes || {}
          ).properties || {}
        ).attributes || {}

      var self = this

      _.each(self.metatype.get('metatype').models, function(metatypeEntry) {
        var tableEntry = self.createIdpConfigurationEntry(
          metatypeEntry,
          metatypeValues
        )

        tableEntry.render()

        self.idpConfigurationEntries.push(tableEntry)

        self.tableBody.append(tableEntry.el)
      })
    },
    createIdpConfigurationEntry: function(metatypeEntry, metatypeValues) {
      var name = metatypeEntry.get('name')
      var id = metatypeEntry.get('id')
      var value = metatypeValues[id]
      var defaultValue = metatypeEntry.get('defaultValue')
      var description = metatypeEntry.get('description')
      var options = metatypeEntry.get('options')
      var cardinality = metatypeEntry.get('cardinality')
      var type = metatypeEntry.get('type')
      var typeName = getTypeNameFromType(type)

      var entryInfo = {
        name: name,
        value: value,
        defaultValue: defaultValue,
        description: description,
        id: id,
        options: options,
        cardinality: cardinality,
        type: type,
        typeName: typeName,
      }

      if (!_.isEmpty(options)) {
        return new IdpConfigurationEntryOptions(entryInfo)
      }

      if (type === BOOLEAN_TYPE) {
        return new IdpConfigurationEntryBoolean(entryInfo)
      }

      if (cardinality !== 0) {
        return new IdpConfigurationEntryMultiple(entryInfo)
      }

      return new IdpConfigurationEntrySimple(entryInfo)
    },
    getConfig: function() {
      var result = {
        metatypeName: this.metatypeName,
        metatypeId: this.metatypeId,
        metatypeEntries: [],
      }
      _.each(this.idpConfigurationEntries, function(idpConfigurationEntry) {
        result.metatypeEntries.push(idpConfigurationEntry.getConfig())
      })

      return result
    },
    hasErrors: function() {
      var hasErrors = false

      _.each(this.idpConfigurationEntries, function(idpConfigurationEntry) {
        if (idpConfigurationEntry.hasErrors()) {
          hasErrors = true
        }
      })

      return hasErrors
    },
  })

  return IdpConfigurationView
})
