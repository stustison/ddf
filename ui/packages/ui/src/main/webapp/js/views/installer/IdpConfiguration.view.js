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
  'templates/installer/idpConfigurationEntrySimple.handlebars',
  'templates/installer/idpConfigurationEntryBoolean.handlebars',
  'templates/installer/idpConfigurationEntryOptions.handlebars',
  'templates/installer/idpConfigurationEntryMultiple.handlebars',
  'templates/installer/deletableEntry.handlebars',
], function(
  Marionette,
  _,
  wreqr,
  $,
  idpConfigurationTemplate,
  idpConfigurationTable,
  idpConfigurationEntrySimple,
  idpConfigurationEntryBoolean,
  idpConfigurationEntryOptions,
  idpConfigurationEntryMultiple,
  deletableEntry
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

  function validateValue(type, value) {
    switch (type) {
      case INTEGER_TYPE:
        if (Number.isNaN(parseInt(value))) {
          return false
        }
        break
      case BOOLEAN_TYPE:
        if (
          value.toString().toLowerCase() !== 'true' &&
          value.toString().toLowerCase() !== 'false'
        ) {
          return false
        }
        break
      case STRING_TYPE:
        if (typeof value !== 'string') {
          return false
        }
        break
      default:
        break
    }

    return true
  }

  function validateValues(type, values) {
    if (!Array.isArray(values)) {
      return false
    }

    var isValid = true

    _.each(values, function(value) {
      if (!validateValue(type, value)) {
        isValid = false
      }
    })

    return isValid
  }

  var IdpConfigurationEntrySimple = Marionette.ItemView.extend({
    template: idpConfigurationEntrySimple,
    tagName: 'tr',
    className: 'table-entry',
    events: {
      'change .form-data': 'updateValue',
    },
    initialize: function(options) {
      this.name = options.name
      this.value = options.value
      if (typeof this.value === 'undefined') {
        this.value = (options.defaultValue || [])[0]
      }
      this.description = options.description
      this.id = options.id
      this.type = options.type
      this.cardinality = options.cardinality

      this.typeName = getTypeNameFromType(this.type)
      this.isValid = validateValue(this.type, this.value)
    },
    serializeData: function() {
      return {
        name: this.name,
        value: this.value,
        description: this.description,
        typeName: this.typeName,
      }
    },
    onRender: function() {
      this.errorElement = this.$el.find('.error-message')

      if (this.isValid) {
        this.hideError()
      } else {
        this.showError()
      }
    },
    updateValue: function(event) {
      this.value = event.currentTarget.value.toString()
      this.isValid = validateValue(this.type, this.value)

      wreqr.vent.trigger('idpConfigModified')

      if (this.isValid) {
        this.hideError()
      } else {
        this.showError()
      }
    },
    getConfig: function() {
      return {
        id: this.id,
        value: this.value,
      }
    },
    hideError: function() {
      this.errorElement[0].setAttribute('hidden', '')
    },
    showError: function() {
      this.errorElement[0].removeAttribute('hidden')
    },
    hasErrors: function() {
      return !this.isValid
    },
  })

  var IdpConfigurationEntryBoolean = Marionette.ItemView.extend({
    template: idpConfigurationEntryBoolean,
    tagName: 'tr',
    className: 'table-entry',
    events: {
      'change .form-data': 'updateValue',
    },
    initialize: function(options) {
      this.name = options.name
      this.value = options.value
      if (typeof this.value === 'undefined') {
        this.value = (options.defaultValue || [])[0]
      }
      this.description = options.description
      this.id = options.id
      this.cardinality = options.cardinality
      this.type = options.type

      this.typeName = getTypeNameFromType(this.type)
      this.isValid = validateValue(this.type, this.value)
      this.checked = this.value.toString().toLowerCase() === 'true'
    },
    serializeData: function() {
      return {
        name: this.name,
        description: this.description,
        checked: this.checked,
        typeName: this.typeName,
      }
    },
    onRender: function() {
      this.checkbox = this.$el.find('.form-data')
      this.errorElement = this.$el.find('.error-message')

      if (this.isValid) {
        this.hideError()
      } else {
        this.showError()
      }
    },
    updateValue: function(event) {
      this.value = event.currentTarget.checked.toString()
      this.isValid = validateValue(this.type, this.value)

      wreqr.vent.trigger('idpConfigModified')

      if (this.isValid) {
        this.hideError()
      } else {
        this.showError()
      }
    },
    getConfig: function() {
      return {
        id: this.id,
        value: this.value,
      }
    },
    hideError: function() {
      this.errorElement[0].setAttribute('hidden', '')
    },
    showError: function() {
      this.errorElement[0].removeAttribute('hidden')
    },
    hasErrors: function() {
      return !this.isValid
    },
  })

  var IdpConfigurationEntryOptions = Marionette.ItemView.extend({
    template: idpConfigurationEntryOptions,
    tagName: 'tr',
    className: 'table-entry',
    events: {
      'change .form-data': 'updateValue',
    },
    initialize: function(options) {
      this.name = options.name
      this.value = options.value
      if (typeof this.value === 'undefined') {
        this.value = (options.defaultValue || [])[0]
      }
      this.description = options.description
      this.id = options.id
      this.options = options.options

      this.optionElements = []
    },
    onRender: function() {
      this.dropdown = this.$el.find('.form-data')

      this.populateOptions()
      this.setDefaultOption()
    },
    populateOptions: function() {
      var self = this
      _.each(self.options, function(option) {
        var optionElement = self.el.ownerDocument.createElement('OPTION')
        optionElement.setAttribute('value', option.value)
        optionElement.innerText = option.label

        self.optionElements.push(optionElement)
        self.dropdown.append(optionElement)
      })
    },
    setDefaultOption: function() {
      var self = this
      _.each(self.optionElements, function(optionElement) {
        if (optionElement.getAttribute('value') === self.value) {
          optionElement.setAttribute('selected', '')
        }
      })
    },
    serializeData: function() {
      return {
        name: this.name,
        description: this.description,
      }
    },
    updateValue: function(event) {
      var updatedValue = event.currentTarget.value

      this.value = event.currentTarget.value
      wreqr.vent.trigger('idpConfigModified')
    },
    getConfig: function() {
      return {
        id: this.id,
        value: this.value,
      }
    },
    hasErrors: function() {
      return false // can only select values from given options
    },
  })

  var IdpConfigurationEntryMultiple = Marionette.ItemView.extend({
    template: idpConfigurationEntryMultiple,
    tagName: 'tr',
    className: 'table-entry',
    events: {
      'click .plus-button': 'addValue',
      'click .minus-button': 'removeValue',
      'change .form-data': 'updateValue',
    },
    initialize: function(options) {
      this.name = options.name
      this.values = options.value
      if (typeof this.values === 'undefined') {
        this.values = options.defaultValue
      }
      this.description = options.description
      this.id = options.id
      this.cardinality = options.cardinality
      this.type = options.type
      this.typeName = getTypeNameFromType(this.type)

      // wrap values in array if not already
      if (!Array.isArray(this.values)) {
        this.values = [this.values]
      }

      this.isValid = validateValues(this.type, this.values)
    },
    serializeData: function() {
      return {
        name: this.name,
        description: this.description,
      }
    },
    onRender: function() {
      this.entriesElement = this.$el.find('.entry-value-multiple-container')
      this.populateValues()
    },
    populateValues: function() {
      var self = this
      _.each(self.values, function(value) {
        self.addValue(value, true)
      })
    },
    addValue: function(value, isInitialization) {
      // default arguments
      value = value || ''
      isInitialization = isInitialization || false

      if (typeof value === 'object') {
        // if the given value is an event, set the new value to ''
        value = ''
      }

      var entry = new DeletableEntry({
        name: name,
        value: value,
        type: this.type,
      })
      entry.render()

      this.entriesElement[0].append(entry.el)

      if (!isInitialization) {
        this.values.push(value)
        wreqr.vent.trigger('idpConfigModified')
      }
    },
    updateValue: function(event) {
      var target = event.currentTarget
      var entry = target.parentElement
      var value = target.value
      var oldValue = target.getAttribute('oldValue')

      this.values[this.values.indexOf(oldValue)] = value

      target.setAttribute('oldValue', value)

      var isValid = validateValue(this.type, value)

      wreqr.vent.trigger('idpConfigModified')
    },
    removeValue: function(event) {
      var removeButton = event.currentTarget
      var entry = removeButton.parentElement
      var inputField = entry.firstChild
      var inputValue = inputField.value

      this.values.splice(this.values.indexOf(inputValue), 1)
      this.entriesElement[0].removeChild(entry)

      wreqr.vent.trigger('idpConfigModified')
    },
    getConfig: function() {
      return {
        id: this.id,
        value: this.values,
      }
    },
    hasErrors: function() {
      return !validateValues(this.type, this.values)
    },
  })

  var DeletableEntry = Marionette.ItemView.extend({
    template: deletableEntry,
    tagName: 'div',
    className: 'deletable-entry',
    events: {
      'change .form-data': 'checkAndSetValid',
    },
    initialize: function(options) {
      this.name = options.name
      this.value = options.value
      this.type = options.type

      this.typeName = getTypeNameFromType(this.type)
      this.isValid = validateValue(this.type, this.value)
    },
    serializeData: function() {
      return {
        value: this.value,
        typeName: this.typeName,
      }
    },
    onRender: function() {
      this.errorElement = this.$el.find('.error-message')

      if (this.isValid) {
        this.hideError()
      } else {
        this.showError()
      }
    },
    checkAndSetValid: function(event) {
      this.value = event.currentTarget.value
      this.isValid = validateValue(this.type, this.value)

      if (this.isValid) {
        this.hideError()
      } else {
        this.showError()
      }
    },
    hideError: function() {
      this.errorElement[0].setAttribute('hidden', '')
    },
    showError: function() {
      this.errorElement[0].removeAttribute('hidden')
    },
    hasErrors: function() {
      return !this.isValid
    },
  })

  var IdpConfigurationTable = Marionette.Layout.extend({
    template: idpConfigurationTable,
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

      var entryInfo = {
        name: name,
        value: value,
        defaultValue: defaultValue,
        description: description,
        id: id,
        options: options,
        cardinality: cardinality,
        type: type,
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

  var IdpConfigurationView = Marionette.Layout.extend({
    template: idpConfigurationTemplate,
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

  return IdpConfigurationView
})
