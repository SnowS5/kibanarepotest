"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.initialWazuhConfig = exports.hostsConfiguration = exports.header = void 0;
exports.printSection = printSection;
exports.printSetting = printSetting;
exports.printSettingCategory = printSettingCategory;
exports.printSettingValue = printSettingValue;
exports.splitDescription = splitDescription;

var _constants = require("../../common/constants");

var _settings = require("../../common/services/settings");

var _web_documentation = require("../../common/services/web_documentation");

/*
 * Wazuh app - App configuration file
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const header = `---
#
# Wazuh app - App configuration file
# Copyright (C) 2015-2022 Wazuh, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Find more information about this on the LICENSE file.
#
${printSection('Wazuh app configuration file', {
  prefix: '# ',
  fill: '='
})}
#
# Please check the documentation for more information about configuration options:
# ${(0, _web_documentation.webDocumentationLink)('user-manual/wazuh-dashboard/config-file.html')}
#
# Also, you can check our repository:
# https://github.com/wazuh/wazuh-kibana-app`;
exports.header = header;
const pluginSettingsConfigurationFile = (0, _settings.getSettingsDefaultList)().filter(({
  isConfigurableFromFile
}) => isConfigurableFromFile);
const pluginSettingsConfigurationFileGroupByCategory = (0, _settings.groupSettingsByCategory)(pluginSettingsConfigurationFile);
const pluginSettingsConfiguration = pluginSettingsConfigurationFileGroupByCategory.map(({
  category: categoryID,
  settings
}) => {
  const category = printSettingCategory(_constants.PLUGIN_SETTINGS_CATEGORIES[categoryID]);
  const pluginSettingsOfCategory = settings.map(setting => printSetting(setting)).join('\n#\n');
  /*
  #------------------- {category name} --------------
  #
  #  {category description}
  #
  # {setting description}
  # settingKey: settingDefaultValue
  #
  # {setting description}
  # settingKey: settingDefaultValue
  # ...
  */

  return [category, pluginSettingsOfCategory].join('\n#\n');
}).join('\n#\n');

function printSettingValue(value) {
  if (typeof value === 'object') {
    return JSON.stringify(value);
  }

  ;

  if (typeof value === 'string' && value.length === 0) {
    return `''`;
  }

  ;
  return value;
}

;

function printSetting(setting) {
  /*
  # {setting description}
  # {settingKey}: {settingDefaultValue}
  */
  return [splitDescription((0, _settings.getPluginSettingDescription)(setting)), `# ${setting.key}: ${printSettingValue(setting.defaultValue)}`].join('\n');
}

function printSettingCategory({
  title,
  description
}) {
  /*
  #------------------------------- {category title} -------------------------------
  # {category description}
  #
  */
  return [printSection(title, {
    prefix: '# ',
    fill: '-'
  }), ...(description ? [splitDescription(description)] : [''])].join('\n#\n');
}

;

function printSection(text, options) {
  var _options$maxLength, _options$prefix, _options$suffix, _options$spaceAround, _options$fill;

  const maxLength = (_options$maxLength = options === null || options === void 0 ? void 0 : options.maxLength) !== null && _options$maxLength !== void 0 ? _options$maxLength : 80;
  const prefix = (_options$prefix = options === null || options === void 0 ? void 0 : options.prefix) !== null && _options$prefix !== void 0 ? _options$prefix : '';
  const sufix = (_options$suffix = options === null || options === void 0 ? void 0 : options.suffix) !== null && _options$suffix !== void 0 ? _options$suffix : '';
  const spaceAround = (_options$spaceAround = options === null || options === void 0 ? void 0 : options.spaceAround) !== null && _options$spaceAround !== void 0 ? _options$spaceAround : 1;
  const fill = (_options$fill = options === null || options === void 0 ? void 0 : options.fill) !== null && _options$fill !== void 0 ? _options$fill : ' ';
  const fillLength = maxLength - prefix.length - sufix.length - 2 * spaceAround - text.length;
  return [prefix, fill.repeat(Math.floor(fillLength / 2)), ` ${text} `, fill.repeat(Math.ceil(fillLength / 2)), sufix].join('');
}

;
const hostsConfiguration = `${printSection('Wazuh hosts', {
  prefix: '# ',
  fill: '-'
})}
#
# The following configuration is the default structure to define a host.
#
# hosts:
#   # Host ID / name,
#   - env-1:
#       # Host URL
#       url: https://env-1.example
#       # Host / API port
#       port: 55000
#       # Host / API username
#       username: wazuh-wui
#       # Host / API password
#       password: wazuh-wui
#       # Use RBAC or not. If set to true, the username must be "wazuh-wui".
#       run_as: true
#   - env-2:
#       url: https://env-2.example
#       port: 55000
#       username: wazuh-wui
#       password: wazuh-wui
#       run_as: true

hosts:
  - default:
      url: https://localhost
      port: 55000
      username: wazuh-wui
      password: wazuh-wui
      run_as: false
`;
/**
 * Given a string, this function builds a multine string, each line about 70
 * characters long, splitted at the closest whitespace character to that lentgh.
 *
 * This function is used to transform the settings description
 * into a multiline string to be used as the setting documentation.
 *
 * The # character is also appended to the beginning of each line.
 *
 * @param text
 * @returns multine string
 */

exports.hostsConfiguration = hostsConfiguration;

function splitDescription(text = '') {
  const lines = text.match(/.{1,80}(?=\s|$)/g) || [];
  return lines.map(z => '# ' + z.trim()).join('\n');
}

const initialWazuhConfig = [header, pluginSettingsConfiguration, hostsConfiguration].join('\n#\n');
exports.initialWazuhConfig = initialWazuhConfig;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluaXRpYWwtd2F6dWgtY29uZmlnLnRzIl0sIm5hbWVzIjpbImhlYWRlciIsInByaW50U2VjdGlvbiIsInByZWZpeCIsImZpbGwiLCJwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYXRpb25GaWxlIiwiZmlsdGVyIiwiaXNDb25maWd1cmFibGVGcm9tRmlsZSIsInBsdWdpblNldHRpbmdzQ29uZmlndXJhdGlvbkZpbGVHcm91cEJ5Q2F0ZWdvcnkiLCJwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYXRpb24iLCJtYXAiLCJjYXRlZ29yeSIsImNhdGVnb3J5SUQiLCJzZXR0aW5ncyIsInByaW50U2V0dGluZ0NhdGVnb3J5IiwiUExVR0lOX1NFVFRJTkdTX0NBVEVHT1JJRVMiLCJwbHVnaW5TZXR0aW5nc09mQ2F0ZWdvcnkiLCJzZXR0aW5nIiwicHJpbnRTZXR0aW5nIiwiam9pbiIsInByaW50U2V0dGluZ1ZhbHVlIiwidmFsdWUiLCJKU09OIiwic3RyaW5naWZ5IiwibGVuZ3RoIiwic3BsaXREZXNjcmlwdGlvbiIsImtleSIsImRlZmF1bHRWYWx1ZSIsInRpdGxlIiwiZGVzY3JpcHRpb24iLCJ0ZXh0Iiwib3B0aW9ucyIsIm1heExlbmd0aCIsInN1Zml4Iiwic3VmZml4Iiwic3BhY2VBcm91bmQiLCJmaWxsTGVuZ3RoIiwicmVwZWF0IiwiTWF0aCIsImZsb29yIiwiY2VpbCIsImhvc3RzQ29uZmlndXJhdGlvbiIsImxpbmVzIiwibWF0Y2giLCJ6IiwidHJpbSIsImluaXRpYWxXYXp1aENvbmZpZyJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7O0FBWUE7O0FBSUE7O0FBQ0E7O0FBakJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFTTyxNQUFNQSxNQUFjLEdBQUk7QUFDL0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEVBQUVDLFlBQVksQ0FBQyw4QkFBRCxFQUFpQztB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R0FBRyxFQUF6QyxFQUFxRDtBQUMxRCxRQUFNWSxLQUFLLEdBQUdaLElBQUksQ0FBQ2EsS0FBTCxDQUFXLGtCQUFYLEtBQWtDLEVBQWhEO0FBQ0EsU0FBT0QsS0FBSyxDQUFDaEMsR0FBTixDQUFXa0MsQ0FBRCxJQUFPLE9BQU9BLENBQUMsQ0FBQ0MsSUFBRixFQUF4QixFQUFrQzFCLElBQWxDLENBQXVDLElBQXZDLENBQVA7QUFDRDs7QUFFTSxNQUFNMkIsa0JBQTBCLEdBQUcsQ0FBQzdDLE1BQUQsRUFBU1EsMkJBQVQsRUFBc0NnQyxrQkFBdEMsRUFBMER0QixJQUExRCxDQUErRCxPQUEvRCxDQUFuQyIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBBcHAgY29uZmlndXJhdGlvbiBmaWxlXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG5pbXBvcnQge1xuICBQTFVHSU5fU0VUVElOR1NfQ0FURUdPUklFUyxcbiAgVFBsdWdpblNldHRpbmdXaXRoS2V5LFxufSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJztcbmltcG9ydCB7IGdldFBsdWdpblNldHRpbmdEZXNjcmlwdGlvbiwgZ2V0U2V0dGluZ3NEZWZhdWx0TGlzdCwgZ3JvdXBTZXR0aW5nc0J5Q2F0ZWdvcnkgfSBmcm9tICcuLi8uLi9jb21tb24vc2VydmljZXMvc2V0dGluZ3MnO1xuaW1wb3J0IHsgd2ViRG9jdW1lbnRhdGlvbkxpbmsgfSBmcm9tICcuLi8uLi9jb21tb24vc2VydmljZXMvd2ViX2RvY3VtZW50YXRpb24nO1xuXG5leHBvcnQgY29uc3QgaGVhZGVyOiBzdHJpbmcgPSBgLS0tXG4jXG4jIFdhenVoIGFwcCAtIEFwcCBjb25maWd1cmF0aW9uIGZpbGVcbiMgQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiNcbiMgVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiMgaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiMgdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiMgKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiNcbiMgRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiNcbiR7cHJpbnRTZWN0aW9uKCdXYXp1aCBhcHAgY29uZmlndXJhdGlvbiBmaWxlJywge3ByZWZpeDogJyMgJywgZmlsbDogJz0nfSl9XG4jXG4jIFBsZWFzZSBjaGVjayB0aGUgZG9jdW1lbnRhdGlvbiBmb3IgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCBjb25maWd1cmF0aW9uIG9wdGlvbnM6XG4jICR7d2ViRG9jdW1lbnRhdGlvbkxpbmsoJ3VzZXItbWFudWFsL3dhenVoLWRhc2hib2FyZC9jb25maWctZmlsZS5odG1sJyl9XG4jXG4jIEFsc28sIHlvdSBjYW4gY2hlY2sgb3VyIHJlcG9zaXRvcnk6XG4jIGh0dHBzOi8vZ2l0aHViLmNvbS93YXp1aC93YXp1aC1raWJhbmEtYXBwYDtcblxuY29uc3QgcGx1Z2luU2V0dGluZ3NDb25maWd1cmF0aW9uRmlsZSA9IGdldFNldHRpbmdzRGVmYXVsdExpc3QoKS5maWx0ZXIoKHtpc0NvbmZpZ3VyYWJsZUZyb21GaWxlfSkgPT4gaXNDb25maWd1cmFibGVGcm9tRmlsZSk7XG5cbmNvbnN0IHBsdWdpblNldHRpbmdzQ29uZmlndXJhdGlvbkZpbGVHcm91cEJ5Q2F0ZWdvcnkgPSBncm91cFNldHRpbmdzQnlDYXRlZ29yeShwbHVnaW5TZXR0aW5nc0NvbmZpZ3VyYXRpb25GaWxlKTtcblxuY29uc3QgcGx1Z2luU2V0dGluZ3NDb25maWd1cmF0aW9uID0gcGx1Z2luU2V0dGluZ3NDb25maWd1cmF0aW9uRmlsZUdyb3VwQnlDYXRlZ29yeS5tYXAoKHtjYXRlZ29yeTogY2F0ZWdvcnlJRCwgc2V0dGluZ3N9KSA9PiB7XG4gIGNvbnN0IGNhdGVnb3J5ID0gcHJpbnRTZXR0aW5nQ2F0ZWdvcnkoUExVR0lOX1NFVFRJTkdTX0NBVEVHT1JJRVNbY2F0ZWdvcnlJRF0pO1xuXG4gIGNvbnN0IHBsdWdpblNldHRpbmdzT2ZDYXRlZ29yeSA9IHNldHRpbmdzXG4gICAgLm1hcChzZXR0aW5nID0+IHByaW50U2V0dGluZyhzZXR0aW5nKVxuICAgICkuam9pbignXFxuI1xcbicpO1xuICAvKlxuICAjLS0tLS0tLS0tLS0tLS0tLS0tLSB7Y2F0ZWdvcnkgbmFtZX0gLS0tLS0tLS0tLS0tLS1cbiAgI1xuICAjICB7Y2F0ZWdvcnkgZGVzY3JpcHRpb259XG4gICNcbiAgIyB7c2V0dGluZyBkZXNjcmlwdGlvbn1cbiAgIyBzZXR0aW5nS2V5OiBzZXR0aW5nRGVmYXVsdFZhbHVlXG4gICNcbiAgIyB7c2V0dGluZyBkZXNjcmlwdGlvbn1cbiAgIyBzZXR0aW5nS2V5OiBzZXR0aW5nRGVmYXVsdFZhbHVlXG4gICMgLi4uXG4gICovXG4gIHJldHVybiBbY2F0ZWdvcnksIHBsdWdpblNldHRpbmdzT2ZDYXRlZ29yeV0uam9pbignXFxuI1xcbicpO1xufSkuam9pbignXFxuI1xcbicpO1xuXG5cbmV4cG9ydCBmdW5jdGlvbiBwcmludFNldHRpbmdWYWx1ZSh2YWx1ZTogdW5rbm93bik6IGFueXtcbiAgaWYodHlwZW9mIHZhbHVlID09PSAnb2JqZWN0Jyl7XG4gICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHZhbHVlKVxuICB9O1xuXG4gIGlmKHR5cGVvZiB2YWx1ZSA9PT0gJ3N0cmluZycgJiYgdmFsdWUubGVuZ3RoID09PSAwKXtcbiAgICByZXR1cm4gYCcnYFxuICB9O1xuXG4gIHJldHVybiB2YWx1ZTtcbn07XG5cbmV4cG9ydCBmdW5jdGlvbiBwcmludFNldHRpbmcoc2V0dGluZzogVFBsdWdpblNldHRpbmdXaXRoS2V5KTogc3RyaW5ne1xuICAvKlxuICAjIHtzZXR0aW5nIGRlc2NyaXB0aW9ufVxuICAjIHtzZXR0aW5nS2V5fToge3NldHRpbmdEZWZhdWx0VmFsdWV9XG4gICovXG4gIHJldHVybiBbXG4gICAgc3BsaXREZXNjcmlwdGlvbihnZXRQbHVnaW5TZXR0aW5nRGVzY3JpcHRpb24oc2V0dGluZykpLFxuICAgIGAjICR7c2V0dGluZy5rZXl9OiAke3ByaW50U2V0dGluZ1ZhbHVlKHNldHRpbmcuZGVmYXVsdFZhbHVlKX1gXG4gIF0uam9pbignXFxuJylcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHByaW50U2V0dGluZ0NhdGVnb3J5KHt0aXRsZSwgZGVzY3JpcHRpb259KXtcbiAgLypcbiAgIy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0ge2NhdGVnb3J5IHRpdGxlfSAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4gICMge2NhdGVnb3J5IGRlc2NyaXB0aW9ufVxuICAjXG4gICovXG4gIHJldHVybiBbXG4gICAgcHJpbnRTZWN0aW9uKHRpdGxlLCB7cHJlZml4OiAnIyAnLCBmaWxsOiAnLSd9KSxcbiAgICAuLi4oZGVzY3JpcHRpb24gPyBbc3BsaXREZXNjcmlwdGlvbihkZXNjcmlwdGlvbildIDogWycnXSlcbiAgXS5qb2luKCdcXG4jXFxuJylcbn07XG5cbmV4cG9ydCBmdW5jdGlvbiBwcmludFNlY3Rpb24odGV4dDogc3RyaW5nLCBvcHRpb25zPzoge21heExlbmd0aD86IG51bWJlciwgcHJlZml4Pzogc3RyaW5nLCAgc3VmZml4Pzogc3RyaW5nLCBzcGFjZUFyb3VuZD86IG51bWJlciwgZmlsbD86IHN0cmluZyB9KXtcbiAgY29uc3QgbWF4TGVuZ3RoID0gb3B0aW9ucz8ubWF4TGVuZ3RoID8/IDgwO1xuICBjb25zdCBwcmVmaXggPSBvcHRpb25zPy5wcmVmaXggPz8gJyc7XG4gIGNvbnN0IHN1Zml4ID0gb3B0aW9ucz8uc3VmZml4ID8/ICcnO1xuICBjb25zdCBzcGFjZUFyb3VuZCA9IG9wdGlvbnM/LnNwYWNlQXJvdW5kID8/IDE7XG4gIGNvbnN0IGZpbGwgPSBvcHRpb25zPy5maWxsID8/ICcgJztcbiAgY29uc3QgZmlsbExlbmd0aCA9IG1heExlbmd0aCAtIHByZWZpeC5sZW5ndGggLSBzdWZpeC5sZW5ndGggLSAoMiAqIHNwYWNlQXJvdW5kKSAtIHRleHQubGVuZ3RoO1xuXG4gIHJldHVybiBbXG4gICAgcHJlZml4LFxuICAgIGZpbGwucmVwZWF0KE1hdGguZmxvb3IoZmlsbExlbmd0aC8yKSksXG4gICAgYCAke3RleHR9IGAsXG4gICAgZmlsbC5yZXBlYXQoTWF0aC5jZWlsKGZpbGxMZW5ndGgvMikpLFxuICAgIHN1Zml4XG4gIF0uam9pbignJyk7XG59O1xuXG5leHBvcnQgY29uc3QgaG9zdHNDb25maWd1cmF0aW9uID0gYCR7cHJpbnRTZWN0aW9uKCdXYXp1aCBob3N0cycsIHtwcmVmaXg6ICcjICcsIGZpbGw6ICctJ30pfVxuI1xuIyBUaGUgZm9sbG93aW5nIGNvbmZpZ3VyYXRpb24gaXMgdGhlIGRlZmF1bHQgc3RydWN0dXJlIHRvIGRlZmluZSBhIGhvc3QuXG4jXG4jIGhvc3RzOlxuIyAgICMgSG9zdCBJRCAvIG5hbWUsXG4jICAgLSBlbnYtMTpcbiMgICAgICAgIyBIb3N0IFVSTFxuIyAgICAgICB1cmw6IGh0dHBzOi8vZW52LTEuZXhhbXBsZVxuIyAgICAgICAjIEhvc3QgLyBBUEkgcG9ydFxuIyAgICAgICBwb3J0OiA1NTAwMFxuIyAgICAgICAjIEhvc3QgLyBBUEkgdXNlcm5hbWVcbiMgICAgICAgdXNlcm5hbWU6IHdhenVoLXd1aVxuIyAgICAgICAjIEhvc3QgLyBBUEkgcGFzc3dvcmRcbiMgICAgICAgcGFzc3dvcmQ6IHdhenVoLXd1aVxuIyAgICAgICAjIFVzZSBSQkFDIG9yIG5vdC4gSWYgc2V0IHRvIHRydWUsIHRoZSB1c2VybmFtZSBtdXN0IGJlIFwid2F6dWgtd3VpXCIuXG4jICAgICAgIHJ1bl9hczogdHJ1ZVxuIyAgIC0gZW52LTI6XG4jICAgICAgIHVybDogaHR0cHM6Ly9lbnYtMi5leGFtcGxlXG4jICAgICAgIHBvcnQ6IDU1MDAwXG4jICAgICAgIHVzZXJuYW1lOiB3YXp1aC13dWlcbiMgICAgICAgcGFzc3dvcmQ6IHdhenVoLXd1aVxuIyAgICAgICBydW5fYXM6IHRydWVcblxuaG9zdHM6XG4gIC0gZGVmYXVsdDpcbiAgICAgIHVybDogaHR0cHM6Ly9sb2NhbGhvc3RcbiAgICAgIHBvcnQ6IDU1MDAwXG4gICAgICB1c2VybmFtZTogd2F6dWgtd3VpXG4gICAgICBwYXNzd29yZDogd2F6dWgtd3VpXG4gICAgICBydW5fYXM6IGZhbHNlXG5gO1xuXG4vKipcbiAqIEdpdmVuIGEgc3RyaW5nLCB0aGlzIGZ1bmN0aW9uIGJ1aWxkcyBhIG11bHRpbmUgc3RyaW5nLCBlYWNoIGxpbmUgYWJvdXQgNzBcbiAqIGNoYXJhY3RlcnMgbG9uZywgc3BsaXR0ZWQgYXQgdGhlIGNsb3Nlc3Qgd2hpdGVzcGFjZSBjaGFyYWN0ZXIgdG8gdGhhdCBsZW50Z2guXG4gKlxuICogVGhpcyBmdW5jdGlvbiBpcyB1c2VkIHRvIHRyYW5zZm9ybSB0aGUgc2V0dGluZ3MgZGVzY3JpcHRpb25cbiAqIGludG8gYSBtdWx0aWxpbmUgc3RyaW5nIHRvIGJlIHVzZWQgYXMgdGhlIHNldHRpbmcgZG9jdW1lbnRhdGlvbi5cbiAqXG4gKiBUaGUgIyBjaGFyYWN0ZXIgaXMgYWxzbyBhcHBlbmRlZCB0byB0aGUgYmVnaW5uaW5nIG9mIGVhY2ggbGluZS5cbiAqXG4gKiBAcGFyYW0gdGV4dFxuICogQHJldHVybnMgbXVsdGluZSBzdHJpbmdcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHNwbGl0RGVzY3JpcHRpb24odGV4dDogc3RyaW5nID0gJycpOiBzdHJpbmcge1xuICBjb25zdCBsaW5lcyA9IHRleHQubWF0Y2goLy57MSw4MH0oPz1cXHN8JCkvZykgfHwgW107XG4gIHJldHVybiBsaW5lcy5tYXAoKHopID0+ICcjICcgKyB6LnRyaW0oKSkuam9pbignXFxuJyk7XG59XG5cbmV4cG9ydCBjb25zdCBpbml0aWFsV2F6dWhDb25maWc6IHN0cmluZyA9IFtoZWFkZXIsIHBsdWdpblNldHRpbmdzQ29uZmlndXJhdGlvbiwgaG9zdHNDb25maWd1cmF0aW9uXS5qb2luKCdcXG4jXFxuJyk7XG4iXX0=