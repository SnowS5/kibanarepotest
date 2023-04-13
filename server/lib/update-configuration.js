"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.UpdateConfigurationFile = void 0;

var _fs = _interopRequireDefault(require("fs"));

var _logger = require("./logger");

var _getConfiguration = require("./get-configuration");

var _constants = require("../../common/constants");

var _settings = require("../../common/services/settings");

/*
 * Wazuh app - Module to update the configuration file
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
class UpdateConfigurationFile {
  constructor() {
    this.busy = false;
    this.file = _constants.WAZUH_DATA_CONFIG_APP_PATH;
  }
  /**
   * Add or replace specific setting from wazuh.yml
   * @param {String} key The setting name.
   * @param {String} value New value for the setting.
   * @param {Boolean} exists If true, it just replaces the value for that key.
   */


  updateLine(key, value, exists = false) {
    try {
      const data = _fs.default.readFileSync(this.file, {
        encoding: 'utf-8'
      });

      const re = new RegExp(`^${key}\\s{0,}:\\s{1,}.*`, 'gm');
      const formatedValue = (0, _settings.formatSettingValueToFile)(value);
      const result = exists ? data.replace(re, `${key}: ${formatedValue}`) : `${data}\n${key}: ${formatedValue}`;

      _fs.default.writeFileSync(this.file, result, 'utf8');

      (0, _logger.log)('update-configuration:updateLine', 'Updating line', 'debug');
      return true;
    } catch (error) {
      (0, _logger.log)('update-configuration:updateLine', error.message || error);
      throw error;
    }
  }
  /**
   * Updates wazuh.yml file. If it fails, it throws the error to the next function.
   * @param {Object} updatedConfiguration
   */


  updateConfiguration(updatedConfiguration) {
    try {
      if (this.busy) {
        throw new Error('Another process is updating the configuration file');
      }

      this.busy = true;
      const pluginConfiguration = (0, _getConfiguration.getConfiguration)({
        force: true
      }) || {};

      for (const pluginSettingKey in updatedConfiguration) {
        // Store the configuration in the configuration file.
        const value = updatedConfiguration[pluginSettingKey];
        this.updateLine(pluginSettingKey, value, typeof pluginConfiguration[pluginSettingKey] !== 'undefined'); // Update the app configuration server-cached setting in memory with the new value.

        pluginConfiguration[pluginSettingKey] = value;
      }

      ;
      this.busy = false;
      (0, _logger.log)('update-configuration:updateConfiguration', 'Updating configuration', 'debug');
    } catch (error) {
      (0, _logger.log)('update-configuration:updateConfiguration', error.message || error);
      this.busy = false;
      throw error;
    }
  }

}

exports.UpdateConfigurationFile = UpdateConfigurationFile;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInVwZGF0ZS1jb25maWd1cmF0aW9uLnRzIl0sIm5hbWVzIjpbIlVwZGF0ZUNvbmZpZ3VyYXRpb25GaWxlIiwiY29uc3RydWN0b3IiLCJidXN5IiwiZmlsZSIsIldBWlVIX0RBVEFfQ09ORklHX0FQUF9QQVRIIiwidXBkYXRlTGluZSIsImtleSIsInZhbHVlIiwiZXhpc3RzIiwiZGF0YSIsImZzIiwicmVhZEZpbGVTeW5jIiwiZW5jb2RpbmciLCJyZSIsIlJlZ0V4cCIsImZvcm1hdGVkVmFsdWUiLCJyZXN1bHQiLCJyZXBsYWNlIiwid3JpdGVGaWxlU3luYyIsImVycm9yIiwibWVzc2FnZSIsInVwZGF0ZUNvbmZpZ3VyYXRpb24iLCJ1cGRhdGVkQ29uZmlndXJhdGlvbiIsIkVycm9yIiwicGx1Z2luQ29uZmlndXJhdGlvbiIsImZvcmNlIiwicGx1Z2luU2V0dGluZ0tleSJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBV0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBZkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQU9PLE1BQU1BLHVCQUFOLENBQThCO0FBQ25DQyxFQUFBQSxXQUFXLEdBQUc7QUFDWixTQUFLQyxJQUFMLEdBQVksS0FBWjtBQUNBLFNBQUtDLElBQUwsR0FBWUMscUNBQVo7QUFDRDtBQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBQ0VDLEVBQUFBLFVBQVUsQ0FBQ0MsR0FBRCxFQUFNQyxLQUFOLEVBQWFDLE1BQU0sR0FBRyxLQUF0QixFQUE2QjtBQUNyQyxRQUFJO0FBQ0YsWUFBTUMsSUFBSSxHQUFHQyxZQUFHQyxZQUFILENBQWdCLEtBQUtSLElBQXJCLEVBQTJCO0FBQUVTLFFBQUFBLFFBQVEsRUFBRTtBQUFaLE9BQTNCLENBQWI7O0FBQ0EsWUFBTUMsRUFBRSxHQUFHLElBQUlDLE1BQUosQ0FBWSxJQUFHUixHQUFJLG1CQUFuQixFQUF1QyxJQUF2QyxDQUFYO0FBQ0EsWUFBTVMsYUFBYSxHQUFHLHdDQUF5QlIsS0FBekIsQ0FBdEI7QUFDQSxZQUFNUyxNQUFNLEdBQUdSLE1BQU0sR0FDakJDLElBQUksQ0FBQ1EsT0FBTCxDQUFhSixFQUFiLEVBQWtCLEdBQUVQLEdBQUksS0FBSVMsYUFBYyxFQUExQyxDQURpQixHQUVoQixHQUFFTixJQUFLLEtBQUlILEdBQUksS0FBSVMsYUFBYyxFQUZ0Qzs7QUFHQUwsa0JBQUdRLGFBQUgsQ0FBaUIsS0FBS2YsSUFBdEIsRUFBNEJhLE1BQTVCLEVBQW9DLE1BQXBDOztBQUNBLHVCQUFJLGlDQUFKLEVBQXVDLGVBQXZDLEVBQXdELE9BQXhEO0FBQ0EsYUFBTyxJQUFQO0FBQ0QsS0FWRCxDQVVFLE9BQU9HLEtBQVAsRUFBYztBQUNkLHVCQUFJLGlDQUFKLEVBQXVDQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQXhEO0FBQ0EsWUFBTUEsS0FBTjtBQUNEO0FBQ0Y7QUFFRDtBQUNGO0FBQ0E7QUFDQTs7O0FBQ0VFLEVBQUFBLG1CQUFtQixDQUFDQyxvQkFBRCxFQUF1QjtBQUN4QyxRQUFJO0FBQ0YsVUFBSSxLQUFLcEIsSUFBVCxFQUFlO0FBQ2IsY0FBTSxJQUFJcUIsS0FBSixDQUFVLG9EQUFWLENBQU47QUFDRDs7QUFDRCxXQUFLckIsSUFBTCxHQUFZLElBQVo7QUFFQSxZQUFNc0IsbUJBQW1CLEdBQUcsd0NBQWlCO0FBQUNDLFFBQUFBLEtBQUssRUFBRTtBQUFSLE9BQWpCLEtBQW1DLEVBQS9EOztBQUVBLFdBQUksTUFBTUMsZ0JBQVYsSUFBOEJKLG9CQUE5QixFQUFtRDtBQUNqRDtBQUNBLGNBQU1mLEtBQUssR0FBR2Usb0JBQW9CLENBQUNJLGdCQUFELENBQWxDO0FBQ0EsYUFBS3JCLFVBQUwsQ0FBZ0JxQixnQkFBaEIsRUFBa0NuQixLQUFsQyxFQUF5QyxPQUFPaUIsbUJBQW1CLENBQUNFLGdCQUFELENBQTFCLEtBQWlELFdBQTFGLEVBSGlELENBSWpEOztBQUNBRixRQUFBQSxtQkFBbUIsQ0FBQ0UsZ0JBQUQsQ0FBbkIsR0FBd0NuQixLQUF4QztBQUNEOztBQUFBO0FBRUQsV0FBS0wsSUFBTCxHQUFZLEtBQVo7QUFDQSx1QkFDRSwwQ0FERixFQUVFLHdCQUZGLEVBR0UsT0FIRjtBQUtELEtBdEJELENBc0JFLE9BQU9pQixLQUFQLEVBQWM7QUFDZCx1QkFBSSwwQ0FBSixFQUFnREEsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUFqRTtBQUNBLFdBQUtqQixJQUFMLEdBQVksS0FBWjtBQUNBLFlBQU1pQixLQUFOO0FBQ0Q7QUFDRjs7QUE3RGtDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSB0byB1cGRhdGUgdGhlIGNvbmZpZ3VyYXRpb24gZmlsZVxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmltcG9ydCBmcyBmcm9tICdmcyc7XG5pbXBvcnQgeyBsb2cgfSBmcm9tICcuL2xvZ2dlcic7XG5pbXBvcnQgeyBnZXRDb25maWd1cmF0aW9uIH0gZnJvbSAnLi9nZXQtY29uZmlndXJhdGlvbic7XG5pbXBvcnQgeyBXQVpVSF9EQVRBX0NPTkZJR19BUFBfUEFUSCB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IHsgZm9ybWF0U2V0dGluZ1ZhbHVlVG9GaWxlIH0gZnJvbSAnLi4vLi4vY29tbW9uL3NlcnZpY2VzL3NldHRpbmdzJztcblxuZXhwb3J0IGNsYXNzIFVwZGF0ZUNvbmZpZ3VyYXRpb25GaWxlIHtcbiAgY29uc3RydWN0b3IoKSB7XG4gICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgdGhpcy5maWxlID0gV0FaVUhfREFUQV9DT05GSUdfQVBQX1BBVEg7XG4gIH1cblxuICAvKipcbiAgICogQWRkIG9yIHJlcGxhY2Ugc3BlY2lmaWMgc2V0dGluZyBmcm9tIHdhenVoLnltbFxuICAgKiBAcGFyYW0ge1N0cmluZ30ga2V5IFRoZSBzZXR0aW5nIG5hbWUuXG4gICAqIEBwYXJhbSB7U3RyaW5nfSB2YWx1ZSBOZXcgdmFsdWUgZm9yIHRoZSBzZXR0aW5nLlxuICAgKiBAcGFyYW0ge0Jvb2xlYW59IGV4aXN0cyBJZiB0cnVlLCBpdCBqdXN0IHJlcGxhY2VzIHRoZSB2YWx1ZSBmb3IgdGhhdCBrZXkuXG4gICAqL1xuICB1cGRhdGVMaW5lKGtleSwgdmFsdWUsIGV4aXN0cyA9IGZhbHNlKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGRhdGEgPSBmcy5yZWFkRmlsZVN5bmModGhpcy5maWxlLCB7IGVuY29kaW5nOiAndXRmLTgnIH0pO1xuICAgICAgY29uc3QgcmUgPSBuZXcgUmVnRXhwKGBeJHtrZXl9XFxcXHN7MCx9OlxcXFxzezEsfS4qYCwgJ2dtJyk7XG4gICAgICBjb25zdCBmb3JtYXRlZFZhbHVlID0gZm9ybWF0U2V0dGluZ1ZhbHVlVG9GaWxlKHZhbHVlKTtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGV4aXN0c1xuICAgICAgICA/IGRhdGEucmVwbGFjZShyZSwgYCR7a2V5fTogJHtmb3JtYXRlZFZhbHVlfWApXG4gICAgICAgIDogYCR7ZGF0YX1cXG4ke2tleX06ICR7Zm9ybWF0ZWRWYWx1ZX1gO1xuICAgICAgZnMud3JpdGVGaWxlU3luYyh0aGlzLmZpbGUsIHJlc3VsdCwgJ3V0ZjgnKTtcbiAgICAgIGxvZygndXBkYXRlLWNvbmZpZ3VyYXRpb246dXBkYXRlTGluZScsICdVcGRhdGluZyBsaW5lJywgJ2RlYnVnJyk7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtY29uZmlndXJhdGlvbjp1cGRhdGVMaW5lJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICB0aHJvdyBlcnJvcjtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVXBkYXRlcyB3YXp1aC55bWwgZmlsZS4gSWYgaXQgZmFpbHMsIGl0IHRocm93cyB0aGUgZXJyb3IgdG8gdGhlIG5leHQgZnVuY3Rpb24uXG4gICAqIEBwYXJhbSB7T2JqZWN0fSB1cGRhdGVkQ29uZmlndXJhdGlvblxuICAgKi9cbiAgdXBkYXRlQ29uZmlndXJhdGlvbih1cGRhdGVkQ29uZmlndXJhdGlvbikge1xuICAgIHRyeSB7XG4gICAgICBpZiAodGhpcy5idXN5KSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignQW5vdGhlciBwcm9jZXNzIGlzIHVwZGF0aW5nIHRoZSBjb25maWd1cmF0aW9uIGZpbGUnKTtcbiAgICAgIH1cbiAgICAgIHRoaXMuYnVzeSA9IHRydWU7XG5cbiAgICAgIGNvbnN0IHBsdWdpbkNvbmZpZ3VyYXRpb24gPSBnZXRDb25maWd1cmF0aW9uKHtmb3JjZTogdHJ1ZX0pIHx8IHt9O1xuXG4gICAgICBmb3IoY29uc3QgcGx1Z2luU2V0dGluZ0tleSBpbiB1cGRhdGVkQ29uZmlndXJhdGlvbil7XG4gICAgICAgIC8vIFN0b3JlIHRoZSBjb25maWd1cmF0aW9uIGluIHRoZSBjb25maWd1cmF0aW9uIGZpbGUuXG4gICAgICAgIGNvbnN0IHZhbHVlID0gdXBkYXRlZENvbmZpZ3VyYXRpb25bcGx1Z2luU2V0dGluZ0tleV07XG4gICAgICAgIHRoaXMudXBkYXRlTGluZShwbHVnaW5TZXR0aW5nS2V5LCB2YWx1ZSwgdHlwZW9mIHBsdWdpbkNvbmZpZ3VyYXRpb25bcGx1Z2luU2V0dGluZ0tleV0gIT09ICd1bmRlZmluZWQnKTtcbiAgICAgICAgLy8gVXBkYXRlIHRoZSBhcHAgY29uZmlndXJhdGlvbiBzZXJ2ZXItY2FjaGVkIHNldHRpbmcgaW4gbWVtb3J5IHdpdGggdGhlIG5ldyB2YWx1ZS5cbiAgICAgICAgcGx1Z2luQ29uZmlndXJhdGlvbltwbHVnaW5TZXR0aW5nS2V5XSA9IHZhbHVlO1xuICAgICAgfTtcblxuICAgICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgICBsb2coXG4gICAgICAgICd1cGRhdGUtY29uZmlndXJhdGlvbjp1cGRhdGVDb25maWd1cmF0aW9uJyxcbiAgICAgICAgJ1VwZGF0aW5nIGNvbmZpZ3VyYXRpb24nLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1jb25maWd1cmF0aW9uOnVwZGF0ZUNvbmZpZ3VyYXRpb24nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHRoaXMuYnVzeSA9IGZhbHNlO1xuICAgICAgdGhyb3cgZXJyb3I7XG4gICAgfVxuICB9XG59XG4iXX0=