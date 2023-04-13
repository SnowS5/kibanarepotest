"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.UiLogsCtrl = void 0;

var _errorResponse = require("../../lib/error-response");

var _readLastLines = require("read-last-lines");

var _constants = require("../../../common/constants");

var _uiLogger = _interopRequireDefault(require("../../lib/ui-logger"));

/*
 * Wazuh app - Class for UI Logs functions
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// Require some libraries
class UiLogsCtrl {
  /**
   * Constructor
   * @param {*} server
   */
  constructor() {}
  /**
   * Returns Wazuh ui logs
   * @param {Object} response
   * @returns {Array<String>} app logs or ErrorResponse
   */


  async getUiLogs(response) {
    try {
      return _uiLogger.default.initDirectory().then(async () => {
        if (!_uiLogger.default.checkFileExist(_constants.WAZUH_UI_LOGS_RAW_PATH)) {
          return response.ok({
            body: {
              error: 0,
              rawLogs: []
            }
          });
        } else {
          let arrayLog = await this.getUiFileLogs(_constants.WAZUH_UI_LOGS_RAW_PATH);
          return response.ok({
            body: {
              error: 0,
              rawLogs: arrayLog.filter(item => typeof item === 'string' && item.length)
            }
          });
        }
      });
    } catch (error) {
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3036, 500, response);
    }
  }
  /**
   * Add new UI Log entry in ui logs file
   * @param request
   * @param response
   * @returns success message or ErrorResponse
   */


  async createUiLogs(request, response) {
    try {
      const {
        location,
        message,
        level
      } = request.body;
      await _uiLogger.default.log(location, message, level);
      return response.ok({
        body: {
          statusCode: 200,
          error: 0,
          message: 'Log has been added'
        }
      });
    } catch (error) {
      return (0, _errorResponse.ErrorResponse)(error.message || error, 3021, 500, response);
    }
  }
  /**
   * Get UI logs from specific log file
   * @param filepath
   * @returns Array
   */


  async getUiFileLogs(filepath) {
    try {
      const lastLogs = await (0, _readLastLines.read)(filepath, 50);
      return lastLogs.split('\n');
    } catch (err) {
      throw err;
    }
  }

}

exports.UiLogsCtrl = UiLogsCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInVpLWxvZ3MuY29udHJvbGxlci50cyJdLCJuYW1lcyI6WyJVaUxvZ3NDdHJsIiwiY29uc3RydWN0b3IiLCJnZXRVaUxvZ3MiLCJyZXNwb25zZSIsInVpTG9nZ2VyIiwiaW5pdERpcmVjdG9yeSIsInRoZW4iLCJjaGVja0ZpbGVFeGlzdCIsIldBWlVIX1VJX0xPR1NfUkFXX1BBVEgiLCJvayIsImJvZHkiLCJlcnJvciIsInJhd0xvZ3MiLCJhcnJheUxvZyIsImdldFVpRmlsZUxvZ3MiLCJmaWx0ZXIiLCJpdGVtIiwibGVuZ3RoIiwibWVzc2FnZSIsImNyZWF0ZVVpTG9ncyIsInJlcXVlc3QiLCJsb2NhdGlvbiIsImxldmVsIiwibG9nIiwic3RhdHVzQ29kZSIsImZpbGVwYXRoIiwibGFzdExvZ3MiLCJzcGxpdCIsImVyciJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBYUE7O0FBQ0E7O0FBQ0E7O0FBRUE7O0FBakJBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFFQTtBQU9PLE1BQU1BLFVBQU4sQ0FBaUI7QUFDdEI7QUFDRjtBQUNBO0FBQ0E7QUFDRUMsRUFBQUEsV0FBVyxHQUFHLENBQUU7QUFFaEI7QUFDRjtBQUNBO0FBQ0E7QUFDQTs7O0FBQ2lCLFFBQVRDLFNBQVMsQ0FBQ0MsUUFBRCxFQUFrQztBQUMvQyxRQUFJO0FBQ0YsYUFBT0Msa0JBQVNDLGFBQVQsR0FBeUJDLElBQXpCLENBQThCLFlBQVk7QUFDL0MsWUFBSSxDQUFDRixrQkFBU0csY0FBVCxDQUF3QkMsaUNBQXhCLENBQUwsRUFBc0Q7QUFDcEQsaUJBQU9MLFFBQVEsQ0FBQ00sRUFBVCxDQUFZO0FBQ2pCQyxZQUFBQSxJQUFJLEVBQUU7QUFDSkMsY0FBQUEsS0FBSyxFQUFFLENBREg7QUFFSkMsY0FBQUEsT0FBTyxFQUFFO0FBRkw7QUFEVyxXQUFaLENBQVA7QUFNRCxTQVBELE1BT087QUFDTCxjQUFJQyxRQUFRLEdBQUcsTUFBTSxLQUFLQyxhQUFMLENBQW1CTixpQ0FBbkIsQ0FBckI7QUFDQSxpQkFBT0wsUUFBUSxDQUFDTSxFQUFULENBQVk7QUFDakJDLFlBQUFBLElBQUksRUFBRTtBQUNKQyxjQUFBQSxLQUFLLEVBQUUsQ0FESDtBQUVKQyxjQUFBQSxPQUFPLEVBQUVDLFFBQVEsQ0FBQ0UsTUFBVCxDQUFpQkMsSUFBRCxJQUFVLE9BQU9BLElBQVAsS0FBZ0IsUUFBaEIsSUFBNEJBLElBQUksQ0FBQ0MsTUFBM0Q7QUFGTDtBQURXLFdBQVosQ0FBUDtBQU1EO0FBQ0YsT0FqQk0sQ0FBUDtBQWtCRCxLQW5CRCxDQW1CRSxPQUFPTixLQUFQLEVBQWM7QUFDZCxhQUFPLGtDQUFjQSxLQUFLLENBQUNPLE9BQU4sSUFBaUJQLEtBQS9CLEVBQXNDLElBQXRDLEVBQTRDLEdBQTVDLEVBQWlEUixRQUFqRCxDQUFQO0FBQ0Q7QUFDRjtBQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBQ29CLFFBQVpnQixZQUFZLENBQUNDLE9BQUQsRUFBeUJqQixRQUF6QixFQUEwRDtBQUMxRSxRQUFJO0FBQ0YsWUFBTTtBQUFFa0IsUUFBQUEsUUFBRjtBQUFZSCxRQUFBQSxPQUFaO0FBQXFCSSxRQUFBQTtBQUFyQixVQUErQkYsT0FBTyxDQUFDVixJQUE3QztBQUNBLFlBQU1OLGtCQUFTbUIsR0FBVCxDQUFhRixRQUFiLEVBQXVCSCxPQUF2QixFQUFnQ0ksS0FBaEMsQ0FBTjtBQUNBLGFBQU9uQixRQUFRLENBQUNNLEVBQVQsQ0FBWTtBQUNqQkMsUUFBQUEsSUFBSSxFQUFFO0FBQ0pjLFVBQUFBLFVBQVUsRUFBRSxHQURSO0FBRUpiLFVBQUFBLEtBQUssRUFBRSxDQUZIO0FBR0pPLFVBQUFBLE9BQU8sRUFBRTtBQUhMO0FBRFcsT0FBWixDQUFQO0FBT0QsS0FWRCxDQVVFLE9BQU9QLEtBQVAsRUFBYztBQUNkLGFBQU8sa0NBQWNBLEtBQUssQ0FBQ08sT0FBTixJQUFpQlAsS0FBL0IsRUFBc0MsSUFBdEMsRUFBNEMsR0FBNUMsRUFBaURSLFFBQWpELENBQVA7QUFDRDtBQUNGO0FBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTs7O0FBQ3FCLFFBQWJXLGFBQWEsQ0FBQ1csUUFBRCxFQUFXO0FBQzVCLFFBQUk7QUFDRixZQUFNQyxRQUFRLEdBQUcsTUFBTSx5QkFBS0QsUUFBTCxFQUFlLEVBQWYsQ0FBdkI7QUFDQSxhQUFPQyxRQUFRLENBQUNDLEtBQVQsQ0FBZSxJQUFmLENBQVA7QUFDRCxLQUhELENBR0UsT0FBT0MsR0FBUCxFQUFZO0FBQ1osWUFBTUEsR0FBTjtBQUNEO0FBQ0Y7O0FBdkVxQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBDbGFzcyBmb3IgVUkgTG9ncyBmdW5jdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5cbi8vIFJlcXVpcmUgc29tZSBsaWJyYXJpZXNcbmltcG9ydCB7IEVycm9yUmVzcG9uc2UgfSBmcm9tICcuLi8uLi9saWIvZXJyb3ItcmVzcG9uc2UnO1xuaW1wb3J0IHsgcmVhZCB9IGZyb20gJ3JlYWQtbGFzdC1saW5lcyc7XG5pbXBvcnQgeyBXQVpVSF9VSV9MT0dTX1JBV19QQVRIIH0gZnJvbSAnLi4vLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgeyBLaWJhbmFSZXF1ZXN0LCBLaWJhbmFSZXNwb25zZUZhY3RvcnkgfSBmcm9tICdzcmMvY29yZS9zZXJ2ZXInO1xuaW1wb3J0IHVpTG9nZ2VyIGZyb20gJy4uLy4uL2xpYi91aS1sb2dnZXInO1xuXG5leHBvcnQgY2xhc3MgVWlMb2dzQ3RybCB7XG4gIC8qKlxuICAgKiBDb25zdHJ1Y3RvclxuICAgKiBAcGFyYW0geyp9IHNlcnZlclxuICAgKi9cbiAgY29uc3RydWN0b3IoKSB7fVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIFdhenVoIHVpIGxvZ3NcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtBcnJheTxTdHJpbmc+fSBhcHAgbG9ncyBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBnZXRVaUxvZ3MocmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICByZXR1cm4gdWlMb2dnZXIuaW5pdERpcmVjdG9yeSgpLnRoZW4oYXN5bmMgKCkgPT4ge1xuICAgICAgICBpZiAoIXVpTG9nZ2VyLmNoZWNrRmlsZUV4aXN0KFdBWlVIX1VJX0xPR1NfUkFXX1BBVEgpKSB7XG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgICAgZXJyb3I6IDAsXG4gICAgICAgICAgICAgIHJhd0xvZ3M6IFtdLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBsZXQgYXJyYXlMb2cgPSBhd2FpdCB0aGlzLmdldFVpRmlsZUxvZ3MoV0FaVUhfVUlfTE9HU19SQVdfUEFUSCk7XG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICAgIGJvZHk6IHtcbiAgICAgICAgICAgICAgZXJyb3I6IDAsXG4gICAgICAgICAgICAgIHJhd0xvZ3M6IGFycmF5TG9nLmZpbHRlcigoaXRlbSkgPT4gdHlwZW9mIGl0ZW0gPT09ICdzdHJpbmcnICYmIGl0ZW0ubGVuZ3RoKSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAzMDM2LCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogQWRkIG5ldyBVSSBMb2cgZW50cnkgaW4gdWkgbG9ncyBmaWxlXG4gICAqIEBwYXJhbSByZXF1ZXN0XG4gICAqIEBwYXJhbSByZXNwb25zZVxuICAgKiBAcmV0dXJucyBzdWNjZXNzIG1lc3NhZ2Ugb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgY3JlYXRlVWlMb2dzKHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgeyBsb2NhdGlvbiwgbWVzc2FnZSwgbGV2ZWwgfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIGF3YWl0IHVpTG9nZ2VyLmxvZyhsb2NhdGlvbiwgbWVzc2FnZSwgbGV2ZWwpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIHN0YXR1c0NvZGU6IDIwMCxcbiAgICAgICAgICBlcnJvcjogMCxcbiAgICAgICAgICBtZXNzYWdlOiAnTG9nIGhhcyBiZWVuIGFkZGVkJyxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAzMDIxLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogR2V0IFVJIGxvZ3MgZnJvbSBzcGVjaWZpYyBsb2cgZmlsZVxuICAgKiBAcGFyYW0gZmlsZXBhdGhcbiAgICogQHJldHVybnMgQXJyYXlcbiAgICovXG4gIGFzeW5jIGdldFVpRmlsZUxvZ3MoZmlsZXBhdGgpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgbGFzdExvZ3MgPSBhd2FpdCByZWFkKGZpbGVwYXRoLCA1MCk7XG4gICAgICByZXR1cm4gbGFzdExvZ3Muc3BsaXQoJ1xcbicpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgdGhyb3cgZXJyO1xuICAgIH1cbiAgfVxufVxuIl19