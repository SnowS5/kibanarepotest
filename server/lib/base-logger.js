"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.BaseLogger = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _winston = _interopRequireDefault(require("winston"));

var _fs = _interopRequireDefault(require("fs"));

var _path = _interopRequireDefault(require("path"));

var _getConfiguration = require("./get-configuration");

var _filesystem = require("./filesystem");

var _constants = require("../../common/constants");

/*
 * Wazuh app - Settings controller
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
class BaseLogger {
  constructor(plainLogsFile, rawLogsFile) {
    (0, _defineProperty2.default)(this, "allowed", false);
    (0, _defineProperty2.default)(this, "wazuhLogger", undefined);
    (0, _defineProperty2.default)(this, "wazuhPlainLogger", undefined);
    (0, _defineProperty2.default)(this, "PLAIN_LOGS_PATH", '');
    (0, _defineProperty2.default)(this, "PLAIN_LOGS_FILE_NAME", '');
    (0, _defineProperty2.default)(this, "RAW_LOGS_PATH", '');
    (0, _defineProperty2.default)(this, "RAW_LOGS_FILE_NAME", '');
    (0, _defineProperty2.default)(this, "initLogger", () => {
      const configurationFile = (0, _getConfiguration.getConfiguration)();
      const level = typeof (configurationFile || {})['logs.level'] !== 'undefined' && ['info', 'debug'].includes(configurationFile['logs.level']) ? configurationFile['logs.level'] : 'info'; // JSON logger

      this.wazuhLogger = _winston.default.createLogger({
        level,
        format: _winston.default.format.json(),
        transports: [new _winston.default.transports.File({
          filename: this.RAW_LOGS_PATH
        })]
      }); // Prevents from exit on error related to the logger.

      this.wazuhLogger.exitOnError = false; // Plain text logger

      this.wazuhPlainLogger = _winston.default.createLogger({
        level,
        format: _winston.default.format.simple(),
        transports: [new _winston.default.transports.File({
          filename: this.PLAIN_LOGS_PATH
        })]
      }); // Prevents from exit on error related to the logger.

      this.wazuhPlainLogger.exitOnError = false;
    });
    (0, _defineProperty2.default)(this, "initDirectory", async () => {
      try {
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDataDirectoryIfNotExists)('logs');

        if (typeof this.wazuhLogger === 'undefined' || typeof this.wazuhPlainLogger === 'undefined') {
          this.initLogger();
        }

        this.allowed = true;
        return;
      } catch (error) {
        this.allowed = false;
        return Promise.reject(error);
      }
    });
    (0, _defineProperty2.default)(this, "getFilesizeInMegaBytes", filename => {
      if (this.allowed) {
        if (_fs.default.existsSync(filename)) {
          const stats = _fs.default.statSync(filename);

          const fileSizeInMegaBytes = stats.size;
          return fileSizeInMegaBytes / 1000000.0;
        }
      }

      return 0;
    });
    (0, _defineProperty2.default)(this, "checkFileExist", filename => {
      return _fs.default.existsSync(filename);
    });
    (0, _defineProperty2.default)(this, "rotateFiles", (file, pathFile, log) => {
      if (this.getFilesizeInMegaBytes(pathFile) >= _constants.MAX_MB_LOG_FILES) {
        const fileExtension = _path.default.extname(file);

        const fileName = _path.default.basename(file, fileExtension);

        _fs.default.renameSync(pathFile, `${_constants.WAZUH_DATA_LOGS_DIRECTORY_PATH}/${fileName}-${new Date().getTime()}${fileExtension}`);

        if (log) {
          _fs.default.writeFileSync(pathFile, log + '\n');
        }
      }
    });
    (0, _defineProperty2.default)(this, "checkFiles", () => {
      (0, _filesystem.createLogFileIfNotExists)(this.RAW_LOGS_PATH);
      (0, _filesystem.createLogFileIfNotExists)(this.PLAIN_LOGS_PATH);

      if (this.allowed) {
        // check raw log file
        this.rotateFiles(this.RAW_LOGS_FILE_NAME, this.RAW_LOGS_PATH, JSON.stringify({
          date: new Date(),
          level: 'info',
          location: 'logger',
          message: 'Rotated log file'
        })); // check log file

        this.rotateFiles(this.PLAIN_LOGS_FILE_NAME, this.PLAIN_LOGS_PATH);
      }
    });
    (0, _defineProperty2.default)(this, "yyyymmdd", () => {
      const now = new Date();
      const y = now.getFullYear();
      const m = now.getMonth() + 1;
      const d = now.getDate();
      const seconds = now.getSeconds();
      const minutes = now.getMinutes();
      const hour = now.getHours();
      return `${y}/${m < 10 ? '0' : ''}${m}/${d < 10 ? '0' : ''}${d} ${hour}:${minutes}:${seconds}`;
    });
    (0, _defineProperty2.default)(this, "parseData", data => {
      let parsedData = data instanceof Error ? {
        message: data.message,
        stack: data.stack
      } : data; // when error is AxiosError, it extends from Error

      if (data.isAxiosError) {
        const {
          config
        } = data;
        parsedData = { ...parsedData,
          config: {
            url: config.url,
            method: config.method,
            data: config.data,
            params: config.params
          }
        };
      }

      if (typeof parsedData === 'object') parsedData.toString = () => JSON.stringify(parsedData);
      return parsedData;
    });
    this.PLAIN_LOGS_PATH = _path.default.join(_constants.WAZUH_DATA_LOGS_DIRECTORY_PATH, plainLogsFile);
    this.RAW_LOGS_PATH = _path.default.join(_constants.WAZUH_DATA_LOGS_DIRECTORY_PATH, rawLogsFile);
    this.PLAIN_LOGS_FILE_NAME = plainLogsFile;
    this.RAW_LOGS_FILE_NAME = rawLogsFile;
  }
  /**
   * Initialize loggers, plain and raw logger
   */


  /**
   * Main function to add a new log
   * @param {*} location File where the log is being thrown
   * @param {*} data Message or object to log
   * @param {*} level Optional, default is 'error'
   */
  async log(location, data, level) {
    const parsedData = this.parseData(data);
    return this.initDirectory().then(() => {
      if (this.allowed) {
        this.checkFiles();
        const plainLogData = {
          level: level || 'error',
          message: `${this.yyyymmdd()}: ${location || 'Unknown origin'}: ${parsedData.toString() || 'An error occurred'}`
        };
        this.wazuhPlainLogger.log(plainLogData);
        const logData = {
          date: new Date(),
          level: level || 'error',
          location: location || 'Unknown origin',
          data: parsedData || 'An error occurred'
        };

        if (typeof data == 'string') {
          logData.message = parsedData;
          delete logData.data;
        }

        this.wazuhLogger.log(logData);
      }
    }).catch(error => {
      console.error(`Cannot create the logs directory due to:\n${error.message || error}`);
      throw error;
    });
  }

}

exports.BaseLogger = BaseLogger;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImJhc2UtbG9nZ2VyLnRzIl0sIm5hbWVzIjpbIkJhc2VMb2dnZXIiLCJjb25zdHJ1Y3RvciIsInBsYWluTG9nc0ZpbGUiLCJyYXdMb2dzRmlsZSIsInVuZGVmaW5lZCIsImNvbmZpZ3VyYXRpb25GaWxlIiwibGV2ZWwiLCJpbmNsdWRlcyIsIndhenVoTG9nZ2VyIiwid2luc3RvbiIsImNyZWF0ZUxvZ2dlciIsImZvcm1hdCIsImpzb24iLCJ0cmFuc3BvcnRzIiwiRmlsZSIsImZpbGVuYW1lIiwiUkFXX0xPR1NfUEFUSCIsImV4aXRPbkVycm9yIiwid2F6dWhQbGFpbkxvZ2dlciIsInNpbXBsZSIsIlBMQUlOX0xPR1NfUEFUSCIsImluaXRMb2dnZXIiLCJhbGxvd2VkIiwiZXJyb3IiLCJQcm9taXNlIiwicmVqZWN0IiwiZnMiLCJleGlzdHNTeW5jIiwic3RhdHMiLCJzdGF0U3luYyIsImZpbGVTaXplSW5NZWdhQnl0ZXMiLCJzaXplIiwiZmlsZSIsInBhdGhGaWxlIiwibG9nIiwiZ2V0RmlsZXNpemVJbk1lZ2FCeXRlcyIsIk1BWF9NQl9MT0dfRklMRVMiLCJmaWxlRXh0ZW5zaW9uIiwicGF0aCIsImV4dG5hbWUiLCJmaWxlTmFtZSIsImJhc2VuYW1lIiwicmVuYW1lU3luYyIsIldBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCIsIkRhdGUiLCJnZXRUaW1lIiwid3JpdGVGaWxlU3luYyIsInJvdGF0ZUZpbGVzIiwiUkFXX0xPR1NfRklMRV9OQU1FIiwiSlNPTiIsInN0cmluZ2lmeSIsImRhdGUiLCJsb2NhdGlvbiIsIm1lc3NhZ2UiLCJQTEFJTl9MT0dTX0ZJTEVfTkFNRSIsIm5vdyIsInkiLCJnZXRGdWxsWWVhciIsIm0iLCJnZXRNb250aCIsImQiLCJnZXREYXRlIiwic2Vjb25kcyIsImdldFNlY29uZHMiLCJtaW51dGVzIiwiZ2V0TWludXRlcyIsImhvdXIiLCJnZXRIb3VycyIsImRhdGEiLCJwYXJzZWREYXRhIiwiRXJyb3IiLCJzdGFjayIsImlzQXhpb3NFcnJvciIsImNvbmZpZyIsInVybCIsIm1ldGhvZCIsInBhcmFtcyIsInRvU3RyaW5nIiwiam9pbiIsInBhcnNlRGF0YSIsImluaXREaXJlY3RvcnkiLCJ0aGVuIiwiY2hlY2tGaWxlcyIsInBsYWluTG9nRGF0YSIsInl5eXltbWRkIiwibG9nRGF0YSIsImNhdGNoIiwiY29uc29sZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7QUFZQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFFQTs7QUFsQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQXFCTyxNQUFNQSxVQUFOLENBQWlCO0FBU3RCQyxFQUFBQSxXQUFXLENBQUNDLGFBQUQsRUFBd0JDLFdBQXhCLEVBQTZDO0FBQUEsbURBUnJDLEtBUXFDO0FBQUEsdURBUGRDLFNBT2M7QUFBQSw0REFOVEEsU0FNUztBQUFBLDJEQUw5QixFQUs4QjtBQUFBLGdFQUp6QixFQUl5QjtBQUFBLHlEQUhoQyxFQUdnQztBQUFBLDhEQUYzQixFQUUyQjtBQUFBLHNEQVVuQyxNQUFNO0FBQ3pCLFlBQU1DLGlCQUFpQixHQUFHLHlDQUExQjtBQUNBLFlBQU1DLEtBQUssR0FDVCxPQUFPLENBQUNELGlCQUFpQixJQUFJLEVBQXRCLEVBQTBCLFlBQTFCLENBQVAsS0FBbUQsV0FBbkQsSUFDQSxDQUFDLE1BQUQsRUFBUyxPQUFULEVBQWtCRSxRQUFsQixDQUEyQkYsaUJBQWlCLENBQUMsWUFBRCxDQUE1QyxDQURBLEdBRUlBLGlCQUFpQixDQUFDLFlBQUQsQ0FGckIsR0FHSSxNQUpOLENBRnlCLENBUXpCOztBQUNBLFdBQUtHLFdBQUwsR0FBbUJDLGlCQUFRQyxZQUFSLENBQXFCO0FBQ3RDSixRQUFBQSxLQURzQztBQUV0Q0ssUUFBQUEsTUFBTSxFQUFFRixpQkFBUUUsTUFBUixDQUFlQyxJQUFmLEVBRjhCO0FBR3RDQyxRQUFBQSxVQUFVLEVBQUUsQ0FDVixJQUFJSixpQkFBUUksVUFBUixDQUFtQkMsSUFBdkIs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Z0IsS0FBSWhDLFFBQVEsSUFBSSxnQkFBaUIsS0FDM0RpQixVQUFVLENBQUNRLFFBQVgsTUFBeUIsbUJBQzFCO0FBSjBDLFNBQTdDO0FBT0EsYUFBSzNELGdCQUFMLENBQXNCZ0IsR0FBdEIsQ0FBMEJpRCxZQUExQjtBQUVBLGNBQU1FLE9BQTBCLEdBQUc7QUFDakNsQyxVQUFBQSxJQUFJLEVBQUUsSUFBSVAsSUFBSixFQUQyQjtBQUVqQ3RDLFVBQUFBLEtBQUssRUFBRUEsS0FBSyxJQUFJLE9BRmlCO0FBR2pDOEMsVUFBQUEsUUFBUSxFQUFFQSxRQUFRLElBQUksZ0JBSFc7QUFJakNnQixVQUFBQSxJQUFJLEVBQUVDLFVBQVUsSUFBSTtBQUphLFNBQW5DOztBQU9BLFlBQUksT0FBT0QsSUFBUCxJQUFlLFFBQW5CLEVBQTZCO0FBQzNCaUIsVUFBQUEsT0FBTyxDQUFDaEMsT0FBUixHQUFrQmdCLFVBQWxCO0FBQ0EsaUJBQU9nQixPQUFPLENBQUNqQixJQUFmO0FBQ0Q7O0FBRUQsYUFBSzVELFdBQUwsQ0FBaUIwQixHQUFqQixDQUFxQm1ELE9BQXJCO0FBQ0Q7QUFDRixLQTNCSSxFQTRCSkMsS0E1QkksQ0E0QkcvRCxLQUFELElBQVc7QUFDaEJnRSxNQUFBQSxPQUFPLENBQUNoRSxLQUFSLENBQWUsNkNBQTRDQSxLQUFLLENBQUM4QixPQUFOLElBQWlCOUIsS0FBTSxFQUFsRjtBQUNBLFlBQU1BLEtBQU47QUFDRCxLQS9CSSxDQUFQO0FBZ0NEOztBQWhPcUIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gU2V0dGluZ3MgY29udHJvbGxlclxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuaW1wb3J0IHdpbnN0b24gZnJvbSAnd2luc3Rvbic7XG5pbXBvcnQgZnMgZnJvbSAnZnMnO1xuaW1wb3J0IHBhdGggZnJvbSAncGF0aCc7XG5pbXBvcnQgeyBnZXRDb25maWd1cmF0aW9uIH0gZnJvbSAnLi9nZXQtY29uZmlndXJhdGlvbic7XG5pbXBvcnQgeyBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMsIGNyZWF0ZUxvZ0ZpbGVJZk5vdEV4aXN0cyB9IGZyb20gJy4vZmlsZXN5c3RlbSc7XG5cbmltcG9ydCB7IFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCwgTUFYX01CX0xPR19GSUxFUyB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuXG5leHBvcnQgaW50ZXJmYWNlIElVSVBsYWluTG9nZ2VyU2V0dGluZ3Mge1xuICBsZXZlbDogc3RyaW5nO1xuICBtZXNzYWdlPzogc3RyaW5nO1xuICBkYXRhPzogYW55O1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIElVSUxvZ2dlclNldHRpbmdzIGV4dGVuZHMgSVVJUGxhaW5Mb2dnZXJTZXR0aW5ncyB7XG4gIGRhdGU6IERhdGU7XG4gIGxvY2F0aW9uOiBzdHJpbmc7XG59XG5cbmV4cG9ydCBjbGFzcyBCYXNlTG9nZ2VyIHtcbiAgYWxsb3dlZDogYm9vbGVhbiA9IGZhbHNlO1xuICB3YXp1aExvZ2dlcjogd2luc3Rvbi5Mb2dnZXIgfCB1bmRlZmluZWQgPSB1bmRlZmluZWQ7XG4gIHdhenVoUGxhaW5Mb2dnZXI6IHdpbnN0b24uTG9nZ2VyIHwgdW5kZWZpbmVkID0gdW5kZWZpbmVkO1xuICBQTEFJTl9MT0dTX1BBVEg6IHN0cmluZyA9ICcnO1xuICBQTEFJTl9MT0dTX0ZJTEVfTkFNRTogc3RyaW5nID0gJyc7XG4gIFJBV19MT0dTX1BBVEg6IHN0cmluZyA9ICcnO1xuICBSQVdfTE9HU19GSUxFX05BTUU6IHN0cmluZyA9ICcnO1xuXG4gIGNvbnN0cnVjdG9yKHBsYWluTG9nc0ZpbGU6IHN0cmluZywgcmF3TG9nc0ZpbGU6IHN0cmluZykge1xuICAgIHRoaXMuUExBSU5fTE9HU19QQVRIID0gcGF0aC5qb2luKFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCwgcGxhaW5Mb2dzRmlsZSk7XG4gICAgdGhpcy5SQVdfTE9HU19QQVRIID0gcGF0aC5qb2luKFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCwgcmF3TG9nc0ZpbGUpO1xuICAgIHRoaXMuUExBSU5fTE9HU19GSUxFX05BTUUgPSBwbGFpbkxvZ3NGaWxlO1xuICAgIHRoaXMuUkFXX0xPR1NfRklMRV9OQU1FID0gcmF3TG9nc0ZpbGU7XG4gIH1cblxuICAvKipcbiAgICogSW5pdGlhbGl6ZSBsb2dnZXJzLCBwbGFpbiBhbmQgcmF3IGxvZ2dlclxuICAgKi9cbiAgcHJpdmF0ZSBpbml0TG9nZ2VyID0gKCkgPT4ge1xuICAgIGNvbnN0IGNvbmZpZ3VyYXRpb25GaWxlID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuICAgIGNvbnN0IGxldmVsID1cbiAgICAgIHR5cGVvZiAoY29uZmlndXJhdGlvbkZpbGUgfHwge30pWydsb2dzLmxldmVsJ10gIT09ICd1bmRlZmluZWQnICYmXG4gICAgICBbJ2luZm8nLCAnZGVidWcnXS5pbmNsdWRlcyhjb25maWd1cmF0aW9uRmlsZVsnbG9ncy5sZXZlbCddKVxuICAgICAgICA/IGNvbmZpZ3VyYXRpb25GaWxlWydsb2dzLmxldmVsJ11cbiAgICAgICAgOiAnaW5mbyc7XG5cbiAgICAvLyBKU09OIGxvZ2dlclxuICAgIHRoaXMud2F6dWhMb2dnZXIgPSB3aW5zdG9uLmNyZWF0ZUxvZ2dlcih7XG4gICAgICBsZXZlbCxcbiAgICAgIGZvcm1hdDogd2luc3Rvbi5mb3JtYXQuanNvbigpLFxuICAgICAgdHJhbnNwb3J0czogW1xuICAgICAgICBuZXcgd2luc3Rvbi50cmFuc3BvcnRzLkZpbGUoe1xuICAgICAgICAgIGZpbGVuYW1lOiB0aGlzLlJBV19MT0dTX1BBVEgsXG4gICAgICAgIH0pLFxuICAgICAgXSxcbiAgICB9KTtcblxuICAgIC8vIFByZXZlbnRzIGZyb20gZXhpdCBvbiBlcnJvciByZWxhdGVkIHRvIHRoZSBsb2dnZXIuXG4gICAgdGhpcy53YXp1aExvZ2dlci5leGl0T25FcnJvciA9IGZhbHNlO1xuXG4gICAgLy8gUGxhaW4gdGV4dCBsb2dnZXJcbiAgICB0aGlzLndhenVoUGxhaW5Mb2dnZXIgPSB3aW5zdG9uLmNyZWF0ZUxvZ2dlcih7XG4gICAgICBsZXZlbCxcbiAgICAgIGZvcm1hdDogd2luc3Rvbi5mb3JtYXQuc2ltcGxlKCksXG4gICAgICB0cmFuc3BvcnRzOiBbXG4gICAgICAgIG5ldyB3aW5zdG9uLnRyYW5zcG9ydHMuRmlsZSh7XG4gICAgICAgICAgZmlsZW5hbWU6IHRoaXMuUExBSU5fTE9HU19QQVRILFxuICAgICAgICB9KSxcbiAgICAgIF0sXG4gICAgfSk7XG5cbiAgICAvLyBQcmV2ZW50cyBmcm9tIGV4aXQgb24gZXJyb3IgcmVsYXRlZCB0byB0aGUgbG9nZ2VyLlxuICAgIHRoaXMud2F6dWhQbGFpbkxvZ2dlci5leGl0T25FcnJvciA9IGZhbHNlO1xuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVja3MgaWYgd2F6dWgvbG9ncyBleGlzdHMuIElmIGl0IGRvZXNuJ3QgZXhpc3QsIGl0IHdpbGwgYmUgY3JlYXRlZC5cbiAgICovXG4gIGluaXREaXJlY3RvcnkgPSBhc3luYyAoKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzKCdsb2dzJyk7XG4gICAgICBpZiAodHlwZW9mIHRoaXMud2F6dWhMb2dnZXIgPT09ICd1bmRlZmluZWQnIHx8IHR5cGVvZiB0aGlzLndhenVoUGxhaW5Mb2dnZXIgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgIHRoaXMuaW5pdExvZ2dlcigpO1xuICAgICAgfVxuICAgICAgdGhpcy5hbGxvd2VkID0gdHJ1ZTtcbiAgICAgIHJldHVybjtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgdGhpcy5hbGxvd2VkID0gZmFsc2U7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfTtcblxuICAvKipcbiAgICogUmV0dXJucyBnaXZlbiBmaWxlIHNpemUgaW4gTUIsIGlmIHRoZSBmaWxlIGRvZXNuJ3QgZXhpc3QgcmV0dXJucyAwXG4gICAqIEBwYXJhbSB7Kn0gZmlsZW5hbWUgUGF0aCB0byB0aGUgZmlsZVxuICAgKi9cbiAgZ2V0RmlsZXNpemVJbk1lZ2FCeXRlcyA9IChmaWxlbmFtZSkgPT4ge1xuICAgIGlmICh0aGlzLmFsbG93ZWQpIHtcbiAgICAgIGlmIChmcy5leGlzdHNTeW5jKGZpbGVuYW1lKSkge1xuICAgICAgICBjb25zdCBzdGF0cyA9IGZzLnN0YXRTeW5jKGZpbGVuYW1lKTtcbiAgICAgICAgY29uc3QgZmlsZVNpemVJbk1lZ2FCeXRlcyA9IHN0YXRzLnNpemU7XG5cbiAgICAgICAgcmV0dXJuIGZpbGVTaXplSW5NZWdhQnl0ZXMgLyAxMDAwMDAwLjA7XG4gICAgICB9XG4gICAgfVxuICAgIHJldHVybiAwO1xuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVjayBpZiBmaWxlIGV4aXN0XG4gICAqIEBwYXJhbSBmaWxlbmFtZVxuICAgKiBAcmV0dXJucyBib29sZWFuXG4gICAqL1xuICBjaGVja0ZpbGVFeGlzdCA9IChmaWxlbmFtZSkgPT4ge1xuICAgIHJldHVybiBmcy5leGlzdHNTeW5jKGZpbGVuYW1lKTtcbiAgfTtcblxuICByb3RhdGVGaWxlcyA9IChmaWxlOiBzdHJpbmcsIHBhdGhGaWxlOiBzdHJpbmcsIGxvZz86IHN0cmluZykgPT4ge1xuICAgIGlmICh0aGlzLmdldEZpbGVzaXplSW5NZWdhQnl0ZXMocGF0aEZpbGUpID49IE1BWF9NQl9MT0dfRklMRVMpIHtcbiAgICAgIGNvbnN0IGZpbGVFeHRlbnNpb24gPSBwYXRoLmV4dG5hbWUoZmlsZSk7XG4gICAgICBjb25zdCBmaWxlTmFtZSA9IHBhdGguYmFzZW5hbWUoZmlsZSwgZmlsZUV4dGVuc2lvbik7XG4gICAgICBmcy5yZW5hbWVTeW5jKFxuICAgICAgICBwYXRoRmlsZSxcbiAgICAgICAgYCR7V0FaVUhfREFUQV9MT0dTX0RJUkVDVE9SWV9QQVRIfS8ke2ZpbGVOYW1lfS0ke25ldyBEYXRlKCkuZ2V0VGltZSgpfSR7ZmlsZUV4dGVuc2lvbn1gXG4gICAgICApO1xuICAgICAgaWYgKGxvZykge1xuICAgICAgICBmcy53cml0ZUZpbGVTeW5jKHBhdGhGaWxlLCBsb2cgKyAnXFxuJyk7XG4gICAgICB9XG4gICAgfVxuICB9O1xuXG4gIC8qKlxuICAgKiBDaGVja3MgaWYgdGhlIHdhenVoYXBwLmxvZyBmaWxlIHNpemUgaXMgZ3JlYXRlciB0aGFuIDEwME1CLCBpZiBzbyBpdCByb3RhdGVzIHRoZSBmaWxlLlxuICAgKi9cbiAgcHJpdmF0ZSBjaGVja0ZpbGVzID0gKCkgPT4ge1xuICAgIGNyZWF0ZUxvZ0ZpbGVJZk5vdEV4aXN0cyh0aGlzLlJBV19MT0dTX1BBVEgpO1xuICAgIGNyZWF0ZUxvZ0ZpbGVJZk5vdEV4aXN0cyh0aGlzLlBMQUlOX0xPR1NfUEFUSCk7XG4gICAgaWYgKHRoaXMuYWxsb3dlZCkge1xuICAgICAgLy8gY2hlY2sgcmF3IGxvZyBmaWxlXG4gICAgICB0aGlzLnJvdGF0ZUZpbGVzKFxuICAgICAgICB0aGlzLlJBV19MT0dTX0ZJTEVfTkFNRSxcbiAgICAgICAgdGhpcy5SQVdfTE9HU19QQVRILFxuICAgICAgICBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgZGF0ZTogbmV3IERhdGUoKSxcbiAgICAgICAgICBsZXZlbDogJ2luZm8nLFxuICAgICAgICAgIGxvY2F0aW9uOiAnbG9nZ2VyJyxcbiAgICAgICAgICBtZXNzYWdlOiAnUm90YXRlZCBsb2cgZmlsZScsXG4gICAgICAgIH0pXG4gICAgICApO1xuICAgICAgLy8gY2hlY2sgbG9nIGZpbGVcbiAgICAgIHRoaXMucm90YXRlRmlsZXModGhpcy5QTEFJTl9MT0dTX0ZJTEVfTkFNRSwgdGhpcy5QTEFJTl9MT0dTX1BBVEgpO1xuICAgIH1cbiAgfTtcblxuICAvKipcbiAgICogR2V0IEN1cnJlbnQgRGF0ZVxuICAgKiBAcmV0dXJucyBzdHJpbmdcbiAgICovXG4gIHByaXZhdGUgeXl5eW1tZGQgPSAoKSA9PiB7XG4gICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcbiAgICBjb25zdCB5ID0gbm93LmdldEZ1bGxZZWFyKCk7XG4gICAgY29uc3QgbSA9IG5vdy5nZXRNb250aCgpICsgMTtcbiAgICBjb25zdCBkID0gbm93LmdldERhdGUoKTtcbiAgICBjb25zdCBzZWNvbmRzID0gbm93LmdldFNlY29uZHMoKTtcbiAgICBjb25zdCBtaW51dGVzID0gbm93LmdldE1pbnV0ZXMoKTtcbiAgICBjb25zdCBob3VyID0gbm93LmdldEhvdXJzKCk7XG4gICAgcmV0dXJuIGAke3l9LyR7bSA8IDEwID8gJzAnIDogJyd9JHttfS8ke2QgPCAxMCA/ICcwJyA6ICcnfSR7ZH0gJHtob3VyfToke21pbnV0ZXN9OiR7c2Vjb25kc31gO1xuICB9O1xuXG4gIC8qKlxuICAgKiBUaGlzIGZ1bmN0aW9uIGZpbHRlciBzb21lIGtub3duIGludGVyZmFjZXMgdG8gYXZvaWQgbG9nIGh1ZyBvYmplY3RzXG4gICAqIEBwYXJhbSBkYXRhIHN0cmluZyB8IG9iamVjdFxuICAgKiBAcmV0dXJucyB0aGUgZGF0YSBwYXJzZWRcbiAgICovXG4gIHByaXZhdGUgcGFyc2VEYXRhID0gKGRhdGE6IGFueSkgPT4ge1xuICAgIGxldCBwYXJzZWREYXRhID1cbiAgICAgIGRhdGEgaW5zdGFuY2VvZiBFcnJvclxuICAgICAgICA/IHtcbiAgICAgICAgICAgIG1lc3NhZ2U6IGRhdGEubWVzc2FnZSxcbiAgICAgICAgICAgIHN0YWNrOiBkYXRhLnN0YWNrLFxuICAgICAgICAgIH1cbiAgICAgICAgOiBkYXRhO1xuXG4gICAgLy8gd2hlbiBlcnJvciBpcyBBeGlvc0Vycm9yLCBpdCBleHRlbmRzIGZyb20gRXJyb3JcbiAgICBpZiAoZGF0YS5pc0F4aW9zRXJyb3IpIHtcbiAgICAgIGNvbnN0IHsgY29uZmlnIH0gPSBkYXRhO1xuICAgICAgcGFyc2VkRGF0YSA9IHtcbiAgICAgICAgLi4ucGFyc2VkRGF0YSxcbiAgICAgICAgY29uZmlnOiB7XG4gICAgICAgICAgdXJsOiBjb25maWcudXJsLFxuICAgICAgICAgIG1ldGhvZDogY29uZmlnLm1ldGhvZCxcbiAgICAgICAgICBkYXRhOiBjb25maWcuZGF0YSxcbiAgICAgICAgICBwYXJhbXM6IGNvbmZpZy5wYXJhbXMsXG4gICAgICAgIH0sXG4gICAgICB9O1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgcGFyc2VkRGF0YSA9PT0gJ29iamVjdCcpIHBhcnNlZERhdGEudG9TdHJpbmcgPSAoKSA9PiBKU09OLnN0cmluZ2lmeShwYXJzZWREYXRhKTtcblxuICAgIHJldHVybiBwYXJzZWREYXRhO1xuICB9O1xuXG4gIC8qKlxuICAgKiBNYWluIGZ1bmN0aW9uIHRvIGFkZCBhIG5ldyBsb2dcbiAgICogQHBhcmFtIHsqfSBsb2NhdGlvbiBGaWxlIHdoZXJlIHRoZSBsb2cgaXMgYmVpbmcgdGhyb3duXG4gICAqIEBwYXJhbSB7Kn0gZGF0YSBNZXNzYWdlIG9yIG9iamVjdCB0byBsb2dcbiAgICogQHBhcmFtIHsqfSBsZXZlbCBPcHRpb25hbCwgZGVmYXVsdCBpcyAnZXJyb3InXG4gICAqL1xuICAgYXN5bmMgbG9nKGxvY2F0aW9uOiBzdHJpbmcsIGRhdGE6IGFueSwgbGV2ZWw6IHN0cmluZykge1xuICAgIGNvbnN0IHBhcnNlZERhdGEgPSB0aGlzLnBhcnNlRGF0YShkYXRhKTtcbiAgICByZXR1cm4gdGhpcy5pbml0RGlyZWN0b3J5KClcbiAgICAgIC50aGVuKCgpID0+IHtcbiAgICAgICAgaWYgKHRoaXMuYWxsb3dlZCkge1xuICAgICAgICAgIHRoaXMuY2hlY2tGaWxlcygpO1xuICAgICAgICAgIGNvbnN0IHBsYWluTG9nRGF0YTogSVVJUGxhaW5Mb2dnZXJTZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIGxldmVsOiBsZXZlbCB8fCAnZXJyb3InLFxuICAgICAgICAgICAgbWVzc2FnZTogYCR7dGhpcy55eXl5bW1kZCgpfTogJHtsb2NhdGlvbiB8fCAnVW5rbm93biBvcmlnaW4nfTogJHtcbiAgICAgICAgICAgICAgcGFyc2VkRGF0YS50b1N0cmluZygpIHx8ICdBbiBlcnJvciBvY2N1cnJlZCdcbiAgICAgICAgICAgIH1gLFxuICAgICAgICAgIH07XG5cbiAgICAgICAgICB0aGlzLndhenVoUGxhaW5Mb2dnZXIubG9nKHBsYWluTG9nRGF0YSk7XG5cbiAgICAgICAgICBjb25zdCBsb2dEYXRhOiBJVUlMb2dnZXJTZXR0aW5ncyA9IHtcbiAgICAgICAgICAgIGRhdGU6IG5ldyBEYXRlKCksXG4gICAgICAgICAgICBsZXZlbDogbGV2ZWwgfHwgJ2Vycm9yJyxcbiAgICAgICAgICAgIGxvY2F0aW9uOiBsb2NhdGlvbiB8fCAnVW5rbm93biBvcmlnaW4nLFxuICAgICAgICAgICAgZGF0YTogcGFyc2VkRGF0YSB8fCAnQW4gZXJyb3Igb2NjdXJyZWQnLFxuICAgICAgICAgIH07XG5cbiAgICAgICAgICBpZiAodHlwZW9mIGRhdGEgPT0gJ3N0cmluZycpIHtcbiAgICAgICAgICAgIGxvZ0RhdGEubWVzc2FnZSA9IHBhcnNlZERhdGE7XG4gICAgICAgICAgICBkZWxldGUgbG9nRGF0YS5kYXRhO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIHRoaXMud2F6dWhMb2dnZXIubG9nKGxvZ0RhdGEpO1xuICAgICAgICB9XG4gICAgICB9KVxuICAgICAgLmNhdGNoKChlcnJvcikgPT4ge1xuICAgICAgICBjb25zb2xlLmVycm9yKGBDYW5ub3QgY3JlYXRlIHRoZSBsb2dzIGRpcmVjdG9yeSBkdWUgdG86XFxuJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWApO1xuICAgICAgICB0aHJvdyBlcnJvcjtcbiAgICAgIH0pO1xuICB9XG59XG4iXX0=