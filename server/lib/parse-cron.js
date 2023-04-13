"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.parseCron = parseCron;

var _logger = require("./logger");

var _nodeCron = _interopRequireDefault(require("node-cron"));

var _constants = require("../../common/constants");

/*
 * Wazuh app - Module to transform seconds interval to cron readable format
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
function parseCron(interval) {
  try {
    if (!interval) throw new Error('Interval not found');
    const intervalToNumber = parseInt(interval);

    if (!intervalToNumber || typeof intervalToNumber !== 'number') {
      throw new Error('Interval not valid');
    }

    ;

    if (intervalToNumber < 60) {
      // 60 seconds / 1 minute
      throw new Error('Interval too low');
    }

    ;

    if (intervalToNumber >= 84600) {
      throw new Error('Interval too high');
    }

    const minutes = parseInt(intervalToNumber / 60);
    const cronstr = `0 */${minutes} * * * *`;

    if (!_nodeCron.default.validate(cronstr)) {
      throw new Error('Generated cron expression not valid for node-cron module');
    }

    (0, _logger.log)('cron:parse-interval', `Using the next interval: ${cronstr}`, 'debug');
    return cronstr;
  } catch (error) {
    (0, _logger.log)('cron:parse-interval', `Using default value ${_constants.WAZUH_MONITORING_DEFAULT_CRON_FREQ} due to: ${error.message || error}`);
    return _constants.WAZUH_MONITORING_DEFAULT_CRON_FREQ;
  }
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInBhcnNlLWNyb24udHMiXSwibmFtZXMiOlsicGFyc2VDcm9uIiwiaW50ZXJ2YWwiLCJFcnJvciIsImludGVydmFsVG9OdW1iZXIiLCJwYXJzZUludCIsIm1pbnV0ZXMiLCJjcm9uc3RyIiwiY3JvbiIsInZhbGlkYXRlIiwiZXJyb3IiLCJXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfQ1JPTl9GUkVRIiwibWVzc2FnZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7O0FBV0E7O0FBQ0E7O0FBQ0E7O0FBYkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUtPLFNBQVNBLFNBQVQsQ0FBbUJDLFFBQW5CLEVBQXFDO0FBQzFDLE1BQUk7QUFDRixRQUFJLENBQUNBLFFBQUwsRUFBZSxNQUFNLElBQUlDLEtBQUosQ0FBVSxvQkFBVixDQUFOO0FBRWYsVUFBTUMsZ0JBQWdCLEdBQUdDLFFBQVEsQ0FBQ0gsUUFBRCxDQUFqQzs7QUFFQSxRQUFJLENBQUNFLGdCQUFELElBQXFCLE9BQU9BLGdCQUFQLEtBQTRCLFFBQXJELEVBQThEO0FBQzVELFlBQU0sSUFBSUQsS0FBSixDQUFVLG9CQUFWLENBQU47QUFDRDs7QUFBQTs7QUFDRCxRQUFJQyxnQkFBZ0IsR0FBRyxFQUF2QixFQUEwQjtBQUFFO0FBQzFCLFlBQU0sSUFBSUQsS0FBSixDQUFVLGtCQUFWLENBQU47QUFDRDs7QUFBQTs7QUFDRCxRQUFJQyxnQkFBZ0IsSUFBSSxLQUF4QixFQUE4QjtBQUM1QixZQUFNLElBQUlELEtBQUosQ0FBVSxtQkFBVixDQUFOO0FBQ0Q7O0FBRUQsVUFBTUcsT0FBTyxHQUFHRCxRQUFRLENBQUNELGdCQUFnQixHQUFHLEVBQXBCLENBQXhCO0FBRUEsVUFBTUcsT0FBTyxHQUFJLE9BQU1ELE9BQVEsVUFBL0I7O0FBRUEsUUFBSSxDQUFDRSxrQkFBS0MsUUFBTCxDQUFjRixPQUFkLENBQUwsRUFBNEI7QUFDMUIsWUFBTSxJQUFJSixLQUFKLENBQ0osMERBREksQ0FBTjtBQUdEOztBQUNELHFCQUFJLHFCQUFKLEVBQTRCLDRCQUEyQkksT0FBUSxFQUEvRCxFQUFrRSxPQUFsRTtBQUNBLFdBQU9BLE9BQVA7QUFDRCxHQTFCRCxDQTBCRSxPQUFPRyxLQUFQLEVBQWM7QUFDZCxxQkFDRSxxQkFERixFQUVHLHVCQUFzQkMsNkNBQW1DLFlBQVdELEtBQUssQ0FBQ0UsT0FBTixJQUFpQkYsS0FBTSxFQUY5RjtBQUlBLFdBQU9DLDZDQUFQO0FBQ0Q7QUFDRiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgdG8gdHJhbnNmb3JtIHNlY29uZHMgaW50ZXJ2YWwgdG8gY3JvbiByZWFkYWJsZSBmb3JtYXRcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5pbXBvcnQgeyBsb2cgfSBmcm9tICcuL2xvZ2dlcic7XG5pbXBvcnQgY3JvbiBmcm9tICdub2RlLWNyb24nO1xuaW1wb3J0IHsgV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0NST05fRlJFUSB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuXG5leHBvcnQgZnVuY3Rpb24gcGFyc2VDcm9uKGludGVydmFsOiBzdHJpbmcpIHtcbiAgdHJ5IHtcbiAgICBpZiAoIWludGVydmFsKSB0aHJvdyBuZXcgRXJyb3IoJ0ludGVydmFsIG5vdCBmb3VuZCcpO1xuXG4gICAgY29uc3QgaW50ZXJ2YWxUb051bWJlciA9IHBhcnNlSW50KGludGVydmFsKTtcblxuICAgIGlmICghaW50ZXJ2YWxUb051bWJlciB8fCB0eXBlb2YgaW50ZXJ2YWxUb051bWJlciAhPT0gJ251bWJlcicpe1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbnRlcnZhbCBub3QgdmFsaWQnKTtcbiAgICB9O1xuICAgIGlmIChpbnRlcnZhbFRvTnVtYmVyIDwgNjApeyAvLyA2MCBzZWNvbmRzIC8gMSBtaW51dGVcbiAgICAgIHRocm93IG5ldyBFcnJvcignSW50ZXJ2YWwgdG9vIGxvdycpO1xuICAgIH07XG4gICAgaWYgKGludGVydmFsVG9OdW1iZXIgPj0gODQ2MDApe1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbnRlcnZhbCB0b28gaGlnaCcpO1xuICAgIH0gXG5cbiAgICBjb25zdCBtaW51dGVzID0gcGFyc2VJbnQoaW50ZXJ2YWxUb051bWJlciAvIDYwKTtcblxuICAgIGNvbnN0IGNyb25zdHIgPSBgMCAqLyR7bWludXRlc30gKiAqICogKmA7XG5cbiAgICBpZiAoIWNyb24udmFsaWRhdGUoY3JvbnN0cikpe1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICAnR2VuZXJhdGVkIGNyb24gZXhwcmVzc2lvbiBub3QgdmFsaWQgZm9yIG5vZGUtY3JvbiBtb2R1bGUnXG4gICAgICApO1xuICAgIH1cbiAgICBsb2coJ2Nyb246cGFyc2UtaW50ZXJ2YWwnLCBgVXNpbmcgdGhlIG5leHQgaW50ZXJ2YWw6ICR7Y3JvbnN0cn1gLCAnZGVidWcnKTtcbiAgICByZXR1cm4gY3JvbnN0cjtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBsb2coXG4gICAgICAnY3JvbjpwYXJzZS1pbnRlcnZhbCcsXG4gICAgICBgVXNpbmcgZGVmYXVsdCB2YWx1ZSAke1dBWlVIX01PTklUT1JJTkdfREVGQVVMVF9DUk9OX0ZSRVF9IGR1ZSB0bzogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWBcbiAgICApO1xuICAgIHJldHVybiBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfQ1JPTl9GUkVRO1xuICB9XG59XG4iXX0=