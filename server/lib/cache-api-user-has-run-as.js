"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.CacheInMemoryAPIUserAllowRunAs = exports.API_USER_STATUS_RUN_AS = exports.APIUserAllowRunAs = void 0;

var ApiInterceptor = _interopRequireWildcard(require("./api-interceptor"));

var _manageHosts = require("./manage-hosts");

var _logger = require("./logger");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

/*
 * Wazuh app - Service which caches the API user allow run as
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// Private variable to save the cache
const _cache = {}; // Export an interface which interacts with the private cache object

const CacheInMemoryAPIUserAllowRunAs = {
  // Set an entry with API ID, username and allow_run_as
  set: (apiID, username, allow_run_as) => {
    if (!_cache[apiID]) {
      _cache[apiID] = {}; // Create a API ID entry if it doesn't exist in cache object
    }

    ;
    _cache[apiID][username] = allow_run_as;
  },
  // Get the value of an entry with API ID and username from cache
  get: (apiID, username) => _cache[apiID] && typeof _cache[apiID][username] !== 'undefined' ? _cache[apiID][username] : API_USER_STATUS_RUN_AS.ALL_DISABLED,
  // Check if it exists the API ID and username in the cache
  has: (apiID, username) => _cache[apiID] && typeof _cache[apiID][username] !== 'undefined' ? true : false
};
exports.CacheInMemoryAPIUserAllowRunAs = CacheInMemoryAPIUserAllowRunAs;
const manageHosts = new _manageHosts.ManageHosts();
const APIUserAllowRunAs = {
  async check(apiId) {
    try {
      const api = await manageHosts.getHostById(apiId);
      (0, _logger.log)('APIUserAllowRunAs:check', `Check if API user ${api.username} (${apiId}) has run_as`, 'debug'); // Check if api.run_as is false or undefined, then it set to false in cache

      if (!api.run_as) {
        CacheInMemoryAPIUserAllowRunAs.set(apiId, api.username, API_USER_STATUS_RUN_AS.HOST_DISABLED);
      }

      ; // Check if the API user is cached and returns it

      if (CacheInMemoryAPIUserAllowRunAs.has(apiId, api.username)) {
        return CacheInMemoryAPIUserAllowRunAs.get(apiId, api.username);
      }

      ;
      const response = await ApiInterceptor.requestAsInternalUser('get', '/security/users/me', {}, {
        apiHostID: apiId
      });
      const statusUserAllowRunAs = response.data.data.affected_items[0].allow_run_as ? API_USER_STATUS_RUN_AS.ENABLED : API_USER_STATUS_RUN_AS.USER_NOT_ALLOWED; // Cache the run_as for the API user

      CacheInMemoryAPIUserAllowRunAs.set(apiId, api.username, statusUserAllowRunAs);
      return statusUserAllowRunAs;
    } catch (error) {
      (0, _logger.log)('APIUserAllowRunAs:check', error.message || error);
      return API_USER_STATUS_RUN_AS.ALL_DISABLED;
    }
  },

  async canUse(apiId) {
    const ApiUserCanUseStatus = await APIUserAllowRunAs.check(apiId);

    if (ApiUserCanUseStatus === API_USER_STATUS_RUN_AS.USER_NOT_ALLOWED) {
      const api = await manageHosts.getHostById(apiId);
      throw new Error(`API with host ID [${apiId}] misconfigured. The Wazuh API user [${api.username}] is not allowed to use [run_as]. Allow it in the user configuration or set [run_as] host setting with [false] value.`);
    }

    return ApiUserCanUseStatus;
  }

};
/**
 * @example
 *   HOST = set in wazuh.yml config
 *   USER = set in user interface
 *
 * ALL_DISABLED
 *   binary 00 = decimal 0 ---> USER 0 y HOST 0
 * 
 * USER_NOT_ALLOWED
 *   binary 01 = decimal 1 ---> USER 0 y HOST 1
 * 
 * HOST_DISABLED
 *   binary 10 = decimal 2 ---> USER 1 y HOST 0
 * 
 * ENABLED
 *   binary 11 = decimal 3 ---> USER 1 y HOST 1
 */

exports.APIUserAllowRunAs = APIUserAllowRunAs;
let API_USER_STATUS_RUN_AS;
exports.API_USER_STATUS_RUN_AS = API_USER_STATUS_RUN_AS;

(function (API_USER_STATUS_RUN_AS) {
  API_USER_STATUS_RUN_AS[API_USER_STATUS_RUN_AS["ALL_DISABLED"] = 0] = "ALL_DISABLED";
  API_USER_STATUS_RUN_AS[API_USER_STATUS_RUN_AS["USER_NOT_ALLOWED"] = 1] = "USER_NOT_ALLOWED";
  API_USER_STATUS_RUN_AS[API_USER_STATUS_RUN_AS["HOST_DISABLED"] = 2] = "HOST_DISABLED";
  API_USER_STATUS_RUN_AS[API_USER_STATUS_RUN_AS["ENABLED"] = 3] = "ENABLED";
})(API_USER_STATUS_RUN_AS || (exports.API_USER_STATUS_RUN_AS = API_USER_STATUS_RUN_AS = {}));
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImNhY2hlLWFwaS11c2VyLWhhcy1ydW4tYXMudHMiXSwibmFtZXMiOlsiX2NhY2hlIiwiQ2FjaGVJbk1lbW9yeUFQSVVzZXJBbGxvd1J1bkFzIiwic2V0IiwiYXBpSUQiLCJ1c2VybmFtZSIsImFsbG93X3J1bl9hcyIsImdldCIsIkFQSV9VU0VSX1NUQVRVU19SVU5fQVMiLCJBTExfRElTQUJMRUQiLCJoYXMiLCJtYW5hZ2VIb3N0cyIsIk1hbmFnZUhvc3RzIiwiQVBJVXNlckFsbG93UnVuQXMiLCJjaGVjayIsImFwaUlkIiwiYXBpIiwiZ2V0SG9zdEJ5SWQiLCJydW5fYXMiLCJIT1NUX0RJU0FCTEVEIiwicmVzcG9uc2UiLCJBcGlJbnRlcmNlcHRvciIsInJlcXVlc3RBc0ludGVybmFsVXNlciIsImFwaUhvc3RJRCIsInN0YXR1c1VzZXJBbGxvd1J1bkFzIiwiZGF0YSIsImFmZmVjdGVkX2l0ZW1zIiwiRU5BQkxFRCIsIlVTRVJfTk9UX0FMTE9XRUQiLCJlcnJvciIsIm1lc3NhZ2UiLCJjYW5Vc2UiLCJBcGlVc2VyQ2FuVXNlU3RhdHVzIiwiRXJyb3IiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFXQTs7QUFDQTs7QUFDQTs7Ozs7O0FBYkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUlBO0FBQ0EsTUFBTUEsTUFBTSxHQUFHLEVBQWYsQyxDQUVBOztBQUNPLE1BQU1DLDhCQUE4QixHQUFHO0FBQzVDO0FBQ0FDLEVBQUFBLEdBQUcsRUFBRSxDQUFDQyxLQUFELEVBQWdCQyxRQUFoQixFQUFrQ0MsWUFBbEMsS0FBa0U7QUFDckUsUUFBRyxDQUFDTCxNQUFNLENBQUNHLEtBQUQsQ0FBVixFQUFrQjtBQUNoQkgsTUFBQUEsTUFBTSxDQUFDRyxLQUFELENBQU4sR0FBZ0IsRUFBaEIsQ0FEZ0IsQ0FDSTtBQUNyQjs7QUFBQTtBQUNESCxJQUFBQSxNQUFNLENBQUNHLEtBQUQsQ0FBTixDQUFjQyxRQUFkLElBQTBCQyxZ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OztBQUNELFdBQU8yQixtQkFBUDtBQUNEOztBQXBDOEIsQ0FBMUI7QUF1Q1A7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0lBQ1l4QixzQjs7O1dBQUFBLHNCO0FBQUFBLEVBQUFBLHNCLENBQUFBLHNCO0FBQUFBLEVBQUFBLHNCLENBQUFBLHNCO0FBQUFBLEVBQUFBLHNCLENBQUFBLHNCO0FBQUFBLEVBQUFBLHNCLENBQUFBLHNCO0dBQUFBLHNCLHNDQUFBQSxzQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBTZXJ2aWNlIHdoaWNoIGNhY2hlcyB0aGUgQVBJIHVzZXIgYWxsb3cgcnVuIGFzXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0ICogYXMgQXBpSW50ZXJjZXB0b3IgZnJvbSAnLi9hcGktaW50ZXJjZXB0b3InO1xuaW1wb3J0IHsgTWFuYWdlSG9zdHMgfSBmcm9tICcuL21hbmFnZS1ob3N0cyc7XG5pbXBvcnQgeyBsb2cgfSBmcm9tICcuL2xvZ2dlcic7XG4vLyBQcml2YXRlIHZhcmlhYmxlIHRvIHNhdmUgdGhlIGNhY2hlXG5jb25zdCBfY2FjaGUgPSB7fTtcblxuLy8gRXhwb3J0IGFuIGludGVyZmFjZSB3aGljaCBpbnRlcmFjdHMgd2l0aCB0aGUgcHJpdmF0ZSBjYWNoZSBvYmplY3RcbmV4cG9ydCBjb25zdCBDYWNoZUluTWVtb3J5QVBJVXNlckFsbG93UnVuQXMgPSB7XG4gIC8vIFNldCBhbiBlbnRyeSB3aXRoIEFQSSBJRCwgdXNlcm5hbWUgYW5kIGFsbG93X3J1bl9hc1xuICBzZXQ6IChhcGlJRDogc3RyaW5nLCB1c2VybmFtZTogc3RyaW5nLCBhbGxvd19ydW5fYXMgOiBudW1iZXIpOiB2b2lkID0+IHtcbiAgICBpZighX2NhY2hlW2FwaUlEXSl7XG4gICAgICBfY2FjaGVbYXBpSURdID0ge307IC8vIENyZWF0ZSBhIEFQSSBJRCBlbnRyeSBpZiBpdCBkb2Vzbid0IGV4aXN0IGluIGNhY2hlIG9iamVjdFxuICAgIH07XG4gICAgX2NhY2hlW2FwaUlEXVt1c2VybmFtZV0gPSBhbGxvd19ydW5fYXM7XG4gIH0sXG4gIC8vIEdldCB0aGUgdmFsdWUgb2YgYW4gZW50cnkgd2l0aCBBUEkgSUQgYW5kIHVzZXJuYW1lIGZyb20gY2FjaGVcbiAgZ2V0OiAoYXBpSUQ6IHN0cmluZywgdXNlcm5hbWU6IHN0cmluZyk6IG51bWJlciA9PiAgX2NhY2hlW2FwaUlEXSAmJiB0eXBlb2YgX2NhY2hlW2FwaUlEXVt1c2VybmFtZV0gIT09ICd1bmRlZmluZWQnID8gX2NhY2hlW2FwaUlEXVt1c2VybmFtZV0gOiBBUElfVVNFUl9TVEFUVVNfUlVOX0FTLkFMTF9ESVNBQkxFRCxcbiAgLy8gQ2hlY2sgaWYgaXQgZXhpc3RzIHRoZSBBUEkgSUQgYW5kIHVzZXJuYW1lIGluIHRoZSBjYWNoZVxuICBoYXM6IChhcGlJRDogc3RyaW5nLCB1c2VybmFtZTogc3RyaW5nKTogYm9vbGVhbiA9PiBfY2FjaGVbYXBpSURdICYmIHR5cGVvZiBfY2FjaGVbYXBpSURdW3VzZXJuYW1lXSAhPT0gJ3VuZGVmaW5lZCcgPyB0cnVlIDogZmFsc2Vcbn07XG5cbmNvbnN0IG1hbmFnZUhvc3RzID0gbmV3IE1hbmFnZUhvc3RzKCk7XG5cbmV4cG9ydCBjb25zdCBBUElVc2VyQWxsb3dSdW5BcyA9IHtcbiAgYXN5bmMgY2hlY2soYXBpSWQ6IHN0cmluZyk6IFByb21pc2U8bnVtYmVyPntcbiAgICB0cnl7XG4gICAgICBjb25zdCBhcGkgPSBhd2FpdCBtYW5hZ2VIb3N0cy5nZXRIb3N0QnlJZChhcGlJZCk7XG4gICAgICBsb2coJ0FQSVVzZXJBbGxvd1J1bkFzOmNoZWNrJywgYENoZWNrIGlmIEFQSSB1c2VyICR7YXBpLnVzZXJuYW1lfSAoJHthcGlJZH0pIGhhcyBydW5fYXNgLCAnZGVidWcnKTtcbiAgICAgIC8vIENoZWNrIGlmIGFwaS5ydW5fYXMgaXMgZmFsc2Ugb3IgdW5kZWZpbmVkLCB0aGVuIGl0IHNldCB0byBmYWxzZSBpbiBjYWNoZVxuICAgICAgaWYoIWFwaS5ydW5fYXMpe1xuICAgICAgICBDYWNoZUluTWVtb3J5QVBJVXNlckFsbG93UnVuQXMuc2V0KGFwaUlkLCBhcGkudXNlcm5hbWUsIEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuSE9TVF9ESVNBQkxFRCk7XG4gICAgICB9O1xuICAgICAgLy8gQ2hlY2sgaWYgdGhlIEFQSSB1c2VyIGlzIGNhY2hlZCBhbmQgcmV0dXJucyBpdFxuICAgICAgaWYoQ2FjaGVJbk1lbW9yeUFQSVVzZXJBbGxvd1J1bkFzLmhhcyhhcGlJZCwgYXBpLnVzZXJuYW1lKSl7XG4gICAgICAgIHJldHVybiBDYWNoZUluTWVtb3J5QVBJVXNlckFsbG93UnVuQXMuZ2V0KGFwaUlkLCBhcGkudXNlcm5hbWUpO1xuICAgICAgfTtcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgQXBpSW50ZXJjZXB0b3IucmVxdWVzdEFzSW50ZXJuYWxVc2VyKFxuICAgICAgICAnZ2V0JyxcbiAgICAgICAgJy9zZWN1cml0eS91c2Vycy9tZScsXG4gICAgICAgIHt9LFxuICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgKTtcbiAgICAgIGNvbnN0IHN0YXR1c1VzZXJBbGxvd1J1bkFzID0gcmVzcG9uc2UuZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdLmFsbG93X3J1bl9hcyA/IEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuRU5BQkxFRCA6IEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuVVNFUl9OT1RfQUxMT1dFRDtcblxuICAgICAgLy8gQ2FjaGUgdGhlIHJ1bl9hcyBmb3IgdGhlIEFQSSB1c2VyXG4gICAgICBDYWNoZUluTWVtb3J5QVBJVXNlckFsbG93UnVuQXMuc2V0KGFwaUlkLCBhcGkudXNlcm5hbWUsIHN0YXR1c1VzZXJBbGxvd1J1bkFzKTtcbiAgICAgIHJldHVybiBzdGF0dXNVc2VyQWxsb3dSdW5BcztcbiAgICB9Y2F0Y2goZXJyb3Ipe1xuICAgICAgbG9nKCdBUElVc2VyQWxsb3dSdW5BczpjaGVjaycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuQUxMX0RJU0FCTEVEO1xuICAgIH1cbiAgfSxcbiAgYXN5bmMgY2FuVXNlKGFwaUlkOiBzdHJpbmcpOiBQcm9taXNlPG51bWJlciB8IG5ldmVyPntcbiAgICBjb25zdCBBcGlVc2VyQ2FuVXNlU3RhdHVzID0gYXdhaXQgQVBJVXNlckFsbG93UnVuQXMuY2hlY2soYXBpSWQpO1xuICAgIGlmKEFwaVVzZXJDYW5Vc2VTdGF0dXMgPT09IEFQSV9VU0VSX1NUQVRVU19SVU5fQVMuVVNFUl9OT1RfQUxMT1dFRCl7XG4gICAgICBjb25zdCBhcGkgPSBhd2FpdCBtYW5hZ2VIb3N0cy5nZXRIb3N0QnlJZChhcGlJZCk7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYEFQSSB3aXRoIGhvc3QgSUQgWyR7YXBpSWR9XSBtaXNjb25maWd1cmVkLiBUaGUgV2F6dWggQVBJIHVzZXIgWyR7YXBpLnVzZXJuYW1lfV0gaXMgbm90IGFsbG93ZWQgdG8gdXNlIFtydW5fYXNdLiBBbGxvdyBpdCBpbiB0aGUgdXNlciBjb25maWd1cmF0aW9uIG9yIHNldCBbcnVuX2FzXSBob3N0IHNldHRpbmcgd2l0aCBbZmFsc2VdIHZhbHVlLmApO1xuICAgIH1cbiAgICByZXR1cm4gQXBpVXNlckNhblVzZVN0YXR1cztcbiAgfVxufTtcblxuLyoqXG4gKiBAZXhhbXBsZVxuICogICBIT1NUID0gc2V0IGluIHdhenVoLnltbCBjb25maWdcbiAqICAgVVNFUiA9IHNldCBpbiB1c2VyIGludGVyZmFjZVxuICpcbiAqIEFMTF9ESVNBQkxFRFxuICogICBiaW5hcnkgMDAgPSBkZWNpbWFsIDAgLS0tPiBVU0VSIDAgeSBIT1NUIDBcbiAqIFxuICogVVNFUl9OT1RfQUxMT1dFRFxuICogICBiaW5hcnkgMDEgPSBkZWNpbWFsIDEgLS0tPiBVU0VSIDAgeSBIT1NUIDFcbiAqIFxuICogSE9TVF9ESVNBQkxFRFxuICogICBiaW5hcnkgMTAgPSBkZWNpbWFsIDIgLS0tPiBVU0VSIDEgeSBIT1NUIDBcbiAqIFxuICogRU5BQkxFRFxuICogICBiaW5hcnkgMTEgPSBkZWNpbWFsIDMgLS0tPiBVU0VSIDEgeSBIT1NUIDFcbiAqL1xuZXhwb3J0IGVudW0gQVBJX1VTRVJfU1RBVFVTX1JVTl9BU3tcbiAgQUxMX0RJU0FCTEVEID0gMCwgLy8gV2F6dWggSE9TVCBhbmQgVVNFUiBBUEkgdXNlciBjb25maWd1cmVkIHdpdGggcnVuX2FzPWZhbHNlIG9yIHVuZGVmaW5lZFxuICBVU0VSX05PVF9BTExPV0VEID0gMSwgLy8gV2F6dWggSE9TVCBBUEkgdXNlciBjb25maWd1cmVkIHdpdGggcnVuX2FzID0gVFJVRSBpbiB3YXp1aC55bWwgYnV0IGl0IGhhcyBub3QgcnVuX2FzIGluIFdhenVoIEFQSVxuICBIT1NUX0RJU0FCTEVEID0gMiwgLy8gV2F6dWggSE9TVCBBUEkgdXNlciBjb25maWd1cmVkIHdpdGggcnVuX2FzPWZhbHNlIGluIHdhenVoLnltbCBidXQgaXQgaGFzIG5vdCBydW5fYXMgaW4gV2F6dWggQVBJXG4gIEVOQUJMRUQgPSAzIC8vIFdhenVoIEFQSSB1c2VyIGNvbmZpZ3VyZWQgd2l0aCBydW5fYXM9dHJ1ZSBhbmQgYWxsb3cgcnVuX2FzXG59XG4iXX0=