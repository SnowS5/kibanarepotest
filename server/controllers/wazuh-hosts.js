"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhHostsCtrl = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _constants = require("../../common/constants");

var _cacheApiUserHasRunAs = require("../lib/cache-api-user-has-run-as");

var _errorResponse = require("../lib/error-response");

var _logger = require("../lib/logger");

var _manageHosts = require("../lib/manage-hosts");

var _updateRegistry = require("../lib/update-registry");

/*
 * Wazuh app - Class for Wazuh-API functions
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
class WazuhHostsCtrl {
  constructor() {
    (0, _defineProperty2.default)(this, "manageHosts", void 0);
    (0, _defineProperty2.default)(this, "updateRegistry", void 0);
    this.manageHosts = new _manageHosts.ManageHosts();
    this.updateRegistry = new _updateRegistry.UpdateRegistry();
  }
  /**
   * This get all hosts entries in the wazuh.yml and the related info in the wazuh-registry.json
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * API entries or ErrorResponse
   */


  async getHostsEntries(context, request, response) {
    try {
      const removePassword = true;
      const hosts = await this.manageHosts.getHosts();
      const registry = await this.updateRegistry.getHosts();
      const result = await this.joinHostRegistry(hosts, registry, removePassword);
      return response.ok({
        body: result
      });
    } catch (error) {
      if (error && error.message && ['ENOENT: no such file or directory', _constants.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH].every(text => error.message.includes(text))) {
        return response.badRequest({
          body: {
            message: `Error getting the hosts entries: The \'${_constants.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH}\' directory could not exist in your ${_constants.PLUGIN_PLATFORM_NAME} installation.
            If this doesn't exist, create it and give the permissions 'sudo mkdir ${_constants.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH};sudo chown -R ${_constants.PLUGIN_PLATFORM_INSTALLATION_USER}:${_constants.PLUGIN_PLATFORM_INSTALLATION_USER_GROUP} ${_constants.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH}'. After, restart the ${_constants.PLUGIN_PLATFORM_NAME} service.`
          }
        });
      }

      (0, _logger.log)('wazuh-hosts:getHostsEntries', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 2001, 500, response);
    }
  }
  /**
   * Joins the hosts with the related information in the registry
   * @param {Object} hosts
   * @param {Object} registry
   * @param {Boolean} removePassword
   */


  async joinHostRegistry(hosts, registry, removePassword = true) {
    try {
      if (!Array.isArray(hosts)) {
        throw new Error('Hosts configuration error in wazuh.yml');
      }

      return await Promise.all(hosts.map(async h => {
        const id = Object.keys(h)[0];
        const api = Object.assign(h[id], {
          id: id
        });
        const host = Object.assign(api, registry[id]); // Add to run_as from API user. Use the cached value or get it doing a request

        host.allow_run_as = await _cacheApiUserHasRunAs.APIUserAllowRunAs.check(id);

        if (removePassword) {
          delete host.password;
          delete host.token;
        }

        ;
        return host;
      }));
    } catch (error) {
      throw new Error(error);
    }
  }
  /**
   * This update an API hostname
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * Status response or ErrorResponse
   */


  async updateClusterInfo(context, request, response) {
    try {
      const {
        id
      } = request.params;
      const {
        cluster_info
      } = request.body;
      await this.updateRegistry.updateClusterInfo(id, cluster_info);
      (0, _logger.log)('wazuh-hosts:updateClusterInfo', `API entry ${id} hostname updated`, 'debug');
      return response.ok({
        body: {
          statusCode: 200,
          message: 'ok'
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-hosts:updateClusterInfo', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Could not update data in wazuh-registry.json due to ${error.message || error}`, 2012, 500, response);
    }
  }
  /**
   * Remove the orphan host entries in the registry
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   */


  async removeOrphanEntries(context, request, response) {
    try {
      const {
        entries
      } = request.body;
      (0, _logger.log)('wazuh-hosts:cleanRegistry', 'Cleaning registry', 'debug');
      await this.updateRegistry.removeOrphanEntries(entries);
      return response.ok({
        body: {
          statusCode: 200,
          message: 'ok'
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-hosts:cleanRegistry', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Could not clean entries in the wazuh-registry.json due to ${error.message || error}`, 2013, 500, response);
    }
  }

}

exports.WazuhHostsCtrl = WazuhHostsCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLWhvc3RzLnRzIl0sIm5hbWVzIjpbIldhenVoSG9zdHNDdHJsIiwiY29uc3RydWN0b3IiLCJtYW5hZ2VIb3N0cyIsIk1hbmFnZUhvc3RzIiwidXBkYXRlUmVnaXN0cnkiLCJVcGRhdGVSZWdpc3RyeSIsImdldEhvc3RzRW50cmllcyIsImNvbnRleHQiLCJyZXF1ZXN0IiwicmVzcG9uc2UiLCJyZW1vdmVQYXNzd29yZCIsImhvc3RzIiwiZ2V0SG9zdHMiLCJyZWdpc3RyeSIsInJlc3VsdCIsImpvaW5Ib3N0UmVnaXN0cnkiLCJvayIsImJvZHkiLCJlcnJvciIsIm1lc3NhZ2UiLCJXQVpVSF9EQVRBX1BMVUdJTl9QTEFURk9STV9CQVNFX0FCU09MVVRFX1BBVEgiLCJldmVyeSIsInRleHQiLCJpbmNsdWRlcyIsImJhZFJlcXVlc3QiLCJQTFVHSU5fUExBVEZPUk1fTkFNRSIsIlBMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUiIsIlBMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUl9HUk9VUCIsIkFycmF5IiwiaXNBcnJheSIsIkVycm9yIiwiUHJvbWlzZSIsImFsbCIsIm1hcCIsImgiLCJpZCIsIk9iamVjdCIsImtleXMiLCJhcGkiLCJhc3NpZ24iLCJob3N0IiwiYWxsb3dfcnVuX2FzIiwiQVBJVXNlckFsbG93UnVuQXMiLCJjaGVjayIsInBhc3N3b3JkIiwidG9rZW4iLCJ1cGRhdGVDbHVzdGVySW5mbyIsInBhcmFtcyIsImNsdXN0ZXJfaW5mbyIsInN0YXR1c0NvZGUiLCJyZW1vdmVPcnBoYW5FbnRyaWVzIiwiZW50cmllcyJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7QUFhQTs7QUFNQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUF2QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQWVPLE1BQU1BLGNBQU4sQ0FBcUI7QUFHMUJDLEVBQUFBLFdBQVcsR0FBRztBQUFBO0FB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SUFBNUI7QUFDQSx1QkFBSSwyQkFBSixFQUFpQyxtQkFBakMsRUFBc0QsT0FBdEQ7QUFDQSxZQUFNLEtBQUtiLGNBQUwsQ0FBb0I4QyxtQkFBcEIsQ0FBd0NDLE9BQXhDLENBQU47QUFDQSxhQUFPMUMsUUFBUSxDQUFDTyxFQUFULENBQVk7QUFDakJDLFFBQUFBLElBQUksRUFBRTtBQUFFZ0MsVUFBQUEsVUFBVSxFQUFFLEdBQWQ7QUFBbUI5QixVQUFBQSxPQUFPLEVBQUU7QUFBNUI7QUFEVyxPQUFaLENBQVA7QUFHRCxLQVBELENBT0UsT0FBT0QsS0FBUCxFQUFjO0FBQ2QsdUJBQUksMkJBQUosRUFBaUNBLEtBQUssQ0FBQ0MsT0FBTixJQUFpQkQsS0FBbEQ7QUFDQSxhQUFPLGtDQUNKLDZEQUE0REEsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUFNLEVBRC9FLEVBRUwsSUFGSyxFQUdMLEdBSEssRUFJTFQsUUFKSyxDQUFQO0FBTUQ7QUFDRjs7QUF4SHlCIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIENsYXNzIGZvciBXYXp1aC1BUEkgZnVuY3Rpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG5pbXBvcnQgeyBLaWJhbmFSZXF1ZXN0LCBLaWJhbmFSZXNwb25zZUZhY3RvcnksIFJlcXVlc3RIYW5kbGVyQ29udGV4dCB9IGZyb20gJ3NyYy9jb3JlL3NlcnZlcic7XG5pbXBvcnQge1xuICBQTFVHSU5fUExBVEZPUk1fSU5TVEFMTEFUSU9OX1VTRVIsXG4gIFBMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUl9HUk9VUCxcbiAgUExVR0lOX1BMQVRGT1JNX05BTUUsXG4gIFdBWlVIX0RBVEFfUExVR0lOX1BMQVRGT1JNX0JBU0VfQUJTT0xVVEVfUEFUSCxcbn0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgeyBBUElVc2VyQWxsb3dSdW5BcyB9IGZyb20gJy4uL2xpYi9jYWNoZS1hcGktdXNlci1oYXMtcnVuLWFzJztcbmltcG9ydCB7IEVycm9yUmVzcG9uc2UgfSBmcm9tICcuLi9saWIvZXJyb3ItcmVzcG9uc2UnO1xuaW1wb3J0IHsgbG9nIH0gZnJvbSAnLi4vbGliL2xvZ2dlcic7XG5pbXBvcnQgeyBNYW5hZ2VIb3N0cyB9IGZyb20gJy4uL2xpYi9tYW5hZ2UtaG9zdHMnO1xuaW1wb3J0IHsgVXBkYXRlUmVnaXN0cnkgfSBmcm9tICcuLi9saWIvdXBkYXRlLXJlZ2lzdHJ5JztcblxuZXhwb3J0IGNsYXNzIFdhenVoSG9zdHNDdHJsIHtcbiAgbWFuYWdlSG9zdHM6IE1hbmFnZUhvc3RzO1xuICB1cGRhdGVSZWdpc3RyeTogVXBkYXRlUmVnaXN0cnk7XG4gIGNvbnN0cnVjdG9yKCkge1xuICAgIHRoaXMubWFuYWdlSG9zdHMgPSBuZXcgTWFuYWdlSG9zdHMoKTtcbiAgICB0aGlzLnVwZGF0ZVJlZ2lzdHJ5ID0gbmV3IFVwZGF0ZVJlZ2lzdHJ5KCk7XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBnZXQgYWxsIGhvc3RzIGVudHJpZXMgaW4gdGhlIHdhenVoLnltbCBhbmQgdGhlIHJlbGF0ZWQgaW5mbyBpbiB0aGUgd2F6dWgtcmVnaXN0cnkuanNvblxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQVBJIGVudHJpZXMgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZ2V0SG9zdHNFbnRyaWVzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCByZW1vdmVQYXNzd29yZCA9IHRydWU7XG4gICAgICBjb25zdCBob3N0cyA9IGF3YWl0IHRoaXMubWFuYWdlSG9zdHMuZ2V0SG9zdHMoKTtcbiAgICAgIGNvbnN0IHJlZ2lzdHJ5ID0gYXdhaXQgdGhpcy51cGRhdGVSZWdpc3RyeS5nZXRIb3N0cygpO1xuICAgICAgY29uc3QgcmVzdWx0ID0gYXdhaXQgdGhpcy5qb2luSG9zdFJlZ2lzdHJ5KGhvc3RzLCByZWdpc3RyeSwgcmVtb3ZlUGFzc3dvcmQpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogcmVzdWx0XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgaWYoZXJyb3IgJiYgZXJyb3IubWVzc2FnZSAmJiBbJ0VOT0VOVDogbm8gc3VjaCBmaWxlIG9yIGRpcmVjdG9yeScsIFdBWlVIX0RBVEFfUExVR0lOX1BMQVRGT1JNX0JBU0VfQUJTT0xVVEVfUEFUSF0uZXZlcnkodGV4dCA9PiBlcnJvci5tZXNzYWdlLmluY2x1ZGVzKHRleHQpKSl7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5iYWRSZXF1ZXN0KHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBtZXNzYWdlOiBgRXJyb3IgZ2V0dGluZyB0aGUgaG9zdHMgZW50cmllczogVGhlIFxcJyR7V0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9BQlNPTFVURV9QQVRIfVxcJyBkaXJlY3RvcnkgY291bGQgbm90IGV4aXN0IGluIHlvdXIgJHtQTFVHSU5fUExBVEZPUk1fTkFNRX0gaW5zdGFsbGF0aW9uLlxuICAgICAgICAgICAgSWYgdGhpcyBkb2Vzbid0IGV4aXN0LCBjcmVhdGUgaXQgYW5kIGdpdmUgdGhlIHBlcm1pc3Npb25zICdzdWRvIG1rZGlyICR7V0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9BQlNPTFVURV9QQVRIfTtzdWRvIGNob3duIC1SICR7UExVR0lOX1BMQVRGT1JNX0lOU1RBTExBVElPTl9VU0VSfToke1BMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUl9HUk9VUH0gJHtXQVpVSF9EQVRBX1BMVUdJTl9QTEFURk9STV9CQVNFX0FCU09MVVRFX1BBVEh9Jy4gQWZ0ZXIsIHJlc3RhcnQgdGhlICR7UExVR0lOX1BMQVRGT1JNX05BTUV9IHNlcnZpY2UuYFxuICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgIH1cbiAgICAgIGxvZygnd2F6dWgtaG9zdHM6Z2V0SG9zdHNFbnRyaWVzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAyMDAxLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogSm9pbnMgdGhlIGhvc3RzIHdpdGggdGhlIHJlbGF0ZWQgaW5mb3JtYXRpb24gaW4gdGhlIHJlZ2lzdHJ5XG4gICAqIEBwYXJhbSB7T2JqZWN0fSBob3N0c1xuICAgKiBAcGFyYW0ge09iamVjdH0gcmVnaXN0cnlcbiAgICogQHBhcmFtIHtCb29sZWFufSByZW1vdmVQYXNzd29yZFxuICAgKi9cbiAgYXN5bmMgam9pbkhvc3RSZWdpc3RyeShob3N0czogYW55LCByZWdpc3RyeTogYW55LCByZW1vdmVQYXNzd29yZDogYm9vbGVhbiA9IHRydWUpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKCFBcnJheS5pc0FycmF5KGhvc3RzKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0hvc3RzIGNvbmZpZ3VyYXRpb24gZXJyb3IgaW4gd2F6dWgueW1sJyk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiBhd2FpdCBQcm9taXNlLmFsbChob3N0cy5tYXAoYXN5bmMgaCA9PiB7XG4gICAgICAgIGNvbnN0IGlkID0gT2JqZWN0LmtleXMoaClbMF07XG4gICAgICAgIGNvbnN0IGFwaSA9IE9iamVjdC5hc3NpZ24oaFtpZF0sIHsgaWQ6IGlkIH0pO1xuICAgICAgICBjb25zdCBob3N0ID0gT2JqZWN0LmFzc2lnbihhcGksIHJlZ2lzdHJ5W2lkXSk7XG4gICAgICAgIC8vIEFkZCB0byBydW5fYXMgZnJvbSBBUEkgdXNlci4gVXNlIHRoZSBjYWNoZWQgdmFsdWUgb3IgZ2V0IGl0IGRvaW5nIGEgcmVxdWVzdFxuICAgICAgICBob3N0LmFsbG93X3J1bl9hcyA9IGF3YWl0IEFQSVVzZXJBbGxvd1J1bkFzLmNoZWNrKGlkKTtcbiAgICAgICAgaWYgKHJlbW92ZVBhc3N3b3JkKSB7XG4gICAgICAgICAgZGVsZXRlIGhvc3QucGFzc3dvcmQ7XG4gICAgICAgICAgZGVsZXRlIGhvc3QudG9rZW47XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiBob3N0O1xuICAgICAgfSkpO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoZXJyb3IpO1xuICAgIH1cbiAgfVxuICAvKipcbiAgICogVGhpcyB1cGRhdGUgYW4gQVBJIGhvc3RuYW1lXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBTdGF0dXMgcmVzcG9uc2Ugb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgdXBkYXRlQ2x1c3RlckluZm8oY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHsgaWQgfSA9IHJlcXVlc3QucGFyYW1zO1xuICAgICAgY29uc3QgeyBjbHVzdGVyX2luZm8gfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIGF3YWl0IHRoaXMudXBkYXRlUmVnaXN0cnkudXBkYXRlQ2x1c3RlckluZm8oaWQsIGNsdXN0ZXJfaW5mbyk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1ob3N0czp1cGRhdGVDbHVzdGVySW5mbycsXG4gICAgICAgIGBBUEkgZW50cnkgJHtpZH0gaG9zdG5hbWUgdXBkYXRlZGAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IHN0YXR1c0NvZGU6IDIwMCwgbWVzc2FnZTogJ29rJyB9XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1ob3N0czp1cGRhdGVDbHVzdGVySW5mbycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgIGBDb3VsZCBub3QgdXBkYXRlIGRhdGEgaW4gd2F6dWgtcmVnaXN0cnkuanNvbiBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWAsXG4gICAgICAgIDIwMTIsXG4gICAgICAgIDUwMCxcbiAgICAgICAgcmVzcG9uc2VcbiAgICAgICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlbW92ZSB0aGUgb3JwaGFuIGhvc3QgZW50cmllcyBpbiB0aGUgcmVnaXN0cnlcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqL1xuICBhc3luYyByZW1vdmVPcnBoYW5FbnRyaWVzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCB7IGVudHJpZXMgfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIGxvZygnd2F6dWgtaG9zdHM6Y2xlYW5SZWdpc3RyeScsICdDbGVhbmluZyByZWdpc3RyeScsICdkZWJ1ZycpO1xuICAgICAgYXdhaXQgdGhpcy51cGRhdGVSZWdpc3RyeS5yZW1vdmVPcnBoYW5FbnRyaWVzKGVudHJpZXMpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogeyBzdGF0dXNDb2RlOiAyMDAsIG1lc3NhZ2U6ICdvaycgfVxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtaG9zdHM6Y2xlYW5SZWdpc3RyeScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgIGBDb3VsZCBub3QgY2xlYW4gZW50cmllcyBpbiB0aGUgd2F6dWgtcmVnaXN0cnkuanNvbiBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWAsXG4gICAgICAgIDIwMTMsXG4gICAgICAgIDUwMCxcbiAgICAgICAgcmVzcG9uc2VcbiAgICAgICk7XG4gICAgfVxuICB9XG59XG4iXX0=