"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.UpdateRegistry = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _fs = _interopRequireDefault(require("fs"));

var _logger = require("./logger");

var _constants = require("../../common/constants");

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
class UpdateRegistry {
  constructor() {
    (0, _defineProperty2.default)(this, "busy", void 0);
    (0, _defineProperty2.default)(this, "file", void 0);
    this.busy = false;
    this.file = _constants.WAZUH_DATA_CONFIG_REGISTRY_PATH;
  }
  /**
   * Reads the Wazuh registry content
   */


  async readContent() {
    try {
      (0, _logger.log)('update-registry:readContent', 'Reading wazuh-registry.json content', 'debug');
      const content = await _fs.default.readFileSync(this.file, {
        encoding: 'utf-8'
      });
      return JSON.parse(content);
    } catch (error) {
      (0, _logger.log)('update-registry:readContent', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Get the hosts and their cluster info stored in the registry
   */


  async getHosts() {
    try {
      (0, _logger.log)('update-registry:getHosts', 'Getting hosts from registry', 'debug');
      const content = await this.readContent();
      return content.hosts || {};
    } catch (error) {
      (0, _logger.log)('update-registry:getHosts', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Returns the cluster information associated to an API id
   * @param {String} id
   */


  async getHostById(id) {
    try {
      if (!id) throw new Error('API id is missing');
      const hosts = await this.getHosts();
      return hosts.id || {};
    } catch (error) {
      (0, _logger.log)('update-registry:getClusterInfoByAPI', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Writes the wazuh-registry.json
   * @param {Object} content
   */


  async writeContent(content) {
    try {
      (0, _logger.log)('update-registry:writeContent', 'Writting wazuh-registry.json content', 'debug');

      if (this.busy) {
        throw new Error('Another process is updating the registry file');
      }

      this.busy = true;
      await _fs.default.writeFileSync(this.file, JSON.stringify(content));
      this.busy = false;
    } catch (error) {
      (0, _logger.log)('update-registry:writeContent', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Checks if the host exist in order to update the data, otherwise creates it
   * @param {String} id
   * @param {Object} hosts
   */


  checkHost(id, hosts) {
    try {
      return Object.keys(hosts).includes(id);
    } catch (error) {
      (0, _logger.log)('update-registry:checkHost', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Migrates the cluster information and extensions associated to an API id
   * @param {String} id
   * @param {Object} clusterInfo
   * @param {Object} clusterExtensions
   */


  async migrateToRegistry(id, clusterInfo, clusterExtensions) {
    try {
      const content = await this.readContent();
      if (!Object.keys(content).includes('hosts')) Object.assign(content, {
        hosts: {}
      });
      const info = {
        cluster_info: clusterInfo,
        extensions: clusterExtensions
      };
      content.hosts[id] = info;
      await this.writeContent(content);
      (0, _logger.log)('update-registry:migrateToRegistry', `API ${id} was properly migrated`, 'debug');
      return info;
    } catch (error) {
      (0, _logger.log)('update-registry:migrateToRegistry', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Updates the cluster-information or manager-information in the registry
   * @param {String} id
   * @param {Object} clusterInfo
   */


  async updateClusterInfo(id, clusterInfo) {
    try {
      const content = await this.readContent(); // Checks if not exists in order to create

      if (!content.hosts[id]) content.hosts[id] = {};
      content.hosts[id].cluster_info = clusterInfo;
      await this.writeContent(content);
      (0, _logger.log)('update-registry:updateClusterInfo', `API ${id} information was properly updated`, 'debug');
      return id;
    } catch (error) {
      (0, _logger.log)('update-registry:updateClusterInfo', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Updates the cluster-information or manager-information in the registry
   * @param {String} id
   * @param {Object} clusterInfo
   */


  async updateAPIExtensions(id, extensions) {
    try {
      const content = await this.readContent();
      if (content.hosts[id]) content.hosts[id].extensions = extensions;
      await this.writeContent(content);
      (0, _logger.log)('update-registry:updateAPIExtensions', `API ${id} extensions were properly updated`, 'debug');
      return id;
    } catch (error) {
      (0, _logger.log)('update-registry:updateAPIHostname', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Remove the given ids from the registry host entries
   * @param {Array} ids
   */


  async removeHostEntries(ids) {
    try {
      (0, _logger.log)('update-registry:removeHostEntry', 'Removing entry', 'debug');
      const content = await this.readContent();
      ids.forEach(id => delete content.hosts[id]);
      await this.writeContent(content);
    } catch (error) {
      (0, _logger.log)('update-registry:removeHostEntry', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Compare the hosts from wazuh.yml and the host in the wazuh-registry.json file in order to remove the orphan registry register
   * @param {Array} hosts
   */


  async removeOrphanEntries(hosts) {
    try {
      (0, _logger.log)('update-registry:removeOrphanEntries', 'Checking orphan registry entries', 'debug');
      const entries = await this.getHosts();
      const hostsKeys = hosts.map(h => {
        return h.id;
      });
      const entriesKeys = Object.keys(entries);
      const diff = entriesKeys.filter(e => {
        return !hostsKeys.includes(e);
      });
      await this.removeHostEntries(diff);
    } catch (error) {
      (0, _logger.log)('update-registry:removeOrphanEntries', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Returns the token information associated to an API id
   * @param {String} id
   */


  async getTokenById(id) {
    try {
      if (!id) throw new Error('API id is missing');
      const hosts = await this.getHosts();
      return hosts[id] ? hosts[id].token || null : null;
    } catch (error) {
      (0, _logger.log)('update-registry:getTokenById', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Updates the token in the registry
   * @param {String} id
   * @param {String} token
   */


  async updateTokenByHost(id, token) {
    try {
      const content = await this.readContent(); // Checks if not exists in order to create

      if (!content.hosts[id]) content.hosts[id] = {};
      content.hosts[id].token = token;
      await this.writeContent(content);
      (0, _logger.log)('update-registry:updateToken', `API ${id} information was properly updated`, 'debug');
      return id;
    } catch (error) {
      (0, _logger.log)('update-registry:updateToken', error.message || error);
      return Promise.reject(error);
    }
  }

}

exports.UpdateRegistry = UpdateRegistry;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInVwZGF0ZS1yZWdpc3RyeS50cyJdLCJuYW1lcyI6WyJVcGRhdGVSZWdpc3RyeSIsImNvbnN0cnVjdG9yIiwiYnVzeSIsImZpbGUiLCJXQVpVSF9EQVRBX0NPTkZJR19SRUdJU1RSWV9QQVRIIiwicmVhZENvbnRlbnQiLCJjb250ZW50IiwiZnMiLCJyZWFkRmlsZVN5bmMiLCJlbmNvZGluZyIsIkpTT04iLCJwYXJzZSIsImVycm9yIiwibWVzc2FnZSIsIlByb21pc2UiLCJyZWplY3QiLCJnZXRIb3N0cyIsImhvc3RzIiwiZ2V0SG9zdEJ5SWQiLCJpZCIsIkVycm9yIiwid3JpdGVDb250ZW50Iiwid3JpdGVGaWxlU3luYyIsInN0cmluZ2lmeSIsImNoZWNrSG9zdCIsIk9iamVjdCIsImtleXMiLCJpbmNsdWRlcyIsIm1pZ3JhdGVUb1JlZ2lzdHJ5IiwiY2x1c3RlckluZm8iLCJjbHVzdGVyRXh0ZW5zaW9ucyIsImFzc2lnbiIsImluZm8iLCJjbHVzdGVyX2luZm8iLCJleHRlbnNpb25zIiwidXBkYXRlQ2x1c3RlckluZm8iLCJ1cGRhdGVBUElFeHRlbnNpb25zIiwicmVtb3ZlSG9zdEVudHJpZXMiLCJpZHMiLCJmb3JFYWNoIiwicmVtb3ZlT3JwaGFuRW50cmllcyIsImVudHJpZXMiLCJob3N0c0tleXMiLCJtYXAiLCJoIiwiZW50cmllc0tleXMiLCJkaWZmIiwiZmlsdGVyIiwiZSIsImdldFRva2VuQnlJZCIsInRva2VuIiwidXBkYXRlVG9rZW5CeUhvc3QiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O0FBV0E7O0FBQ0E7O0FBQ0E7O0FBYkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUtPLE1BQU1BLGNBQU4sQ0FBcUI7QUFHMUJDLEVBQUFBLFdBQVcsR0FBRztBQUFBO0FBQUE7QUFDWixTQUFLQyxJQUFMLEdBQVksS0FBWjtBQUNBLFNBQUtDLElBQUwsR0FBWUMsMENBQVo7QUFDRDtBQUVEO0FBQ0Y7QUFDQTs7O0FBQ21CLFFBQVhDLFdBQVcsR0FBRztBQUNsQixRQUFJO0FBQ0YsdUJBQUksNkJBQUosRUFBbUMscUNBQW5DLEVBQTBFLE9BQTFFO0FBQ0EsWUFBTUMsT0FBTyxHQUFHLE1BQU1DLFlBQUdDLFlBQUgsQ0FBZ0IsS0FBS0wsSUFBckIsRUFBMkI7QUFBRU0sUUFBQUEsUUFBUSxFQUFFO0FBQVosT0FBM0IsQ0FBdEI7QUFDQSxhQUFPQyxJQUFJLENBQUNDLEtBQUwsQ0FBV0wsT0FBWCxDQUFQO0FBQ0QsS0FKRCxDQUlFLE9BQU9NLEtBQVAsRUFBYztBQUNkLHVCQUFJLDZCQUFKLEVBQW1DQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQXBEO0FBQ0EsYUFBT0UsT0FBTyxDQUFDQyxNQUFSLENBQWVILEtBQWYsQ0FBUDtBQUNEO0FBQ0Y7QUFFRDtBQUNGO0FBQ0E7OztBQUNnQixRQUFSSSxRQUFRLEdBQUc7QUFDZixRQUFJO0FBQ0YsdUJBQUksMEJBQUosRUFBZ0MsNkJBQWhDLEVBQStELE9BQS9EO0FBQ0EsWUFBTVYsT0FBTyxHQUFHLE1BQU0sS0FBS0QsV0FBTCxFQUF0QjtBQUNBLGFBQU9DLE9BQU8sQ0FBQ1csS0FBUixJQUFpQixFQUF4QjtBQUNELEtBSkQsQ0FJRSxPQUFPTCxLQUFQLEVBQWM7QUFDZCx1QkFBSSwwQkFBSixFQUFnQ0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUFqRDtBQUNBLGFBQU9FLE9BQU8sQ0FBQ0MsTUFBUixDQUFlSCxLQUFmLENBQVA7QUFDRDtBQUNGO0FBRUQ7QUFDRjtBQUNBO0FBQ0E7OztBQUNtQixRQUFYTSxXQUFXLENBQUNDLEVBQUQsRUFBSztBQUNwQixRQUFJO0FBQ0YsVUFBSSxDQUFDQSxFQUFMLEVBQVMsTUFBTSxJQUFJQyxLQUFKLENBQVUsbUJBQVYsQ0FBTjtBQUNULFlBQU1ILEtBQUssR0FBRyxNQUFNLEtBQUtELFFBQUwsRUFBcEI7QUFDQSxhQUFPQyxLQUFLLENBQUNFLEVBQU4sSUFBWSxFQUFuQjtBQUNELEtBSkQsQ0FJRSxPQUFPUCxLQUFQLEVBQWM7QUFDZCx1QkFBSSxxQ0FBSixFQUEyQ0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUE1RDtBQUNBLGFBQU9FLE9BQU8sQ0FBQ0MsTUFBUixDQUFlSCxLQUFmLENBQVA7QUFDRDtBQUNGO0FBRUQ7QUFDRjtBQUNBO0FBQ0E7OztBQUNvQixRQUFaUyxZQUFZLENBQUNmLE9BQUQsRUFBVTtBQUMxQixRQUFJO0FBQ0YsdUJBQUksOEJBQUosRUFBb0Msc0NBQXBDLEVBQTRFLE9BQTVFOztBQUNBLFVBQUksS0FBS0osSUFBVCxFQUFlO0FBQ2IsY0FBTSxJQUFJa0IsS0FBSixDQUFVLCtDQUFWLENBQU47QUFDRDs7QUFDRCxXQUFLbEIsSUFBTCxHQUFZLElBQVo7QUFDQSxZQUFNSyxZQUFHZSxhQUFILENBQWlCLEtBQUtuQixJQUF0QixFQUE0Qk8sSUFBSSxDQUFDYSxTQUFMLENBQWVqQixPQUFmLENBQTVCLENBQU47QUFDQSxXQUFLSixJQUFMLEdBQVksS0FBWjtBQUNELEtBUkQsQ0FRRSxPQUFPVSxLQUFQLEVBQWM7QUFDZCx1QkFBSSw4QkFBSixFQUFvQ0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUFyRDtBQUNBLGFBQU9FLE9BQU8sQ0FBQ0MsTUFBUixDQUFlSCxLQUFmLENBQVA7QUFDRDtBQUNGO0FBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTs7O0FBQ0VZLEVBQUFBLFNBQVMsQ0FBQ0wsRUFBRCxFQUFLRixLQUFMLEVBQVk7QUFDbkIsUUFBSTtBQUNGLGFBQU9RLE1BQU0sQ0FBQ0MsSUFBUCxDQUFZVCxLQUFaLEVBQW1CVSxRQUFuQixDQUE0QlIsRUFBNUIsQ0FBUDtBQUNELEtBRkQsQ0FFRSxPQUFPUCxLQUFQLEVBQWM7QUFDZCx1QkFBSSwyQkFBSixFQUFpQ0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUFsRDtBQUNBLGFBQU9FLE9BQU8sQ0FBQ0MsTUFBUixDQUFlSCxLQUFmLENBQVA7QUFDRDtBQUNGO0FBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFDeUIsUUFBakJnQixpQkFBaUIsQ0FBQ1QsRUFBRCxFQUFLVSxXQUFMLEVBQWtCQyxpQkFBbEIsRUFBcUM7QUFDMUQsUUFBSTtBQUNGLFlBQU14QixPQUFPLEdBQUcsTUFBTSxLQUFLRCxXQUFMLEVBQXRCO0FBQ0EsVUFBSSxDQUFDb0IsTUFBTSxDQUFDQyxJQUFQLENBQVlwQixPQUFaLEVBQXFCcUIsUUFBckIsQ0FBOEIsT0FBOUIsQ0FBTCxFQUE2Q0YsTUFBTSxDQUFDTSxNQUFQLENBQWN6QixPQUFkLEVBQXVCO0FBQUVXLFFBQUFBLEtBQUssRUFBRTtBQUFULE9BQXZCO0FBQzdDLFlBQU1lLElBQUksR0FBRztBQUFFQyxRQUFBQSxZQUFZLEVBQUVKLFdBQWhCO0FBQTZCSyxRQUFBQSxVQUFVLEVBQUVKO0FBQXpDLE9BQWI7QUFDQXhCLE1BQUFBLE9BQU8sQ0FBQ1csS0FBUixDQUFjRSxFQUFkLElBQW9CYSxJQUFwQjtBQUNBLFlBQU0sS0FBS1gsWUFBTCxDQUFrQmYsT0FBbEIsQ0FBTjtBQUNBLHVCQUFJLG1DQUFKLEVBQTBDLE9BQU1hLEVBQUcsd0JBQW5ELEVBQTRFLE9BQTVFO0FBQ0EsYUFBT2EsSUFBUDtBQUNELEtBUkQsQ0FRRSxPQUFPcEIsS0FBUCxFQUFjO0FBQ2QsdUJBQUksbUNBQUosRUFBeUNBLEtBQUssQ0FBQ0MsT0FBTixJQUFpQkQsS0FBMUQ7QUFDQSxhQUFPRSxPQUFPLENBQUNDLE1BQVIsQ0FBZUgsS0FBZixDQUFQO0FBQ0Q7QUFDRjtBQUVEO0FBQ0Y7QUFDQTtBQUNBO0FBQ0E7OztBQUN5QixRQUFqQnVCLGlCQUFpQixDQUFDaEIsRUFBRCxFQUFLVSxXQUFMLEVBQWtCO0FBQ3ZDLFFBQUk7QUFDRixZQUFNdkIsT0FBTyxHQUFHLE1BQU0sS0FBS0QsV0FBTCxFQUF0QixDQURFLENBRUY7O0FBQ0EsVUFBSSxDQUFDQyxPQUFPLENBQUNXLEtBQVIsQ0FBY0UsRUFBZCxDQUFMLEVBQXdCYixPQUFPLENBQUNXLEtBQVIsQ0FBY0UsRUFBZCxJQUFvQixFQUFwQjtBQUN4QmIsTUFBQUEsT0FBTyxDQUFDVyxLQUFSLENBQWNFLEVBQWQsRUFBa0JjLFlBQWxCLEdBQWlDSixXQUFqQztBQUNBLFlBQU0sS0FBS1IsWUFBTCxDQUFrQmYsT0FBbEIsQ0FBTjtBQUNBLHVCQUNFLG1DQURGLEVBRUcsT0FBTWEsRUFBRyxtQ0FGWixFQUdFLE9BSEY7QUFLQSxhQUFPQSxFQUFQO0FBQ0QsS0FaRCxDQVlFLE9BQU9QLEtBQVAsRUFBYztBQUNkLHVCQUFJLG1DQUFKLEVBQXlDQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQTFEO0FBQ0EsYUFBT0UsT0FBTyxDQUFDQyxNQUFSLENBQWVILEtBQWYsQ0FBUDtBQUNEO0FBQ0Y7QUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBOzs7QUFDMkIsUUFBbkJ3QixtQkFBbUIsQ0FBQ2pCLEVBQUQsRUFBS2UsVUFBTCxFQUFpQjtBQUN4QyxRQUFJO0FBQ0YsWUFBTTVCLE9BQU8sR0FBRyxNQUFNLEtBQUtELFdBQUwsRUFBdEI7QUFDQSxVQUFHQyxPQUFPLENBQUNXLEtBQVIsQ0FBY0UsRUFBZCxDQUFILEVBQXNCYixPQUFPLENBQUNXLEtBQVIsQ0FBY0UsRUFBZCxFQUFrQmUsVUFBbEIsR0FBK0JBLFVBQS9CO0FBQ3RCLFlBQU0sS0FBS2IsWUFBTCxDQUFrQmYsT0FBbEIsQ0FBTjtBQUNBLHVCQUNFLHFDQURGLEVBRUcsT0FBTWEsRUFBRyxtQ0FGWixFQUdFLE9BSEY7QUFLQSxhQUFPQSxFQUFQO0FBQ0QsS0FWRCxDQVVFLE9BQU9QLEtBQVAsRUFBYztBQUNkLHVCQUFJLG1DQUFKLEVBQXlDQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQTFEO0FBQ0EsYUFBT0UsT0FBTyxDQUFDQyxNQUFSLENBQWVILEtBQWYsQ0FBUDtBQUNEO0FBQ0Y7QUFFRDtBQUNGO0FBQ0E7QUFDQTs7O0FBQ3lCLFFBQWpCeUIsaUJBQWlCLENBQUNDLEdBQUQsRUFBTTtBQUMzQixRQUFJO0FBQ0YsdUJBQUksaUNBQUosRUFBdUMsZ0JBQXZDLEVBQXlELE9BQXpEO0FBQ0EsWUFBTWhDLE9BQU8sR0FBRyxNQUFNLEtBQUtELFdBQUwsRUFBdEI7QUFDQWlDLE1BQUFBLEdBQUcsQ0FBQ0MsT0FBSixDQUFZcEIsRUFBRSxJQUFJLE9BQU9iLE9BQU8sQ0FBQ1csS0FBUixDQUFjRSxFQUFkLENBQXpCO0FBQ0EsWUFBTSxLQUFLRSxZQUFMLENBQWtCZixPQUFsQixDQUFOO0FBQ0QsS0FMRCxDQUtFLE9BQU9NLEtBQVAsRUFBYztBQUNkLHVCQUFJLGlDQUFKLEVBQXVDQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQXhEO0FBQ0EsYUFBT0UsT0FBTyxDQUFDQyxNQUFSLENBQWVILEtBQWYsQ0FBUDtBQUNEO0FBQ0Y7QUFFRDtBQUNGO0FBQ0E7QUFDQTs7O0FBQzJCLFFBQW5CNEIsbUJBQW1CLENBQUN2QixLQUFELEVBQVE7QUFDL0IsUUFBSTtBQUNGLHVCQUFJLHFDQUFKLEVBQTJDLGtDQUEzQyxFQUErRSxPQUEvRTtBQUNBLFlBQU13QixPQUFPLEdBQUcsTUFBTSxLQUFLekIsUUFBTCxFQUF0QjtBQUNBLFlBQU0wQixTQUFTLEdBQUd6QixLQUFLLENBQUMwQixHQUFOLENBQVVDLENBQUMsSUFBSTtBQUMvQixlQUFPQSxDQUFDLENBQUN6QixFQUFUO0FBQ0QsT0FGaUIsQ0FBbEI7QUFHQSxZQUFNMEIsV0FBVyxHQUFHcEIsTUFBTSxDQUFDQyxJQUFQLENBQVllLE9BQVosQ0FBcEI7QUFDQSxZQUFNSyxJQUFJLEdBQUdELFdBQVcsQ0FBQ0UsTUFBWixDQUFtQkMsQ0FBQyxJQUFJO0FBQ25DLGVBQU8sQ0FBQ04sU0FBUyxDQUFDZixRQUFWLENBQW1CcUIsQ0FBbkIsQ0FBUjtBQUNELE9BRlksQ0FBYjtBQUdBLFlBQU0sS0FBS1gsaUJBQUwsQ0FBdUJTLElBQXZCLENBQU47QUFDRCxLQVhELENBV0UsT0FBT2xDLEtBQVAsRUFBYztBQUNkLHVCQUFJLHFDQUFKLEVBQTJDQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQTVEO0FBQ0EsYUFBT0UsT0FBTyxDQUFDQyxNQUFSLENBQWVILEtBQWYsQ0FBUDtBQUNEO0FBQ0Y7QUFFRDtBQUNGO0FBQ0E7QUFDQTs7O0FBQ29CLFFBQVpxQyxZQUFZLENBQUM5QixFQUFELEVBQUs7QUFDckIsUUFBSTtBQUNGLFVBQUksQ0FBQ0EsRUFBTCxFQUFTLE1BQU0sSUFBSUMsS0FBSixDQUFVLG1CQUFWLENBQU47QUFDVCxZQUFNSCxLQUFLLEdBQUcsTUFBTSxLQUFLRCxRQUFMLEVBQXBCO0FBQ0EsYUFBT0MsS0FBSyxDQUFDRSxFQUFELENBQUwsR0FBWUYsS0FBSyxDQUFDRSxFQUFELENBQUwsQ0FBVStCLEtBQVYsSUFBbUIsSUFBL0IsR0FBc0MsSUFBN0M7QUFDRCxLQUpELENBSUUsT0FBT3RDLEtBQVAsRUFBYztBQUNkLHVCQUFJLDhCQUFKLEVBQW9DQSxLQUFLLENBQUNDLE9BQU4sSUFBaUJELEtBQXJEO0FBQ0EsYUFBT0UsT0FBTyxDQUFDQyxNQUFSLENBQWVILEtBQWYsQ0FBUDtBQUNEO0FBQ0Y7QUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBOzs7QUFDeUIsUUFBakJ1QyxpQkFBaUIsQ0FBQ2hDLEVBQUQsRUFBSytCLEtBQUwsRUFBWTtBQUNqQyxRQUFJO0FBQ0YsWUFBTTVDLE9BQU8sR0FBRyxNQUFNLEtBQUtELFdBQUwsRUFBdEIsQ0FERSxDQUVGOztBQUNBLFVBQUksQ0FBQ0MsT0FBTyxDQUFDVyxLQUFSLENBQWNFLEVBQWQsQ0FBTCxFQUF3QmIsT0FBTyxDQUFDVyxLQUFSLENBQWNFLEVBQWQsSUFBb0IsRUFBcEI7QUFDeEJiLE1BQUFBLE9BQU8sQ0FBQ1csS0FBUixDQUFjRSxFQUFkLEVBQWtCK0IsS0FBbEIsR0FBMEJBLEtBQTFCO0FBQ0EsWUFBTSxLQUFLN0IsWUFBTCxDQUFrQmYsT0FBbEIsQ0FBTjtBQUNBLHVCQUFJLDZCQUFKLEVBQW9DLE9BQU1hLEVBQUcsbUNBQTdDLEVBQWlGLE9BQWpGO0FBQ0EsYUFBT0EsRUFBUDtBQUNELEtBUkQsQ0FRRSxPQUFPUCxLQUFQLEVBQWM7QUFDZCx1QkFBSSw2QkFBSixFQUFtQ0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUFwRDtBQUNBLGFBQU9FLE9BQU8sQ0FBQ0MsTUFBUixDQUFlSCxLQUFmLENBQVA7QUFDRDtBQUNGOztBQTlOeUIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTW9kdWxlIHRvIHVwZGF0ZSB0aGUgY29uZmlndXJhdGlvbiBmaWxlXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IGZzIGZyb20gJ2ZzJztcbmltcG9ydCB7IGxvZyB9IGZyb20gJy4vbG9nZ2VyJztcbmltcG9ydCB7IFdBWlVIX0RBVEFfQ09ORklHX1JFR0lTVFJZX1BBVEggfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJztcblxuZXhwb3J0IGNsYXNzIFVwZGF0ZVJlZ2lzdHJ5IHtcbiAgYnVzeTogYm9vbGVhbjtcbiAgZmlsZTogc3RyaW5nO1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLmJ1c3kgPSBmYWxzZTtcbiAgICB0aGlzLmZpbGUgPSBXQVpVSF9EQVRBX0NPTkZJR19SRUdJU1RSWV9QQVRIO1xuICB9XG5cbiAgLyoqXG4gICAqIFJlYWRzIHRoZSBXYXp1aCByZWdpc3RyeSBjb250ZW50XG4gICAqL1xuICBhc3luYyByZWFkQ29udGVudCgpIHtcbiAgICB0cnkge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6cmVhZENvbnRlbnQnLCAnUmVhZGluZyB3YXp1aC1yZWdpc3RyeS5qc29uIGNvbnRlbnQnLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGNvbnRlbnQgPSBhd2FpdCBmcy5yZWFkRmlsZVN5bmModGhpcy5maWxlLCB7IGVuY29kaW5nOiAndXRmLTgnIH0pO1xuICAgICAgcmV0dXJuIEpTT04ucGFyc2UoY29udGVudCk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OnJlYWRDb250ZW50JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBHZXQgdGhlIGhvc3RzIGFuZCB0aGVpciBjbHVzdGVyIGluZm8gc3RvcmVkIGluIHRoZSByZWdpc3RyeVxuICAgKi9cbiAgYXN5bmMgZ2V0SG9zdHMoKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OmdldEhvc3RzJywgJ0dldHRpbmcgaG9zdHMgZnJvbSByZWdpc3RyeScsICdkZWJ1ZycpO1xuICAgICAgY29uc3QgY29udGVudCA9IGF3YWl0IHRoaXMucmVhZENvbnRlbnQoKTtcbiAgICAgIHJldHVybiBjb250ZW50Lmhvc3RzIHx8IHt9O1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTpnZXRIb3N0cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmV0dXJucyB0aGUgY2x1c3RlciBpbmZvcm1hdGlvbiBhc3NvY2lhdGVkIHRvIGFuIEFQSSBpZFxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWRcbiAgICovXG4gIGFzeW5jIGdldEhvc3RCeUlkKGlkKSB7XG4gICAgdHJ5IHtcbiAgICAgIGlmICghaWQpIHRocm93IG5ldyBFcnJvcignQVBJIGlkIGlzIG1pc3NpbmcnKTtcbiAgICAgIGNvbnN0IGhvc3RzID0gYXdhaXQgdGhpcy5nZXRIb3N0cygpO1xuICAgICAgcmV0dXJuIGhvc3RzLmlkIHx8IHt9O1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTpnZXRDbHVzdGVySW5mb0J5QVBJJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBXcml0ZXMgdGhlIHdhenVoLXJlZ2lzdHJ5Lmpzb25cbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRlbnRcbiAgICovXG4gIGFzeW5jIHdyaXRlQ29udGVudChjb250ZW50KSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OndyaXRlQ29udGVudCcsICdXcml0dGluZyB3YXp1aC1yZWdpc3RyeS5qc29uIGNvbnRlbnQnLCAnZGVidWcnKTtcbiAgICAgIGlmICh0aGlzLmJ1c3kpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdBbm90aGVyIHByb2Nlc3MgaXMgdXBkYXRpbmcgdGhlIHJlZ2lzdHJ5IGZpbGUnKTtcbiAgICAgIH1cbiAgICAgIHRoaXMuYnVzeSA9IHRydWU7XG4gICAgICBhd2FpdCBmcy53cml0ZUZpbGVTeW5jKHRoaXMuZmlsZSwgSlNPTi5zdHJpbmdpZnkoY29udGVudCkpO1xuICAgICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OndyaXRlQ29udGVudCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogQ2hlY2tzIGlmIHRoZSBob3N0IGV4aXN0IGluIG9yZGVyIHRvIHVwZGF0ZSB0aGUgZGF0YSwgb3RoZXJ3aXNlIGNyZWF0ZXMgaXRcbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBob3N0c1xuICAgKi9cbiAgY2hlY2tIb3N0KGlkLCBob3N0cykge1xuICAgIHRyeSB7XG4gICAgICByZXR1cm4gT2JqZWN0LmtleXMoaG9zdHMpLmluY2x1ZGVzKGlkKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6Y2hlY2tIb3N0JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBNaWdyYXRlcyB0aGUgY2x1c3RlciBpbmZvcm1hdGlvbiBhbmQgZXh0ZW5zaW9ucyBhc3NvY2lhdGVkIHRvIGFuIEFQSSBpZFxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWRcbiAgICogQHBhcmFtIHtPYmplY3R9IGNsdXN0ZXJJbmZvXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjbHVzdGVyRXh0ZW5zaW9uc1xuICAgKi9cbiAgYXN5bmMgbWlncmF0ZVRvUmVnaXN0cnkoaWQsIGNsdXN0ZXJJbmZvLCBjbHVzdGVyRXh0ZW5zaW9ucykge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgdGhpcy5yZWFkQ29udGVudCgpO1xuICAgICAgaWYgKCFPYmplY3Qua2V5cyhjb250ZW50KS5pbmNsdWRlcygnaG9zdHMnKSkgT2JqZWN0LmFzc2lnbihjb250ZW50LCB7IGhvc3RzOiB7fSB9KTtcbiAgICAgIGNvbnN0IGluZm8gPSB7IGNsdXN0ZXJfaW5mbzogY2x1c3RlckluZm8sIGV4dGVuc2lvbnM6IGNsdXN0ZXJFeHRlbnNpb25zIH07XG4gICAgICBjb250ZW50Lmhvc3RzW2lkXSA9IGluZm87XG4gICAgICBhd2FpdCB0aGlzLndyaXRlQ29udGVudChjb250ZW50KTtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5Om1pZ3JhdGVUb1JlZ2lzdHJ5JywgYEFQSSAke2lkfSB3YXMgcHJvcGVybHkgbWlncmF0ZWRgLCAnZGVidWcnKTtcbiAgICAgIHJldHVybiBpbmZvO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTptaWdyYXRlVG9SZWdpc3RyeScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVXBkYXRlcyB0aGUgY2x1c3Rlci1pbmZvcm1hdGlvbiBvciBtYW5hZ2VyLWluZm9ybWF0aW9uIGluIHRoZSByZWdpc3RyeVxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWRcbiAgICogQHBhcmFtIHtPYmplY3R9IGNsdXN0ZXJJbmZvXG4gICAqL1xuICBhc3luYyB1cGRhdGVDbHVzdGVySW5mbyhpZCwgY2x1c3RlckluZm8pIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29udGVudCA9IGF3YWl0IHRoaXMucmVhZENvbnRlbnQoKTtcbiAgICAgIC8vIENoZWNrcyBpZiBub3QgZXhpc3RzIGluIG9yZGVyIHRvIGNyZWF0ZVxuICAgICAgaWYgKCFjb250ZW50Lmhvc3RzW2lkXSkgY29udGVudC5ob3N0c1tpZF0gPSB7fTtcbiAgICAgIGNvbnRlbnQuaG9zdHNbaWRdLmNsdXN0ZXJfaW5mbyA9IGNsdXN0ZXJJbmZvO1xuICAgICAgYXdhaXQgdGhpcy53cml0ZUNvbnRlbnQoY29udGVudCk7XG4gICAgICBsb2coXG4gICAgICAgICd1cGRhdGUtcmVnaXN0cnk6dXBkYXRlQ2x1c3RlckluZm8nLFxuICAgICAgICBgQVBJICR7aWR9IGluZm9ybWF0aW9uIHdhcyBwcm9wZXJseSB1cGRhdGVkYCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiBpZDtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6dXBkYXRlQ2x1c3RlckluZm8nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFVwZGF0ZXMgdGhlIGNsdXN0ZXItaW5mb3JtYXRpb24gb3IgbWFuYWdlci1pbmZvcm1hdGlvbiBpbiB0aGUgcmVnaXN0cnlcbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjbHVzdGVySW5mb1xuICAgKi9cbiAgYXN5bmMgdXBkYXRlQVBJRXh0ZW5zaW9ucyhpZCwgZXh0ZW5zaW9ucykge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgdGhpcy5yZWFkQ29udGVudCgpO1xuICAgICAgaWYoY29udGVudC5ob3N0c1tpZF0pIGNvbnRlbnQuaG9zdHNbaWRdLmV4dGVuc2lvbnMgPSBleHRlbnNpb25zO1xuICAgICAgYXdhaXQgdGhpcy53cml0ZUNvbnRlbnQoY29udGVudCk7XG4gICAgICBsb2coXG4gICAgICAgICd1cGRhdGUtcmVnaXN0cnk6dXBkYXRlQVBJRXh0ZW5zaW9ucycsXG4gICAgICAgIGBBUEkgJHtpZH0gZXh0ZW5zaW9ucyB3ZXJlIHByb3Blcmx5IHVwZGF0ZWRgLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgcmV0dXJuIGlkO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTp1cGRhdGVBUElIb3N0bmFtZScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmVtb3ZlIHRoZSBnaXZlbiBpZHMgZnJvbSB0aGUgcmVnaXN0cnkgaG9zdCBlbnRyaWVzXG4gICAqIEBwYXJhbSB7QXJyYXl9IGlkc1xuICAgKi9cbiAgYXN5bmMgcmVtb3ZlSG9zdEVudHJpZXMoaWRzKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OnJlbW92ZUhvc3RFbnRyeScsICdSZW1vdmluZyBlbnRyeScsICdkZWJ1ZycpO1xuICAgICAgY29uc3QgY29udGVudCA9IGF3YWl0IHRoaXMucmVhZENvbnRlbnQoKTtcbiAgICAgIGlkcy5mb3JFYWNoKGlkID0+IGRlbGV0ZSBjb250ZW50Lmhvc3RzW2lkXSk7XG4gICAgICBhd2FpdCB0aGlzLndyaXRlQ29udGVudChjb250ZW50KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6cmVtb3ZlSG9zdEVudHJ5JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBDb21wYXJlIHRoZSBob3N0cyBmcm9tIHdhenVoLnltbCBhbmQgdGhlIGhvc3QgaW4gdGhlIHdhenVoLXJlZ2lzdHJ5Lmpzb24gZmlsZSBpbiBvcmRlciB0byByZW1vdmUgdGhlIG9ycGhhbiByZWdpc3RyeSByZWdpc3RlclxuICAgKiBAcGFyYW0ge0FycmF5fSBob3N0c1xuICAgKi9cbiAgYXN5bmMgcmVtb3ZlT3JwaGFuRW50cmllcyhob3N0cykge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTpyZW1vdmVPcnBoYW5FbnRyaWVzJywgJ0NoZWNraW5nIG9ycGhhbiByZWdpc3RyeSBlbnRyaWVzJywgJ2RlYnVnJyk7XG4gICAgICBjb25zdCBlbnRyaWVzID0gYXdhaXQgdGhpcy5nZXRIb3N0cygpO1xuICAgICAgY29uc3QgaG9zdHNLZXlzID0gaG9zdHMubWFwKGggPT4ge1xuICAgICAgICByZXR1cm4gaC5pZDtcbiAgICAgIH0pO1xuICAgICAgY29uc3QgZW50cmllc0tleXMgPSBPYmplY3Qua2V5cyhlbnRyaWVzKTtcbiAgICAgIGNvbnN0IGRpZmYgPSBlbnRyaWVzS2V5cy5maWx0ZXIoZSA9PiB7XG4gICAgICAgIHJldHVybiAhaG9zdHNLZXlzLmluY2x1ZGVzKGUpO1xuICAgICAgfSk7XG4gICAgICBhd2FpdCB0aGlzLnJlbW92ZUhvc3RFbnRyaWVzKGRpZmYpO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3VwZGF0ZS1yZWdpc3RyeTpyZW1vdmVPcnBoYW5FbnRyaWVzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSB0b2tlbiBpbmZvcm1hdGlvbiBhc3NvY2lhdGVkIHRvIGFuIEFQSSBpZFxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWRcbiAgICovXG4gIGFzeW5jIGdldFRva2VuQnlJZChpZCkge1xuICAgIHRyeSB7XG4gICAgICBpZiAoIWlkKSB0aHJvdyBuZXcgRXJyb3IoJ0FQSSBpZCBpcyBtaXNzaW5nJyk7XG4gICAgICBjb25zdCBob3N0cyA9IGF3YWl0IHRoaXMuZ2V0SG9zdHMoKTtcbiAgICAgIHJldHVybiBob3N0c1tpZF0gPyBob3N0c1tpZF0udG9rZW4gfHwgbnVsbCA6IG51bGw7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OmdldFRva2VuQnlJZCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVXBkYXRlcyB0aGUgdG9rZW4gaW4gdGhlIHJlZ2lzdHJ5XG4gICAqIEBwYXJhbSB7U3RyaW5nfSBpZFxuICAgKiBAcGFyYW0ge1N0cmluZ30gdG9rZW5cbiAgICovXG4gIGFzeW5jIHVwZGF0ZVRva2VuQnlIb3N0KGlkLCB0b2tlbikge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBjb250ZW50ID0gYXdhaXQgdGhpcy5yZWFkQ29udGVudCgpO1xuICAgICAgLy8gQ2hlY2tzIGlmIG5vdCBleGlzdHMgaW4gb3JkZXIgdG8gY3JlYXRlXG4gICAgICBpZiAoIWNvbnRlbnQuaG9zdHNbaWRdKSBjb250ZW50Lmhvc3RzW2lkXSA9IHt9O1xuICAgICAgY29udGVudC5ob3N0c1tpZF0udG9rZW4gPSB0b2tlbjtcbiAgICAgIGF3YWl0IHRoaXMud3JpdGVDb250ZW50KGNvbnRlbnQpO1xuICAgICAgbG9nKCd1cGRhdGUtcmVnaXN0cnk6dXBkYXRlVG9rZW4nLCBgQVBJICR7aWR9IGluZm9ybWF0aW9uIHdhcyBwcm9wZXJseSB1cGRhdGVkYCwgJ2RlYnVnJyk7XG4gICAgICByZXR1cm4gaWQ7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygndXBkYXRlLXJlZ2lzdHJ5OnVwZGF0ZVRva2VuJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxufVxuIl19