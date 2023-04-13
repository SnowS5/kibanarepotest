"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ManageHosts = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _fs = _interopRequireDefault(require("fs"));

var _jsYaml = _interopRequireDefault(require("js-yaml"));

var _logger = require("./logger");

var _updateRegistry = require("./update-registry");

var _initialWazuhConfig = require("./initial-wazuh-config");

var _constants = require("../../common/constants");

var _filesystem = require("../lib/filesystem");

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
class ManageHosts {
  constructor() {
    (0, _defineProperty2.default)(this, "busy", void 0);
    (0, _defineProperty2.default)(this, "file", void 0);
    (0, _defineProperty2.default)(this, "updateRegistry", void 0);
    (0, _defineProperty2.default)(this, "initialConfig", void 0);
    this.busy = false;
    this.file = _constants.WAZUH_DATA_CONFIG_APP_PATH;
    this.updateRegistry = new _updateRegistry.UpdateRegistry();
    this.initialConfig = _initialWazuhConfig.initialWazuhConfig;
  }
  /**
   * Composes the host structure
   * @param {Object} host
   * @param {String} id
   */


  composeHost(host, id) {
    try {
      (0, _logger.log)('manage-hosts:composeHost', 'Composing host', 'debug');
      return `  - ${!id ? new Date().getTime() : id}:
      url: ${host.url}
      port: ${host.port}
      username: ${host.username || host.user}
      password: ${host.password}`;
    } catch (error) {
      (0, _logger.log)('manage-hosts:composeHost', error.message || error);
      throw error;
    }
  }
  /**
   * Regex to build the host
   * @param {Object} host
   */


  composeRegex(host) {
    try {
      const hostId = Object.keys(host)[0];
      const reg = `\\s*-\\s*${hostId}\\s*:\\s*\\n*\\s*url\\s*:\\s*\\S*\\s*\\n*\\s*port\\s*:\\s*\\S*\\s*\\n*\\s*username\\s*:\\s*\\S*\\s*\\n*\\s*password\\s*:\\s*\\S*`;
      (0, _logger.log)('manage-hosts:composeRegex', 'Composing regex', 'debug');
      return new RegExp(`${reg}`, 'gm');
    } catch (error) {
      (0, _logger.log)('manage-hosts:composeRegex', error.message || error);
      throw error;
    }
  }
  /**
   * Returns the hosts in the wazuh.yml
   */


  async getHosts() {
    try {
      this.checkBusy();
      this.busy = true;
      (0, _filesystem.createDataDirectoryIfNotExists)();
      (0, _filesystem.createDataDirectoryIfNotExists)('config');

      if (!_fs.default.existsSync(_constants.WAZUH_DATA_CONFIG_APP_PATH)) {
        await _fs.default.writeFileSync(this.file, this.initialConfig, {
          encoding: 'utf8',
          mode: 0o600
        });
      }

      const raw = _fs.default.readFileSync(this.file, {
        encoding: 'utf-8'
      });

      this.busy = false;

      const content = _jsYaml.default.load(raw);

      (0, _logger.log)('manage-hosts:getHosts', 'Getting hosts', 'debug');
      const entries = (content || {})['hosts'] || [];
      return entries;
    } catch (error) {
      this.busy = false;
      (0, _logger.log)('manage-hosts:getHosts', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * This function checks if the hosts: key exists in the wazuh.yml for preventing duplicate in case of there's not any host defined
   */


  async checkIfHostsKeyExists() {
    try {
      (0, _logger.log)('manage-hosts:checkIfHostsKeyExists', 'Checking hosts key', 'debug');
      this.busy = true;

      const raw = _fs.default.readFileSync(this.file, {
        encoding: 'utf-8'
      });

      this.busy = false;

      const content = _jsYaml.default.load(raw);

      return Object.keys(content || {}).includes('hosts');
    } catch (error) {
      (0, _logger.log)('manage-hosts:checkIfHostsKeyExists', error.message || error);
      this.busy = false;
      return Promise.reject(error);
    }
  }
  /**
   * Returns the IDs of the current hosts in the wazuh.yml
   */


  async getCurrentHostsIds() {
    try {
      const hosts = await this.getHosts();
      const ids = hosts.map(h => {
        return Object.keys(h)[0];
      });
      (0, _logger.log)('manage-hosts:getCurrentHostsIds', 'Getting hosts ids', 'debug');
      return ids;
    } catch (error) {
      (0, _logger.log)('manage-hosts:getCurrentHostsIds', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Get host by id
   * @param {String} id
   */


  async getHostById(id) {
    try {
      (0, _logger.log)('manage-hosts:getHostById', `Getting host ${id}`, 'debug');
      const hosts = await this.getHosts();
      const host = hosts.filter(h => {
        return Object.keys(h)[0] == id;
      });

      if (host && !host.length) {
        throw new Error('Selected API is no longer available in wazuh.yml');
      }

      const key = Object.keys(host[0])[0];
      const result = Object.assign(host[0][key], {
        id: key
      }) || {};
      return result;
    } catch (error) {
      (0, _logger.log)('manage-hosts:getHostById', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Decodes the API password
   * @param {String} password
   */


  decodeApiPassword(password) {
    return Buffer.from(password, 'base64').toString('ascii');
  }
  /**
   *  Iterate the array with the API entries in given from the .wazuh index in order to create a valid array
   * @param {Object} apiEntries
   */


  transformIndexedApis(apiEntries) {
    const entries = [];

    try {
      apiEntries.map(entry => {
        const id = entry._id;
        const host = entry._source;
        const api = {
          id: id,
          url: host.url,
          port: host.api_port,
          username: host.api_username,
          password: this.decodeApiPassword(host.api_password),
          cluster_info: host.cluster_info,
          extensions: host.extensions
        };
        entries.push(api);
      });
      (0, _logger.log)('manage-hosts:transformIndexedApis', 'Transforming index API schedule to wazuh.yml', 'debug');
    } catch (error) {
      (0, _logger.log)('manage-hosts:transformIndexedApis', error.message || error);
      throw error;
    }

    return entries;
  }
  /**
   * Calls transformIndexedApis() to get the entries to migrate and after that calls addSeveralHosts()
   * @param {Object} apiEntries
   */


  async migrateFromIndex(apiEntries) {
    try {
      const apis = this.transformIndexedApis(apiEntries);
      return await this.addSeveralHosts(apis);
    } catch (error) {
      (0, _logger.log)('manage-hosts:migrateFromIndex', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Receives an array of hosts and checks if any host is already in the wazuh.yml, in this case is removed from the received array and returns the resulting array
   * @param {Array} hosts
   */


  async cleanExistingHosts(hosts) {
    try {
      const currentHosts = await this.getCurrentHostsIds();
      const cleanHosts = hosts.filter(h => {
        return !currentHosts.includes(h.id);
      });
      (0, _logger.log)('manage-hosts:cleanExistingHosts', 'Preventing add existings hosts', 'debug');
      return cleanHosts;
    } catch (error) {
      (0, _logger.log)('manage-hosts:cleanExistingHosts', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Throws an error is the wazuh.yml is busy
   */


  checkBusy() {
    if (this.busy) throw new Error('Another process is writting the configuration file');
  }
  /**
   * Recursive function used to add several APIs entries
   * @param {Array} hosts
   */


  async addSeveralHosts(hosts) {
    try {
      (0, _logger.log)('manage-hosts:addSeveralHosts', 'Adding several', 'debug');
      const hostsToAdd = await this.cleanExistingHosts(hosts);
      if (!hostsToAdd.length) return 'There are not APIs entries to migrate';

      for (let idx in hostsToAdd) {
        const entry = hostsToAdd[idx];
        await this.addHost(entry);
      }

      return 'All APIs entries were migrated to the wazuh.yml';
    } catch (error) {
      (0, _logger.log)('manage-hosts:addSeveralHosts', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Add a single host
   * @param {Obeject} host
   */


  async addHost(host) {
    const id = host.id || new Date().getTime();
    const compose = this.composeHost(host, id);
    let data = await _fs.default.readFileSync(this.file, {
      encoding: 'utf-8'
    });

    try {
      this.checkBusy();
      const hosts = (await this.getHosts()) || [];
      this.busy = true;

      if (!hosts.length) {
        const hostsExists = await this.checkIfHostsKeyExists();
        const result = !hostsExists ? `${data}\nhosts:\n${compose}\n` : `${data}\n${compose}\n`;
        await _fs.default.writeFileSync(this.file, result, 'utf8');
      } else {
        const lastHost = (hosts || []).pop();

        if (lastHost) {
          const lastHostObject = this.composeHost(lastHost[Object.keys(lastHost)[0]], Object.keys(lastHost)[0]);
          const regex = this.composeRegex(lastHost);
          const replace = data.replace(regex, `\n${lastHostObject}\n${compose}\n`);
          await _fs.default.writeFileSync(this.file, replace, 'utf8');
        }
      }

      this.busy = false;
      this.updateRegistry.migrateToRegistry(id, host.cluster_info, host.extensions);
      (0, _logger.log)('manage-hosts:addHost', `Host ${id} was properly added`, 'debug');
      return id;
    } catch (error) {
      this.busy = false;
      (0, _logger.log)('manage-hosts:addHost', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Delete a host from the wazuh.yml
   * @param {Object} req
   */


  async deleteHost(req) {
    let data = await _fs.default.readFileSync(this.file, {
      encoding: 'utf-8'
    });

    try {
      this.checkBusy();
      const hosts = (await this.getHosts()) || [];
      this.busy = true;

      if (!hosts.length) {
        throw new Error('There are not configured hosts.');
      } else {
        const hostsNumber = hosts.length;
        const target = (hosts || []).find(element => {
          return Object.keys(element)[0] === req.params.id;
        });

        if (!target) {
          throw new Error(`Host ${req.params.id} not found.`);
        }

        const regex = this.composeRegex(target);
        const result = data.replace(regex, ``);
        await _fs.default.writeFileSync(this.file, result, 'utf8');

        if (hostsNumber === 1) {
          data = await _fs.default.readFileSync(this.file, {
            encoding: 'utf-8'
          });
          const clearHosts = data.replace(new RegExp(`hosts:\\s*[\\n\\r]`, 'gm'), '');
          await _fs.default.writeFileSync(this.file, clearHosts, 'utf8');
        }
      }

      this.busy = false;
      (0, _logger.log)('manage-hosts:deleteHost', `Host ${req.params.id} was properly deleted`, 'debug');
      return true;
    } catch (error) {
      this.busy = false;
      (0, _logger.log)('manage-hosts:deleteHost', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Updates the hosts information
   * @param {String} id
   * @param {Object} host
   */


  async updateHost(id, host) {
    let data = await _fs.default.readFileSync(this.file, {
      encoding: 'utf-8'
    });

    try {
      this.checkBusy();
      const hosts = (await this.getHosts()) || [];
      this.busy = true;

      if (!hosts.length) {
        throw new Error('There are not configured hosts.');
      } else {
        const target = (hosts || []).find(element => {
          return Object.keys(element)[0] === id;
        });

        if (!target) {
          throw new Error(`Host ${id} not found.`);
        }

        const regex = this.composeRegex(target);
        const result = data.replace(regex, `\n${this.composeHost(host, id)}`);
        await _fs.default.writeFileSync(this.file, result, 'utf8');
      }

      this.busy = false;
      (0, _logger.log)('manage-hosts:updateHost', `Host ${id} was properly updated`, 'debug');
      return true;
    } catch (error) {
      this.busy = false;
      (0, _logger.log)('manage-hosts:updateHost', error.message || error);
      return Promise.reject(error);
    }
  }

}

exports.ManageHosts = ManageHosts;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1hbmFnZS1ob3N0cy50cyJdLCJuYW1lcyI6WyJNYW5hZ2VIb3N0cyIsImNvbnN0cnVjdG9yIiwiYnVzeSIsImZpbGUiLCJXQVpVSF9EQVRBX0NPTkZJR19BUFBfUEFUSCIsInVwZGF0ZVJlZ2lzdHJ5IiwiVXBkYXRlUmVnaXN0cnkiLCJpbml0aWFsQ29uZmlnIiwiaW5pdGlhbFdhenVoQ29uZmlnIiwiY29tcG9zZUhvc3QiLCJob3N0IiwiaWQiLCJEYXRlIiwiZ2V0VGltZSIsInVybCIsInBvcnQiLCJ1c2VybmFtZSIsInVzZXIiLCJwYXNzd29yZCIsImVycm9yIiwibWVzc2FnZSIsImNvbXBvc2VSZWdleCIsImhvc3RJZCIsIk9iamVjdCIsImtleXMiLCJyZWciLCJSZWdFeHAiLCJnZXRIb3N0cyIsImNoZWNrQnVzeSIsImZzIiwiZXhpc3RzU3luYyIsIndyaXRlRmlsZVN5bmMiLCJlbmNvZGluZyIsIm1vZGUiLCJyYXciLCJyZWFkRmlsZVN5bmMiLCJjb250ZW50IiwieW1sIiwibG9hZCIsImVudHJpZXMiLCJQcm9taXNlIiwicmVqZWN0IiwiY2hlY2tJZkhvc3RzS2V5RXhpc3RzIiwiaW5jbHVkZXMiLCJnZXRDdXJyZW50SG9zdHNJZHMiLCJob3N0cyIsImlkcyIsIm1hcCIsImgiLCJnZXRIb3N0QnlJZCIsImZpbHRlciIsImxlbmd0aCIsIkVycm9yIiwia2V5IiwicmVzdWx0IiwiYXNzaWduIiwiZGVjb2RlQXBpUGFzc3dvcmQiLCJCdWZmZXIiLCJmcm9tIiwidG9TdHJpbmciLCJ0cmFuc2Zvcm1JbmRleGVkQXBpcyIsImFwaUVudHJpZXMiLCJlbnRyeSIsIl9pZCIsIl9zb3VyY2UiLCJhcGkiLCJhcGlfcG9ydCIsImFwaV91c2VybmFtZSIsImFwaV9wYXNzd29yZCIsImNsdXN0ZXJfaW5mbyIsImV4dGVuc2lvbnMiLCJwdXNoIiwibWlncmF0ZUZyb21JbmRleCIsImFwaXMiLCJhZGRTZXZlcmFsSG9zdHMiLCJjbGVhbkV4aXN0aW5nSG9zdHMiLCJjdXJyZW50SG9zdHMiLCJjbGVhbkhvc3RzIiwiaG9zdHNUb0FkZCIsImlkeCIsImFkZEhvc3QiLCJjb21wb3NlIiwiZGF0YSIsImhvc3RzRXhpc3RzIiwibGFzdEhvc3QiLCJwb3AiLCJsYXN0SG9zdE9iamVjdCIsInJlZ2V4IiwicmVwbGFjZSIsIm1pZ3JhdGVUb1JlZ2lzdHJ5IiwiZGVsZXRlSG9zdCIsInJlcSIsImhvc3RzTnVtYmVyIiwidGFyZ2V0IiwiZmluZCIsImVsZW1lbnQiLCJwYXJhbXMiLCJjbGVhckhvc3RzIiwidXBkYXRlSG9zdCJdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7QUFXQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFqQkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQVNPLE1BQU1BLFdBQU4sQ0FBa0I7QUFLdkJDLEVBQUFBLFdBQVcsR0FBRztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQ1osU0FBS0MsSUFBTCxHQUFZLEtBQVo7QUFDQSxTQUFLQyxJQUFMLEdBQVlDLHFDQUFaO0FBQ0EsU0FBS0MsY0FBTCxHQUFzQixJQUFJQyw4QkFBSixFQUF0QjtBQUNBLFNBQUtDLGFBQUwsR0FBcUJDLHNDQUFyQjtBQUNEO0FBRUQ7QUFDRjtBQUNBO0FBQ0E7QUFDQTs7O0FBQ0VDLEVBQUFBLFdBQVcsQ0FBQ0MsSUFBRCxFQUFPQyxFQUFQLEVBQVc7QUFDcEIsUUFBSTtBQUNGLHVCQUFJLDBCQUFKLEVBQWdDLGdCQUFoQyxFQUFrRCxPQUFsRDtBQUNBLGFBQVEsT0FBTSxDQUFDQSxFQUFELEdBQU0sSUFBSUMsSUFBSixHQUFXQyxPQUFYLEVBQU4sR0FBNkJGLEVBQUc7QUFDcEQsYUFBYUQsSUFBSSxDQUFDSSxHQUFJO0FBQ3RCLGNBQWNKLElBQUksQ0FBQ0ssSUFBSztBQUN4QixrQkFBa0JMLElBQUksQ0FBQ00sUUFBTCxJQUFpQk4sSUFBSSxDQUFDTyxJQUFLO0FBQzdDLGtCQUFrQlAsSUFBSSxDQUFDUSxRQUFT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QUFrQndFLE1BQWxCLENBQWQ7QUFDQSxjQUFNdkMsTUFBTSxHQUFHNEIsSUFBSSxDQUFDTSxPQUFMLENBQWFELEtBQWIsRUFBcUIsS0FBSSxLQUFLOUUsV0FBTCxDQUFpQkMsSUFBakIsRUFBdUJDLEVBQXZCLENBQTJCLEVBQXBELENBQWY7QUFDQSxjQUFNa0IsWUFBR0UsYUFBSCxDQUFpQixLQUFLNUIsSUFBdEIsRUFBNEJtRCxNQUE1QixFQUFvQyxNQUFwQyxDQUFOO0FBQ0Q7O0FBQ0QsV0FBS3BELElBQUwsR0FBWSxLQUFaO0FBQ0EsdUJBQ0UseUJBREYsRUFFRyxRQUFPUyxFQUFHLHVCQUZiLEVBR0UsT0FIRjtBQUtBLGFBQU8sSUFBUDtBQUNELEtBeEJELENBd0JFLE9BQU9RLEtBQVAsRUFBYztBQUNkLFdBQUtqQixJQUFMLEdBQVksS0FBWjtBQUNBLHVCQUFJLHlCQUFKLEVBQStCaUIsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUFoRDtBQUNBLGFBQU9xQixPQUFPLENBQUNDLE1BQVIsQ0FBZXRCLEtBQWYsQ0FBUDtBQUNEO0FBQ0Y7O0FBN1dzQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgdG8gdXBkYXRlIHRoZSBjb25maWd1cmF0aW9uIGZpbGVcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5pbXBvcnQgZnMgZnJvbSAnZnMnO1xuaW1wb3J0IHltbCBmcm9tICdqcy15YW1sJztcbmltcG9ydCB7IGxvZyB9IGZyb20gJy4vbG9nZ2VyJztcbmltcG9ydCB7IFVwZGF0ZVJlZ2lzdHJ5IH0gZnJvbSAnLi91cGRhdGUtcmVnaXN0cnknO1xuaW1wb3J0IHsgaW5pdGlhbFdhenVoQ29uZmlnIH0gZnJvbSAnLi9pbml0aWFsLXdhenVoLWNvbmZpZyc7XG5pbXBvcnQgeyBXQVpVSF9EQVRBX0NPTkZJR19BUFBfUEFUSCB9IGZyb20gJy4uLy4uL2NvbW1vbi9jb25zdGFudHMnO1xuaW1wb3J0IHsgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzIH0gZnJvbSAnLi4vbGliL2ZpbGVzeXN0ZW0nO1xuXG5leHBvcnQgY2xhc3MgTWFuYWdlSG9zdHMge1xuICBidXN5OiBib29sZWFuO1xuICBmaWxlOiBzdHJpbmc7XG4gIHVwZGF0ZVJlZ2lzdHJ5OiBVcGRhdGVSZWdpc3RyeTtcbiAgaW5pdGlhbENvbmZpZzogc3RyaW5nO1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLmJ1c3kgPSBmYWxzZTtcbiAgICB0aGlzLmZpbGUgPSBXQVpVSF9EQVRBX0NPTkZJR19BUFBfUEFUSDtcbiAgICB0aGlzLnVwZGF0ZVJlZ2lzdHJ5ID0gbmV3IFVwZGF0ZVJlZ2lzdHJ5KCk7XG4gICAgdGhpcy5pbml0aWFsQ29uZmlnID0gaW5pdGlhbFdhenVoQ29uZmlnO1xuICB9XG5cbiAgLyoqXG4gICAqIENvbXBvc2VzIHRoZSBob3N0IHN0cnVjdHVyZVxuICAgKiBAcGFyYW0ge09iamVjdH0gaG9zdFxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWRcbiAgICovXG4gIGNvbXBvc2VIb3N0KGhvc3QsIGlkKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygnbWFuYWdlLWhvc3RzOmNvbXBvc2VIb3N0JywgJ0NvbXBvc2luZyBob3N0JywgJ2RlYnVnJyk7XG4gICAgICByZXR1cm4gYCAgLSAkeyFpZCA/IG5ldyBEYXRlKCkuZ2V0VGltZSgpIDogaWR9OlxuICAgICAgdXJsOiAke2hvc3QudXJsfVxuICAgICAgcG9ydDogJHtob3N0LnBvcnR9XG4gICAgICB1c2VybmFtZTogJHtob3N0LnVzZXJuYW1lIHx8IGhvc3QudXNlcn1cbiAgICAgIHBhc3N3b3JkOiAke2hvc3QucGFzc3dvcmR9YDtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdtYW5hZ2UtaG9zdHM6Y29tcG9zZUhvc3QnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZWdleCB0byBidWlsZCB0aGUgaG9zdFxuICAgKiBAcGFyYW0ge09iamVjdH0gaG9zdFxuICAgKi9cbiAgY29tcG9zZVJlZ2V4KGhvc3QpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgaG9zdElkID0gT2JqZWN0LmtleXMoaG9zdClbMF07XG4gICAgICBjb25zdCByZWcgPSBgXFxcXHMqLVxcXFxzKiR7aG9zdElkfVxcXFxzKjpcXFxccypcXFxcbipcXFxccyp1cmxcXFxccyo6XFxcXHMqXFxcXFMqXFxcXHMqXFxcXG4qXFxcXHMqcG9ydFxcXFxzKjpcXFxccypcXFxcUypcXFxccypcXFxcbipcXFxccyp1c2VybmFtZVxcXFxzKjpcXFxccypcXFxcUypcXFxccypcXFxcbipcXFxccypwYXNzd29yZFxcXFxzKjpcXFxccypcXFxcUypgO1xuICAgICAgbG9nKCdtYW5hZ2UtaG9zdHM6Y29tcG9zZVJlZ2V4JywgJ0NvbXBvc2luZyByZWdleCcsICdkZWJ1ZycpO1xuICAgICAgcmV0dXJuIG5ldyBSZWdFeHAoYCR7cmVnfWAsICdnbScpO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ21hbmFnZS1ob3N0czpjb21wb3NlUmVnZXgnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBob3N0cyBpbiB0aGUgd2F6dWgueW1sXG4gICAqL1xuICBhc3luYyBnZXRIb3N0cygpIHtcbiAgICB0cnkge1xuICAgICAgdGhpcy5jaGVja0J1c3koKTtcbiAgICAgIHRoaXMuYnVzeSA9IHRydWU7XG4gICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoKTtcbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygnY29uZmlnJyk7XG4gICAgICBpZiAoIWZzLmV4aXN0c1N5bmMoV0FaVUhfREFUQV9DT05GSUdfQVBQX1BBVEgpKSB7XG4gICAgICAgIGF3YWl0IGZzLndyaXRlRmlsZVN5bmModGhpcy5maWxlLCB0aGlzLmluaXRpYWxDb25maWcsIHsgZW5jb2Rpbmc6ICd1dGY4JywgbW9kZTogMG82MDAgfSk7XG4gICAgICB9XG4gICAgICBjb25zdCByYXcgPSBmcy5yZWFkRmlsZVN5bmModGhpcy5maWxlLCB7IGVuY29kaW5nOiAndXRmLTgnIH0pO1xuICAgICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgICBjb25zdCBjb250ZW50ID0geW1sLmxvYWQocmF3KTtcbiAgICAgIGxvZygnbWFuYWdlLWhvc3RzOmdldEhvc3RzJywgJ0dldHRpbmcgaG9zdHMnLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGVudHJpZXMgPSAoY29udGVudCB8fCB7fSlbJ2hvc3RzJ10gfHwgW107XG4gICAgICByZXR1cm4gZW50cmllcztcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgICBsb2coJ21hbmFnZS1ob3N0czpnZXRIb3N0cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogVGhpcyBmdW5jdGlvbiBjaGVja3MgaWYgdGhlIGhvc3RzOiBrZXkgZXhpc3RzIGluIHRoZSB3YXp1aC55bWwgZm9yIHByZXZlbnRpbmcgZHVwbGljYXRlIGluIGNhc2Ugb2YgdGhlcmUncyBub3QgYW55IGhvc3QgZGVmaW5lZFxuICAgKi9cbiAgYXN5bmMgY2hlY2tJZkhvc3RzS2V5RXhpc3RzKCkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ21hbmFnZS1ob3N0czpjaGVja0lmSG9zdHNLZXlFeGlzdHMnLCAnQ2hlY2tpbmcgaG9zdHMga2V5JywgJ2RlYnVnJyk7XG4gICAgICB0aGlzLmJ1c3kgPSB0cnVlO1xuICAgICAgY29uc3QgcmF3ID0gZnMucmVhZEZpbGVTeW5jKHRoaXMuZmlsZSwgeyBlbmNvZGluZzogJ3V0Zi04JyB9KTtcbiAgICAgIHRoaXMuYnVzeSA9IGZhbHNlO1xuICAgICAgY29uc3QgY29udGVudCA9IHltbC5sb2FkKHJhdyk7XG4gICAgICByZXR1cm4gT2JqZWN0LmtleXMoY29udGVudCB8fCB7fSkuaW5jbHVkZXMoJ2hvc3RzJyk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnbWFuYWdlLWhvc3RzOmNoZWNrSWZIb3N0c0tleUV4aXN0cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSBJRHMgb2YgdGhlIGN1cnJlbnQgaG9zdHMgaW4gdGhlIHdhenVoLnltbFxuICAgKi9cbiAgYXN5bmMgZ2V0Q3VycmVudEhvc3RzSWRzKCkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBob3N0cyA9IGF3YWl0IHRoaXMuZ2V0SG9zdHMoKTtcbiAgICAgIGNvbnN0IGlkcyA9IGhvc3RzLm1hcChoID0+IHtcbiAgICAgICAgcmV0dXJuIE9iamVjdC5rZXlzKGgpWzBdO1xuICAgICAgfSk7XG4gICAgICBsb2coJ21hbmFnZS1ob3N0czpnZXRDdXJyZW50SG9zdHNJZHMnLCAnR2V0dGluZyBob3N0cyBpZHMnLCAnZGVidWcnKTtcbiAgICAgIHJldHVybiBpZHM7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnbWFuYWdlLWhvc3RzOmdldEN1cnJlbnRIb3N0c0lkcycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogR2V0IGhvc3QgYnkgaWRcbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkXG4gICAqL1xuICBhc3luYyBnZXRIb3N0QnlJZChpZCkge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ21hbmFnZS1ob3N0czpnZXRIb3N0QnlJZCcsIGBHZXR0aW5nIGhvc3QgJHtpZH1gLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGhvc3RzID0gYXdhaXQgdGhpcy5nZXRIb3N0cygpO1xuICAgICAgY29uc3QgaG9zdCA9IGhvc3RzLmZpbHRlcihoID0+IHtcbiAgICAgICAgcmV0dXJuIE9iamVjdC5rZXlzKGgpWzBdID09IGlkO1xuICAgICAgfSk7XG4gICAgICBpZihob3N0ICYmICFob3N0Lmxlbmd0aCl7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignU2VsZWN0ZWQgQVBJIGlzIG5vIGxvbmdlciBhdmFpbGFibGUgaW4gd2F6dWgueW1sJyk7XG4gICAgICB9XG4gICAgICBjb25zdCBrZXkgPSBPYmplY3Qua2V5cyhob3N0WzBdKVswXTtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IE9iamVjdC5hc3NpZ24oaG9zdFswXVtrZXldLCB7IGlkOiBrZXkgfSkgfHwge307XG4gICAgICByZXR1cm4gcmVzdWx0O1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ21hbmFnZS1ob3N0czpnZXRIb3N0QnlJZCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogRGVjb2RlcyB0aGUgQVBJIHBhc3N3b3JkXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBwYXNzd29yZFxuICAgKi9cbiAgZGVjb2RlQXBpUGFzc3dvcmQocGFzc3dvcmQpIHtcbiAgICByZXR1cm4gQnVmZmVyLmZyb20ocGFzc3dvcmQsICdiYXNlNjQnKS50b1N0cmluZygnYXNjaWknKTtcbiAgfVxuXG4gIC8qKlxuICAgKiAgSXRlcmF0ZSB0aGUgYXJyYXkgd2l0aCB0aGUgQVBJIGVudHJpZXMgaW4gZ2l2ZW4gZnJvbSB0aGUgLndhenVoIGluZGV4IGluIG9yZGVyIHRvIGNyZWF0ZSBhIHZhbGlkIGFycmF5XG4gICAqIEBwYXJhbSB7T2JqZWN0fSBhcGlFbnRyaWVzXG4gICAqL1xuICB0cmFuc2Zvcm1JbmRleGVkQXBpcyhhcGlFbnRyaWVzKSB7XG4gICAgY29uc3QgZW50cmllcyA9IFtdO1xuICAgIHRyeSB7XG4gICAgICBhcGlFbnRyaWVzLm1hcChlbnRyeSA9PiB7XG4gICAgICAgIGNvbnN0IGlkID0gZW50cnkuX2lkO1xuICAgICAgICBjb25zdCBob3N0ID0gZW50cnkuX3NvdXJjZTtcbiAgICAgICAgY29uc3QgYXBpID0ge1xuICAgICAgICAgIGlkOiBpZCxcbiAgICAgICAgICB1cmw6IGhvc3QudXJsLFxuICAgICAgICAgIHBvcnQ6IGhvc3QuYXBpX3BvcnQsXG4gICAgICAgICAgdXNlcm5hbWU6IGhvc3QuYXBpX3VzZXJuYW1lLFxuICAgICAgICAgIHBhc3N3b3JkOiB0aGlzLmRlY29kZUFwaVBhc3N3b3JkKGhvc3QuYXBpX3Bhc3N3b3JkKSxcbiAgICAgICAgICBjbHVzdGVyX2luZm86IGhvc3QuY2x1c3Rlcl9pbmZvLFxuICAgICAgICAgIGV4dGVuc2lvbnM6IGhvc3QuZXh0ZW5zaW9uc1xuICAgICAgICB9O1xuICAgICAgICBlbnRyaWVzLnB1c2goYXBpKTtcbiAgICAgIH0pO1xuICAgICAgbG9nKFxuICAgICAgICAnbWFuYWdlLWhvc3RzOnRyYW5zZm9ybUluZGV4ZWRBcGlzJyxcbiAgICAgICAgJ1RyYW5zZm9ybWluZyBpbmRleCBBUEkgc2NoZWR1bGUgdG8gd2F6dWgueW1sJyxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdtYW5hZ2UtaG9zdHM6dHJhbnNmb3JtSW5kZXhlZEFwaXMnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHRocm93IGVycm9yO1xuICAgIH1cbiAgICByZXR1cm4gZW50cmllcztcbiAgfVxuXG4gIC8qKlxuICAgKiBDYWxscyB0cmFuc2Zvcm1JbmRleGVkQXBpcygpIHRvIGdldCB0aGUgZW50cmllcyB0byBtaWdyYXRlIGFuZCBhZnRlciB0aGF0IGNhbGxzIGFkZFNldmVyYWxIb3N0cygpXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBhcGlFbnRyaWVzXG4gICAqL1xuICBhc3luYyBtaWdyYXRlRnJvbUluZGV4KGFwaUVudHJpZXMpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgYXBpcyA9IHRoaXMudHJhbnNmb3JtSW5kZXhlZEFwaXMoYXBpRW50cmllcyk7XG4gICAgICByZXR1cm4gYXdhaXQgdGhpcy5hZGRTZXZlcmFsSG9zdHMoYXBpcyk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnbWFuYWdlLWhvc3RzOm1pZ3JhdGVGcm9tSW5kZXgnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFJlY2VpdmVzIGFuIGFycmF5IG9mIGhvc3RzIGFuZCBjaGVja3MgaWYgYW55IGhvc3QgaXMgYWxyZWFkeSBpbiB0aGUgd2F6dWgueW1sLCBpbiB0aGlzIGNhc2UgaXMgcmVtb3ZlZCBmcm9tIHRoZSByZWNlaXZlZCBhcnJheSBhbmQgcmV0dXJucyB0aGUgcmVzdWx0aW5nIGFycmF5XG4gICAqIEBwYXJhbSB7QXJyYXl9IGhvc3RzXG4gICAqL1xuICBhc3luYyBjbGVhbkV4aXN0aW5nSG9zdHMoaG9zdHMpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY3VycmVudEhvc3RzID0gYXdhaXQgdGhpcy5nZXRDdXJyZW50SG9zdHNJZHMoKTtcbiAgICAgIGNvbnN0IGNsZWFuSG9zdHMgPSBob3N0cy5maWx0ZXIoaCA9PiB7XG4gICAgICAgIHJldHVybiAhY3VycmVudEhvc3RzLmluY2x1ZGVzKGguaWQpO1xuICAgICAgfSk7XG4gICAgICBsb2coXG4gICAgICAgICdtYW5hZ2UtaG9zdHM6Y2xlYW5FeGlzdGluZ0hvc3RzJyxcbiAgICAgICAgJ1ByZXZlbnRpbmcgYWRkIGV4aXN0aW5ncyBob3N0cycsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICByZXR1cm4gY2xlYW5Ib3N0cztcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdtYW5hZ2UtaG9zdHM6Y2xlYW5FeGlzdGluZ0hvc3RzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaHJvd3MgYW4gZXJyb3IgaXMgdGhlIHdhenVoLnltbCBpcyBidXN5XG4gICAqL1xuICBjaGVja0J1c3koKSB7XG4gICAgaWYgKHRoaXMuYnVzeSlcbiAgICAgIHRocm93IG5ldyBFcnJvcignQW5vdGhlciBwcm9jZXNzIGlzIHdyaXR0aW5nIHRoZSBjb25maWd1cmF0aW9uIGZpbGUnKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZWN1cnNpdmUgZnVuY3Rpb24gdXNlZCB0byBhZGQgc2V2ZXJhbCBBUElzIGVudHJpZXNcbiAgICogQHBhcmFtIHtBcnJheX0gaG9zdHNcbiAgICovXG4gIGFzeW5jIGFkZFNldmVyYWxIb3N0cyhob3N0cykge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ21hbmFnZS1ob3N0czphZGRTZXZlcmFsSG9zdHMnLCAnQWRkaW5nIHNldmVyYWwnLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGhvc3RzVG9BZGQgPSBhd2FpdCB0aGlzLmNsZWFuRXhpc3RpbmdIb3N0cyhob3N0cyk7XG4gICAgICBpZiAoIWhvc3RzVG9BZGQubGVuZ3RoKSByZXR1cm4gJ1RoZXJlIGFyZSBub3QgQVBJcyBlbnRyaWVzIHRvIG1pZ3JhdGUnO1xuICAgICAgZm9yIChsZXQgaWR4IGluIGhvc3RzVG9BZGQpIHtcbiAgICAgICAgY29uc3QgZW50cnkgPSBob3N0c1RvQWRkW2lkeF07XG4gICAgICAgIGF3YWl0IHRoaXMuYWRkSG9zdChlbnRyeSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gJ0FsbCBBUElzIGVudHJpZXMgd2VyZSBtaWdyYXRlZCB0byB0aGUgd2F6dWgueW1sJztcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdtYW5hZ2UtaG9zdHM6YWRkU2V2ZXJhbEhvc3RzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBBZGQgYSBzaW5nbGUgaG9zdFxuICAgKiBAcGFyYW0ge09iZWplY3R9IGhvc3RcbiAgICovXG4gIGFzeW5jIGFkZEhvc3QoaG9zdCkge1xuICAgIGNvbnN0IGlkID0gaG9zdC5pZCB8fCBuZXcgRGF0ZSgpLmdldFRpbWUoKTtcbiAgICBjb25zdCBjb21wb3NlID0gdGhpcy5jb21wb3NlSG9zdChob3N0LCBpZCk7XG4gICAgbGV0IGRhdGEgPSBhd2FpdCBmcy5yZWFkRmlsZVN5bmModGhpcy5maWxlLCB7IGVuY29kaW5nOiAndXRmLTgnIH0pO1xuICAgIHRyeSB7XG4gICAgICB0aGlzLmNoZWNrQnVzeSgpO1xuICAgICAgY29uc3QgaG9zdHMgPSAoYXdhaXQgdGhpcy5nZXRIb3N0cygpKSB8fCBbXTtcbiAgICAgIHRoaXMuYnVzeSA9IHRydWU7XG4gICAgICBpZiAoIWhvc3RzLmxlbmd0aCkge1xuICAgICAgICBjb25zdCBob3N0c0V4aXN0cyA9IGF3YWl0IHRoaXMuY2hlY2tJZkhvc3RzS2V5RXhpc3RzKCk7XG4gICAgICAgIGNvbnN0IHJlc3VsdCA9ICFob3N0c0V4aXN0c1xuICAgICAgICAgID8gYCR7ZGF0YX1cXG5ob3N0czpcXG4ke2NvbXBvc2V9XFxuYFxuICAgICAgICAgIDogYCR7ZGF0YX1cXG4ke2NvbXBvc2V9XFxuYDtcbiAgICAgICAgYXdhaXQgZnMud3JpdGVGaWxlU3luYyh0aGlzLmZpbGUsIHJlc3VsdCwgJ3V0ZjgnKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGNvbnN0IGxhc3RIb3N0ID0gKGhvc3RzIHx8IFtdKS5wb3AoKTtcbiAgICAgICAgaWYgKGxhc3RIb3N0KSB7XG4gICAgICAgICAgY29uc3QgbGFzdEhvc3RPYmplY3QgPSB0aGlzLmNvbXBvc2VIb3N0KFxuICAgICAgICAgICAgbGFzdEhvc3RbT2JqZWN0LmtleXMobGFzdEhvc3QpWzBdXSxcbiAgICAgICAgICAgIE9iamVjdC5rZXlzKGxhc3RIb3N0KVswXVxuICAgICAgICAgICk7XG4gICAgICAgICAgY29uc3QgcmVnZXggPSB0aGlzLmNvbXBvc2VSZWdleChsYXN0SG9zdCk7XG4gICAgICAgICAgY29uc3QgcmVwbGFjZSA9IGRhdGEucmVwbGFjZShcbiAgICAgICAgICAgIHJlZ2V4LFxuICAgICAgICAgICAgYFxcbiR7bGFzdEhvc3RPYmplY3R9XFxuJHtjb21wb3NlfVxcbmBcbiAgICAgICAgICApO1xuICAgICAgICAgIGF3YWl0IGZzLndyaXRlRmlsZVN5bmModGhpcy5maWxlLCByZXBsYWNlLCAndXRmOCcpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICB0aGlzLmJ1c3kgPSBmYWxzZTtcbiAgICAgIHRoaXMudXBkYXRlUmVnaXN0cnkubWlncmF0ZVRvUmVnaXN0cnkoXG4gICAgICAgIGlkLFxuICAgICAgICBob3N0LmNsdXN0ZXJfaW5mbyxcbiAgICAgICAgaG9zdC5leHRlbnNpb25zXG4gICAgICApO1xuICAgICAgbG9nKCdtYW5hZ2UtaG9zdHM6YWRkSG9zdCcsIGBIb3N0ICR7aWR9IHdhcyBwcm9wZXJseSBhZGRlZGAsICdkZWJ1ZycpO1xuICAgICAgcmV0dXJuIGlkO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICB0aGlzLmJ1c3kgPSBmYWxzZTtcbiAgICAgIGxvZygnbWFuYWdlLWhvc3RzOmFkZEhvc3QnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIERlbGV0ZSBhIGhvc3QgZnJvbSB0aGUgd2F6dWgueW1sXG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXFcbiAgICovXG4gIGFzeW5jIGRlbGV0ZUhvc3QocmVxKSB7XG4gICAgbGV0IGRhdGEgPSBhd2FpdCBmcy5yZWFkRmlsZVN5bmModGhpcy5maWxlLCB7IGVuY29kaW5nOiAndXRmLTgnIH0pO1xuICAgIHRyeSB7XG4gICAgICB0aGlzLmNoZWNrQnVzeSgpO1xuICAgICAgY29uc3QgaG9zdHMgPSAoYXdhaXQgdGhpcy5nZXRIb3N0cygpKSB8fCBbXTtcbiAgICAgIHRoaXMuYnVzeSA9IHRydWU7XG4gICAgICBpZiAoIWhvc3RzLmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ1RoZXJlIGFyZSBub3QgY29uZmlndXJlZCBob3N0cy4nKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIGNvbnN0IGhvc3RzTnVtYmVyID0gaG9zdHMubGVuZ3RoO1xuICAgICAgICBjb25zdCB0YXJnZXQgPSAoaG9zdHMgfHwgW10pLmZpbmQoZWxlbWVudCA9PiB7XG4gICAgICAgICAgcmV0dXJuIE9iamVjdC5rZXlzKGVsZW1lbnQpWzBdID09PSByZXEucGFyYW1zLmlkO1xuICAgICAgICB9KTtcbiAgICAgICAgaWYgKCF0YXJnZXQpIHtcbiAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEhvc3QgJHtyZXEucGFyYW1zLmlkfSBub3QgZm91bmQuYCk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgcmVnZXggPSB0aGlzLmNvbXBvc2VSZWdleCh0YXJnZXQpO1xuICAgICAgICBjb25zdCByZXN1bHQgPSBkYXRhLnJlcGxhY2UocmVnZXgsIGBgKTtcbiAgICAgICAgYXdhaXQgZnMud3JpdGVGaWxlU3luYyh0aGlzLmZpbGUsIHJlc3VsdCwgJ3V0ZjgnKTtcbiAgICAgICAgaWYgKGhvc3RzTnVtYmVyID09PSAxKSB7XG4gICAgICAgICAgZGF0YSA9IGF3YWl0IGZzLnJlYWRGaWxlU3luYyh0aGlzLmZpbGUsIHsgZW5jb2Rpbmc6ICd1dGYtOCcgfSk7XG4gICAgICAgICAgY29uc3QgY2xlYXJIb3N0cyA9IGRhdGEucmVwbGFjZShcbiAgICAgICAgICAgIG5ldyBSZWdFeHAoYGhvc3RzOlxcXFxzKltcXFxcblxcXFxyXWAsICdnbScpLFxuICAgICAgICAgICAgJydcbiAgICAgICAgICApO1xuICAgICAgICAgIGF3YWl0IGZzLndyaXRlRmlsZVN5bmModGhpcy5maWxlLCBjbGVhckhvc3RzLCAndXRmOCcpO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgICB0aGlzLmJ1c3kgPSBmYWxzZTtcbiAgICAgIGxvZyhcbiAgICAgICAgJ21hbmFnZS1ob3N0czpkZWxldGVIb3N0JyxcbiAgICAgICAgYEhvc3QgJHtyZXEucGFyYW1zLmlkfSB3YXMgcHJvcGVybHkgZGVsZXRlZGAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICByZXR1cm4gdHJ1ZTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgICBsb2coJ21hbmFnZS1ob3N0czpkZWxldGVIb3N0JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBVcGRhdGVzIHRoZSBob3N0cyBpbmZvcm1hdGlvblxuICAgKiBAcGFyYW0ge1N0cmluZ30gaWRcbiAgICogQHBhcmFtIHtPYmplY3R9IGhvc3RcbiAgICovXG4gIGFzeW5jIHVwZGF0ZUhvc3QoaWQsIGhvc3QpIHtcbiAgICBsZXQgZGF0YSA9IGF3YWl0IGZzLnJlYWRGaWxlU3luYyh0aGlzLmZpbGUsIHsgZW5jb2Rpbmc6ICd1dGYtOCcgfSk7XG4gICAgdHJ5IHtcbiAgICAgIHRoaXMuY2hlY2tCdXN5KCk7XG4gICAgICBjb25zdCBob3N0cyA9IChhd2FpdCB0aGlzLmdldEhvc3RzKCkpIHx8IFtdO1xuICAgICAgdGhpcy5idXN5ID0gdHJ1ZTtcbiAgICAgIGlmICghaG9zdHMubGVuZ3RoKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignVGhlcmUgYXJlIG5vdCBjb25maWd1cmVkIGhvc3RzLicpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgY29uc3QgdGFyZ2V0ID0gKGhvc3RzIHx8IFtdKS5maW5kKGVsZW1lbnQgPT4ge1xuICAgICAgICAgIHJldHVybiBPYmplY3Qua2V5cyhlbGVtZW50KVswXSA9PT0gaWQ7XG4gICAgICAgIH0pO1xuICAgICAgICBpZiAoIXRhcmdldCkge1xuICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgSG9zdCAke2lkfSBub3QgZm91bmQuYCk7XG4gICAgICAgIH1cbiAgICAgICAgY29uc3QgcmVnZXggPSB0aGlzLmNvbXBvc2VSZWdleCh0YXJnZXQpO1xuICAgICAgICBjb25zdCByZXN1bHQgPSBkYXRhLnJlcGxhY2UocmVnZXgsIGBcXG4ke3RoaXMuY29tcG9zZUhvc3QoaG9zdCwgaWQpfWApO1xuICAgICAgICBhd2FpdCBmcy53cml0ZUZpbGVTeW5jKHRoaXMuZmlsZSwgcmVzdWx0LCAndXRmOCcpO1xuICAgICAgfVxuICAgICAgdGhpcy5idXN5ID0gZmFsc2U7XG4gICAgICBsb2coXG4gICAgICAgICdtYW5hZ2UtaG9zdHM6dXBkYXRlSG9zdCcsXG4gICAgICAgIGBIb3N0ICR7aWR9IHdhcyBwcm9wZXJseSB1cGRhdGVkYCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiB0cnVlO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICB0aGlzLmJ1c3kgPSBmYWxzZTtcbiAgICAgIGxvZygnbWFuYWdlLWhvc3RzOnVwZGF0ZUhvc3QnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG59XG4iXX0=