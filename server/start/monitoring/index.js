"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.jobMonitoringRun = jobMonitoringRun;

var _nodeCron = _interopRequireDefault(require("node-cron"));

var _logger = require("../../lib/logger");

var _monitoringTemplate = require("../../integration-files/monitoring-template");

var _getConfiguration = require("../../lib/get-configuration");

var _parseCron = require("../../lib/parse-cron");

var _indexDate = require("../../lib/index-date");

var _buildIndexSettings = require("../../lib/build-index-settings");

var _wazuhHosts = require("../../controllers/wazuh-hosts");

var _constants = require("../../../common/constants");

var _tryCatchForIndexPermissionError = require("../tryCatchForIndexPermissionError");

var _utils = require("../../../common/utils");

var _settings = require("../../../common/services/settings");

/*
 * Wazuh app - Module for agent info fetching functions
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const blueWazuh = '\u001b[34mwazuh\u001b[39m';
const monitoringErrorLogColors = [blueWazuh, 'monitoring', 'error'];
const wazuhHostController = new _wazuhHosts.WazuhHostsCtrl();
let MONITORING_ENABLED, MONITORING_FREQUENCY, MONITORING_CRON_FREQ, MONITORING_CREATION, MONITORING_INDEX_PATTERN, MONITORING_INDEX_PREFIX; // Utils functions

/**
 * Get the setting value from the configuration
 * @param setting
 * @param configuration
 * @param defaultValue
 */

function getAppConfigurationSetting(setting, configuration, defaultValue) {
  return typeof configuration[setting] !== 'undefined' ? configuration[setting] : defaultValue;
}

;
/**
 * Set the monitoring variables
 * @param context
 */

function initMonitoringConfiguration(context) {
  try {
    const appConfig = (0, _getConfiguration.getConfiguration)();
    MONITORING_ENABLED = appConfig && typeof appConfig['wazuh.monitoring.enabled'] !== 'undefined' ? appConfig['wazuh.monitoring.enabled'] && appConfig['wazuh.monitoring.enabled'] !== 'worker' : (0, _settings.getSettingDefaultValue)('wazuh.monitoring.enabled');
    MONITORING_FREQUENCY = getAppConfigurationSetting('wazuh.monitoring.frequency', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.frequency'));
    MONITORING_CRON_FREQ = (0, _parseCron.parseCron)(MONITORING_FREQUENCY);
    MONITORING_CREATION = getAppConfigurationSetting('wazuh.monitoring.creation', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.creation'));
    MONITORING_INDEX_PATTERN = getAppConfigurationSetting('wazuh.monitoring.pattern', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.pattern'));
    const lastCharIndexPattern = MONITORING_INDEX_PATTERN[MONITORING_INDEX_PATTERN.length - 1];

    if (lastCharIndexPattern !== '*') {
      MONITORING_INDEX_PATTERN += '*';
    }

    ;
    MONITORING_INDEX_PREFIX = MONITORING_INDEX_PATTERN.slice(0, MONITORING_INDEX_PATTERN.length - 1);
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.enabled: ${MONITORING_ENABLED}`, 'debug');
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.frequency: ${MONITORING_FREQUENCY} (${MONITORING_CRON_FREQ})`, 'debug');
    (0, _logger.log)('monitoring:initMonitoringConfiguration', `wazuh.monitoring.pattern: ${MONITORING_INDEX_PATTERN} (index prefix: ${MONITORING_INDEX_PREFIX})`, 'debug');
  } catch (error) {
    const errorMessage = error.message || error;
    (0, _logger.log)('monitoring:initMonitoringConfiguration', errorMessage);
    context.wazuh.logger.error(errorMessage);
  }
}

;
/**
 * Main. First execution when installing / loading App.
 * @param context
 */

async function init(context) {
  try {
    if (MONITORING_ENABLED) {
      await checkTemplate(context);
    }

    ;
  } catch (error) {
    const errorMessage = error.message || error;
    (0, _logger.log)('monitoring:init', error.message || error);
    context.wazuh.logger.error(errorMessage);
  }
}
/**
 * Verify wazuh-agent template
 */


async function checkTemplate(context) {
  try {
    (0, _logger.log)('monitoring:checkTemplate', 'Updating the monitoring template', 'debug');

    try {
      // Check if the template already exists
      const currentTemplate = await context.core.elasticsearch.client.asInternalUser.indices.getTemplate({
        name: _constants.WAZUH_MONITORING_TEMPLATE_NAME
      }); // Copy already created index patterns

      _monitoringTemplate.monitoringTemplate.index_patterns = currentTemplate.body[_constants.WAZUH_MONITORING_TEMPLATE_NAME].index_patterns;
    } catch (error) {
      // Init with the default index pattern
      _monitoringTemplate.monitoringTemplate.index_patterns = [(0, _settings.getSettingDefaultValue)('wazuh.monitoring.pattern')];
    } // Check if the user is using a custom pattern and add it to the template if it does


    if (!_monitoringTemplate.monitoringTemplate.index_patterns.includes(MONITORING_INDEX_PATTERN)) {
      _monitoringTemplate.monitoringTemplate.index_patterns.push(MONITORING_INDEX_PATTERN);
    }

    ; // Update the monitoring template

    await context.core.elasticsearch.client.asInternalUser.indices.putTemplate({
      name: _constants.WAZUH_MONITORING_TEMPLATE_NAME,
      body: _monitoringTemplate.monitoringTemplate
    });
    (0, _logger.log)('monitoring:checkTemplate', 'Updated the monitoring template', 'debug');
  } catch (error) {
    const errorMessage = `Something went wrong updating the monitoring template ${error.message || error}`;
    (0, _logger.log)('monitoring:checkTemplate', errorMessage);
    context.wazuh.logger.error(monitoringErrorLogColors, errorMessage);
    throw error;
  }
}
/**
 * Save agent status into elasticsearch, create index and/or insert document
 * @param {*} context
 * @param {*} data
 */


async function insertMonitoringDataElasticsearch(context, data) {
  const monitoringIndexName = MONITORING_INDEX_PREFIX + (0, _indexDate.indexDate)(MONITORING_CREATION);

  if (!MONITORING_ENABLED) {
    return;
  }

  ;

  try {
    await (0, _tryCatchForIndexPermissionError.tryCatchForIndexPermissionError)(monitoringIndexName)(async () => {
      const exists = await context.core.elasticsearch.client.asInternalUser.indices.exists({
        index: monitoringIndexName
      });

      if (!exists.body) {
        await createIndex(context, monitoringIndexName);
      }

      ; // Update the index configuration

      const appConfig = (0, _getConfiguration.getConfiguration)();
      const indexConfiguration = (0, _buildIndexSettings.buildIndexSettings)(appConfig, 'wazuh.monitoring', (0, _settings.getSettingDefaultValue)('wazuh.monitoring.shards')); // To update the index settings with this client is required close the index, update the settings and open it
      // Number of shards is not dynamic so delete that setting if it's given

      delete indexConfiguration.settings.index.number_of_shards;
      await context.core.elasticsearch.client.asInternalUser.indices.putSettings({
        index: monitoringIndexName,
        body: indexConfiguration
      }); // Insert data to the monitoring index

      await insertDataToIndex(context, monitoringIndexName, data);
    })();
  } catch (error) {
    (0, _logger.log)('monitoring:insertMonitoringDataElasticsearch', error.message || error);
    context.wazuh.logger.error(error.message);
  }
}
/**
 * Inserting one document per agent into Elastic. Bulk.
 * @param {*} context Endpoint
 * @param {String} indexName The name for the index (e.g. daily: wazuh-monitoring-YYYY.MM.DD)
 * @param {*} data
 */


async function insertDataToIndex(context, indexName, data) {
  const {
    agents,
    apiHost
  } = data;

  try {
    if (agents.length > 0) {
      (0, _logger.log)('monitoring:insertDataToIndex', `Bulk data to index ${indexName} for ${agents.length} agents`, 'debug');
      const bodyBulk = agents.map(agent => {
        const agentInfo = { ...agent
        };
        agentInfo['timestamp'] = new Date(Date.now()).toISOString();
        agentInfo.host = agent.manager;
        agentInfo.cluster = {
          name: apiHost.clusterName ? apiHost.clusterName : 'disabled'
        };
        return `{ "index":  { "_index": "${indexName}" } }\n${JSON.stringify(agentInfo)}\n`;
      }).join('');
      await context.core.elasticsearch.client.asInternalUser.bulk({
        index: indexName,
        body: bodyBulk
      });
      (0, _logger.log)('monitoring:insertDataToIndex', `Bulk data to index ${indexName} for ${agents.length} agents completed`, 'debug');
    }
  } catch (error) {
    (0, _logger.log)('monitoring:insertDataToIndex', `Error inserting agent data into elasticsearch. Bulk request failed due to ${error.message || error}`);
  }
}
/**
 * Create the wazuh-monitoring index
 * @param {*} context context
 * @param {String} indexName The name for the index (e.g. daily: wazuh-monitoring-YYYY.MM.DD)
 */


async function createIndex(context, indexName) {
  try {
    if (!MONITORING_ENABLED) return;
    const appConfig = (0, _getConfiguration.getConfiguration)();
    const IndexConfiguration = {
      settings: {
        index: {
          number_of_shards: getAppConfigurationSetting('wazuh.monitoring.shards', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.shards')),
          number_of_replicas: getAppConfigurationSetting('wazuh.monitoring.replicas', appConfig, (0, _settings.getSettingDefaultValue)('wazuh.monitoring.replicas'))
        }
      }
    };
    await context.core.elasticsearch.client.asInternalUser.indices.create({
      index: indexName,
      body: IndexConfiguration
    });
    (0, _logger.log)('monitoring:createIndex', `Successfully created new index: ${indexName}`, 'debug');
  } catch (error) {
    const errorMessage = `Could not create ${indexName} index on elasticsearch due to ${error.message || error}`;
    (0, _logger.log)('monitoring:createIndex', errorMessage);
    context.wazuh.logger.error(errorMessage);
  }
}
/**
* Wait until Kibana server is ready
*/


async function checkPluginPlatformStatus(context) {
  try {
    (0, _logger.log)('monitoring:checkPluginPlatformStatus', 'Waiting for Kibana and Elasticsearch servers to be ready...', 'debug');
    await checkElasticsearchServer(context);
    await init(context);
    return;
  } catch (error) {
    (0, _logger.log)('monitoring:checkPluginPlatformStatus', error.mesage || error);

    try {
      await (0, _utils.delayAsPromise)(3000);
      await checkPluginPlatformStatus(context);
    } catch (error) {}

    ;
  }
}
/**
 * Check Elasticsearch Server status and Kibana index presence
 */


async function checkElasticsearchServer(context) {
  try {
    const data = await context.core.elasticsearch.client.asInternalUser.indices.exists({
      index: context.server.config.kibana.index
    });
    return data.body; // TODO: check if Elasticsearch can receive requests
    // if (data) {
    //   const pluginsData = await this.server.plugins.elasticsearch.waitUntilReady();
    //   return pluginsData;
    // }

    return Promise.reject(data);
  } catch (error) {
    (0, _logger.log)('monitoring:checkElasticsearchServer', error.message || error);
    return Promise.reject(error);
  }
}

const fakeResponseEndpoint = {
  ok: body => body,
  custom: body => body
};
/**
 * Get API configuration from elastic and callback to loadCredentials
 */

async function getHostsConfiguration() {
  try {
    const hosts = await wazuhHostController.getHostsEntries(false, false, fakeResponseEndpoint);

    if (hosts.body.length) {
      return hosts.body;
    }

    ;
    (0, _logger.log)('monitoring:getConfig', 'There are no Wazuh API entries yet', 'debug');
    return Promise.reject({
      error: 'no credentials',
      error_code: 1
    });
  } catch (error) {
    (0, _logger.log)('monitoring:getHostsConfiguration', error.message || error);
    return Promise.reject({
      error: 'no wazuh hosts',
      error_code: 2
    });
  }
}
/**
   * Task used by the cron job.
   */


async function cronTask(context) {
  try {
    const templateMonitoring = await context.core.elasticsearch.client.asInternalUser.indices.getTemplate({
      name: _constants.WAZUH_MONITORING_TEMPLATE_NAME
    });
    const apiHosts = await getHostsConfiguration();
    const apiHostsUnique = (apiHosts || []).filter((apiHost, index, self) => index === self.findIndex(t => t.user === apiHost.user && t.password === apiHost.password && t.url === apiHost.url && t.port === apiHost.port));

    for (let apiHost of apiHostsUnique) {
      try {
        const {
          agents,
          apiHost: host
        } = await getApiInfo(context, apiHost);
        await insertMonitoringDataElasticsearch(context, {
          agents,
          apiHost: host
        });
      } catch (error) {}

      ;
    }
  } catch (error) {
    // Retry to call itself again if Kibana index is not ready yet
    // try {
    //   if (
    //     this.wzWrapper.buildingKibanaIndex ||
    //     ((error || {}).status === 404 &&
    //       (error || {}).displayName === 'NotFound')
    //   ) {
    //     await delayAsPromise(1000);
    //     return cronTask(context);
    //   }
    // } catch (error) {} //eslint-disable-line
    (0, _logger.log)('monitoring:cronTask', error.message || error);
    context.wazuh.logger.error(error.message || error);
  }
}
/**
 * Get API and agents info
 * @param context
 * @param apiHost
 */


async function getApiInfo(context, apiHost) {
  try {
    (0, _logger.log)('monitoring:getApiInfo', `Getting API info for ${apiHost.id}`, 'debug');
    const responseIsCluster = await context.wazuh.api.client.asInternalUser.request('GET', '/cluster/status', {}, {
      apiHostID: apiHost.id
    });
    const isCluster = (((responseIsCluster || {}).data || {}).data || {}).enabled === 'yes';

    if (isCluster) {
      const responseClusterInfo = await context.wazuh.api.client.asInternalUser.request('GET', `/cluster/local/info`, {}, {
        apiHostID: apiHost.id
      });
      apiHost.clusterName = responseClusterInfo.data.data.affected_items[0].cluster;
    }

    ;
    const agents = await fetchAllAgentsFromApiHost(context, apiHost);
    return {
      agents,
      apiHost
    };
  } catch (error) {
    (0, _logger.log)('monitoring:getApiInfo', error.message || error);
    throw error;
  }
}

;
/**
 * Fetch all agents for the API provided
 * @param context
 * @param apiHost
 */

async function fetchAllAgentsFromApiHost(context, apiHost) {
  let agents = [];

  try {
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `Getting all agents from ApiID: ${apiHost.id}`, 'debug');
    const responseAgentsCount = await context.wazuh.api.client.asInternalUser.request('GET', '/agents', {
      params: {
        offset: 0,
        limit: 1,
        q: 'id!=000'
      }
    }, {
      apiHostID: apiHost.id
    });
    const agentsCount = responseAgentsCount.data.data.total_affected_items;
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}, Agent count: ${agentsCount}`, 'debug');
    let payload = {
      offset: 0,
      limit: 500,
      q: 'id!=000'
    };

    while (agents.length < agentsCount && payload.offset < agentsCount) {
      try {
        /* 
        TODO: Improve the performance of request with:
          - Reduce the number of requests to the Wazuh API
          - Reduce (if possible) the quantity of data to index by document
         Requirements:
          - Research about the neccesary data to index.
         How to do:
          - Wazuh API request:
            - select the required data to retrieve depending on is required to index (using the `select` query param)
            - increase the limit of results to retrieve (currently, the requests use the recommended value: 500).
              See the allowed values. This depends on the selected data because the response could fail if contains a lot of data
        */
        const responseAgents = await context.wazuh.api.client.asInternalUser.request('GET', `/agents`, {
          params: payload
        }, {
          apiHostID: apiHost.id
        });
        agents = [...agents, ...responseAgents.data.data.affected_items];
        payload.offset += payload.limit;
      } catch (error) {
        (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}, Error request with offset/limit ${payload.offset}/${payload.limit}: ${error.message || error}`);
      }
    }

    return agents;
  } catch (error) {
    (0, _logger.log)('monitoring:fetchAllAgentsFromApiHost', `ApiID: ${apiHost.id}. Error: ${error.message || error}`);
    throw error;
  }
}

;
/**
 * Start the cron job
 */

async function jobMonitoringRun(context) {
  // Init the monitoring variables
  initMonitoringConfiguration(context); // Check Kibana index and if it is prepared, start the initialization of Wazuh App.

  await checkPluginPlatformStatus(context); // // Run the cron job only it it's enabled

  if (MONITORING_ENABLED) {
    cronTask(context);

    _nodeCron.default.schedule(MONITORING_CRON_FREQ, () => cronTask(context));
  }
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LnRzIl0sIm5hbWVzIjpbImJsdWVXYXp1aCIsIm1vbml0b3JpbmdFcnJvckxvZ0NvbG9ycyIsIndhenVoSG9zdENvbnRyb2xsZXIiLCJXYXp1aEhvc3RzQ3RybCIsIk1PTklUT1JJTkdfRU5BQkxFRCIsIk1PTklUT1JJTkdfRlJFUVVFTkNZIiwiTU9OSVRPUklOR19DUk9OX0ZSRVEiLCJNT05JVE9SSU5HX0NSRUFUSU9OIiwiTU9OSVRPUklOR19JTkRFWF9QQVRURVJOIiwiTU9OSVRPUklOR19JTkRFWF9QUkVGSVgiLCJnZXRBcHBDb25maWd1cmF0aW9uU2V0dGluZyIsInNldHRpbmciLCJjb25maWd1cmF0aW9uIiwiZGVmYXVsdFZhbHVlIiwiaW5pdE1vbml0b3JpbmdDb25maWd1cmF0aW9uIiwiY29udGV4dCIsImFwcENvbmZpZyIsImxhc3RDaGFySW5kZXhQYXR0ZXJuIiwibGVuZ3RoIiwic2xpY2UiLCJlcnJvciIsImVycm9yTWVzc2FnZSIsIm1lc3NhZ2UiLCJ3YXp1aCIsImxvZ2dlciIsImluaXQiLCJjaGVja1RlbXBsYXRlIiwiY3VycmVudFRlbXBsYXRlIiwiY29yZSIsImVsYXN0aWNzZWFyY2giLCJjbGllbnQiLCJhc0ludGVybmFsVXNlciIsImluZGljZXMiLCJnZXRUZW1wbGF0ZSIsIm5hbWUiLCJXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUUiLCJtb25pdG9yaW5nVGVtcGxhdGUiLCJpbmRleF9wYXR0ZXJucyIsImJvZHkiLCJpbmNsdWRlcyIsInB1c2giLCJwdXRUZW1wbGF0ZSIsImluc2VydE1vbml0b3JpbmdEYXRhRWxhc3RpY3NlYXJjaCIsImRhdGEiLCJtb25pdG9yaW5nSW5kZXhOYW1lIiwiZXhpc3RzIiwiaW5kZXgiLCJjcmVhdGVJbmRleCIsImluZGV4Q29uZmlndXJhdGlvbiIsInNldHRpbmdzIiwibnVtYmVyX29mX3NoYXJkcyIsInB1dFNldHRpbmdzIiwiaW5zZXJ0RGF0YVRvSW5kZXgiLCJpbmRleE5hbWUiLCJhZ2VudHMiLCJhcGlIb3N0IiwiYm9keUJ1bGsiLCJtYXAiLCJhZ2VudCIsImFnZW50SW5mbyIsIkRhdGUiLCJub3ciLCJ0b0lTT1N0cmluZyIsImhvc3QiLCJtYW5hZ2VyIiwiY2x1c3RlciIsImNsdXN0ZXJOYW1lIiwiSlNPTiIsInN0cmluZ2lmeSIsImpvaW4iLCJidWxrIiwiSW5kZXhDb25maWd1cmF0aW9uIiwibnVtYmVyX29mX3JlcGxpY2FzIiwiY3JlYXRlIiwiY2hlY2tQbHVnaW5QbGF0Zm9ybVN0YXR1cyIsImNoZWNrRWxhc3RpY3NlYXJjaFNlcnZlciIsIm1lc2FnZSIsInNlcnZlciIsImNvbmZpZyIsImtpYmFuYSIsIlByb21pc2UiLCJyZWplY3QiLCJmYWtlUmVzcG9uc2VFbmRwb2ludCIsIm9rIiwiY3VzdG9tIiwiZ2V0SG9zdHNDb25maWd1cmF0aW9uIiwiaG9zdHMiLCJnZXRIb3N0c0VudHJpZXMiLCJlcnJvcl9jb2RlIiwiY3JvblRhc2siLCJ0ZW1wbGF0ZU1vbml0b3JpbmciLCJhcGlIb3N0cyIsImFwaUhvc3RzVW5pcXVlIiwiZmlsdGVyIiwic2VsZiIsImZpbmRJbmRleCIsInQiLCJ1c2VyIiwicGFzc3dvcmQiLCJ1cmwiLCJwb3J0IiwiZ2V0QXBpSW5mbyIsImlkIiwicmVzcG9uc2VJc0NsdXN0ZXIiLCJhcGkiLCJyZXF1ZXN0IiwiYXBpSG9zdElEIiwiaXNDbHVzdGVyIiwiZW5hYmxlZCIsInJlc3BvbnNlQ2x1c3RlckluZm8iLCJhZmZlY3RlZF9pdGVtcyIsImZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QiLCJyZXNwb25zZUFnZW50c0NvdW50IiwicGFyYW1zIiwib2Zmc2V0IiwibGltaXQiLCJxIiwiYWdlbnRzQ291bnQiLCJ0b3RhbF9hZmZlY3RlZF9pdGVtcyIsInBheWxvYWQiLCJyZXNwb25zZUFnZW50cyIsImpvYk1vbml0b3JpbmdSdW4iLCJjcm9uIiwic2NoZWR1bGUiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7OztBQVdBOztBQUNBOztBQUNBOztBQUNBOztBQUNB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OztBQUNBLFFBQU0yRCx5QkFBeUIsQ0FBQzNELE9BQUQsQ0FBL0IsQ0FKOEMsQ0FLOUM7O0FBQ0EsTUFBSVgsa0JBQUosRUFBd0I7QUFDdEJxRixJQUFBQSxRQUFRLENBQUMxRSxPQUFELENBQVI7O0FBQ0EyRyxzQkFBS0MsUUFBTCxDQUFjckgsb0JBQWQsRUFBb0MsTUFBTW1GLFFBQVEsQ0FBQzFFLE9BQUQsQ0FBbEQ7QUFDRDtBQUNGIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgYWdlbnQgaW5mbyBmZXRjaGluZyBmdW5jdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5pbXBvcnQgY3JvbiBmcm9tICdub2RlLWNyb24nO1xuaW1wb3J0IHsgbG9nIH0gZnJvbSAnLi4vLi4vbGliL2xvZ2dlcic7XG5pbXBvcnQgeyBtb25pdG9yaW5nVGVtcGxhdGUgfSBmcm9tICcuLi8uLi9pbnRlZ3JhdGlvbi1maWxlcy9tb25pdG9yaW5nLXRlbXBsYXRlJztcbmltcG9ydCB7IGdldENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi8uLi9saWIvZ2V0LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHsgcGFyc2VDcm9uIH0gZnJvbSAnLi4vLi4vbGliL3BhcnNlLWNyb24nO1xuaW1wb3J0IHsgaW5kZXhEYXRlIH0gZnJvbSAnLi4vLi4vbGliL2luZGV4LWRhdGUnO1xuaW1wb3J0IHsgYnVpbGRJbmRleFNldHRpbmdzIH0gZnJvbSAnLi4vLi4vbGliL2J1aWxkLWluZGV4LXNldHRpbmdzJztcbmltcG9ydCB7IFdhenVoSG9zdHNDdHJsIH0gZnJvbSAnLi4vLi4vY29udHJvbGxlcnMvd2F6dWgtaG9zdHMnO1xuaW1wb3J0IHsgXG4gIFdBWlVIX01PTklUT1JJTkdfVEVNUExBVEVfTkFNRSxcbn0gZnJvbSAnLi4vLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgeyB0cnlDYXRjaEZvckluZGV4UGVybWlzc2lvbkVycm9yIH0gZnJvbSAnLi4vdHJ5Q2F0Y2hGb3JJbmRleFBlcm1pc3Npb25FcnJvcic7XG5pbXBvcnQgeyBkZWxheUFzUHJvbWlzZSB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi91dGlscyc7XG5pbXBvcnQgeyBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlIH0gZnJvbSAnLi4vLi4vLi4vY29tbW9uL3NlcnZpY2VzL3NldHRpbmdzJztcblxuY29uc3QgYmx1ZVdhenVoID0gJ1xcdTAwMWJbMzRtd2F6dWhcXHUwMDFiWzM5bSc7XG5jb25zdCBtb25pdG9yaW5nRXJyb3JMb2dDb2xvcnMgPSBbYmx1ZVdhenVoLCAnbW9uaXRvcmluZycsICdlcnJvciddO1xuY29uc3Qgd2F6dWhIb3N0Q29udHJvbGxlciA9IG5ldyBXYXp1aEhvc3RzQ3RybCgpO1xuXG5sZXQgTU9OSVRPUklOR19FTkFCTEVELCBNT05JVE9SSU5HX0ZSRVFVRU5DWSwgTU9OSVRPUklOR19DUk9OX0ZSRVEsIE1PTklUT1JJTkdfQ1JFQVRJT04sIE1PTklUT1JJTkdfSU5ERVhfUEFUVEVSTiwgTU9OSVRPUklOR19JTkRFWF9QUkVGSVg7XG5cbi8vIFV0aWxzIGZ1bmN0aW9uc1xuLyoqXG4gKiBHZXQgdGhlIHNldHRpbmcgdmFsdWUgZnJvbSB0aGUgY29uZmlndXJhdGlvblxuICogQHBhcmFtIHNldHRpbmdcbiAqIEBwYXJhbSBjb25maWd1cmF0aW9uXG4gKiBAcGFyYW0gZGVmYXVsdFZhbHVlXG4gKi9cbmZ1bmN0aW9uIGdldEFwcENvbmZpZ3VyYXRpb25TZXR0aW5nKHNldHRpbmc6IHN0cmluZywgY29uZmlndXJhdGlvbjogYW55LCBkZWZhdWx0VmFsdWU6IGFueSl7XG4gIHJldHVybiB0eXBlb2YgY29uZmlndXJhdGlvbltzZXR0aW5nXSAhPT0gJ3VuZGVmaW5lZCcgPyBjb25maWd1cmF0aW9uW3NldHRpbmddIDogZGVmYXVsdFZhbHVlO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIG1vbml0b3JpbmcgdmFyaWFibGVzXG4gKiBAcGFyYW0gY29udGV4dFxuICovXG5mdW5jdGlvbiBpbml0TW9uaXRvcmluZ0NvbmZpZ3VyYXRpb24oY29udGV4dCl7XG4gIHRyeXtcbiAgICBjb25zdCBhcHBDb25maWcgPSBnZXRDb25maWd1cmF0aW9uKCk7XG4gICAgTU9OSVRPUklOR19FTkFCTEVEID0gYXBwQ29uZmlnICYmIHR5cGVvZiBhcHBDb25maWdbJ3dhenVoLm1vbml0b3JpbmcuZW5hYmxlZCddICE9PSAndW5kZWZpbmVkJ1xuICAgICAgPyBhcHBDb25maWdbJ3dhenVoLm1vbml0b3JpbmcuZW5hYmxlZCddICYmXG4gICAgICAgIGFwcENvbmZpZ1snd2F6dWgubW9uaXRvcmluZy5lbmFibGVkJ10gIT09ICd3b3JrZXInXG4gICAgICA6IGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3JpbmcuZW5hYmxlZCcpO1xuICAgIE1PTklUT1JJTkdfRlJFUVVFTkNZID0gZ2V0QXBwQ29uZmlndXJhdGlvblNldHRpbmcoJ3dhenVoLm1vbml0b3JpbmcuZnJlcXVlbmN5JywgYXBwQ29uZmlnLCBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCd3YXp1aC5tb25pdG9yaW5nLmZyZXF1ZW5jeScpKTtcbiAgICBNT05JVE9SSU5HX0NST05fRlJFUSA9IHBhcnNlQ3JvbihNT05JVE9SSU5HX0ZSRVFVRU5DWSk7XG4gICAgTU9OSVRPUklOR19DUkVBVElPTiA9IGdldEFwcENvbmZpZ3VyYXRpb25TZXR0aW5nKCd3YXp1aC5tb25pdG9yaW5nLmNyZWF0aW9uJywgYXBwQ29uZmlnLCBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCd3YXp1aC5tb25pdG9yaW5nLmNyZWF0aW9uJykpO1xuXG4gICAgTU9OSVRPUklOR19JTkRFWF9QQVRURVJOID0gZ2V0QXBwQ29uZmlndXJhdGlvblNldHRpbmcoJ3dhenVoLm1vbml0b3JpbmcucGF0dGVybicsIGFwcENvbmZpZywgZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSgnd2F6dWgubW9uaXRvcmluZy5wYXR0ZXJuJykpO1xuICAgIGNvbnN0IGxhc3RDaGFySW5kZXhQYXR0ZXJuID0gTU9OSVRPUklOR19JTkRFWF9QQVRURVJOW01PTklUT1JJTkdfSU5ERVhfUEFUVEVSTi5sZW5ndGggLSAxXTtcbiAgICBpZiAobGFzdENoYXJJbmRleFBhdHRlcm4gIT09ICcqJykge1xuICAgICAgTU9OSVRPUklOR19JTkRFWF9QQVRURVJOICs9ICcqJztcbiAgICB9O1xuICAgIE1PTklUT1JJTkdfSU5ERVhfUFJFRklYID0gTU9OSVRPUklOR19JTkRFWF9QQVRURVJOLnNsaWNlKDAsTU9OSVRPUklOR19JTkRFWF9QQVRURVJOLmxlbmd0aCAtIDEpO1xuXG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6aW5pdE1vbml0b3JpbmdDb25maWd1cmF0aW9uJyxcbiAgICAgIGB3YXp1aC5tb25pdG9yaW5nLmVuYWJsZWQ6ICR7TU9OSVRPUklOR19FTkFCTEVEfWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcblxuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmluaXRNb25pdG9yaW5nQ29uZmlndXJhdGlvbicsXG4gICAgICBgd2F6dWgubW9uaXRvcmluZy5mcmVxdWVuY3k6ICR7TU9OSVRPUklOR19GUkVRVUVOQ1l9ICgke01PTklUT1JJTkdfQ1JPTl9GUkVRfSlgLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzppbml0TW9uaXRvcmluZ0NvbmZpZ3VyYXRpb24nLFxuICAgICAgYHdhenVoLm1vbml0b3JpbmcucGF0dGVybjogJHtNT05JVE9SSU5HX0lOREVYX1BBVFRFUk59IChpbmRleCBwcmVmaXg6ICR7TU9OSVRPUklOR19JTkRFWF9QUkVGSVh9KWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcbiAgfWNhdGNoKGVycm9yKXtcbiAgICBjb25zdCBlcnJvck1lc3NhZ2UgPSBlcnJvci5tZXNzYWdlIHx8IGVycm9yO1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmluaXRNb25pdG9yaW5nQ29uZmlndXJhdGlvbicsXG4gICAgICBlcnJvck1lc3NhZ2VcbiAgICApO1xuICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKGVycm9yTWVzc2FnZSlcbiAgfVxufTtcblxuLyoqXG4gKiBNYWluLiBGaXJzdCBleGVjdXRpb24gd2hlbiBpbnN0YWxsaW5nIC8gbG9hZGluZyBBcHAuXG4gKiBAcGFyYW0gY29udGV4dFxuICovXG5hc3luYyBmdW5jdGlvbiBpbml0KGNvbnRleHQpIHtcbiAgdHJ5IHtcbiAgICBpZiAoTU9OSVRPUklOR19FTkFCTEVEKSB7XG4gICAgICBhd2FpdCBjaGVja1RlbXBsYXRlKGNvbnRleHQpO1xuICAgIH07XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgY29uc3QgZXJyb3JNZXNzYWdlID0gZXJyb3IubWVzc2FnZSB8fCBlcnJvcjtcbiAgICBsb2coJ21vbml0b3Jpbmc6aW5pdCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKGVycm9yTWVzc2FnZSk7XG4gIH1cbn1cblxuLyoqXG4gKiBWZXJpZnkgd2F6dWgtYWdlbnQgdGVtcGxhdGVcbiAqL1xuYXN5bmMgZnVuY3Rpb24gY2hlY2tUZW1wbGF0ZShjb250ZXh0KSB7XG4gIHRyeSB7XG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Y2hlY2tUZW1wbGF0ZScsXG4gICAgICAnVXBkYXRpbmcgdGhlIG1vbml0b3JpbmcgdGVtcGxhdGUnLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICB0cnkge1xuICAgICAgLy8gQ2hlY2sgaWYgdGhlIHRlbXBsYXRlIGFscmVhZHkgZXhpc3RzXG4gICAgICBjb25zdCBjdXJyZW50VGVtcGxhdGUgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5nZXRUZW1wbGF0ZSh7XG4gICAgICAgIG5hbWU6IFdBWlVIX01PTklUT1JJTkdfVEVNUExBVEVfTkFNRVxuICAgICAgfSk7XG4gICAgICAvLyBDb3B5IGFscmVhZHkgY3JlYXRlZCBpbmRleCBwYXR0ZXJuc1xuICAgICAgbW9uaXRvcmluZ1RlbXBsYXRlLmluZGV4X3BhdHRlcm5zID0gY3VycmVudFRlbXBsYXRlLmJvZHlbV0FaVUhfTU9OSVRPUklOR19URU1QTEFURV9OQU1FXS5pbmRleF9wYXR0ZXJucztcbiAgICB9Y2F0Y2ggKGVycm9yKSB7XG4gICAgICAvLyBJbml0IHdpdGggdGhlIGRlZmF1bHQgaW5kZXggcGF0dGVyblxuICAgICAgbW9uaXRvcmluZ1RlbXBsYXRlLmluZGV4X3BhdHRlcm5zID0gW2dldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3JpbmcucGF0dGVybicpXTtcbiAgICB9XG5cbiAgICAvLyBDaGVjayBpZiB0aGUgdXNlciBpcyB1c2luZyBhIGN1c3RvbSBwYXR0ZXJuIGFuZCBhZGQgaXQgdG8gdGhlIHRlbXBsYXRlIGlmIGl0IGRvZXNcbiAgICBpZiAoIW1vbml0b3JpbmdUZW1wbGF0ZS5pbmRleF9wYXR0ZXJucy5pbmNsdWRlcyhNT05JVE9SSU5HX0lOREVYX1BBVFRFUk4pKSB7XG4gICAgICBtb25pdG9yaW5nVGVtcGxhdGUuaW5kZXhfcGF0dGVybnMucHVzaChNT05JVE9SSU5HX0lOREVYX1BBVFRFUk4pO1xuICAgIH07XG5cbiAgICAvLyBVcGRhdGUgdGhlIG1vbml0b3JpbmcgdGVtcGxhdGVcbiAgICBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5wdXRUZW1wbGF0ZSh7XG4gICAgICBuYW1lOiBXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUUsXG4gICAgICBib2R5OiBtb25pdG9yaW5nVGVtcGxhdGVcbiAgICB9KTtcbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzpjaGVja1RlbXBsYXRlJyxcbiAgICAgICdVcGRhdGVkIHRoZSBtb25pdG9yaW5nIHRlbXBsYXRlJyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGNvbnN0IGVycm9yTWVzc2FnZSA9IGBTb21ldGhpbmcgd2VudCB3cm9uZyB1cGRhdGluZyB0aGUgbW9uaXRvcmluZyB0ZW1wbGF0ZSAke2Vycm9yLm1lc3NhZ2UgfHwgZXJyb3J9YDtcbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzpjaGVja1RlbXBsYXRlJyxcbiAgICAgIGVycm9yTWVzc2FnZVxuICAgICk7XG4gICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IobW9uaXRvcmluZ0Vycm9yTG9nQ29sb3JzLCBlcnJvck1lc3NhZ2UpO1xuICAgIHRocm93IGVycm9yO1xuICB9XG59XG5cbi8qKlxuICogU2F2ZSBhZ2VudCBzdGF0dXMgaW50byBlbGFzdGljc2VhcmNoLCBjcmVhdGUgaW5kZXggYW5kL29yIGluc2VydCBkb2N1bWVudFxuICogQHBhcmFtIHsqfSBjb250ZXh0XG4gKiBAcGFyYW0geyp9IGRhdGFcbiAqL1xuYXN5bmMgZnVuY3Rpb24gaW5zZXJ0TW9uaXRvcmluZ0RhdGFFbGFzdGljc2VhcmNoKGNvbnRleHQsIGRhdGEpIHtcbiAgY29uc3QgbW9uaXRvcmluZ0luZGV4TmFtZSA9IE1PTklUT1JJTkdfSU5ERVhfUFJFRklYICsgaW5kZXhEYXRlKE1PTklUT1JJTkdfQ1JFQVRJT04pO1xuICAgIGlmICghTU9OSVRPUklOR19FTkFCTEVEKXtcbiAgICAgIHJldHVybjtcbiAgICB9O1xuICAgIHRyeSB7XG4gICAgICBhd2FpdCB0cnlDYXRjaEZvckluZGV4UGVybWlzc2lvbkVycm9yKG1vbml0b3JpbmdJbmRleE5hbWUpIChhc3luYygpID0+IHtcbiAgICAgICAgY29uc3QgZXhpc3RzID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuZXhpc3RzKHtpbmRleDogbW9uaXRvcmluZ0luZGV4TmFtZX0pO1xuICAgICAgICBpZighZXhpc3RzLmJvZHkpe1xuICAgICAgICAgIGF3YWl0IGNyZWF0ZUluZGV4KGNvbnRleHQsIG1vbml0b3JpbmdJbmRleE5hbWUpO1xuICAgICAgICB9O1xuXG4gICAgICAgIC8vIFVwZGF0ZSB0aGUgaW5kZXggY29uZmlndXJhdGlvblxuICAgICAgICBjb25zdCBhcHBDb25maWcgPSBnZXRDb25maWd1cmF0aW9uKCk7XG4gICAgICAgIGNvbnN0IGluZGV4Q29uZmlndXJhdGlvbiA9IGJ1aWxkSW5kZXhTZXR0aW5ncyhcbiAgICAgICAgICBhcHBDb25maWcsXG4gICAgICAgICAgJ3dhenVoLm1vbml0b3JpbmcnLFxuICAgICAgICAgIGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3Jpbmcuc2hhcmRzJylcbiAgICAgICAgKTtcblxuICAgICAgICAvLyBUbyB1cGRhdGUgdGhlIGluZGV4IHNldHRpbmdzIHdpdGggdGhpcyBjbGllbnQgaXMgcmVxdWlyZWQgY2xvc2UgdGhlIGluZGV4LCB1cGRhdGUgdGhlIHNldHRpbmdzIGFuZCBvcGVuIGl0XG4gICAgICAgIC8vIE51bWJlciBvZiBzaGFyZHMgaXMgbm90IGR5bmFtaWMgc28gZGVsZXRlIHRoYXQgc2V0dGluZyBpZiBpdCdzIGdpdmVuXG4gICAgICAgIGRlbGV0ZSBpbmRleENvbmZpZ3VyYXRpb24uc2V0dGluZ3MuaW5kZXgubnVtYmVyX29mX3NoYXJkcztcbiAgICAgICAgYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMucHV0U2V0dGluZ3Moe1xuICAgICAgICAgIGluZGV4OiBtb25pdG9yaW5nSW5kZXhOYW1lLFxuICAgICAgICAgIGJvZHk6IGluZGV4Q29uZmlndXJhdGlvblxuICAgICAgICB9KTtcblxuICAgICAgICAvLyBJbnNlcnQgZGF0YSB0byB0aGUgbW9uaXRvcmluZyBpbmRleFxuICAgICAgICBhd2FpdCBpbnNlcnREYXRhVG9JbmRleChjb250ZXh0LCBtb25pdG9yaW5nSW5kZXhOYW1lLCBkYXRhKTtcbiAgICAgIH0pKCk7XG4gICAgfWNhdGNoKGVycm9yKXtcbiAgICAgIGxvZygnbW9uaXRvcmluZzppbnNlcnRNb25pdG9yaW5nRGF0YUVsYXN0aWNzZWFyY2gnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIGNvbnRleHQud2F6dWgubG9nZ2VyLmVycm9yKGVycm9yLm1lc3NhZ2UpO1xuICAgIH1cbn1cblxuLyoqXG4gKiBJbnNlcnRpbmcgb25lIGRvY3VtZW50IHBlciBhZ2VudCBpbnRvIEVsYXN0aWMuIEJ1bGsuXG4gKiBAcGFyYW0geyp9IGNvbnRleHQgRW5kcG9pbnRcbiAqIEBwYXJhbSB7U3RyaW5nfSBpbmRleE5hbWUgVGhlIG5hbWUgZm9yIHRoZSBpbmRleCAoZS5nLiBkYWlseTogd2F6dWgtbW9uaXRvcmluZy1ZWVlZLk1NLkREKVxuICogQHBhcmFtIHsqfSBkYXRhXG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGluc2VydERhdGFUb0luZGV4KGNvbnRleHQsIGluZGV4TmFtZTogc3RyaW5nLCBkYXRhOiB7YWdlbnRzOiBhbnlbXSwgYXBpSG9zdH0pIHtcbiAgY29uc3QgeyBhZ2VudHMsIGFwaUhvc3QgfSA9IGRhdGE7XG4gIHRyeSB7XG4gICAgaWYgKGFnZW50cy5sZW5ndGggPiAwKSB7XG4gICAgICBsb2coXG4gICAgICAgICdtb25pdG9yaW5nOmluc2VydERhdGFUb0luZGV4JyxcbiAgICAgICAgYEJ1bGsgZGF0YSB0byBpbmRleCAke2luZGV4TmFtZX0gZm9yICR7YWdlbnRzLmxlbmd0aH0gYWdlbnRzYCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcblxuICAgICAgY29uc3QgYm9keUJ1bGsgPSBhZ2VudHMubWFwKGFnZW50ID0+IHtcbiAgICAgICAgY29uc3QgYWdlbnRJbmZvID0gey4uLmFnZW50fTtcbiAgICAgICAgYWdlbnRJbmZvWyd0aW1lc3RhbXAnXSA9IG5ldyBEYXRlKERhdGUubm93KCkpLnRvSVNPU3RyaW5nKCk7XG4gICAgICAgIGFnZW50SW5mby5ob3N0ID0gYWdlbnQubWFuYWdlcjtcbiAgICAgICAgYWdlbnRJbmZvLmNsdXN0ZXIgPSB7IG5hbWU6IGFwaUhvc3QuY2x1c3Rlck5hbWUgPyBhcGlIb3N0LmNsdXN0ZXJOYW1lIDogJ2Rpc2FibGVkJyB9O1xuICAgICAgICByZXR1cm4gYHsgXCJpbmRleFwiOiAgeyBcIl9pbmRleFwiOiBcIiR7aW5kZXhOYW1lfVwiIH0gfVxcbiR7SlNPTi5zdHJpbmdpZnkoYWdlbnRJbmZvKX1cXG5gO1xuICAgICAgfSkuam9pbignJyk7XG5cbiAgICAgIGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5idWxrKHtcbiAgICAgICAgaW5kZXg6IGluZGV4TmFtZSxcbiAgICAgICAgYm9keTogYm9keUJ1bGtcbiAgICAgIH0pO1xuICAgICAgbG9nKFxuICAgICAgICAnbW9uaXRvcmluZzppbnNlcnREYXRhVG9JbmRleCcsXG4gICAgICAgIGBCdWxrIGRhdGEgdG8gaW5kZXggJHtpbmRleE5hbWV9IGZvciAke2FnZW50cy5sZW5ndGh9IGFnZW50cyBjb21wbGV0ZWRgLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgIH1cbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzppbnNlcnREYXRhVG9JbmRleCcsXG4gICAgICBgRXJyb3IgaW5zZXJ0aW5nIGFnZW50IGRhdGEgaW50byBlbGFzdGljc2VhcmNoLiBCdWxrIHJlcXVlc3QgZmFpbGVkIGR1ZSB0byAke2Vycm9yLm1lc3NhZ2UgfHxcbiAgICAgICAgZXJyb3J9YFxuICAgICk7XG4gIH1cbn1cblxuLyoqXG4gKiBDcmVhdGUgdGhlIHdhenVoLW1vbml0b3JpbmcgaW5kZXhcbiAqIEBwYXJhbSB7Kn0gY29udGV4dCBjb250ZXh0XG4gKiBAcGFyYW0ge1N0cmluZ30gaW5kZXhOYW1lIFRoZSBuYW1lIGZvciB0aGUgaW5kZXggKGUuZy4gZGFpbHk6IHdhenVoLW1vbml0b3JpbmctWVlZWS5NTS5ERClcbiAqL1xuYXN5bmMgZnVuY3Rpb24gY3JlYXRlSW5kZXgoY29udGV4dCwgaW5kZXhOYW1lOiBzdHJpbmcpIHtcbiAgdHJ5IHtcbiAgICBpZiAoIU1PTklUT1JJTkdfRU5BQkxFRCkgcmV0dXJuO1xuICAgIGNvbnN0IGFwcENvbmZpZyA9IGdldENvbmZpZ3VyYXRpb24oKTtcblxuICAgIGNvbnN0IEluZGV4Q29uZmlndXJhdGlvbiA9IHtcbiAgICAgIHNldHRpbmdzOiB7XG4gICAgICAgIGluZGV4OiB7XG4gICAgICAgICAgbnVtYmVyX29mX3NoYXJkczogZ2V0QXBwQ29uZmlndXJhdGlvblNldHRpbmcoJ3dhenVoLm1vbml0b3Jpbmcuc2hhcmRzJywgYXBwQ29uZmlnLCBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCd3YXp1aC5tb25pdG9yaW5nLnNoYXJkcycpKSxcbiAgICAgICAgICBudW1iZXJfb2ZfcmVwbGljYXM6IGdldEFwcENvbmZpZ3VyYXRpb25TZXR0aW5nKCd3YXp1aC5tb25pdG9yaW5nLnJlcGxpY2FzJywgYXBwQ29uZmlnLCBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCd3YXp1aC5tb25pdG9yaW5nLnJlcGxpY2FzJykpXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9O1xuXG4gICAgYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmluZGljZXMuY3JlYXRlKHtcbiAgICAgIGluZGV4OiBpbmRleE5hbWUsXG4gICAgICBib2R5OiBJbmRleENvbmZpZ3VyYXRpb25cbiAgICB9KTtcblxuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNyZWF0ZUluZGV4JyxcbiAgICAgIGBTdWNjZXNzZnVsbHkgY3JlYXRlZCBuZXcgaW5kZXg6ICR7aW5kZXhOYW1lfWAsXG4gICAgICAnZGVidWcnXG4gICAgKTtcbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICBjb25zdCBlcnJvck1lc3NhZ2UgPSBgQ291bGQgbm90IGNyZWF0ZSAke2luZGV4TmFtZX0gaW5kZXggb24gZWxhc3RpY3NlYXJjaCBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWA7XG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Y3JlYXRlSW5kZXgnLFxuICAgICAgZXJyb3JNZXNzYWdlXG4gICAgKTtcbiAgICBjb250ZXh0LndhenVoLmxvZ2dlci5lcnJvcihlcnJvck1lc3NhZ2UpO1xuICB9XG59XG5cbi8qKlxuKiBXYWl0IHVudGlsIEtpYmFuYSBzZXJ2ZXIgaXMgcmVhZHlcbiovXG5hc3luYyBmdW5jdGlvbiBjaGVja1BsdWdpblBsYXRmb3JtU3RhdHVzKGNvbnRleHQpIHtcbiB0cnkge1xuICAgIGxvZyhcbiAgICAgICdtb25pdG9yaW5nOmNoZWNrUGx1Z2luUGxhdGZvcm1TdGF0dXMnLFxuICAgICAgJ1dhaXRpbmcgZm9yIEtpYmFuYSBhbmQgRWxhc3RpY3NlYXJjaCBzZXJ2ZXJzIHRvIGJlIHJlYWR5Li4uJyxcbiAgICAgICdkZWJ1ZydcbiAgICApO1xuXG4gICBhd2FpdCBjaGVja0VsYXN0aWNzZWFyY2hTZXJ2ZXIoY29udGV4dCk7XG4gICBhd2FpdCBpbml0KGNvbnRleHQpO1xuICAgcmV0dXJuO1xuIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgbG9nKFxuICAgICAgJ21vbml0b3Jpbmc6Y2hlY2tQbHVnaW5QbGF0Zm9ybVN0YXR1cycsXG4gICAgICBlcnJvci5tZXNhZ2UgfHxlcnJvclxuICAgICk7XG4gICAgdHJ5e1xuICAgICAgYXdhaXQgZGVsYXlBc1Byb21pc2UoMzAwMCk7XG4gICAgICBhd2FpdCBjaGVja1BsdWdpblBsYXRmb3JtU3RhdHVzKGNvbnRleHQpO1xuICAgIH1jYXRjaChlcnJvcil7fTtcbiB9XG59XG5cblxuLyoqXG4gKiBDaGVjayBFbGFzdGljc2VhcmNoIFNlcnZlciBzdGF0dXMgYW5kIEtpYmFuYSBpbmRleCBwcmVzZW5jZVxuICovXG5hc3luYyBmdW5jdGlvbiBjaGVja0VsYXN0aWNzZWFyY2hTZXJ2ZXIoY29udGV4dCkge1xuICB0cnkge1xuICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuaW5kaWNlcy5leGlzdHMoe1xuICAgICAgaW5kZXg6IGNvbnRleHQuc2VydmVyLmNvbmZpZy5raWJhbmEuaW5kZXhcbiAgICB9KTtcblxuICAgIHJldHVybiBkYXRhLmJvZHk7XG4gICAgLy8gVE9ETzogY2hlY2sgaWYgRWxhc3RpY3NlYXJjaCBjYW4gcmVjZWl2ZSByZXF1ZXN0c1xuICAgIC8vIGlmIChkYXRhKSB7XG4gICAgLy8gICBjb25zdCBwbHVnaW5zRGF0YSA9IGF3YWl0IHRoaXMuc2VydmVyLnBsdWdpbnMuZWxhc3RpY3NlYXJjaC53YWl0VW50aWxSZWFkeSgpO1xuICAgIC8vICAgcmV0dXJuIHBsdWdpbnNEYXRhO1xuICAgIC8vIH1cbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZGF0YSk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgbG9nKCdtb25pdG9yaW5nOmNoZWNrRWxhc3RpY3NlYXJjaFNlcnZlcicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gIH1cbn1cblxuY29uc3QgZmFrZVJlc3BvbnNlRW5kcG9pbnQgPSB7XG4gIG9rOiAoYm9keTogYW55KSA9PiBib2R5LFxuICBjdXN0b206IChib2R5OiBhbnkpID0+IGJvZHksXG59XG4vKipcbiAqIEdldCBBUEkgY29uZmlndXJhdGlvbiBmcm9tIGVsYXN0aWMgYW5kIGNhbGxiYWNrIHRvIGxvYWRDcmVkZW50aWFsc1xuICovXG5hc3luYyBmdW5jdGlvbiBnZXRIb3N0c0NvbmZpZ3VyYXRpb24oKSB7XG4gIHRyeSB7XG4gICAgY29uc3QgaG9zdHMgPSBhd2FpdCB3YXp1aEhvc3RDb250cm9sbGVyLmdldEhvc3RzRW50cmllcyhmYWxzZSwgZmFsc2UsIGZha2VSZXNwb25zZUVuZHBvaW50KTtcbiAgICBpZiAoaG9zdHMuYm9keS5sZW5ndGgpIHtcbiAgICAgIHJldHVybiBob3N0cy5ib2R5O1xuICAgIH07XG5cbiAgICBsb2coXG4gICAgICAnbW9uaXRvcmluZzpnZXRDb25maWcnLFxuICAgICAgJ1RoZXJlIGFyZSBubyBXYXp1aCBBUEkgZW50cmllcyB5ZXQnLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHtcbiAgICAgIGVycm9yOiAnbm8gY3JlZGVudGlhbHMnLFxuICAgICAgZXJyb3JfY29kZTogMVxuICAgIH0pO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGxvZygnbW9uaXRvcmluZzpnZXRIb3N0c0NvbmZpZ3VyYXRpb24nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3Qoe1xuICAgICAgZXJyb3I6ICdubyB3YXp1aCBob3N0cycsXG4gICAgICBlcnJvcl9jb2RlOiAyXG4gICAgfSk7XG4gIH1cbn1cblxuLyoqXG4gICAqIFRhc2sgdXNlZCBieSB0aGUgY3JvbiBqb2IuXG4gICAqL1xuYXN5bmMgZnVuY3Rpb24gY3JvblRhc2soY29udGV4dCkge1xuICB0cnkge1xuICAgIGNvbnN0IHRlbXBsYXRlTW9uaXRvcmluZyA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0ludGVybmFsVXNlci5pbmRpY2VzLmdldFRlbXBsYXRlKHtuYW1lOiBXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUV9KTtcblxuICAgIGNvbnN0IGFwaUhvc3RzID0gYXdhaXQgZ2V0SG9zdHNDb25maWd1cmF0aW9uKCk7XG4gICAgY29uc3QgYXBpSG9zdHNVbmlxdWUgPSAoYXBpSG9zdHMgfHwgW10pLmZpbHRlcihcbiAgICAgIChhcGlIb3N0LCBpbmRleCwgc2VsZikgPT5cbiAgICAgICAgaW5kZXggPT09XG4gICAgICAgIHNlbGYuZmluZEluZGV4KFxuICAgICAgICAgIHQgPT5cbiAgICAgICAgICAgIHQudXNlciA9PT0gYXBpSG9zdC51c2VyICYmXG4gICAgICAgICAgICB0LnBhc3N3b3JkID09PSBhcGlIb3N0LnBhc3N3b3JkICYmXG4gICAgICAgICAgICB0LnVybCA9PT0gYXBpSG9zdC51cmwgJiZcbiAgICAgICAgICAgIHQucG9ydCA9PT0gYXBpSG9zdC5wb3J0XG4gICAgICAgIClcbiAgICApO1xuICAgIGZvcihsZXQgYXBpSG9zdCBvZiBhcGlIb3N0c1VuaXF1ZSl7XG4gICAgICB0cnl7XG4gICAgICAgIGNvbnN0IHsgYWdlbnRzLCBhcGlIb3N0OiBob3N0fSA9IGF3YWl0IGdldEFwaUluZm8oY29udGV4dCwgYXBpSG9zdCk7XG4gICAgICAgIGF3YWl0IGluc2VydE1vbml0b3JpbmdEYXRhRWxhc3RpY3NlYXJjaChjb250ZXh0LCB7YWdlbnRzLCBhcGlIb3N0OiBob3N0fSk7XG4gICAgICB9Y2F0Y2goZXJyb3Ipe1xuXG4gICAgICB9O1xuICAgIH1cbiAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAvLyBSZXRyeSB0byBjYWxsIGl0c2VsZiBhZ2FpbiBpZiBLaWJhbmEgaW5kZXggaXMgbm90IHJlYWR5IHlldFxuICAgIC8vIHRyeSB7XG4gICAgLy8gICBpZiAoXG4gICAgLy8gICAgIHRoaXMud3pXcmFwcGVyLmJ1aWxkaW5nS2liYW5hSW5kZXggfHxcbiAgICAvLyAgICAgKChlcnJvciB8fCB7fSkuc3RhdHVzID09PSA0MDQgJiZcbiAgICAvLyAgICAgICAoZXJyb3IgfHwge30pLmRpc3BsYXlOYW1lID09PSAnTm90Rm91bmQnKVxuICAgIC8vICAgKSB7XG4gICAgLy8gICAgIGF3YWl0IGRlbGF5QXNQcm9taXNlKDEwMDApO1xuICAgIC8vICAgICByZXR1cm4gY3JvblRhc2soY29udGV4dCk7XG4gICAgLy8gICB9XG4gICAgLy8gfSBjYXRjaCAoZXJyb3IpIHt9IC8vZXNsaW50LWRpc2FibGUtbGluZVxuXG4gICAgbG9nKCdtb25pdG9yaW5nOmNyb25UYXNrJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgY29udGV4dC53YXp1aC5sb2dnZXIuZXJyb3IoZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gIH1cbn1cblxuLyoqXG4gKiBHZXQgQVBJIGFuZCBhZ2VudHMgaW5mb1xuICogQHBhcmFtIGNvbnRleHRcbiAqIEBwYXJhbSBhcGlIb3N0XG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGdldEFwaUluZm8oY29udGV4dCwgYXBpSG9zdCl7XG4gIHRyeXtcbiAgICBsb2coJ21vbml0b3Jpbmc6Z2V0QXBpSW5mbycsIGBHZXR0aW5nIEFQSSBpbmZvIGZvciAke2FwaUhvc3QuaWR9YCwgJ2RlYnVnJyk7XG4gICAgY29uc3QgcmVzcG9uc2VJc0NsdXN0ZXIgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdCgnR0VUJywgJy9jbHVzdGVyL3N0YXR1cycsIHt9LCB7IGFwaUhvc3RJRDogYXBpSG9zdC5pZCB9KTtcbiAgICBjb25zdCBpc0NsdXN0ZXIgPSAoKChyZXNwb25zZUlzQ2x1c3RlciB8fCB7fSkuZGF0YSB8fCB7fSkuZGF0YSB8fCB7fSkuZW5hYmxlZCA9PT0gJ3llcyc7XG4gICAgaWYoaXNDbHVzdGVyKXtcbiAgICAgIGNvbnN0IHJlc3BvbnNlQ2x1c3RlckluZm8gPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNJbnRlcm5hbFVzZXIucmVxdWVzdCgnR0VUJywgYC9jbHVzdGVyL2xvY2FsL2luZm9gLCB7fSwgIHsgYXBpSG9zdElEOiBhcGlIb3N0LmlkIH0pO1xuICAgICAgYXBpSG9zdC5jbHVzdGVyTmFtZSA9IHJlc3BvbnNlQ2x1c3RlckluZm8uZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdLmNsdXN0ZXI7XG4gICAgfTtcbiAgICBjb25zdCBhZ2VudHMgPSBhd2FpdCBmZXRjaEFsbEFnZW50c0Zyb21BcGlIb3N0KGNvbnRleHQsIGFwaUhvc3QpO1xuICAgIHJldHVybiB7IGFnZW50cywgYXBpSG9zdCB9O1xuICB9Y2F0Y2goZXJyb3Ipe1xuICAgIGxvZygnbW9uaXRvcmluZzpnZXRBcGlJbmZvJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgdGhyb3cgZXJyb3I7XG4gIH1cbn07XG5cbi8qKlxuICogRmV0Y2ggYWxsIGFnZW50cyBmb3IgdGhlIEFQSSBwcm92aWRlZFxuICogQHBhcmFtIGNvbnRleHRcbiAqIEBwYXJhbSBhcGlIb3N0XG4gKi9cbmFzeW5jIGZ1bmN0aW9uIGZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QoY29udGV4dCwgYXBpSG9zdCl7XG4gIGxldCBhZ2VudHMgPSBbXTtcbiAgdHJ5e1xuICAgIGxvZygnbW9uaXRvcmluZzpmZXRjaEFsbEFnZW50c0Zyb21BcGlIb3N0JywgYEdldHRpbmcgYWxsIGFnZW50cyBmcm9tIEFwaUlEOiAke2FwaUhvc3QuaWR9YCwgJ2RlYnVnJyk7XG4gICAgY29uc3QgcmVzcG9uc2VBZ2VudHNDb3VudCA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgJ0dFVCcsXG4gICAgICAnL2FnZW50cycsXG4gICAgICB7XG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIG9mZnNldDogMCxcbiAgICAgICAgICBsaW1pdDogMSxcbiAgICAgICAgICBxOiAnaWQhPTAwMCdcbiAgICAgICAgfVxuICAgICAgfSwge2FwaUhvc3RJRDogYXBpSG9zdC5pZH0pO1xuXG4gICAgY29uc3QgYWdlbnRzQ291bnQgPSByZXNwb25zZUFnZW50c0NvdW50LmRhdGEuZGF0YS50b3RhbF9hZmZlY3RlZF9pdGVtcztcbiAgICBsb2coJ21vbml0b3Jpbmc6ZmV0Y2hBbGxBZ2VudHNGcm9tQXBpSG9zdCcsIGBBcGlJRDogJHthcGlIb3N0LmlkfSwgQWdlbnQgY291bnQ6ICR7YWdlbnRzQ291bnR9YCwgJ2RlYnVnJyk7XG5cbiAgICBsZXQgcGF5bG9hZCA9IHtcbiAgICAgIG9mZnNldDogMCxcbiAgICAgIGxpbWl0OiA1MDAsXG4gICAgICBxOiAnaWQhPTAwMCdcbiAgICB9O1xuXG4gICAgd2hpbGUgKGFnZW50cy5sZW5ndGggPCBhZ2VudHNDb3VudCAmJiBwYXlsb2FkLm9mZnNldCA8IGFnZW50c0NvdW50KSB7XG4gICAgICB0cnl7XG4gICAgICAgIC8qIFxuICAgICAgICBUT0RPOiBJbXByb3ZlIHRoZSBwZXJmb3JtYW5jZSBvZiByZXF1ZXN0IHdpdGg6XG4gICAgICAgICAgLSBSZWR1Y2UgdGhlIG51bWJlciBvZiByZXF1ZXN0cyB0byB0aGUgV2F6dWggQVBJXG4gICAgICAgICAgLSBSZWR1Y2UgKGlmIHBvc3NpYmxlKSB0aGUgcXVhbnRpdHkgb2YgZGF0YSB0byBpbmRleCBieSBkb2N1bWVudFxuXG4gICAgICAgIFJlcXVpcmVtZW50czpcbiAgICAgICAgICAtIFJlc2VhcmNoIGFib3V0IHRoZSBuZWNjZXNhcnkgZGF0YSB0byBpbmRleC5cblxuICAgICAgICBIb3cgdG8gZG86XG4gICAgICAgICAgLSBXYXp1aCBBUEkgcmVxdWVzdDpcbiAgICAgICAgICAgIC0gc2VsZWN0IHRoZSByZXF1aXJlZCBkYXRhIHRvIHJldHJpZXZlIGRlcGVuZGluZyBvbiBpcyByZXF1aXJlZCB0byBpbmRleCAodXNpbmcgdGhlIGBzZWxlY3RgIHF1ZXJ5IHBhcmFtKVxuICAgICAgICAgICAgLSBpbmNyZWFzZSB0aGUgbGltaXQgb2YgcmVzdWx0cyB0byByZXRyaWV2ZSAoY3VycmVudGx5LCB0aGUgcmVxdWVzdHMgdXNlIHRoZSByZWNvbW1lbmRlZCB2YWx1ZTogNTAwKS5cbiAgICAgICAgICAgICAgU2VlIHRoZSBhbGxvd2VkIHZhbHVlcy4gVGhpcyBkZXBlbmRzIG9uIHRoZSBzZWxlY3RlZCBkYXRhIGJlY2F1c2UgdGhlIHJlc3BvbnNlIGNvdWxkIGZhaWwgaWYgY29udGFpbnMgYSBsb3Qgb2YgZGF0YVxuICAgICAgICAqL1xuICAgICAgICBjb25zdCByZXNwb25zZUFnZW50cyA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0ludGVybmFsVXNlci5yZXF1ZXN0KFxuICAgICAgICAgICdHRVQnLFxuICAgICAgICAgIGAvYWdlbnRzYCxcbiAgICAgICAgICB7cGFyYW1zOiBwYXlsb2FkfSxcbiAgICAgICAgICB7YXBpSG9zdElEOiBhcGlIb3N0LmlkfVxuICAgICAgICApO1xuICAgICAgICBhZ2VudHMgPSBbLi4uYWdlbnRzLCAuLi5yZXNwb25zZUFnZW50cy5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXNdO1xuICAgICAgICBwYXlsb2FkLm9mZnNldCArPSBwYXlsb2FkLmxpbWl0O1xuICAgICAgfWNhdGNoKGVycm9yKXtcbiAgICAgICAgbG9nKCdtb25pdG9yaW5nOmZldGNoQWxsQWdlbnRzRnJvbUFwaUhvc3QnLCBgQXBpSUQ6ICR7YXBpSG9zdC5pZH0sIEVycm9yIHJlcXVlc3Qgd2l0aCBvZmZzZXQvbGltaXQgJHtwYXlsb2FkLm9mZnNldH0vJHtwYXlsb2FkLmxpbWl0fTogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWApO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gYWdlbnRzO1xuICB9Y2F0Y2goZXJyb3Ipe1xuICAgIGxvZygnbW9uaXRvcmluZzpmZXRjaEFsbEFnZW50c0Zyb21BcGlIb3N0JywgYEFwaUlEOiAke2FwaUhvc3QuaWR9LiBFcnJvcjogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWApO1xuICAgIHRocm93IGVycm9yO1xuICB9XG59O1xuXG4vKipcbiAqIFN0YXJ0IHRoZSBjcm9uIGpvYlxuICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gam9iTW9uaXRvcmluZ1J1bihjb250ZXh0KSB7XG4gIC8vIEluaXQgdGhlIG1vbml0b3JpbmcgdmFyaWFibGVzXG4gIGluaXRNb25pdG9yaW5nQ29uZmlndXJhdGlvbihjb250ZXh0KTtcbiAgLy8gQ2hlY2sgS2liYW5hIGluZGV4IGFuZCBpZiBpdCBpcyBwcmVwYXJlZCwgc3RhcnQgdGhlIGluaXRpYWxpemF0aW9uIG9mIFdhenVoIEFwcC5cbiAgYXdhaXQgY2hlY2tQbHVnaW5QbGF0Zm9ybVN0YXR1cyhjb250ZXh0KTtcbiAgLy8gLy8gUnVuIHRoZSBjcm9uIGpvYiBvbmx5IGl0IGl0J3MgZW5hYmxlZFxuICBpZiAoTU9OSVRPUklOR19FTkFCTEVEKSB7XG4gICAgY3JvblRhc2soY29udGV4dCk7XG4gICAgY3Jvbi5zY2hlZHVsZShNT05JVE9SSU5HX0NST05fRlJFUSwgKCkgPT4gY3JvblRhc2soY29udGV4dCkpO1xuICB9XG59XG5cbiJdfQ==