"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhElasticCtrl = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _errorResponse = require("../lib/error-response");

var _logger = require("../lib/logger");

var _getConfiguration = require("../lib/get-configuration");

var _visualizations = require("../integration-files/visualizations");

var _generateAlertsScript = require("../lib/generate-alerts/generate-alerts-script");

var _constants = require("../../common/constants");

var _jwtDecode = _interopRequireDefault(require("jwt-decode"));

var _manageHosts = require("../lib/manage-hosts");

var _cookie = require("../lib/cookie");

var _settings = require("../../common/services/settings");

/*
 * Wazuh app - Class for Wazuh-Elastic functions
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
class WazuhElasticCtrl {
  constructor() {
    (0, _defineProperty2.default)(this, "wzSampleAlertsIndexPrefix", void 0);
    (0, _defineProperty2.default)(this, "manageHosts", void 0);
    this.wzSampleAlertsIndexPrefix = this.getSampleAlertPrefix();
    this.manageHosts = new _manageHosts.ManageHosts();
  }
  /**
   * This returns the index according the category
   * @param {string} category
   */


  buildSampleIndexByCategory(category) {
    return `${this.wzSampleAlertsIndexPrefix}sample-${category}`;
  }
  /**
   * This returns the defined config for sample alerts prefix or the default value.
   */


  getSampleAlertPrefix() {
    const config = (0, _getConfiguration.getConfiguration)();
    return config['alerts.sample.prefix'] || (0, _settings.getSettingDefaultValue)('alerts.sample.prefix');
  }
  /**
   * This retrieves a template from Elasticsearch
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} template or ErrorResponse
   */


  async getTemplate(context, request, response) {
    try {
      const data = await context.core.elasticsearch.client.asInternalUser.cat.templates();
      const templates = data.body;

      if (!templates || typeof templates !== 'string') {
        throw new Error('An unknown error occurred when fetching templates from Elasticseach');
      }

      const lastChar = request.params.pattern[request.params.pattern.length - 1]; // Split into separate patterns

      const tmpdata = templates.match(/\[.*\]/g);
      const tmparray = [];

      for (let item of tmpdata) {
        // A template might use more than one pattern
        if (item.includes(',')) {
          item = item.substr(1).slice(0, -1);
          const subItems = item.split(',');

          for (const subitem of subItems) {
            tmparray.push(`[${subitem.trim()}]`);
          }
        } else {
          tmparray.push(item);
        }
      } // Ensure we are handling just patterns


      const array = tmparray.filter(item => item.includes('[') && item.includes(']'));
      const pattern = lastChar === '*' ? request.params.pattern.slice(0, -1) : request.params.pattern;
      const isIncluded = array.filter(item => {
        item = item.slice(1, -1);
        const lastChar = item[item.length - 1];
        item = lastChar === '*' ? item.slice(0, -1) : item;
        return item.includes(pattern) || pattern.includes(item);
      });
      (0, _logger.log)('wazuh-elastic:getTemplate', `Template is valid: ${isIncluded && Array.isArray(isIncluded) && isIncluded.length ? 'yes' : 'no'}`, 'debug');
      return isIncluded && Array.isArray(isIncluded) && isIncluded.length ? response.ok({
        body: {
          statusCode: 200,
          status: true,
          data: `Template found for ${request.params.pattern}`
        }
      }) : response.ok({
        body: {
          statusCode: 200,
          status: false,
          data: `No template found for ${request.params.pattern}`
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getTemplate', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Could not retrieve templates from Elasticsearch due to ${error.message || error}`, 4002, 500, response);
    }
  }
  /**
   * This check index-pattern
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} status obj or ErrorResponse
   */


  async checkPattern(context, request, response) {
    try {
      const data = await context.core.savedObjects.client.find({
        type: 'index-pattern'
      });
      const existsIndexPattern = data.saved_objects.find(item => item.attributes.title === request.params.pattern);
      (0, _logger.log)('wazuh-elastic:checkPattern', `Index pattern found: ${existsIndexPattern ? existsIndexPattern.attributes.title : 'no'}`, 'debug');
      return existsIndexPattern ? response.ok({
        body: {
          statusCode: 200,
          status: true,
          data: 'Index pattern found'
        }
      }) : response.ok({
        body: {
          statusCode: 500,
          status: false,
          error: 10020,
          message: 'Index pattern not found'
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:checkPattern', error.message || error);
      return (0, _errorResponse.ErrorResponse)(`Something went wrong retrieving index-patterns from Elasticsearch due to ${error.message || error}`, 4003, 500, response);
    }
  }
  /**
   * This get the fields keys
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Array<Object>} fields or ErrorResponse
   */


  async getFieldTop(context, request, response) {
    try {
      // Top field payload
      let payload = {
        size: 1,
        query: {
          bool: {
            must: [],
            must_not: {
              term: {
                'agent.id': '000'
              }
            },
            filter: [{
              range: {
                timestamp: {}
              }
            }]
          }
        },
        aggs: {
          '2': {
            terms: {
              field: '',
              size: 1,
              order: {
                _count: 'desc'
              }
            }
          }
        }
      }; // Set up time interval, default to Last 24h

      const timeGTE = 'now-1d';
      const timeLT = 'now';
      payload.query.bool.filter[0].range['timestamp']['gte'] = timeGTE;
      payload.query.bool.filter[0].range['timestamp']['lt'] = timeLT; // Set up match for default cluster name

      payload.query.bool.must.push(request.params.mode === 'cluster' ? {
        match: {
          'cluster.name': request.params.cluster
        }
      } : {
        match: {
          'manager.name': request.params.cluster
        }
      });
      if (request.query.agentsList) payload.query.bool.filter.push({
        terms: {
          'agent.id': request.query.agentsList.split(',')
        }
      });
      payload.aggs['2'].terms.field = request.params.field;
      const data = await context.core.elasticsearch.client.asCurrentUser.search({
        size: 1,
        index: request.params.pattern,
        body: payload
      });
      return data.body.hits.total.value === 0 || typeof data.body.aggregations['2'].buckets[0] === 'undefined' ? response.ok({
        body: {
          statusCode: 200,
          data: ''
        }
      }) : response.ok({
        body: {
          statusCode: 200,
          data: data.body.aggregations['2'].buckets[0].key
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getFieldTop', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4004, 500, response);
    }
  }
  /**
   * Checks one by one if the requesting user has enough privileges to use
   * an index pattern from the list.
   * @param {Array<Object>} list List of index patterns
   * @param {Object} req
   * @returns {Array<Object>} List of allowed index
   */


  async filterAllowedIndexPatternList(context, list, req) {
    //TODO: review if necesary to delete
    let finalList = [];

    for (let item of list) {
      let results = false,
          forbidden = false;

      try {
        results = await context.core.elasticsearch.client.asCurrentUser.search({
          index: item.title
        });
      } catch (error) {
        forbidden = true;
      }

      if ((((results || {}).body || {}).hits || {}).total.value >= 1 || !forbidden && (((results || {}).body || {}).hits || {}).total === 0) {
        finalList.push(item);
      }
    }

    return finalList;
  }
  /**
   * Checks for minimum index pattern fields in a list of index patterns.
   * @param {Array<Object>} indexPatternList List of index patterns
   */


  validateIndexPattern(indexPatternList) {
    const minimum = ['timestamp', 'rule.groups', 'manager.name', 'agent.id'];
    let list = [];

    for (const index of indexPatternList) {
      let valid, parsed;

      try {
        parsed = JSON.parse(index.attributes.fields);
      } catch (error) {
        continue;
      }

      valid = parsed.filter(item => minimum.includes(item.name));

      if (valid.length === 4) {
        list.push({
          id: index.id,
          title: index.attributes.title
        });
      }
    }

    return list;
  }
  /**
   * Returns current security platform
   * @param {Object} req
   * @param {Object} reply
   * @returns {String}
   */


  async getCurrentPlatform(context, request, response) {
    try {
      return response.ok({
        body: {
          platform: context.wazuh.security.platform
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:getCurrentPlatform', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4011, 500, response);
    }
  }
  /**
   * Replaces visualizations main fields to fit a certain pattern.
   * @param {Array<Object>} app_objects Object containing raw visualizations.
   * @param {String} id Index-pattern id to use in the visualizations. Eg: 'wazuh-alerts'
   */


  async buildVisualizationsRaw(app_objects, id, namespace = false) {
    try {
      const config = (0, _getConfiguration.getConfiguration)();
      let monitoringPattern = (config || {})['wazuh.monitoring.pattern'] || (0, _settings.getSettingDefaultValue)('wazuh.monitoring.pattern');
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', `Building ${app_objects.length} visualizations`, 'debug');
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', `Index pattern ID: ${id}`, 'debug');
      const visArray = [];
      let aux_source, bulk_content;

      for (let element of app_objects) {
        aux_source = JSON.parse(JSON.stringify(element._source)); // Replace index-pattern for visualizations

        if (aux_source && aux_source.kibanaSavedObjectMeta && aux_source.kibanaSavedObjectMeta.searchSourceJSON && typeof aux_source.kibanaSavedObjectMeta.searchSourceJSON === 'string') {
          const defaultStr = aux_source.kibanaSavedObjectMeta.searchSourceJSON;
          const isMonitoring = defaultStr.includes('wazuh-monitoring');

          if (isMonitoring) {
            if (namespace && namespace !== 'default') {
              if (monitoringPattern.includes(namespace) && monitoringPattern.includes('index-pattern:')) {
                monitoringPattern = monitoringPattern.split('index-pattern:')[1];
              }
            }

            aux_source.kibanaSavedObjectMeta.searchSourceJSON = defaultStr.replace(/wazuh-monitoring/g, monitoringPattern[monitoringPattern.length - 1] === '*' || namespace && namespace !== 'default' ? monitoringPattern : monitoringPattern + '*');
          } else {
            aux_source.kibanaSavedObjectMeta.searchSourceJSON = defaultStr.replace(/wazuh-alerts/g, id);
          }
        } // Replace index-pattern for selector visualizations


        if (typeof (aux_source || {}).visState === 'string') {
          aux_source.visState = aux_source.visState.replace(/wazuh-alerts/g, id);
        } // Bulk source


        bulk_content = {};
        bulk_content[element._type] = aux_source;
        visArray.push({
          attributes: bulk_content.visualization,
          type: element._type,
          id: element._id,
          _version: bulk_content.visualization.version
        });
      }

      return visArray;
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:buildVisualizationsRaw', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * Replaces cluster visualizations main fields.
   * @param {Array<Object>} app_objects Object containing raw visualizations.
   * @param {String} id Index-pattern id to use in the visualizations. Eg: 'wazuh-alerts'
   * @param {Array<String>} nodes Array of node names. Eg: ['node01', 'node02']
   * @param {String} name Cluster name. Eg: 'wazuh'
   * @param {String} master_node Master node name. Eg: 'node01'
   */


  buildClusterVisualizationsRaw(app_objects, id, nodes = [], name, master_node, pattern_name = '*') {
    try {
      const visArray = [];
      let aux_source, bulk_content;

      for (const element of app_objects) {
        // Stringify and replace index-pattern for visualizations
        aux_source = JSON.stringify(element._source);
        aux_source = aux_source.replace(/wazuh-alerts/g, id);
        aux_source = JSON.parse(aux_source); // Bulk source

        bulk_content = {};
        bulk_content[element._type] = aux_source;
        const visState = JSON.parse(bulk_content.visualization.visState);
        const title = visState.title;

        if (visState.type && visState.type === 'timelion') {
          let query = '';

          if (title === 'Wazuh App Cluster Overview') {
            for (const node of nodes) {
              query += `.es(index=${pattern_name},q="cluster.name: ${name} AND cluster.node: ${node.name}").label("${node.name}"),`;
            }

            query = query.substring(0, query.length - 1);
          } else if (title === 'Wazuh App Cluster Overview Manager') {
            query += `.es(index=${pattern_name},q="cluster.name: ${name}").label("${name} cluster")`;
          } else {
            if (title.startsWith('Wazuh App Statistics')) {
              const {
                searchSourceJSON
              } = bulk_content.visualization.kibanaSavedObjectMeta;
              bulk_content.visualization.kibanaSavedObjectMeta.searchSourceJSON = searchSourceJSON.replace('wazuh-statistics-*', pattern_name);
            }

            if (title.startsWith('Wazuh App Statistics') && name !== '-' && name !== 'all' && visState.params.expression.includes('q=')) {
              const expressionRegex = /q='\*'/gi;

              const _visState = bulk_content.visualization.visStateByNode ? JSON.parse(bulk_content.visualization.visStateByNode) : visState;

              query += _visState.params.expression.replace(/wazuh-statistics-\*/g, pattern_name).replace(expressionRegex, `q="nodeName.keyword:${name} AND apiName.keyword:${master_node}"`).replace("NODE_NAME", name);
            } else if (title.startsWith('Wazuh App Statistics')) {
              const expressionRegex = /q='\*'/gi;
              query += visState.params.expression.replace(/wazuh-statistics-\*/g, pattern_name).replace(expressionRegex, `q="apiName.keyword:${master_node}"`);
            } else {
              query = visState.params.expression;
            }
          }

          visState.params.expression = query.replace(/'/g, "\"");
          bulk_content.visualization.visState = JSON.stringify(visState);
        }

        visArray.push({
          attributes: bulk_content.visualization,
          type: element._type,
          id: element._id,
          _version: bulk_content.visualization.version
        });
      }

      return visArray;
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:buildClusterVisualizationsRaw', error.message || error);
      return Promise.reject(error);
    }
  }
  /**
   * This creates a visualization of data in req
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} vis obj or ErrorResponse
   */


  async createVis(context, request, response) {
    try {
      if (!request.params.tab.includes('overview-') && !request.params.tab.includes('agents-')) {
        throw new Error('Missing parameters creating visualizations');
      }

      const tabPrefix = request.params.tab.includes('overview') ? 'overview' : 'agents';
      const tabSplit = request.params.tab.split('-');
      const tabSufix = tabSplit[1];
      const file = tabPrefix === 'overview' ? _visualizations.OverviewVisualizations[tabSufix] : _visualizations.AgentsVisualizations[tabSufix];

      if (!file) {
        return response.notFound({
          body: {
            message: `Visualizations not found for ${request.params.tab}`
          }
        });
      }

      (0, _logger.log)('wazuh-elastic:createVis', `${tabPrefix}[${tabSufix}] with index pattern ${request.params.pattern}`, 'debug');
      const namespace = context.wazuh.plugins.spaces && context.wazuh.plugins.spaces.spacesService && context.wazuh.plugins.spaces.spacesService.getSpaceId(request);
      const raw = await this.buildVisualizationsRaw(file, request.params.pattern, namespace);
      return response.ok({
        body: {
          acknowledge: true,
          raw: raw
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createVis', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4007, 500, response);
    }
  }
  /**
   * This creates a visualization of cluster
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} vis obj or ErrorResponse
   */


  async createClusterVis(context, request, response) {
    try {
      if (!request.params.pattern || !request.params.tab || !request.body || !request.body.nodes || !request.body.nodes.affected_items || !request.body.nodes.name || request.params.tab && !request.params.tab.includes('cluster-')) {
        throw new Error('Missing parameters creating visualizations');
      }

      const type = request.params.tab.split('-')[1];
      const file = _visualizations.ClusterVisualizations[type];
      const nodes = request.body.nodes.affected_items;
      const name = request.body.nodes.name;
      const masterNode = request.body.nodes.master_node;
      const {
        id: patternID,
        title: patternName
      } = request.body.pattern;
      const raw = await this.buildClusterVisualizationsRaw(file, patternID, nodes, name, masterNode, patternName);
      return response.ok({
        body: {
          acknowledge: true,
          raw: raw
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createClusterVis', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4009, 500, response);
    }
  }
  /**
   * This checks if there is sample alerts
   * GET /elastic/samplealerts
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {alerts: [...]} or ErrorResponse
   */


  async haveSampleAlerts(context, request, response) {
    try {
      // Check if wazuh sample alerts index exists
      const results = await Promise.all(Object.keys(_constants.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS).map(category => context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: this.buildSampleIndexByCategory(category)
      })));
      return response.ok({
        body: {
          sampleAlertsInstalled: results.some(result => result.body)
        }
      });
    } catch (error) {
      return (0, _errorResponse.ErrorResponse)('Sample Alerts category not valid', 1000, 500, response);
    }
  }
  /**
   * This creates sample alerts in wazuh-sample-alerts
   * GET /elastic/samplealerts/{category}
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {alerts: [...]} or ErrorResponse
   */


  async haveSampleAlertsOfCategory(context, request, response) {
    try {
      const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category); // Check if wazuh sample alerts index exists

      const existsSampleIndex = await context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: sampleAlertsIndex
      });
      return response.ok({
        body: {
          index: sampleAlertsIndex,
          exists: existsSampleIndex.body
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:haveSampleAlertsOfCategory', `Error checking if there are sample alerts indices: ${error.message || error}`);
      const [statusCode, errorMessage] = this.getErrorDetails(error);
      return (0, _errorResponse.ErrorResponse)(`Error checking if there are sample alerts indices: ${errorMessage || error}`, 1000, statusCode, response);
    }
  }
  /**
   * This creates sample alerts in wazuh-sample-alerts
   * POST /elastic/samplealerts/{category}
   * {
   *   "manager": {
   *      "name": "manager_name"
   *    },
   *    cluster: {
   *      name: "mycluster",
   *      node: "mynode"
   *    }
   * }
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {index: string, alerts: [...], count: number} or ErrorResponse
   */


  async createSampleAlerts(context, request, response) {
    const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category);

    try {
      // Check if user has administrator role in token
      const token = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token');

      if (!token) {
        return (0, _errorResponse.ErrorResponse)('No token provided', 401, 401, response);
      }

      ;
      const decodedToken = (0, _jwtDecode.default)(token);

      if (!decodedToken) {
        return (0, _errorResponse.ErrorResponse)('No permissions in token', 401, 401, response);
      }

      ;

      if (!decodedToken.rbac_roles || !decodedToken.rbac_roles.includes(_constants.WAZUH_ROLE_ADMINISTRATOR_ID)) {
        return (0, _errorResponse.ErrorResponse)('No administrator role', 401, 401, response);
      }

      ; // Check the provided token is valid

      const apiHostID = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

      if (!apiHostID) {
        return (0, _errorResponse.ErrorResponse)('No API id provided', 401, 401, response);
      }

      ;
      const responseTokenIsWorking = await context.wazuh.api.client.asCurrentUser.request('GET', `//`, {}, {
        apiHostID
      });

      if (responseTokenIsWorking.status !== 200) {
        return (0, _errorResponse.ErrorResponse)('Token is not valid', 500, 500, response);
      }

      ;
      const bulkPrefix = JSON.stringify({
        index: {
          _index: sampleAlertsIndex
        }
      });
      const alertGenerateParams = request.body && request.body.params || {};

      const sampleAlerts = _constants.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS[request.params.category].map(typeAlert => (0, _generateAlertsScript.generateAlerts)({ ...typeAlert,
        ...alertGenerateParams
      }, request.body.alerts || typeAlert.alerts || _constants.WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS)).flat();

      const bulk = sampleAlerts.map(sampleAlert => `${bulkPrefix}\n${JSON.stringify(sampleAlert)}\n`).join(''); // Index alerts
      // Check if wazuh sample alerts index exists

      const existsSampleIndex = await context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: sampleAlertsIndex
      });

      if (!existsSampleIndex.body) {
        // Create wazuh sample alerts index
        const configuration = {
          settings: {
            index: {
              number_of_shards: _constants.WAZUH_SAMPLE_ALERTS_INDEX_SHARDS,
              number_of_replicas: _constants.WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS
            }
          }
        };
        await context.core.elasticsearch.client.asCurrentUser.indices.create({
          index: sampleAlertsIndex,
          body: configuration
        });
        (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Created ${sampleAlertsIndex} index`, 'debug');
      }

      await context.core.elasticsearch.client.asCurrentUser.bulk({
        index: sampleAlertsIndex,
        body: bulk
      });
      (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Added sample alerts to ${sampleAlertsIndex} index`, 'debug');
      return response.ok({
        body: {
          index: sampleAlertsIndex,
          alertCount: sampleAlerts.length
        }
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:createSampleAlerts', `Error adding sample alerts to ${sampleAlertsIndex} index: ${error.message || error}`);
      const [statusCode, errorMessage] = this.getErrorDetails(error);
      return (0, _errorResponse.ErrorResponse)(errorMessage || error, 1000, statusCode, response);
    }
  }
  /**
   * This deletes sample alerts
   * @param {*} context
   * @param {*} request
   * @param {*} response
   * {result: "deleted", index: string} or ErrorResponse
   */


  async deleteSampleAlerts(context, request, response) {
    // Delete Wazuh sample alert index
    const sampleAlertsIndex = this.buildSampleIndexByCategory(request.params.category);

    try {
      // Check if user has administrator role in token
      const token = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-token');

      if (!token) {
        return (0, _errorResponse.ErrorResponse)('No token provided', 401, 401, response);
      }

      ;
      const decodedToken = (0, _jwtDecode.default)(token);

      if (!decodedToken) {
        return (0, _errorResponse.ErrorResponse)('No permissions in token', 401, 401, response);
      }

      ;

      if (!decodedToken.rbac_roles || !decodedToken.rbac_roles.includes(_constants.WAZUH_ROLE_ADMINISTRATOR_ID)) {
        return (0, _errorResponse.ErrorResponse)('No administrator role', 401, 401, response);
      }

      ; // Check the provided token is valid

      const apiHostID = (0, _cookie.getCookieValueByName)(request.headers.cookie, 'wz-api');

      if (!apiHostID) {
        return (0, _errorResponse.ErrorResponse)('No API id provided', 401, 401, response);
      }

      ;
      const responseTokenIsWorking = await context.wazuh.api.client.asCurrentUser.request('GET', `//`, {}, {
        apiHostID
      });

      if (responseTokenIsWorking.status !== 200) {
        return (0, _errorResponse.ErrorResponse)('Token is not valid', 500, 500, response);
      }

      ; // Check if Wazuh sample alerts index exists

      const existsSampleIndex = await context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: sampleAlertsIndex
      });

      if (existsSampleIndex.body) {
        // Delete Wazuh sample alerts index
        await context.core.elasticsearch.client.asCurrentUser.indices.delete({
          index: sampleAlertsIndex
        });
        (0, _logger.log)('wazuh-elastic:deleteSampleAlerts', `Deleted ${sampleAlertsIndex} index`, 'debug');
        return response.ok({
          body: {
            result: 'deleted',
            index: sampleAlertsIndex
          }
        });
      } else {
        return (0, _errorResponse.ErrorResponse)(`${sampleAlertsIndex} index doesn't exist`, 1000, 500, response);
      }
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:deleteSampleAlerts', `Error deleting sample alerts of ${sampleAlertsIndex} index: ${error.message || error}`);
      const [statusCode, errorMessage] = this.getErrorDetails(error);
      return (0, _errorResponse.ErrorResponse)(errorMessage || error, 1000, statusCode, response);
    }
  }

  async alerts(context, request, response) {
    try {
      const data = await context.core.elasticsearch.client.asCurrentUser.search(request.body);
      return response.ok({
        body: data.body
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:alerts', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 4010, 500, response);
    }
  } // Check if there are indices for Statistics


  async existStatisticsIndices(context, request, response) {
    try {
      const config = (0, _getConfiguration.getConfiguration)();
      const statisticsPattern = `${config['cron.prefix'] || 'wazuh'}-${config['cron.statistics.index.name'] || 'statistics'}*`; //TODO: replace by default as constants instead hardcoded ('wazuh' and 'statistics')

      const existIndex = await context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: statisticsPattern,
        allow_no_indices: false
      });
      return response.ok({
        body: existIndex.body
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:existsStatisticsIndices', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 1000, 500, response);
    }
  } // Check if there are indices for Monitoring


  async existMonitoringIndices(context, request, response) {
    try {
      const config = (0, _getConfiguration.getConfiguration)();
      const monitoringIndexPattern = config['wazuh.monitoring.pattern'] || (0, _settings.getSettingDefaultValue)('wazuh.monitoring.pattern');
      const existIndex = await context.core.elasticsearch.client.asCurrentUser.indices.exists({
        index: monitoringIndexPattern,
        allow_no_indices: false
      });
      return response.ok({
        body: existIndex.body
      });
    } catch (error) {
      (0, _logger.log)('wazuh-elastic:existsMonitoringIndices', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 1000, 500, response);
    }
  }

  async usingCredentials(context) {
    try {
      const data = await context.core.elasticsearch.client.asInternalUser.cluster.getSettings({
        include_defaults: true
      });
      return (((((data || {}).body || {}).defaults || {}).xpack || {}).security || {}).user !== null;
    } catch (error) {
      return Promise.reject(error);
    }
  }

  getErrorDetails(error) {
    var _error$meta;

    const statusCode = (error === null || error === void 0 ? void 0 : (_error$meta = error.meta) === null || _error$meta === void 0 ? void 0 : _error$meta.statusCode) || 500;
    let errorMessage = error.message;

    if (statusCode === 403) {
      var _error$meta2, _error$meta2$body, _error$meta2$body$err;

      errorMessage = (error === null || error === void 0 ? void 0 : (_error$meta2 = error.meta) === null || _error$meta2 === void 0 ? void 0 : (_error$meta2$body = _error$meta2.body) === null || _error$meta2$body === void 0 ? void 0 : (_error$meta2$body$err = _error$meta2$body.error) === null || _error$meta2$body$err === void 0 ? void 0 : _error$meta2$body$err.reason) || 'Permission denied';
    }

    return [statusCode, errorMessage];
  }

}

exports.WazuhElasticCtrl = WazuhElasticCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLWVsYXN0aWMudHMiXSwibmFtZXMiOlsiV2F6dWhFbGFzdGljQ3RybCIsImNvbnN0cnVjdG9yIiwid3pTYW1wbGVBbGVydHNJbmRleFByZWZpeCIsImdldFNhbXBsZUFsZXJ0UHJlZml4IiwibWFuYWdlSG9zdHMiLCJNYW5hZ2VIb3N0cyIsImJ1aWxkU2FtcGxlSW5kZXhCeUNhdGVnb3J5IiwiY2F0ZWdvcnkiLCJjb25maWciLCJnZXRUZW1wbGF0ZSIsImNvbnRleHQiLCJyZXF1ZXN0IiwicmVzcG9uc2UiLCJkYXRhIiwiY29yZSIsImVsYXN0aWNzZWFyY2giLCJjbGllbnQiLCJhc0ludGVybmFsVXNlciIsImNhdCIsInRlbXBsYXRlcyIsImJvZHkiLCJFcnJvciIsImxhc3RDaGFyIiwicGFyYW1zIiwicGF0dGVybiIsImxlbmd0aCIsInRtcGRhdGEiLCJtYXRjaCIsInRtcGFycmF5IiwiaXRlbSIsImluY2x1ZGVzIiwic3Vic3RyIiwic2xpY2UiLCJzdWJJdGVtcyIsInNwbGl0Iiwic3ViaXRlbSIsInB1c2giLCJ0cmltIiwiYXJyYXkiLCJmaWx0ZXIiLCJpc0luY2x1ZGVkIiwiQXJyYXkiLCJpc0FycmF5Iiwib2siLCJzdGF0dXNDb2RlIiwic3RhdHVzIiwiZXJyb3IiLCJtZXNzYWdlIiwiY2hlY2tQYXR0ZXJuIiwic2F2ZWRPYmplY3RzIiwiZmluZCIsInR5cGUiLCJleGlzdHNJbmRleFBhdHRlcm4iLCJzYXZlZF9vYmplY3RzIiwiYXR0cmlidXRlcyIsInRpdGxlIiwiZ2V0RmllbGRUb3AiLCJwYXlsb2FkIiwic2l6ZSIsInF1ZXJ5IiwiYm9vbCIsIm11c3QiLCJtdXN0X25vdCIsInRlcm0iLCJyYW5nZSIsInRpbWVzdGFtcCIsImFnZ3MiLCJ0ZXJtcyIsImZpZWxkIiwib3JkZXIiLCJfY291bnQiLCJ0aW1lR1RFIiwidGltZUxUIiwibW9kZSIsImNsdXN0ZXIiLCJhZ2VudHNMaXN0IiwiYXNDdXJyZW50VXNlciIsInNlYXJjaCIsImluZGV4IiwiaGl0cyIsInRvdGFsIiwidmFsdWUiLCJhZ2dyZWdhdGlvbnMiLCJidWNrZXRzIiwia2V5IiwiZmlsdGVyQWxsb3dlZEluZGV4UGF0dGVybkxpc3QiLCJsaXN0IiwicmVxIiwiZmluYWxMaXN0IiwicmVzdWx0cyIsImZvcmJpZGRlbiIsInZhbGlkYXRlSW5kZXhQYXR0ZXJuIiwiaW5kZXhQYXR0ZXJuTGlzdCIsIm1pbmltdW0iLCJ2YWxpZCIsInBhcnNlZCIsIkpTT04iLCJwYXJzZSIsImZpZWxkcyIsIm5hbWUiLCJpZCIsImdldEN1cnJlbnRQbGF0Zm9ybSIsInBsYXRmb3JtIiwid2F6dWgiLCJzZWN1cml0eSIsImJ1aWxkVmlzdWFsaXphdGlvbnNSYXciLCJhcHBfb2JqZWN0cyIsIm5hbWVzcGFjZSIsIm1vbml0b3JpbmdQYXR0ZXJuIiwidmlzQXJyYXkiLCJhdXhfc291cmNlIiwiYnVsa19jb250ZW50IiwiZWxlbWVudCIsInN0cmluZ2lmeSIsIl9zb3VyY2UiLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiZGVmYXVsdFN0ciIsImlzTW9uaXRvcmluZyIsInJlcGxhY2UiLCJ2aXNTdGF0ZSIsIl90eXBlIiwidmlzdWFsaXphdGlvbiIsIl9pZCIsIl92ZXJzaW9uIiwidmVyc2lvbiIsIlByb21pc2UiLCJyZWplY3QiLCJidWlsZENsdXN0ZXJWaXN1YWxpemF0aW9uc1JhdyIsIm5vZGVzIiwibWFzdGVyX25vZGUiLCJwYXR0ZXJuX25hbWUiLCJub2RlIiwic3Vic3RyaW5nIiwic3RhcnRzV2l0aCIsImV4cHJlc3Npb24iLCJleHByZXNzaW9uUmVnZXgiLCJfdmlzU3RhdGUiLCJ2aXNTdGF0ZUJ5Tm9kZSIsImNyZWF0ZVZpcyIsInRhYiIsInRhYlByZWZpeCIsInRhYlNwbGl0IiwidGFiU3VmaXgiLCJmaWxlIiwiT3ZlcnZpZXdWaXN1YWxpemF0aW9ucyIsIkFnZW50c1Zpc3VhbGl6YXRpb25zIiwibm90Rm91bmQiLCJwbHVnaW5zIiwic3BhY2VzIiwic3BhY2VzU2VydmljZSIsImdldFNwYWNlSWQiLCJyYXciLCJhY2tub3dsZWRnZSIsImNyZWF0ZUNsdXN0ZXJWaXMiLCJhZmZlY3RlZF9pdGVtcyIsIkNsdXN0ZXJWaXN1YWxpemF0aW9ucyIsIm1hc3Rlck5vZGUiLCJwYXR0ZXJuSUQiLCJwYXR0ZXJuTmFtZSIsImhhdmVTYW1wbGVBbGVydHMiLCJhbGwiLCJPYmplY3QiLCJrZXlzIiwiV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SSUVTX1RZUEVfQUxFUlRTIiwibWFwIiwiaW5kaWNlcyIsImV4aXN0cyIsInNhbXBsZUFsZXJ0c0luc3RhbGxlZCIsInNvbWUiLCJyZXN1bHQiLCJoYXZlU2FtcGxlQWxlcnRzT2ZDYXRlZ29yeSIsInNhbXBsZUFsZXJ0c0luZGV4IiwiZXhpc3RzU2FtcGxlSW5kZXgiLCJlcnJvck1lc3NhZ2UiLCJnZXRFcnJvckRldGFpbHMiLCJjcmVhdGVTYW1wbGVBbGVydHMiLCJ0b2tlbiIsImhlYWRlcnMiLCJjb29raWUiLCJkZWNvZGVkVG9rZW4iLCJyYmFjX3JvbGVzIiwiV0FaVUhfUk9MRV9BRE1JTklTVFJBVE9SX0lEIiwiYXBpSG9zdElEIiwicmVzcG9uc2VUb2tlbklzV29ya2luZyIsImFwaSIsImJ1bGtQcmVmaXgiLCJfaW5kZXgiLCJhbGVydEdlbmVyYXRlUGFyYW1zIiwic2FtcGxlQWxlcnRzIiwidHlwZUFsZXJ0IiwiYWxlcnRzIiwiV0FaVUhfU0FNUExFX0FMRVJUU19ERUZBVUxUX05VTUJFUl9BTEVSVFMiLCJmbGF0IiwiYnVsayIsInNhbXBsZUFsZXJ0Iiwiam9pbiIsImNvbmZpZ3VyYXRpb24iLCJzZXR0aW5ncyIsIm51bWJlcl9vZl9zaGFyZHMiLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1NIQVJEUyIsIm51bWJlcl9vZl9yZXBsaWNhcyIsIldBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfUkVQTElDQVMiLCJjcmVhdGUiLCJhbGVydENvdW50IiwiZGVsZXRlU2FtcGxlQWxlcnRzIiwiZGVsZXRlIiwiZXhpc3RTdGF0aXN0aWNzSW5kaWNlcyIsInN0YXRpc3RpY3NQYXR0ZXJuIiwiZXhpc3RJbmRleCIsImFsbG93X25vX2luZGljZXMiLCJleGlzdE1vbml0b3JpbmdJbmRpY2VzIiwibW9uaXRvcmluZ0luZGV4UGF0dGVybiIsInVzaW5nQ3JlZGVudGlhbHMiLCJnZXRTZXR0aW5ncyIsImluY2x1ZGVfZGVmYXVsdHMiLCJkZWZhdWx0cyIsInhwYWNrIiwidXNlciIsIm1ldGEiLCJyZWFzb24iXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7O0FBV0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBTUE7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBRUE7O0FBRUE7O0FBM0JBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFtQk8sTUFBTUEsZ0JBQU4sQ0FBdUI7QUFHNUJDLEVBQUFBLFdBQVcsR0FBRztBQUFBO0FBQUE7QUFDWixTQUFLQyx5QkFBTCxHQUFpQyxLQUFLQyxvQkFBTCxFQUFqQztBQUNBLFNBQUtDLFdBQUwsR0FBbUIsSUFBSUMsd0JBQUosRUFBbkI7QUFDRDtBQUVEO0FBQ0Y7QUFDQTtBQUNBOzs7QUFDRUMsRUFBQUEsMEJBQTBCLENBQUNDLFFBQUQsRUFBMkI7QUFDbkQsV0FBUSxHQUFFLEtBQUtMLHlCQUEwQixVQUFTSyxRQUFTLEVBQTNEO0FBQ0Q7QUFFRDtBQUNGO0FBQ0E7OztBQUNFSixFQUFBQSxvQkFBb0IsR0FBVztBQUM3QixVQUFNSyxNQUFNLEdBQUcseUNBQWY7QUFDQSxXQUFPQSxNQUFNLENBQUMsc0JBQUQsQ0FBTixJQUFrQyxzQ0FBdUIsc0JBQXZCLENBQXpDO0FBQ0Q7QUFFRDtBQUNGO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBQ21CLFFBQVhDLFdBQVcsQ0FBQ0MsT0FBRCxFQUFpQ0MsT0FBakMsRUFBOEVDLFFBQTlFLEVBQStHO0FBQzlILFFBQUk7QUFDRixZQUFNQyxJQUFJLEdBQUcsTUFBTUgsT0FBTyxDQUFDSSxJQUFSLENBQWFDLGFBQWIs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QUF2QyxFQUEyQ0MsS0FBM0MsSUFBb0QsRUFBckQsRUFBeURqSCxRQUF6RCxJQUFxRSxFQUF0RSxFQUEwRWtILElBQTFFLEtBQW1GLElBQTFGO0FBQ0QsS0FMRCxDQUtFLE9BQU81SyxLQUFQLEVBQWM7QUFDZCxhQUFPZ0YsT0FBTyxDQUFDQyxNQUFSLENBQWVqRixLQUFmLENBQVA7QUFDRDtBQUNGOztBQUVEaUksRUFBQUEsZUFBZSxDQUFDakksS0FBRCxFQUFPO0FBQUE7O0FBQ3BCLFVBQU1GLFVBQVUsR0FBRyxDQUFBRSxLQUFLLFNBQUwsSUFBQUEsS0FBSyxXQUFMLDJCQUFBQSxLQUFLLENBQUU2SyxJQUFQLDREQUFhL0ssVUFBYixLQUEyQixHQUE5QztBQUNBLFFBQUlrSSxZQUFZLEdBQUdoSSxLQUFLLENBQUNDLE9BQXpCOztBQUVBLFFBQUdILFVBQVUsS0FBSyxHQUFsQixFQUFzQjtBQUFBOztBQUNwQmtJLE1BQUFBLFlBQVksR0FBRyxDQUFBaEksS0FBSyxTQUFMLElBQUFBLEtBQUssV0FBTCw0QkFBQUEsS0FBSyxDQUFFNkssSUFBUCxtRkFBYXZNLElBQWIsaUdBQW1CMEIsS0FBbkIsZ0ZBQTBCOEssTUFBMUIsS0FBb0MsbUJBQW5EO0FBQ0Q7O0FBRUQsV0FBTyxDQUFDaEwsVUFBRCxFQUFha0ksWUFBYixDQUFQO0FBQ0Q7O0FBOTFCMkIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gQ2xhc3MgZm9yIFdhenVoLUVsYXN0aWMgZnVuY3Rpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHsgRXJyb3JSZXNwb25zZSB9IGZyb20gJy4uL2xpYi9lcnJvci1yZXNwb25zZSc7XG5pbXBvcnQgeyBsb2cgfSBmcm9tICcuLi9saWIvbG9nZ2VyJztcbmltcG9ydCB7IGdldENvbmZpZ3VyYXRpb24gfSBmcm9tICcuLi9saWIvZ2V0LWNvbmZpZ3VyYXRpb24nO1xuaW1wb3J0IHtcbiAgQWdlbnRzVmlzdWFsaXphdGlvbnMsXG4gIE92ZXJ2aWV3VmlzdWFsaXphdGlvbnMsXG4gIENsdXN0ZXJWaXN1YWxpemF0aW9uc1xufSBmcm9tICcuLi9pbnRlZ3JhdGlvbi1maWxlcy92aXN1YWxpemF0aW9ucyc7XG5cbmltcG9ydCB7IGdlbmVyYXRlQWxlcnRzIH0gZnJvbSAnLi4vbGliL2dlbmVyYXRlLWFsZXJ0cy9nZW5lcmF0ZS1hbGVydHMtc2NyaXB0JztcbmltcG9ydCB7IFdBWlVIX1JPTEVfQURNSU5JU1RSQVRPUl9JRCwgV0FaVUhfU0FNUExFX0FMRVJUU19JTkRFWF9TSEFSRFMsIFdBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfUkVQTElDQVMgfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJztcbmltcG9ydCBqd3REZWNvZGUgZnJvbSAnand0LWRlY29kZSc7XG5pbXBvcnQgeyBNYW5hZ2VIb3N0cyB9IGZyb20gJy4uL2xpYi9tYW5hZ2UtaG9zdHMnO1xuaW1wb3J0IHsgS2liYW5hUmVxdWVzdCwgUmVxdWVzdEhhbmRsZXJDb250ZXh0LCBLaWJhbmFSZXNwb25zZUZhY3RvcnksIFNhdmVkT2JqZWN0LCBTYXZlZE9iamVjdHNGaW5kUmVzcG9uc2UgfSBmcm9tICdzcmMvY29yZS9zZXJ2ZXInO1xuaW1wb3J0IHsgZ2V0Q29va2llVmFsdWVCeU5hbWUgfSBmcm9tICcuLi9saWIvY29va2llJztcbmltcG9ydCB7IFdBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUklFU19UWVBFX0FMRVJUUywgV0FaVUhfU0FNUExFX0FMRVJUU19ERUZBVUxUX05VTUJFUl9BTEVSVFMgfSBmcm9tICcuLi8uLi9jb21tb24vY29uc3RhbnRzJ1xuaW1wb3J0IHsgZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSB9IGZyb20gJy4uLy4uL2NvbW1vbi9zZXJ2aWNlcy9zZXR0aW5ncyc7XG5cbmV4cG9ydCBjbGFzcyBXYXp1aEVsYXN0aWNDdHJsIHtcbiAgd3pTYW1wbGVBbGVydHNJbmRleFByZWZpeDogc3RyaW5nXG4gIG1hbmFnZUhvc3RzOiBNYW5hZ2VIb3N0c1xuICBjb25zdHJ1Y3RvcigpIHtcbiAgICB0aGlzLnd6U2FtcGxlQWxlcnRzSW5kZXhQcmVmaXggPSB0aGlzLmdldFNhbXBsZUFsZXJ0UHJlZml4KCk7XG4gICAgdGhpcy5tYW5hZ2VIb3N0cyA9IG5ldyBNYW5hZ2VIb3N0cygpO1xuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgcmV0dXJucyB0aGUgaW5kZXggYWNjb3JkaW5nIHRoZSBjYXRlZ29yeVxuICAgKiBAcGFyYW0ge3N0cmluZ30gY2F0ZWdvcnlcbiAgICovXG4gIGJ1aWxkU2FtcGxlSW5kZXhCeUNhdGVnb3J5KGNhdGVnb3J5OiBzdHJpbmcpOiBzdHJpbmcge1xuICAgIHJldHVybiBgJHt0aGlzLnd6U2FtcGxlQWxlcnRzSW5kZXhQcmVmaXh9c2FtcGxlLSR7Y2F0ZWdvcnl9YDtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIHJldHVybnMgdGhlIGRlZmluZWQgY29uZmlnIGZvciBzYW1wbGUgYWxlcnRzIHByZWZpeCBvciB0aGUgZGVmYXVsdCB2YWx1ZS5cbiAgICovXG4gIGdldFNhbXBsZUFsZXJ0UHJlZml4KCk6IHN0cmluZyB7XG4gICAgY29uc3QgY29uZmlnID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuICAgIHJldHVybiBjb25maWdbJ2FsZXJ0cy5zYW1wbGUucHJlZml4J10gfHwgZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSgnYWxlcnRzLnNhbXBsZS5wcmVmaXgnKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIHJldHJpZXZlcyBhIHRlbXBsYXRlIGZyb20gRWxhc3RpY3NlYXJjaFxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gdGVtcGxhdGUgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZ2V0VGVtcGxhdGUoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0PHsgcGF0dGVybjogc3RyaW5nIH0+LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNJbnRlcm5hbFVzZXIuY2F0LnRlbXBsYXRlcygpO1xuXG4gICAgICBjb25zdCB0ZW1wbGF0ZXMgPSBkYXRhLmJvZHk7XG4gICAgICBpZiAoIXRlbXBsYXRlcyB8fCB0eXBlb2YgdGVtcGxhdGVzICE9PSAnc3RyaW5nJykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgICAgJ0FuIHVua25vd24gZXJyb3Igb2NjdXJyZWQgd2hlbiBmZXRjaGluZyB0ZW1wbGF0ZXMgZnJvbSBFbGFzdGljc2VhY2gnXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGxhc3RDaGFyID0gcmVxdWVzdC5wYXJhbXMucGF0dGVybltyZXF1ZXN0LnBhcmFtcy5wYXR0ZXJuLmxlbmd0aCAtIDFdO1xuXG4gICAgICAvLyBTcGxpdCBpbnRvIHNlcGFyYXRlIHBhdHRlcm5zXG4gICAgICBjb25zdCB0bXBkYXRhID0gdGVtcGxhdGVzLm1hdGNoKC9cXFsuKlxcXS9nKTtcbiAgICAgIGNvbnN0IHRtcGFycmF5ID0gW107XG4gICAgICBmb3IgKGxldCBpdGVtIG9mIHRtcGRhdGEpIHtcbiAgICAgICAgLy8gQSB0ZW1wbGF0ZSBtaWdodCB1c2UgbW9yZSB0aGFuIG9uZSBwYXR0ZXJuXG4gICAgICAgIGlmIChpdGVtLmluY2x1ZGVzKCcsJykpIHtcbiAgICAgICAgICBpdGVtID0gaXRlbS5zdWJzdHIoMSkuc2xpY2UoMCwgLTEpO1xuICAgICAgICAgIGNvbnN0IHN1Ykl0ZW1zID0gaXRlbS5zcGxpdCgnLCcpO1xuICAgICAgICAgIGZvciAoY29uc3Qgc3ViaXRlbSBvZiBzdWJJdGVtcykge1xuICAgICAgICAgICAgdG1wYXJyYXkucHVzaChgWyR7c3ViaXRlbS50cmltKCl9XWApO1xuICAgICAgICAgIH1cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB0bXBhcnJheS5wdXNoKGl0ZW0pO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIC8vIEVuc3VyZSB3ZSBhcmUgaGFuZGxpbmcganVzdCBwYXR0ZXJuc1xuICAgICAgY29uc3QgYXJyYXkgPSB0bXBhcnJheS5maWx0ZXIoXG4gICAgICAgIGl0ZW0gPT4gaXRlbS5pbmNsdWRlcygnWycpICYmIGl0ZW0uaW5jbHVkZXMoJ10nKVxuICAgICAgKTtcblxuICAgICAgY29uc3QgcGF0dGVybiA9XG4gICAgICAgIGxhc3RDaGFyID09PSAnKicgPyByZXF1ZXN0LnBhcmFtcy5wYXR0ZXJuLnNsaWNlKDAsIC0xKSA6IHJlcXVlc3QucGFyYW1zLnBhdHRlcm47XG4gICAgICBjb25zdCBpc0luY2x1ZGVkID0gYXJyYXkuZmlsdGVyKGl0ZW0gPT4ge1xuICAgICAgICBpdGVtID0gaXRlbS5zbGljZSgxLCAtMSk7XG4gICAgICAgIGNvbnN0IGxhc3RDaGFyID0gaXRlbVtpdGVtLmxlbmd0aCAtIDFdO1xuICAgICAgICBpdGVtID0gbGFzdENoYXIgPT09ICcqJyA/IGl0ZW0uc2xpY2UoMCwgLTEpIDogaXRlbTtcbiAgICAgICAgcmV0dXJuIGl0ZW0uaW5jbHVkZXMocGF0dGVybikgfHwgcGF0dGVybi5pbmNsdWRlcyhpdGVtKTtcbiAgICAgIH0pO1xuICAgICAgbG9nKFxuICAgICAgICAnd2F6dWgtZWxhc3RpYzpnZXRUZW1wbGF0ZScsXG4gICAgICAgIGBUZW1wbGF0ZSBpcyB2YWxpZDogJHtpc0luY2x1ZGVkICYmIEFycmF5LmlzQXJyYXkoaXNJbmNsdWRlZCkgJiYgaXNJbmNsdWRlZC5sZW5ndGhcbiAgICAgICAgICA/ICd5ZXMnXG4gICAgICAgICAgOiAnbm8nXG4gICAgICAgIH1gLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgcmV0dXJuIGlzSW5jbHVkZWQgJiYgQXJyYXkuaXNBcnJheShpc0luY2x1ZGVkKSAmJiBpc0luY2x1ZGVkLmxlbmd0aFxuICAgICAgICA/IHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiAyMDAsXG4gICAgICAgICAgICBzdGF0dXM6IHRydWUsXG4gICAgICAgICAgICBkYXRhOiBgVGVtcGxhdGUgZm91bmQgZm9yICR7cmVxdWVzdC5wYXJhbXMucGF0dGVybn1gXG4gICAgICAgICAgfVxuICAgICAgICB9KVxuICAgICAgICA6IHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiAyMDAsXG4gICAgICAgICAgICBzdGF0dXM6IGZhbHNlLFxuICAgICAgICAgICAgZGF0YTogYE5vIHRlbXBsYXRlIGZvdW5kIGZvciAke3JlcXVlc3QucGFyYW1zLnBhdHRlcm59YFxuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpnZXRUZW1wbGF0ZScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoXG4gICAgICAgIGBDb3VsZCBub3QgcmV0cmlldmUgdGVtcGxhdGVzIGZyb20gRWxhc3RpY3NlYXJjaCBkdWUgdG8gJHtlcnJvci5tZXNzYWdlIHx8XG4gICAgICAgIGVycm9yfWAsXG4gICAgICAgIDQwMDIsXG4gICAgICAgIDUwMCxcbiAgICAgICAgcmVzcG9uc2VcbiAgICAgICk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgY2hlY2sgaW5kZXgtcGF0dGVyblxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gc3RhdHVzIG9iaiBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjaGVja1BhdHRlcm4oY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0PHsgcGF0dGVybjogc3RyaW5nIH0+LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IGRhdGEgPSBhd2FpdCBjb250ZXh0LmNvcmUuc2F2ZWRPYmplY3RzLmNsaWVudC5maW5kPFNhdmVkT2JqZWN0c0ZpbmRSZXNwb25zZTxTYXZlZE9iamVjdD4+KHsgdHlwZTogJ2luZGV4LXBhdHRlcm4nIH0pO1xuXG4gICAgICBjb25zdCBleGlzdHNJbmRleFBhdHRlcm4gPSBkYXRhLnNhdmVkX29iamVjdHMuZmluZChcbiAgICAgICAgaXRlbSA9PiBpdGVtLmF0dHJpYnV0ZXMudGl0bGUgPT09IHJlcXVlc3QucGFyYW1zLnBhdHRlcm5cbiAgICAgICk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmNoZWNrUGF0dGVybicsXG4gICAgICAgIGBJbmRleCBwYXR0ZXJuIGZvdW5kOiAke2V4aXN0c0luZGV4UGF0dGVybiA/IGV4aXN0c0luZGV4UGF0dGVybi5hdHRyaWJ1dGVzLnRpdGxlIDogJ25vJ31gLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgcmV0dXJuIGV4aXN0c0luZGV4UGF0dGVyblxuICAgICAgICA/IHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7IHN0YXR1c0NvZGU6IDIwMCwgc3RhdHVzOiB0cnVlLCBkYXRhOiAnSW5kZXggcGF0dGVybiBmb3VuZCcgfVxuICAgICAgICB9KVxuICAgICAgICA6IHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiA1MDAsXG4gICAgICAgICAgICBzdGF0dXM6IGZhbHNlLFxuICAgICAgICAgICAgZXJyb3I6IDEwMDIwLFxuICAgICAgICAgICAgbWVzc2FnZTogJ0luZGV4IHBhdHRlcm4gbm90IGZvdW5kJ1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpjaGVja1BhdHRlcm4nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKFxuICAgICAgICBgU29tZXRoaW5nIHdlbnQgd3JvbmcgcmV0cmlldmluZyBpbmRleC1wYXR0ZXJucyBmcm9tIEVsYXN0aWNzZWFyY2ggZHVlIHRvICR7ZXJyb3IubWVzc2FnZSB8fFxuICAgICAgICBlcnJvcn1gLFxuICAgICAgICA0MDAzLFxuICAgICAgICA1MDAsXG4gICAgICAgIHJlc3BvbnNlXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIGdldCB0aGUgZmllbGRzIGtleXNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtBcnJheTxPYmplY3Q+fSBmaWVsZHMgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZ2V0RmllbGRUb3AoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0PHsgbW9kZTogc3RyaW5nLCBjbHVzdGVyOiBzdHJpbmcsIGZpZWxkOiBzdHJpbmcsIHBhdHRlcm46IHN0cmluZyB9LCB7IGFnZW50c0xpc3Q6IHN0cmluZyB9PiwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICAvLyBUb3AgZmllbGQgcGF5bG9hZFxuICAgICAgbGV0IHBheWxvYWQgPSB7XG4gICAgICAgIHNpemU6IDEsXG4gICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgYm9vbDoge1xuICAgICAgICAgICAgbXVzdDogW10sXG4gICAgICAgICAgICBtdXN0X25vdDoge1xuICAgICAgICAgICAgICB0ZXJtOiB7XG4gICAgICAgICAgICAgICAgJ2FnZW50LmlkJzogJzAwMCdcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgcmFuZ2U6IHsgdGltZXN0YW1wOiB7fSB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIF1cbiAgICAgICAgICB9XG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IHtcbiAgICAgICAgICAnMic6IHtcbiAgICAgICAgICAgIHRlcm1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnJyxcbiAgICAgICAgICAgICAgc2l6ZTogMSxcbiAgICAgICAgICAgICAgb3JkZXI6IHsgX2NvdW50OiAnZGVzYycgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfTtcblxuICAgICAgLy8gU2V0IHVwIHRpbWUgaW50ZXJ2YWwsIGRlZmF1bHQgdG8gTGFzdCAyNGhcbiAgICAgIGNvbnN0IHRpbWVHVEUgPSAnbm93LTFkJztcbiAgICAgIGNvbnN0IHRpbWVMVCA9ICdub3cnO1xuICAgICAgcGF5bG9hZC5xdWVyeS5ib29sLmZpbHRlclswXS5yYW5nZVsndGltZXN0YW1wJ11bJ2d0ZSddID0gdGltZUdURTtcbiAgICAgIHBheWxvYWQucXVlcnkuYm9vbC5maWx0ZXJbMF0ucmFuZ2VbJ3RpbWVzdGFtcCddWydsdCddID0gdGltZUxUO1xuXG4gICAgICAvLyBTZXQgdXAgbWF0Y2ggZm9yIGRlZmF1bHQgY2x1c3RlciBuYW1lXG4gICAgICBwYXlsb2FkLnF1ZXJ5LmJvb2wubXVzdC5wdXNoKFxuICAgICAgICByZXF1ZXN0LnBhcmFtcy5tb2RlID09PSAnY2x1c3RlcidcbiAgICAgICAgICA/IHsgbWF0Y2g6IHsgJ2NsdXN0ZXIubmFtZSc6IHJlcXVlc3QucGFyYW1zLmNsdXN0ZXIgfSB9XG4gICAgICAgICAgOiB7IG1hdGNoOiB7ICdtYW5hZ2VyLm5hbWUnOiByZXF1ZXN0LnBhcmFtcy5jbHVzdGVyIH0gfVxuICAgICAgKTtcblxuICAgICAgaWYocmVxdWVzdC5xdWVyeS5hZ2VudHNMaXN0KVxuICAgICAgICBwYXlsb2FkLnF1ZXJ5LmJvb2wuZmlsdGVyLnB1c2goXG4gICAgICAgICAge1xuICAgICAgICAgICAgdGVybXM6IHtcbiAgICAgICAgICAgICAgJ2FnZW50LmlkJzogcmVxdWVzdC5xdWVyeS5hZ2VudHNMaXN0LnNwbGl0KCcsJylcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICAgICk7XG4gICAgICBwYXlsb2FkLmFnZ3NbJzInXS50ZXJtcy5maWVsZCA9IHJlcXVlc3QucGFyYW1zLmZpZWxkO1xuXG4gICAgICBjb25zdCBkYXRhID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuc2VhcmNoKHtcbiAgICAgICAgc2l6ZTogMSxcbiAgICAgICAgaW5kZXg6IHJlcXVlc3QucGFyYW1zLnBhdHRlcm4sXG4gICAgICAgIGJvZHk6IHBheWxvYWRcbiAgICAgIH0pO1xuXG4gICAgICByZXR1cm4gZGF0YS5ib2R5LmhpdHMudG90YWwudmFsdWUgPT09IDAgfHxcbiAgICAgICAgdHlwZW9mIGRhdGEuYm9keS5hZ2dyZWdhdGlvbnNbJzInXS5idWNrZXRzWzBdID09PSAndW5kZWZpbmVkJ1xuICAgICAgICA/IHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7IHN0YXR1c0NvZGU6IDIwMCwgZGF0YTogJycgfVxuICAgICAgICB9KVxuICAgICAgICA6IHJlc3BvbnNlLm9rKHtcbiAgICAgICAgICBib2R5OiB7XG4gICAgICAgICAgICBzdGF0dXNDb2RlOiAyMDAsXG4gICAgICAgICAgICBkYXRhOiBkYXRhLmJvZHkuYWdncmVnYXRpb25zWycyJ10uYnVja2V0c1swXS5rZXlcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6Z2V0RmllbGRUb3AnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDQwMDQsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBDaGVja3Mgb25lIGJ5IG9uZSBpZiB0aGUgcmVxdWVzdGluZyB1c2VyIGhhcyBlbm91Z2ggcHJpdmlsZWdlcyB0byB1c2VcbiAgICogYW4gaW5kZXggcGF0dGVybiBmcm9tIHRoZSBsaXN0LlxuICAgKiBAcGFyYW0ge0FycmF5PE9iamVjdD59IGxpc3QgTGlzdCBvZiBpbmRleCBwYXR0ZXJuc1xuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxXG4gICAqIEByZXR1cm5zIHtBcnJheTxPYmplY3Q+fSBMaXN0IG9mIGFsbG93ZWQgaW5kZXhcbiAgICovXG4gIGFzeW5jIGZpbHRlckFsbG93ZWRJbmRleFBhdHRlcm5MaXN0KGNvbnRleHQsIGxpc3QsIHJlcSkge1xuICAgIC8vVE9ETzogcmV2aWV3IGlmIG5lY2VzYXJ5IHRvIGRlbGV0ZVxuICAgIGxldCBmaW5hbExpc3QgPSBbXTtcbiAgICBmb3IgKGxldCBpdGVtIG9mIGxpc3QpIHtcbiAgICAgIGxldCByZXN1bHRzID0gZmFsc2UsXG4gICAgICAgIGZvcmJpZGRlbiA9IGZhbHNlO1xuICAgICAgdHJ5IHtcbiAgICAgICAgcmVzdWx0cyA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnNlYXJjaCh7XG4gICAgICAgICAgaW5kZXg6IGl0ZW0udGl0bGVcbiAgICAgICAgfSk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBmb3JiaWRkZW4gPSB0cnVlO1xuICAgICAgfVxuICAgICAgaWYgKFxuICAgICAgICAoKChyZXN1bHRzIHx8IHt9KS5ib2R5IHx8IHt9KS5oaXRzIHx8IHt9KS50b3RhbC52YWx1ZSA+PSAxIHx8XG4gICAgICAgICghZm9yYmlkZGVuICYmICgoKHJlc3VsdHMgfHwge30pLmJvZHkgfHwge30pLmhpdHMgfHwge30pLnRvdGFsID09PSAwKVxuICAgICAgKSB7XG4gICAgICAgIGZpbmFsTGlzdC5wdXNoKGl0ZW0pO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gZmluYWxMaXN0O1xuICB9XG5cbiAgLyoqXG4gICAqIENoZWNrcyBmb3IgbWluaW11bSBpbmRleCBwYXR0ZXJuIGZpZWxkcyBpbiBhIGxpc3Qgb2YgaW5kZXggcGF0dGVybnMuXG4gICAqIEBwYXJhbSB7QXJyYXk8T2JqZWN0Pn0gaW5kZXhQYXR0ZXJuTGlzdCBMaXN0IG9mIGluZGV4IHBhdHRlcm5zXG4gICAqL1xuICB2YWxpZGF0ZUluZGV4UGF0dGVybihpbmRleFBhdHRlcm5MaXN0KSB7XG4gICAgY29uc3QgbWluaW11bSA9IFsndGltZXN0YW1wJywgJ3J1bGUuZ3JvdXBzJywgJ21hbmFnZXIubmFtZScsICdhZ2VudC5pZCddO1xuICAgIGxldCBsaXN0ID0gW107XG4gICAgZm9yIChjb25zdCBpbmRleCBvZiBpbmRleFBhdHRlcm5MaXN0KSB7XG4gICAgICBsZXQgdmFsaWQsIHBhcnNlZDtcbiAgICAgIHRyeSB7XG4gICAgICAgIHBhcnNlZCA9IEpTT04ucGFyc2UoaW5kZXguYXR0cmlidXRlcy5maWVsZHMpO1xuICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgY29udGludWU7XG4gICAgICB9XG5cbiAgICAgIHZhbGlkID0gcGFyc2VkLmZpbHRlcihpdGVtID0+IG1pbmltdW0uaW5jbHVkZXMoaXRlbS5uYW1lKSk7XG4gICAgICBpZiAodmFsaWQubGVuZ3RoID09PSA0KSB7XG4gICAgICAgIGxpc3QucHVzaCh7XG4gICAgICAgICAgaWQ6IGluZGV4LmlkLFxuICAgICAgICAgIHRpdGxlOiBpbmRleC5hdHRyaWJ1dGVzLnRpdGxlXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gbGlzdDtcbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIGN1cnJlbnQgc2VjdXJpdHkgcGxhdGZvcm1cbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcVxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVwbHlcbiAgICogQHJldHVybnMge1N0cmluZ31cbiAgICovXG4gIGFzeW5jIGdldEN1cnJlbnRQbGF0Zm9ybShjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3Q8eyB1c2VyOiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIHBsYXRmb3JtOiBjb250ZXh0LndhenVoLnNlY3VyaXR5LnBsYXRmb3JtXG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6Z2V0Q3VycmVudFBsYXRmb3JtJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA0MDExLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogUmVwbGFjZXMgdmlzdWFsaXphdGlvbnMgbWFpbiBmaWVsZHMgdG8gZml0IGEgY2VydGFpbiBwYXR0ZXJuLlxuICAgKiBAcGFyYW0ge0FycmF5PE9iamVjdD59IGFwcF9vYmplY3RzIE9iamVjdCBjb250YWluaW5nIHJhdyB2aXN1YWxpemF0aW9ucy5cbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkIEluZGV4LXBhdHRlcm4gaWQgdG8gdXNlIGluIHRoZSB2aXN1YWxpemF0aW9ucy4gRWc6ICd3YXp1aC1hbGVydHMnXG4gICAqL1xuICBhc3luYyBidWlsZFZpc3VhbGl6YXRpb25zUmF3KGFwcF9vYmplY3RzLCBpZCwgbmFtZXNwYWNlID0gZmFsc2UpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29uZmlnID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuICAgICAgbGV0IG1vbml0b3JpbmdQYXR0ZXJuID1cbiAgICAgICAgKGNvbmZpZyB8fCB7fSlbJ3dhenVoLm1vbml0b3JpbmcucGF0dGVybiddIHx8IGdldFNldHRpbmdEZWZhdWx0VmFsdWUoJ3dhenVoLm1vbml0b3JpbmcucGF0dGVybicpO1xuICAgICAgbG9nKFxuICAgICAgICAnd2F6dWgtZWxhc3RpYzpidWlsZFZpc3VhbGl6YXRpb25zUmF3JyxcbiAgICAgICAgYEJ1aWxkaW5nICR7YXBwX29iamVjdHMubGVuZ3RofSB2aXN1YWxpemF0aW9uc2AsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmJ1aWxkVmlzdWFsaXphdGlvbnNSYXcnLFxuICAgICAgICBgSW5kZXggcGF0dGVybiBJRDogJHtpZH1gLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgY29uc3QgdmlzQXJyYXkgPSBbXTtcbiAgICAgIGxldCBhdXhfc291cmNlLCBidWxrX2NvbnRlbnQ7XG4gICAgICBmb3IgKGxldCBlbGVtZW50IG9mIGFwcF9vYmplY3RzKSB7XG4gICAgICAgIGF1eF9zb3VyY2UgPSBKU09OLnBhcnNlKEpTT04uc3RyaW5naWZ5KGVsZW1lbnQuX3NvdXJjZSkpO1xuXG4gICAgICAgIC8vIFJlcGxhY2UgaW5kZXgtcGF0dGVybiBmb3IgdmlzdWFsaXphdGlvbnNcbiAgICAgICAgaWYgKFxuICAgICAgICAgIGF1eF9zb3VyY2UgJiZcbiAgICAgICAgICBhdXhfc291cmNlLmtpYmFuYVNhdmVkT2JqZWN0TWV0YSAmJlxuICAgICAgICAgIGF1eF9zb3VyY2Uua2liYW5hU2F2ZWRPYmplY3RNZXRhLnNlYXJjaFNvdXJjZUpTT04gJiZcbiAgICAgICAgICB0eXBlb2YgYXV4X3NvdXJjZS5raWJhbmFTYXZlZE9iamVjdE1ldGEuc2VhcmNoU291cmNlSlNPTiA9PT0gJ3N0cmluZydcbiAgICAgICAgKSB7XG4gICAgICAgICAgY29uc3QgZGVmYXVsdFN0ciA9IGF1eF9zb3VyY2Uua2liYW5hU2F2ZWRPYmplY3RNZXRhLnNlYXJjaFNvdXJjZUpTT047XG5cbiAgICAgICAgICBjb25zdCBpc01vbml0b3JpbmcgPSBkZWZhdWx0U3RyLmluY2x1ZGVzKCd3YXp1aC1tb25pdG9yaW5nJyk7XG4gICAgICAgICAgaWYgKGlzTW9uaXRvcmluZykge1xuICAgICAgICAgICAgaWYgKG5hbWVzcGFjZSAmJiBuYW1lc3BhY2UgIT09ICdkZWZhdWx0Jykge1xuICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgbW9uaXRvcmluZ1BhdHRlcm4uaW5jbHVkZXMobmFtZXNwYWNlKSAmJlxuICAgICAgICAgICAgICAgIG1vbml0b3JpbmdQYXR0ZXJuLmluY2x1ZGVzKCdpbmRleC1wYXR0ZXJuOicpXG4gICAgICAgICAgICAgICkge1xuICAgICAgICAgICAgICAgIG1vbml0b3JpbmdQYXR0ZXJuID0gbW9uaXRvcmluZ1BhdHRlcm4uc3BsaXQoXG4gICAgICAgICAgICAgICAgICAnaW5kZXgtcGF0dGVybjonXG4gICAgICAgICAgICAgICAgKVsxXTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgICAgYXV4X3NvdXJjZS5raWJhbmFTYXZlZE9iamVjdE1ldGEuc2VhcmNoU291cmNlSlNPTiA9IGRlZmF1bHRTdHIucmVwbGFjZShcbiAgICAgICAgICAgICAgL3dhenVoLW1vbml0b3JpbmcvZyxcbiAgICAgICAgICAgICAgbW9uaXRvcmluZ1BhdHRlcm5bbW9uaXRvcmluZ1BhdHRlcm4ubGVuZ3RoIC0gMV0gPT09ICcqJyB8fFxuICAgICAgICAgICAgICAgIChuYW1lc3BhY2UgJiYgbmFtZXNwYWNlICE9PSAnZGVmYXVsdCcpXG4gICAgICAgICAgICAgICAgPyBtb25pdG9yaW5nUGF0dGVyblxuICAgICAgICAgICAgICAgIDogbW9uaXRvcmluZ1BhdHRlcm4gKyAnKidcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGF1eF9zb3VyY2Uua2liYW5hU2F2ZWRPYmplY3RNZXRhLnNlYXJjaFNvdXJjZUpTT04gPSBkZWZhdWx0U3RyLnJlcGxhY2UoXG4gICAgICAgICAgICAgIC93YXp1aC1hbGVydHMvZyxcbiAgICAgICAgICAgICAgaWRcbiAgICAgICAgICAgICk7XG4gICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgLy8gUmVwbGFjZSBpbmRleC1wYXR0ZXJuIGZvciBzZWxlY3RvciB2aXN1YWxpemF0aW9uc1xuICAgICAgICBpZiAodHlwZW9mIChhdXhfc291cmNlIHx8IHt9KS52aXNTdGF0ZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgICAgICBhdXhfc291cmNlLnZpc1N0YXRlID0gYXV4X3NvdXJjZS52aXNTdGF0ZS5yZXBsYWNlKFxuICAgICAgICAgICAgL3dhenVoLWFsZXJ0cy9nLFxuICAgICAgICAgICAgaWRcbiAgICAgICAgICApO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQnVsayBzb3VyY2VcbiAgICAgICAgYnVsa19jb250ZW50ID0ge307XG4gICAgICAgIGJ1bGtfY29udGVudFtlbGVtZW50Ll90eXBlXSA9IGF1eF9zb3VyY2U7XG5cbiAgICAgICAgdmlzQXJyYXkucHVzaCh7XG4gICAgICAgICAgYXR0cmlidXRlczogYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24sXG4gICAgICAgICAgdHlwZTogZWxlbWVudC5fdHlwZSxcbiAgICAgICAgICBpZDogZWxlbWVudC5faWQsXG4gICAgICAgICAgX3ZlcnNpb246IGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLnZlcnNpb25cbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gdmlzQXJyYXk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygnd2F6dWgtZWxhc3RpYzpidWlsZFZpc3VhbGl6YXRpb25zUmF3JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXBsYWNlcyBjbHVzdGVyIHZpc3VhbGl6YXRpb25zIG1haW4gZmllbGRzLlxuICAgKiBAcGFyYW0ge0FycmF5PE9iamVjdD59IGFwcF9vYmplY3RzIE9iamVjdCBjb250YWluaW5nIHJhdyB2aXN1YWxpemF0aW9ucy5cbiAgICogQHBhcmFtIHtTdHJpbmd9IGlkIEluZGV4LXBhdHRlcm4gaWQgdG8gdXNlIGluIHRoZSB2aXN1YWxpemF0aW9ucy4gRWc6ICd3YXp1aC1hbGVydHMnXG4gICAqIEBwYXJhbSB7QXJyYXk8U3RyaW5nPn0gbm9kZXMgQXJyYXkgb2Ygbm9kZSBuYW1lcy4gRWc6IFsnbm9kZTAxJywgJ25vZGUwMiddXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBuYW1lIENsdXN0ZXIgbmFtZS4gRWc6ICd3YXp1aCdcbiAgICogQHBhcmFtIHtTdHJpbmd9IG1hc3Rlcl9ub2RlIE1hc3RlciBub2RlIG5hbWUuIEVnOiAnbm9kZTAxJ1xuICAgKi9cbiAgYnVpbGRDbHVzdGVyVmlzdWFsaXphdGlvbnNSYXcoXG4gICAgYXBwX29iamVjdHMsXG4gICAgaWQsXG4gICAgbm9kZXMgPSBbXSxcbiAgICBuYW1lLFxuICAgIG1hc3Rlcl9ub2RlLFxuICAgIHBhdHRlcm5fbmFtZSA9ICcqJ1xuICApIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgdmlzQXJyYXkgPSBbXTtcbiAgICAgIGxldCBhdXhfc291cmNlLCBidWxrX2NvbnRlbnQ7XG5cbiAgICAgIGZvciAoY29uc3QgZWxlbWVudCBvZiBhcHBfb2JqZWN0cykge1xuICAgICAgICAvLyBTdHJpbmdpZnkgYW5kIHJlcGxhY2UgaW5kZXgtcGF0dGVybiBmb3IgdmlzdWFsaXphdGlvbnNcbiAgICAgICAgYXV4X3NvdXJjZSA9IEpTT04uc3RyaW5naWZ5KGVsZW1lbnQuX3NvdXJjZSk7XG4gICAgICAgIGF1eF9zb3VyY2UgPSBhdXhfc291cmNlLnJlcGxhY2UoL3dhenVoLWFsZXJ0cy9nLCBpZCk7XG4gICAgICAgIGF1eF9zb3VyY2UgPSBKU09OLnBhcnNlKGF1eF9zb3VyY2UpO1xuXG4gICAgICAgIC8vIEJ1bGsgc291cmNlXG4gICAgICAgIGJ1bGtfY29udGVudCA9IHt9O1xuICAgICAgICBidWxrX2NvbnRlbnRbZWxlbWVudC5fdHlwZV0gPSBhdXhfc291cmNlO1xuXG4gICAgICAgIGNvbnN0IHZpc1N0YXRlID0gSlNPTi5wYXJzZShidWxrX2NvbnRlbnQudmlzdWFsaXphdGlvbi52aXNTdGF0ZSk7XG4gICAgICAgIGNvbnN0IHRpdGxlID0gdmlzU3RhdGUudGl0bGU7XG5cbiAgICAgICAgaWYgKHZpc1N0YXRlLnR5cGUgJiYgdmlzU3RhdGUudHlwZSA9PT0gJ3RpbWVsaW9uJykge1xuICAgICAgICAgIGxldCBxdWVyeSA9ICcnO1xuICAgICAgICAgIGlmICh0aXRsZSA9PT0gJ1dhenVoIEFwcCBDbHVzdGVyIE92ZXJ2aWV3Jykge1xuICAgICAgICAgICAgZm9yIChjb25zdCBub2RlIG9mIG5vZGVzKSB7XG4gICAgICAgICAgICAgIHF1ZXJ5ICs9IGAuZXMoaW5kZXg9JHtwYXR0ZXJuX25hbWV9LHE9XCJjbHVzdGVyLm5hbWU6ICR7bmFtZX0gQU5EIGNsdXN0ZXIubm9kZTogJHtub2RlLm5hbWV9XCIpLmxhYmVsKFwiJHtub2RlLm5hbWV9XCIpLGA7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBxdWVyeSA9IHF1ZXJ5LnN1YnN0cmluZygwLCBxdWVyeS5sZW5ndGggLSAxKTtcbiAgICAgICAgICB9IGVsc2UgaWYgKHRpdGxlID09PSAnV2F6dWggQXBwIENsdXN0ZXIgT3ZlcnZpZXcgTWFuYWdlcicpIHtcbiAgICAgICAgICAgIHF1ZXJ5ICs9IGAuZXMoaW5kZXg9JHtwYXR0ZXJuX25hbWV9LHE9XCJjbHVzdGVyLm5hbWU6ICR7bmFtZX1cIikubGFiZWwoXCIke25hbWV9IGNsdXN0ZXJcIilgO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBpZiAodGl0bGUuc3RhcnRzV2l0aCgnV2F6dWggQXBwIFN0YXRpc3RpY3MnKSkge1xuICAgICAgICAgICAgICBjb25zdCB7IHNlYXJjaFNvdXJjZUpTT04gfSA9IGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLmtpYmFuYVNhdmVkT2JqZWN0TWV0YTtcbiAgICAgICAgICAgICAgYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24ua2liYW5hU2F2ZWRPYmplY3RNZXRhLnNlYXJjaFNvdXJjZUpTT04gPSBzZWFyY2hTb3VyY2VKU09OLnJlcGxhY2UoJ3dhenVoLXN0YXRpc3RpY3MtKicsIHBhdHRlcm5fbmFtZSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBpZiAodGl0bGUuc3RhcnRzV2l0aCgnV2F6dWggQXBwIFN0YXRpc3RpY3MnKSAmJiBuYW1lICE9PSAnLScgJiYgbmFtZSAhPT0gJ2FsbCcgJiYgdmlzU3RhdGUucGFyYW1zLmV4cHJlc3Npb24uaW5jbHVkZXMoJ3E9JykpIHtcbiAgICAgICAgICAgICAgY29uc3QgZXhwcmVzc2lvblJlZ2V4ID0gL3E9J1xcKicvZ2k7XG4gICAgICAgICAgICAgIGNvbnN0IF92aXNTdGF0ZSA9IGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLnZpc1N0YXRlQnlOb2RlXG4gICAgICAgICAgICAgICAgPyBKU09OLnBhcnNlKGJ1bGtfY29udGVudC52aXN1YWxpemF0aW9uLnZpc1N0YXRlQnlOb2RlKVxuICAgICAgICAgICAgICAgIDogdmlzU3RhdGU7XG4gICAgICAgICAgICAgIHF1ZXJ5ICs9IF92aXNTdGF0ZS5wYXJhbXMuZXhwcmVzc2lvbi5yZXBsYWNlKC93YXp1aC1zdGF0aXN0aWNzLVxcKi9nLCBwYXR0ZXJuX25hbWUpLnJlcGxhY2UoZXhwcmVzc2lvblJlZ2V4LCBgcT1cIm5vZGVOYW1lLmtleXdvcmQ6JHtuYW1lfSBBTkQgYXBpTmFtZS5rZXl3b3JkOiR7bWFzdGVyX25vZGV9XCJgKVxuICAgICAgICAgICAgICAgIC5yZXBsYWNlKFwiTk9ERV9OQU1FXCIsIG5hbWUpXG4gICAgICAgICAgICB9IGVsc2UgaWYgKHRpdGxlLnN0YXJ0c1dpdGgoJ1dhenVoIEFwcCBTdGF0aXN0aWNzJykpIHtcbiAgICAgICAgICAgICAgY29uc3QgZXhwcmVzc2lvblJlZ2V4ID0gL3E9J1xcKicvZ2lcbiAgICAgICAgICAgICAgcXVlcnkgKz0gdmlzU3RhdGUucGFyYW1zLmV4cHJlc3Npb24ucmVwbGFjZSgvd2F6dWgtc3RhdGlzdGljcy1cXCovZywgcGF0dGVybl9uYW1lKS5yZXBsYWNlKGV4cHJlc3Npb25SZWdleCwgYHE9XCJhcGlOYW1lLmtleXdvcmQ6JHttYXN0ZXJfbm9kZX1cImApXG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBxdWVyeSA9IHZpc1N0YXRlLnBhcmFtcy5leHByZXNzaW9uO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH1cblxuICAgICAgICAgIHZpc1N0YXRlLnBhcmFtcy5leHByZXNzaW9uID0gcXVlcnkucmVwbGFjZSgvJy9nLCBcIlxcXCJcIik7XG4gICAgICAgICAgYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24udmlzU3RhdGUgPSBKU09OLnN0cmluZ2lmeSh2aXNTdGF0ZSk7XG4gICAgICAgIH1cblxuICAgICAgICB2aXNBcnJheS5wdXNoKHtcbiAgICAgICAgICBhdHRyaWJ1dGVzOiBidWxrX2NvbnRlbnQudmlzdWFsaXphdGlvbixcbiAgICAgICAgICB0eXBlOiBlbGVtZW50Ll90eXBlLFxuICAgICAgICAgIGlkOiBlbGVtZW50Ll9pZCxcbiAgICAgICAgICBfdmVyc2lvbjogYnVsa19jb250ZW50LnZpc3VhbGl6YXRpb24udmVyc2lvblxuICAgICAgICB9KTtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHZpc0FycmF5O1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmJ1aWxkQ2x1c3RlclZpc3VhbGl6YXRpb25zUmF3JyxcbiAgICAgICAgZXJyb3IubWVzc2FnZSB8fCBlcnJvclxuICAgICAgKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgY3JlYXRlcyBhIHZpc3VhbGl6YXRpb24gb2YgZGF0YSBpbiByZXFcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHtPYmplY3R9IHZpcyBvYmogb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgY3JlYXRlVmlzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdDx7IHBhdHRlcm46IHN0cmluZywgdGFiOiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKFxuICAgICAgICAoIXJlcXVlc3QucGFyYW1zLnRhYi5pbmNsdWRlcygnb3ZlcnZpZXctJykgJiZcbiAgICAgICAgICAhcmVxdWVzdC5wYXJhbXMudGFiLmluY2x1ZGVzKCdhZ2VudHMtJykpXG4gICAgICApIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdNaXNzaW5nIHBhcmFtZXRlcnMgY3JlYXRpbmcgdmlzdWFsaXphdGlvbnMnKTtcbiAgICAgIH1cblxuICAgICAgY29uc3QgdGFiUHJlZml4ID0gcmVxdWVzdC5wYXJhbXMudGFiLmluY2x1ZGVzKCdvdmVydmlldycpXG4gICAgICAgID8gJ292ZXJ2aWV3J1xuICAgICAgICA6ICdhZ2VudHMnO1xuXG4gICAgICBjb25zdCB0YWJTcGxpdCA9IHJlcXVlc3QucGFyYW1zLnRhYi5zcGxpdCgnLScpO1xuICAgICAgY29uc3QgdGFiU3VmaXggPSB0YWJTcGxpdFsxXTtcblxuICAgICAgY29uc3QgZmlsZSA9XG4gICAgICAgIHRhYlByZWZpeCA9PT0gJ292ZXJ2aWV3J1xuICAgICAgICAgID8gT3ZlcnZpZXdWaXN1YWxpemF0aW9uc1t0YWJTdWZpeF1cbiAgICAgICAgICA6IEFnZW50c1Zpc3VhbGl6YXRpb25zW3RhYlN1Zml4XTtcbiAgICAgIGlmICghZmlsZSkge1xuICAgICAgICByZXR1cm4gcmVzcG9uc2Uubm90Rm91bmQoe2JvZHk6e21lc3NhZ2U6IGBWaXN1YWxpemF0aW9ucyBub3QgZm91bmQgZm9yICR7cmVxdWVzdC5wYXJhbXMudGFifWB9fSk7XG4gICAgICB9XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6Y3JlYXRlVmlzJywgYCR7dGFiUHJlZml4fVske3RhYlN1Zml4fV0gd2l0aCBpbmRleCBwYXR0ZXJuICR7cmVxdWVzdC5wYXJhbXMucGF0dGVybn1gLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IG5hbWVzcGFjZSA9IGNvbnRleHQud2F6dWgucGx1Z2lucy5zcGFjZXMgJiYgY29udGV4dC53YXp1aC5wbHVnaW5zLnNwYWNlcy5zcGFjZXNTZXJ2aWNlICYmIGNvbnRleHQud2F6dWgucGx1Z2lucy5zcGFjZXMuc3BhY2VzU2VydmljZS5nZXRTcGFjZUlkKHJlcXVlc3QpO1xuICAgICAgY29uc3QgcmF3ID0gYXdhaXQgdGhpcy5idWlsZFZpc3VhbGl6YXRpb25zUmF3KFxuICAgICAgICBmaWxlLFxuICAgICAgICByZXF1ZXN0LnBhcmFtcy5wYXR0ZXJuLFxuICAgICAgICBuYW1lc3BhY2VcbiAgICAgICk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IGFja25vd2xlZGdlOiB0cnVlLCByYXc6IHJhdyB9XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmNyZWF0ZVZpcycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNDAwNywgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgY3JlYXRlcyBhIHZpc3VhbGl6YXRpb24gb2YgY2x1c3RlclxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gdmlzIG9iaiBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjcmVhdGVDbHVzdGVyVmlzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdDx7IHBhdHRlcm46IHN0cmluZywgdGFiOiBzdHJpbmcgfSwgdW5rbm93biwgYW55PiwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBpZiAoXG4gICAgICAgICFyZXF1ZXN0LnBhcmFtcy5wYXR0ZXJuIHx8XG4gICAgICAgICFyZXF1ZXN0LnBhcmFtcy50YWIgfHxcbiAgICAgICAgIXJlcXVlc3QuYm9keSB8fFxuICAgICAgICAhcmVxdWVzdC5ib2R5Lm5vZGVzIHx8XG4gICAgICAgICFyZXF1ZXN0LmJvZHkubm9kZXMuYWZmZWN0ZWRfaXRlbXMgfHxcbiAgICAgICAgIXJlcXVlc3QuYm9keS5ub2Rlcy5uYW1lIHx8XG4gICAgICAgIChyZXF1ZXN0LnBhcmFtcy50YWIgJiYgIXJlcXVlc3QucGFyYW1zLnRhYi5pbmNsdWRlcygnY2x1c3Rlci0nKSlcbiAgICAgICkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ01pc3NpbmcgcGFyYW1ldGVycyBjcmVhdGluZyB2aXN1YWxpemF0aW9ucycpO1xuICAgICAgfVxuXG4gICAgICBjb25zdCB0eXBlID0gcmVxdWVzdC5wYXJhbXMudGFiLnNwbGl0KCctJylbMV07XG5cbiAgICAgIGNvbnN0IGZpbGUgPSBDbHVzdGVyVmlzdWFsaXphdGlvbnNbdHlwZV07XG4gICAgICBjb25zdCBub2RlcyA9IHJlcXVlc3QuYm9keS5ub2Rlcy5hZmZlY3RlZF9pdGVtcztcbiAgICAgIGNvbnN0IG5hbWUgPSByZXF1ZXN0LmJvZHkubm9kZXMubmFtZTtcbiAgICAgIGNvbnN0IG1hc3Rlck5vZGUgPSByZXF1ZXN0LmJvZHkubm9kZXMubWFzdGVyX25vZGU7XG5cbiAgICAgIGNvbnN0IHsgaWQ6IHBhdHRlcm5JRCwgdGl0bGU6IHBhdHRlcm5OYW1lIH0gPSByZXF1ZXN0LmJvZHkucGF0dGVybjtcblxuICAgICAgY29uc3QgcmF3ID0gYXdhaXQgdGhpcy5idWlsZENsdXN0ZXJWaXN1YWxpemF0aW9uc1JhdyhcbiAgICAgICAgZmlsZSxcbiAgICAgICAgcGF0dGVybklELFxuICAgICAgICBub2RlcyxcbiAgICAgICAgbmFtZSxcbiAgICAgICAgbWFzdGVyTm9kZSxcbiAgICAgICAgcGF0dGVybk5hbWVcbiAgICAgICk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgYWNrbm93bGVkZ2U6IHRydWUsIHJhdzogcmF3IH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6Y3JlYXRlQ2x1c3RlclZpcycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNDAwOSwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIFRoaXMgY2hlY2tzIGlmIHRoZXJlIGlzIHNhbXBsZSBhbGVydHNcbiAgICogR0VUIC9lbGFzdGljL3NhbXBsZWFsZXJ0c1xuICAgKiBAcGFyYW0geyp9IGNvbnRleHRcbiAgICogQHBhcmFtIHsqfSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7Kn0gcmVzcG9uc2VcbiAgICoge2FsZXJ0czogWy4uLl19IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGhhdmVTYW1wbGVBbGVydHMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LCByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5KSB7XG4gICAgdHJ5IHtcbiAgICAgIC8vIENoZWNrIGlmIHdhenVoIHNhbXBsZSBhbGVydHMgaW5kZXggZXhpc3RzXG4gICAgICBjb25zdCByZXN1bHRzID0gYXdhaXQgUHJvbWlzZS5hbGwoT2JqZWN0LmtleXMoV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SSUVTX1RZUEVfQUxFUlRTKVxuICAgICAgICAubWFwKChjYXRlZ29yeSkgPT4gY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuaW5kaWNlcy5leGlzdHMoe1xuICAgICAgICAgIGluZGV4OiB0aGlzLmJ1aWxkU2FtcGxlSW5kZXhCeUNhdGVnb3J5KGNhdGVnb3J5KVxuICAgICAgICB9KSkpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogeyBzYW1wbGVBbGVydHNJbnN0YWxsZWQ6IHJlc3VsdHMuc29tZShyZXN1bHQgPT4gcmVzdWx0LmJvZHkpIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnU2FtcGxlIEFsZXJ0cyBjYXRlZ29yeSBub3QgdmFsaWQnLCAxMDAwLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cbiAgLyoqXG4gICAqIFRoaXMgY3JlYXRlcyBzYW1wbGUgYWxlcnRzIGluIHdhenVoLXNhbXBsZS1hbGVydHNcbiAgICogR0VUIC9lbGFzdGljL3NhbXBsZWFsZXJ0cy97Y2F0ZWdvcnl9XG4gICAqIEBwYXJhbSB7Kn0gY29udGV4dFxuICAgKiBAcGFyYW0geyp9IHJlcXVlc3RcbiAgICogQHBhcmFtIHsqfSByZXNwb25zZVxuICAgKiB7YWxlcnRzOiBbLi4uXX0gb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgaGF2ZVNhbXBsZUFsZXJ0c09mQ2F0ZWdvcnkoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0PHsgY2F0ZWdvcnk6IHN0cmluZyB9PiwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBzYW1wbGVBbGVydHNJbmRleCA9IHRoaXMuYnVpbGRTYW1wbGVJbmRleEJ5Q2F0ZWdvcnkocmVxdWVzdC5wYXJhbXMuY2F0ZWdvcnkpO1xuICAgICAgLy8gQ2hlY2sgaWYgd2F6dWggc2FtcGxlIGFsZXJ0cyBpbmRleCBleGlzdHNcbiAgICAgIGNvbnN0IGV4aXN0c1NhbXBsZUluZGV4ID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuaW5kaWNlcy5leGlzdHMoe1xuICAgICAgICBpbmRleDogc2FtcGxlQWxlcnRzSW5kZXhcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogeyBpbmRleDogc2FtcGxlQWxlcnRzSW5kZXgsIGV4aXN0czogZXhpc3RzU2FtcGxlSW5kZXguYm9keSB9XG4gICAgICB9KVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmhhdmVTYW1wbGVBbGVydHNPZkNhdGVnb3J5JyxcbiAgICAgICAgYEVycm9yIGNoZWNraW5nIGlmIHRoZXJlIGFyZSBzYW1wbGUgYWxlcnRzIGluZGljZXM6ICR7ZXJyb3IubWVzc2FnZSB8fCBlcnJvcn1gXG4gICAgICApO1xuXG4gICAgICBjb25zdCBbc3RhdHVzQ29kZSwgZXJyb3JNZXNzYWdlXSA9IHRoaXMuZ2V0RXJyb3JEZXRhaWxzKGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGBFcnJvciBjaGVja2luZyBpZiB0aGVyZSBhcmUgc2FtcGxlIGFsZXJ0cyBpbmRpY2VzOiAke2Vycm9yTWVzc2FnZSB8fCBlcnJvcn1gLCAxMDAwLCBzdGF0dXNDb2RlLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG4gIC8qKlxuICAgKiBUaGlzIGNyZWF0ZXMgc2FtcGxlIGFsZXJ0cyBpbiB3YXp1aC1zYW1wbGUtYWxlcnRzXG4gICAqIFBPU1QgL2VsYXN0aWMvc2FtcGxlYWxlcnRzL3tjYXRlZ29yeX1cbiAgICoge1xuICAgKiAgIFwibWFuYWdlclwiOiB7XG4gICAqICAgICAgXCJuYW1lXCI6IFwibWFuYWdlcl9uYW1lXCJcbiAgICogICAgfSxcbiAgICogICAgY2x1c3Rlcjoge1xuICAgKiAgICAgIG5hbWU6IFwibXljbHVzdGVyXCIsXG4gICAqICAgICAgbm9kZTogXCJteW5vZGVcIlxuICAgKiAgICB9XG4gICAqIH1cbiAgICogQHBhcmFtIHsqfSBjb250ZXh0XG4gICAqIEBwYXJhbSB7Kn0gcmVxdWVzdFxuICAgKiBAcGFyYW0geyp9IHJlc3BvbnNlXG4gICAqIHtpbmRleDogc3RyaW5nLCBhbGVydHM6IFsuLi5dLCBjb3VudDogbnVtYmVyfSBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBhc3luYyBjcmVhdGVTYW1wbGVBbGVydHMoY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LCByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0PHsgY2F0ZWdvcnk6IHN0cmluZyB9PiwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIGNvbnN0IHNhbXBsZUFsZXJ0c0luZGV4ID0gdGhpcy5idWlsZFNhbXBsZUluZGV4QnlDYXRlZ29yeShyZXF1ZXN0LnBhcmFtcy5jYXRlZ29yeSk7XG5cbiAgICB0cnkge1xuICAgICAgLy8gQ2hlY2sgaWYgdXNlciBoYXMgYWRtaW5pc3RyYXRvciByb2xlIGluIHRva2VuXG4gICAgICBjb25zdCB0b2tlbiA9IGdldENvb2tpZVZhbHVlQnlOYW1lKHJlcXVlc3QuaGVhZGVycy5jb29raWUsICd3ei10b2tlbicpO1xuICAgICAgaWYgKCF0b2tlbikge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTm8gdG9rZW4gcHJvdmlkZWQnLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgfTtcbiAgICAgIGNvbnN0IGRlY29kZWRUb2tlbiA9IGp3dERlY29kZSh0b2tlbik7XG4gICAgICBpZiAoIWRlY29kZWRUb2tlbikge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTm8gcGVybWlzc2lvbnMgaW4gdG9rZW4nLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgfTtcbiAgICAgIGlmICghZGVjb2RlZFRva2VuLnJiYWNfcm9sZXMgfHwgIWRlY29kZWRUb2tlbi5yYmFjX3JvbGVzLmluY2x1ZGVzKFdBWlVIX1JPTEVfQURNSU5JU1RSQVRPUl9JRCkpIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIGFkbWluaXN0cmF0b3Igcm9sZScsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICB9O1xuICAgICAgLy8gQ2hlY2sgdGhlIHByb3ZpZGVkIHRva2VuIGlzIHZhbGlkXG4gICAgICBjb25zdCBhcGlIb3N0SUQgPSBnZXRDb29raWVWYWx1ZUJ5TmFtZShyZXF1ZXN0LmhlYWRlcnMuY29va2llLCAnd3otYXBpJyk7XG4gICAgICBpZiAoIWFwaUhvc3RJRCkge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZSgnTm8gQVBJIGlkIHByb3ZpZGVkJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgIH07XG4gICAgICBjb25zdCByZXNwb25zZVRva2VuSXNXb3JraW5nID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdCgnR0VUJywgYC8vYCwge30sIHsgYXBpSG9zdElEIH0pO1xuICAgICAgaWYgKHJlc3BvbnNlVG9rZW5Jc1dvcmtpbmcuc3RhdHVzICE9PSAyMDApIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ1Rva2VuIGlzIG5vdCB2YWxpZCcsIDUwMCwgNTAwLCByZXNwb25zZSk7XG4gICAgICB9O1xuXG4gICAgICBjb25zdCBidWxrUHJlZml4ID0gSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICBpbmRleDoge1xuICAgICAgICAgIF9pbmRleDogc2FtcGxlQWxlcnRzSW5kZXhcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgICBjb25zdCBhbGVydEdlbmVyYXRlUGFyYW1zID0gcmVxdWVzdC5ib2R5ICYmIHJlcXVlc3QuYm9keS5wYXJhbXMgfHwge307XG5cbiAgICAgIGNvbnN0IHNhbXBsZUFsZXJ0cyA9IFdBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUklFU19UWVBFX0FMRVJUU1tyZXF1ZXN0LnBhcmFtcy5jYXRlZ29yeV0ubWFwKCh0eXBlQWxlcnQpID0+IGdlbmVyYXRlQWxlcnRzKHsgLi4udHlwZUFsZXJ0LCAuLi5hbGVydEdlbmVyYXRlUGFyYW1zIH0sIHJlcXVlc3QuYm9keS5hbGVydHMgfHwgdHlwZUFsZXJ0LmFsZXJ0cyB8fCBXQVpVSF9TQU1QTEVfQUxFUlRTX0RFRkFVTFRfTlVNQkVSX0FMRVJUUykpLmZsYXQoKTtcbiAgICAgIGNvbnN0IGJ1bGsgPSBzYW1wbGVBbGVydHMubWFwKHNhbXBsZUFsZXJ0ID0+IGAke2J1bGtQcmVmaXh9XFxuJHtKU09OLnN0cmluZ2lmeShzYW1wbGVBbGVydCl9XFxuYCkuam9pbignJyk7XG5cbiAgICAgIC8vIEluZGV4IGFsZXJ0c1xuXG4gICAgICAvLyBDaGVjayBpZiB3YXp1aCBzYW1wbGUgYWxlcnRzIGluZGV4IGV4aXN0c1xuICAgICAgY29uc3QgZXhpc3RzU2FtcGxlSW5kZXggPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgIGluZGV4OiBzYW1wbGVBbGVydHNJbmRleFxuICAgICAgfSk7XG4gICAgICBpZiAoIWV4aXN0c1NhbXBsZUluZGV4LmJvZHkpIHtcbiAgICAgICAgLy8gQ3JlYXRlIHdhenVoIHNhbXBsZSBhbGVydHMgaW5kZXhcblxuICAgICAgICBjb25zdCBjb25maWd1cmF0aW9uID0ge1xuICAgICAgICAgIHNldHRpbmdzOiB7XG4gICAgICAgICAgICBpbmRleDoge1xuICAgICAgICAgICAgICBudW1iZXJfb2Zfc2hhcmRzOiBXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1NIQVJEUyxcbiAgICAgICAgICAgICAgbnVtYmVyX29mX3JlcGxpY2FzOiBXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1JFUExJQ0FTXG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICB9O1xuXG4gICAgICAgIGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLmluZGljZXMuY3JlYXRlKHtcbiAgICAgICAgICBpbmRleDogc2FtcGxlQWxlcnRzSW5kZXgsXG4gICAgICAgICAgYm9keTogY29uZmlndXJhdGlvblxuICAgICAgICB9KTtcbiAgICAgICAgbG9nKFxuICAgICAgICAgICd3YXp1aC1lbGFzdGljOmNyZWF0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgICAgYENyZWF0ZWQgJHtzYW1wbGVBbGVydHNJbmRleH0gaW5kZXhgLFxuICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuYnVsayh7XG4gICAgICAgIGluZGV4OiBzYW1wbGVBbGVydHNJbmRleCxcbiAgICAgICAgYm9keTogYnVsa1xuICAgICAgfSk7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmNyZWF0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgIGBBZGRlZCBzYW1wbGUgYWxlcnRzIHRvICR7c2FtcGxlQWxlcnRzSW5kZXh9IGluZGV4YCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHsgaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4LCBhbGVydENvdW50OiBzYW1wbGVBbGVydHMubGVuZ3RoIH1cbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coXG4gICAgICAgICd3YXp1aC1lbGFzdGljOmNyZWF0ZVNhbXBsZUFsZXJ0cycsXG4gICAgICAgIGBFcnJvciBhZGRpbmcgc2FtcGxlIGFsZXJ0cyB0byAke3NhbXBsZUFsZXJ0c0luZGV4fSBpbmRleDogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWBcbiAgICAgICk7XG4gICAgICBcbiAgICAgIGNvbnN0IFtzdGF0dXNDb2RlLCBlcnJvck1lc3NhZ2VdID0gdGhpcy5nZXRFcnJvckRldGFpbHMoZXJyb3IpO1xuICAgICAgXG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvck1lc3NhZ2UgfHwgZXJyb3IsIDEwMDAsIHN0YXR1c0NvZGUsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cbiAgLyoqXG4gICAqIFRoaXMgZGVsZXRlcyBzYW1wbGUgYWxlcnRzXG4gICAqIEBwYXJhbSB7Kn0gY29udGV4dFxuICAgKiBAcGFyYW0geyp9IHJlcXVlc3RcbiAgICogQHBhcmFtIHsqfSByZXNwb25zZVxuICAgKiB7cmVzdWx0OiBcImRlbGV0ZWRcIiwgaW5kZXg6IHN0cmluZ30gb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZGVsZXRlU2FtcGxlQWxlcnRzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdDx7IGNhdGVnb3J5OiBzdHJpbmcgfT4sIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICAvLyBEZWxldGUgV2F6dWggc2FtcGxlIGFsZXJ0IGluZGV4XG5cbiAgICBjb25zdCBzYW1wbGVBbGVydHNJbmRleCA9IHRoaXMuYnVpbGRTYW1wbGVJbmRleEJ5Q2F0ZWdvcnkocmVxdWVzdC5wYXJhbXMuY2F0ZWdvcnkpO1xuXG4gICAgdHJ5IHtcbiAgICAgIC8vIENoZWNrIGlmIHVzZXIgaGFzIGFkbWluaXN0cmF0b3Igcm9sZSBpbiB0b2tlblxuICAgICAgY29uc3QgdG9rZW4gPSBnZXRDb29raWVWYWx1ZUJ5TmFtZShyZXF1ZXN0LmhlYWRlcnMuY29va2llLCAnd3otdG9rZW4nKTtcbiAgICAgIGlmICghdG9rZW4pIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIHRva2VuIHByb3ZpZGVkJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgIH07XG4gICAgICBjb25zdCBkZWNvZGVkVG9rZW4gPSBqd3REZWNvZGUodG9rZW4pO1xuICAgICAgaWYgKCFkZWNvZGVkVG9rZW4pIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIHBlcm1pc3Npb25zIGluIHRva2VuJywgNDAxLCA0MDEsIHJlc3BvbnNlKTtcbiAgICAgIH07XG4gICAgICBpZiAoIWRlY29kZWRUb2tlbi5yYmFjX3JvbGVzIHx8ICFkZWNvZGVkVG9rZW4ucmJhY19yb2xlcy5pbmNsdWRlcyhXQVpVSF9ST0xFX0FETUlOSVNUUkFUT1JfSUQpKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdObyBhZG1pbmlzdHJhdG9yIHJvbGUnLCA0MDEsIDQwMSwgcmVzcG9uc2UpO1xuICAgICAgfTtcbiAgICAgIC8vIENoZWNrIHRoZSBwcm92aWRlZCB0b2tlbiBpcyB2YWxpZFxuICAgICAgY29uc3QgYXBpSG9zdElEID0gZ2V0Q29va2llVmFsdWVCeU5hbWUocmVxdWVzdC5oZWFkZXJzLmNvb2tpZSwgJ3d6LWFwaScpO1xuICAgICAgaWYgKCFhcGlIb3N0SUQpIHtcbiAgICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoJ05vIEFQSSBpZCBwcm92aWRlZCcsIDQwMSwgNDAxLCByZXNwb25zZSk7XG4gICAgICB9O1xuICAgICAgY29uc3QgcmVzcG9uc2VUb2tlbklzV29ya2luZyA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoJ0dFVCcsIGAvL2AsIHt9LCB7IGFwaUhvc3RJRCB9KTtcbiAgICAgIGlmIChyZXNwb25zZVRva2VuSXNXb3JraW5nLnN0YXR1cyAhPT0gMjAwKSB7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKCdUb2tlbiBpcyBub3QgdmFsaWQnLCA1MDAsIDUwMCwgcmVzcG9uc2UpO1xuICAgICAgfTtcblxuICAgICAgLy8gQ2hlY2sgaWYgV2F6dWggc2FtcGxlIGFsZXJ0cyBpbmRleCBleGlzdHNcbiAgICAgIGNvbnN0IGV4aXN0c1NhbXBsZUluZGV4ID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuaW5kaWNlcy5leGlzdHMoe1xuICAgICAgICBpbmRleDogc2FtcGxlQWxlcnRzSW5kZXhcbiAgICAgIH0pO1xuICAgICAgaWYgKGV4aXN0c1NhbXBsZUluZGV4LmJvZHkpIHtcbiAgICAgICAgLy8gRGVsZXRlIFdhenVoIHNhbXBsZSBhbGVydHMgaW5kZXhcbiAgICAgICAgYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuaW5kaWNlcy5kZWxldGUoeyBpbmRleDogc2FtcGxlQWxlcnRzSW5kZXggfSk7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAnd2F6dWgtZWxhc3RpYzpkZWxldGVTYW1wbGVBbGVydHMnLFxuICAgICAgICAgIGBEZWxldGVkICR7c2FtcGxlQWxlcnRzSW5kZXh9IGluZGV4YCxcbiAgICAgICAgICAnZGVidWcnXG4gICAgICAgICk7XG4gICAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgICAgYm9keTogeyByZXN1bHQ6ICdkZWxldGVkJywgaW5kZXg6IHNhbXBsZUFsZXJ0c0luZGV4IH1cbiAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShgJHtzYW1wbGVBbGVydHNJbmRleH0gaW5kZXggZG9lc24ndCBleGlzdGAsIDEwMDAsIDUwMCwgcmVzcG9uc2UpXG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3dhenVoLWVsYXN0aWM6ZGVsZXRlU2FtcGxlQWxlcnRzJyxcbiAgICAgICAgYEVycm9yIGRlbGV0aW5nIHNhbXBsZSBhbGVydHMgb2YgJHtzYW1wbGVBbGVydHNJbmRleH0gaW5kZXg6ICR7ZXJyb3IubWVzc2FnZSB8fCBlcnJvcn1gXG4gICAgICApO1xuICAgICAgY29uc3QgW3N0YXR1c0NvZGUsIGVycm9yTWVzc2FnZV0gPSB0aGlzLmdldEVycm9yRGV0YWlscyhlcnJvcik7XG5cbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yTWVzc2FnZSB8fCBlcnJvciwgMTAwMCwgc3RhdHVzQ29kZSwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIGFsZXJ0cyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgZGF0YSA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnNlYXJjaChyZXF1ZXN0LmJvZHkpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogZGF0YS5ib2R5XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmFsZXJ0cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNDAxMCwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLy8gQ2hlY2sgaWYgdGhlcmUgYXJlIGluZGljZXMgZm9yIFN0YXRpc3RpY3NcbiAgYXN5bmMgZXhpc3RTdGF0aXN0aWNzSW5kaWNlcyhjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnkpIHtcbiAgICB0cnkge1xuICAgICAgY29uc3QgY29uZmlnID0gZ2V0Q29uZmlndXJhdGlvbigpO1xuICAgICAgY29uc3Qgc3RhdGlzdGljc1BhdHRlcm4gPSBgJHtjb25maWdbJ2Nyb24ucHJlZml4J10gfHwgJ3dhenVoJ30tJHtjb25maWdbJ2Nyb24uc3RhdGlzdGljcy5pbmRleC5uYW1lJ10gfHwgJ3N0YXRpc3RpY3MnfSpgOyAvL1RPRE86IHJlcGxhY2UgYnkgZGVmYXVsdCBhcyBjb25zdGFudHMgaW5zdGVhZCBoYXJkY29kZWQgKCd3YXp1aCcgYW5kICdzdGF0aXN0aWNzJylcbiAgICAgIGNvbnN0IGV4aXN0SW5kZXggPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgIGluZGV4OiBzdGF0aXN0aWNzUGF0dGVybixcbiAgICAgICAgYWxsb3dfbm9faW5kaWNlczogZmFsc2VcbiAgICAgIH0pO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogZXhpc3RJbmRleC5ib2R5XG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCd3YXp1aC1lbGFzdGljOmV4aXN0c1N0YXRpc3RpY3NJbmRpY2VzJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAxMDAwLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH1cblxuICAvLyBDaGVjayBpZiB0aGVyZSBhcmUgaW5kaWNlcyBmb3IgTW9uaXRvcmluZ1xuICBhc3luYyBleGlzdE1vbml0b3JpbmdJbmRpY2VzKGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCwgcmVxdWVzdDogS2liYW5hUmVxdWVzdCwgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeSkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBjb25maWcgPSBnZXRDb25maWd1cmF0aW9uKCk7XG4gICAgICBjb25zdCBtb25pdG9yaW5nSW5kZXhQYXR0ZXJuID0gY29uZmlnWyd3YXp1aC5tb25pdG9yaW5nLnBhdHRlcm4nXSB8fCBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCd3YXp1aC5tb25pdG9yaW5nLnBhdHRlcm4nKTtcbiAgICAgIGNvbnN0IGV4aXN0SW5kZXggPSBhd2FpdCBjb250ZXh0LmNvcmUuZWxhc3RpY3NlYXJjaC5jbGllbnQuYXNDdXJyZW50VXNlci5pbmRpY2VzLmV4aXN0cyh7XG4gICAgICAgIGluZGV4OiBtb25pdG9yaW5nSW5kZXhQYXR0ZXJuLFxuICAgICAgICBhbGxvd19ub19pbmRpY2VzOiBmYWxzZVxuICAgICAgfSk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiBleGlzdEluZGV4LmJvZHlcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3dhenVoLWVsYXN0aWM6ZXhpc3RzTW9uaXRvcmluZ0luZGljZXMnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDEwMDAsIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfVxuXG4gIGFzeW5jIHVzaW5nQ3JlZGVudGlhbHMoY29udGV4dCkge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBkYXRhID0gYXdhaXQgY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzSW50ZXJuYWxVc2VyLmNsdXN0ZXIuZ2V0U2V0dGluZ3MoXG4gICAgICAgIHsgaW5jbHVkZV9kZWZhdWx0czogdHJ1ZSB9XG4gICAgICApO1xuICAgICAgcmV0dXJuICgoKCgoZGF0YSB8fCB7fSkuYm9keSB8fCB7fSkuZGVmYXVsdHMgfHwge30pLnhwYWNrIHx8IHt9KS5zZWN1cml0eSB8fCB7fSkudXNlciAhPT0gbnVsbDtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgICB9XG4gIH07XG5cbiAgZ2V0RXJyb3JEZXRhaWxzKGVycm9yKXtcbiAgICBjb25zdCBzdGF0dXNDb2RlID0gZXJyb3I/Lm1ldGE/LnN0YXR1c0NvZGUgfHwgNTAwO1xuICAgIGxldCBlcnJvck1lc3NhZ2UgPSBlcnJvci5tZXNzYWdlO1xuXG4gICAgaWYoc3RhdHVzQ29kZSA9PT0gNDAzKXtcbiAgICAgIGVycm9yTWVzc2FnZSA9IGVycm9yPy5tZXRhPy5ib2R5Py5lcnJvcj8ucmVhc29uIHx8ICdQZXJtaXNzaW9uIGRlbmllZCc7XG4gICAgfVxuXG4gICAgcmV0dXJuIFtzdGF0dXNDb2RlLCBlcnJvck1lc3NhZ2VdO1xuICB9XG59XG4iXX0=