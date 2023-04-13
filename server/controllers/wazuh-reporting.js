"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WazuhReportingCtrl = void 0;

var _defineProperty2 = _interopRequireDefault(require("@babel/runtime/helpers/defineProperty"));

var _path = _interopRequireDefault(require("path"));

var _fs = _interopRequireDefault(require("fs"));

var _wazuhModules = require("../../common/wazuh-modules");

var TimSort = _interopRequireWildcard(require("timsort"));

var _errorResponse = require("../lib/error-response");

var _processStateEquivalence = _interopRequireDefault(require("../lib/process-state-equivalence"));

var _csvKeyEquivalence = require("../../common/csv-key-equivalence");

var _agentConfiguration = require("../lib/reporting/agent-configuration");

var _extendedInformation = require("../lib/reporting/extended-information");

var _printer = require("../lib/reporting/printer");

var _logger = require("../lib/logger");

var _constants = require("../../common/constants");

var _filesystem = require("../lib/filesystem");

var _wz_agent_status = require("../../common/services/wz_agent_status");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

/*
 * Wazuh app - Class for Wazuh reporting controller
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
class WazuhReportingCtrl {
  constructor() {
    (0, _defineProperty2.default)(this, "createReportsModules", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:createReportsModules', `Report started`, 'info');
        const {
          array,
          agents,
          browserTimezone,
          searchBar,
          filters,
          time,
          tables,
          section,
          indexPatternTitle,
          apiId
        } = request.body;
        const {
          moduleID
        } = request.params;
        const {
          from,
          to
        } = time || {};
        let additionalTables = []; // Init

        const printer = new _printer.ReportPrinter();
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, context.wazuhEndpointParams.hashUsername));
        await this.renderHeader(context, printer, section, moduleID, agents, apiId);
        const [sanitizedFilters, agentsFilter] = filters ? this.sanitizeKibanaFilters(filters, searchBar) : [false, null];

        if (time && sanitizedFilters) {
          printer.addTimeRangeAndFilters(from, to, sanitizedFilters, browserTimezone);
        }

        if (time) {
          additionalTables = await (0, _extendedInformation.extendedInformation)(context, printer, section, moduleID, apiId, new Date(from).getTime(), new Date(to).getTime(), sanitizedFilters, agentsFilter, indexPatternTitle, agents);
        }

        printer.addVisualizations(array, agents, moduleID);

        if (tables) {
          printer.addTables([...tables, ...(additionalTables || [])]);
        } //add authorized agents


        if (agentsFilter !== null && agentsFilter !== void 0 && agentsFilter.agentsText) {
          printer.addAgentsFilters(agentsFilter.agentsText);
        }

        await printer.print(context.wazuhEndpointParams.pathFilename);
        return response.ok({
          body: {
            success: true,
            message: `Report ${context.wazuhEndpointParams.filename} was created`
          }
        });
      } catch (error) {
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
      }
    }, ({
      body: {
        agents
      },
      params: {
        moduleID
      }
    }) => `wazuh-module-${agents ? `agents-${agents}` : 'overview'}-${moduleID}-${this.generateReportTimestamp()}.pdf`));
    (0, _defineProperty2.default)(this, "createReportsGroups", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:createReportsGroups', `Report started`, 'info');
        const {
          components,
          apiId
        } = request.body;
        const {
          groupID
        } = request.params; // Init

        const printer = new _printer.ReportPrinter();
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, context.wazuhEndpointParams.hashUsername));
        let tables = [];
        const equivalences = {
          localfile: 'Local files',
          osquery: 'Osquery',
          command: 'Command',
          syscheck: 'Syscheck',
          'open-scap': 'OpenSCAP',
          'cis-cat': 'CIS-CAT',
          syscollector: 'Syscollector',
          rootcheck: 'Rootcheck',
          labels: 'Labels',
          sca: 'Security configuration assessment'
        };
        printer.addContent({
          text: `Group ${groupID} configuration`,
          style: 'h1'
        }); // Group configuration

        if (components['0']) {
          const {
            data: {
              data: configuration
            }
          } = await context.wazuh.api.client.asCurrentUser.request('GET', `/groups/${groupID}/configuration`, {}, {
            apiHostID: apiId
          });

          if (configuration.affected_items.length > 0 && Object.keys(configuration.affected_items[0].config).length) {
            printer.addContent({
              text: 'Configurations',
              style: {
                fontSize: 14,
                color: '#000'
              },
              margin: [0, 10, 0, 15]
            });
            const section = {
              labels: [],
              isGroupConfig: true
            };

            for (let config of configuration.affected_items) {
              let filterTitle = '';
              let index = 0;

              for (let filter of Object.keys(config.filters)) {
                filterTitle = filterTitle.concat(`${filter}: ${config.filters[filter]}`);

                if (index < Object.keys(config.filters).length - 1) {
                  filterTitle = filterTitle.concat(' | ');
                }

                index++;
              }

              printer.addContent({
                text: filterTitle,
                style: 'h4',
                margin: [0, 0, 0, 10]
              });
              let idx = 0;
              section.tabs = [];

              for (let _d of Object.keys(config.config)) {
                for (let c of _agentConfiguration.AgentConfiguration.configurations) {
                  for (let s of c.sections) {
                    section.opts = s.opts || {};

                    for (let cn of s.config || []) {
                      if (cn.configuration === _d) {
                        section.labels = s.labels || [[]];
                      }
                    }

                    for (let wo of s.wodle || []) {
                      if (wo.name === _d) {
                        section.labels = s.labels || [[]];
                      }
                    }
                  }
                }

                section.labels[0]['pack'] = 'Packs';
                section.labels[0]['content'] = 'Evaluations';
                section.labels[0]['7'] = 'Scan listening netwotk ports';
                section.tabs.push(equivalences[_d]);

                if (Array.isArray(config.config[_d])) {
                  /* LOG COLLECTOR */
                  if (_d === 'localfile') {
                    let groups = [];

                    config.config[_d].forEach(obj => {
                      if (!groups[obj.logformat]) {
                        groups[obj.logformat] = [];
                      }

                      groups[obj.logformat].push(obj);
                    });

                    Object.keys(groups).forEach(group => {
                      let saveidx = 0;
                      groups[group].forEach((x, i) => {
                        if (Object.keys(x).length > Object.keys(groups[group][saveidx]).length) {
                          saveidx = i;
                        }
                      });
                      const columns = Object.keys(groups[group][saveidx]);
                      const rows = groups[group].map(x => {
                        let row = [];
                        columns.forEach(key => {
                          row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
                            return x + '\n';
                          }) : JSON.stringify(x[key]));
                        });
                        return row;
                      });
                      columns.forEach((col, i) => {
                        columns[i] = col[0].toUpperCase() + col.slice(1);
                      });
                      tables.push({
                        title: 'Local files',
                        type: 'table',
                        columns,
                        rows
                      });
                    });
                  } else if (_d === 'labels') {
                    const obj = config.config[_d][0].label;
                    const columns = Object.keys(obj[0]);

                    if (!columns.includes('hidden')) {
                      columns.push('hidden');
                    }

                    const rows = obj.map(x => {
                      let row = [];
                      columns.forEach(key => {
                        row.push(x[key]);
                      });
                      return row;
                    });
                    columns.forEach((col, i) => {
                      columns[i] = col[0].toUpperCase() + col.slice(1);
                    });
                    tables.push({
                      title: 'Labels',
                      type: 'table',
                      columns,
                      rows
                    });
                  } else {
                    for (let _d2 of config.config[_d]) {
                      tables.push(...this.getConfigTables(_d2, section, idx));
                    }
                  }
                } else {
                  /*INTEGRITY MONITORING MONITORED DIRECTORIES */
                  if (config.config[_d].directories) {
                    const directories = config.config[_d].directories;
                    delete config.config[_d].directories;
                    tables.push(...this.getConfigTables(config.config[_d], section, idx));
                    let diffOpts = [];
                    Object.keys(section.opts).forEach(x => {
                      diffOpts.push(x);
                    });
                    const columns = ['', ...diffOpts.filter(x => x !== 'check_all' && x !== 'check_sum')];
                    let rows = [];
                    directories.forEach(x => {
                      let row = [];
                      row.push(x.path);
                      columns.forEach(y => {
                        if (y !== '') {
                          y = y !== 'check_whodata' ? y : 'whodata';
                          row.push(x[y] ? x[y] : 'no');
                        }
                      });
                      row.push(x.recursion_level);
                      rows.push(row);
                    });
                    columns.forEach((x, idx) => {
                      columns[idx] = section.opts[x];
                    });
                    columns.push('RL');
                    tables.push({
                      title: 'Monitored directories',
                      type: 'table',
                      columns,
                      rows
                    });
                  } else {
                    tables.push(...this.getConfigTables(config.config[_d], section, idx));
                  }
                }

                for (const table of tables) {
                  printer.addConfigTables([table]);
                }

                idx++;
                tables = [];
              }

              tables = [];
            }
          } else {
            printer.addContent({
              text: 'A configuration for this group has not yet been set up.',
              style: {
                fontSize: 12,
                color: '#000'
              },
              margin: [0, 10, 0, 15]
            });
          }
        } // Agents in group


        if (components['1']) {
          await this.renderHeader(context, printer, 'groupConfig', groupID, [], apiId);
        }

        await printer.print(context.wazuhEndpointParams.pathFilename);
        return response.ok({
          body: {
            success: true,
            message: `Report ${context.wazuhEndpointParams.filename} was created`
          }
        });
      } catch (error) {
        (0, _logger.log)('reporting:createReportsGroups', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
      }
    }, ({
      params: {
        groupID
      }
    }) => `wazuh-group-configuration-${groupID}-${this.generateReportTimestamp()}.pdf`));
    (0, _defineProperty2.default)(this, "createReportsAgentsConfiguration", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:createReportsAgentsConfiguration', `Report started`, 'info');
        const {
          components,
          apiId
        } = request.body;
        const {
          agentID
        } = request.params;
        const printer = new _printer.ReportPrinter();
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, context.wazuhEndpointParams.hashUsername));
        let wmodulesResponse = {};
        let tables = [];

        try {
          wmodulesResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents/${agentID}/config/wmodules/wmodules`, {}, {
            apiHostID: apiId
          });
        } catch (error) {
          (0, _logger.log)('reporting:report', error.message || error, 'debug');
        }

        await this.renderHeader(context, printer, 'agentConfig', 'agentConfig', agentID, apiId);
        let idxComponent = 0;

        for (let config of _agentConfiguration.AgentConfiguration.configurations) {
          let titleOfSection = false;
          (0, _logger.log)('reporting:createReportsAgentsConfiguration', `Iterate over ${config.sections.length} configuration sections`, 'debug');

          for (let section of config.sections) {
            let titleOfSubsection = false;

            if (components[idxComponent] && (section.config || section.wodle)) {
              let idx = 0;
              const configs = (section.config || []).concat(section.wodle || []);
              (0, _logger.log)('reporting:createReportsAgentsConfiguration', `Iterate over ${configs.length} configuration blocks`, 'debug');

              for (let conf of configs) {
                let agentConfigResponse = {};

                try {
                  if (!conf['name']) {
                    agentConfigResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents/${agentID}/config/${conf.component}/${conf.configuration}`, {}, {
                      apiHostID: apiId
                    });
                  } else {
                    for (let wodle of wmodulesResponse.data.data['wmodules']) {
                      if (Object.keys(wodle)[0] === conf['name']) {
                        agentConfigResponse.data = {
                          data: wodle
                        };
                      }
                    }
                  }

                  const agentConfig = agentConfigResponse && agentConfigResponse.data && agentConfigResponse.data.data;

                  if (!titleOfSection) {
                    printer.addContent({
                      text: config.title,
                      style: 'h1',
                      margin: [0, 0, 0, 15]
                    });
                    titleOfSection = true;
                  }

                  if (!titleOfSubsection) {
                    printer.addContent({
                      text: section.subtitle,
                      style: 'h4'
                    });
                    printer.addContent({
                      text: section.desc,
                      style: {
                        fontSize: 12,
                        color: '#000'
                      },
                      margin: [0, 0, 0, 10]
                    });
                    titleOfSubsection = true;
                  }

                  if (agentConfig) {
                    for (let agentConfigKey of Object.keys(agentConfig)) {
                      if (Array.isArray(agentConfig[agentConfigKey])) {
                        /* LOG COLLECTOR */
                        if (conf.filterBy) {
                          let groups = [];
                          agentConfig[agentConfigKey].forEach(obj => {
                            if (!groups[obj.logformat]) {
                              groups[obj.logformat] = [];
                            }

                            groups[obj.logformat].push(obj);
                          });
                          Object.keys(groups).forEach(group => {
                            let saveidx = 0;
                            groups[group].forEach((x, i) => {
                              if (Object.keys(x).length > Object.keys(groups[group][saveidx]).length) {
                                saveidx = i;
                              }
                            });
                            const columns = Object.keys(groups[group][saveidx]);
                            const rows = groups[group].map(x => {
                              let row = [];
                              columns.forEach(key => {
                                row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
                                  return x + '\n';
                                }) : JSON.stringify(x[key]));
                              });
                              return row;
                            });
                            columns.forEach((col, i) => {
                              columns[i] = col[0].toUpperCase() + col.slice(1);
                            });
                            tables.push({
                              title: section.labels[0][group],
                              type: 'table',
                              columns,
                              rows
                            });
                          });
                        } else if (agentConfigKey.configuration !== 'socket') {
                          tables.push(...this.getConfigTables(agentConfig[agentConfigKey], section, idx));
                        } else {
                          for (let _d2 of agentConfig[agentConfigKey]) {
                            tables.push(...this.getConfigTables(_d2, section, idx));
                          }
                        }
                      } else {
                        /*INTEGRITY MONITORING MONITORED DIRECTORIES */
                        if (conf.matrix) {
                          const {
                            directories,
                            diff,
                            synchronization,
                            file_limit,
                            ...rest
                          } = agentConfig[agentConfigKey];
                          tables.push(...this.getConfigTables(rest, section, idx), ...(diff && diff.disk_quota ? this.getConfigTables(diff.disk_quota, {
                            tabs: ['Disk quota']
                          }, 0) : []), ...(diff && diff.file_size ? this.getConfigTables(diff.file_size, {
                            tabs: ['File size']
                          }, 0) : []), ...(synchronization ? this.getConfigTables(synchronization, {
                            tabs: ['Synchronization']
                          }, 0) : []), ...(file_limit ? this.getConfigTables(file_limit, {
                            tabs: ['File limit']
                          }, 0) : []));
                          let diffOpts = [];
                          Object.keys(section.opts).forEach(x => {
                            diffOpts.push(x);
                          });
                          const columns = ['', ...diffOpts.filter(x => x !== 'check_all' && x !== 'check_sum')];
                          let rows = [];
                          directories.forEach(x => {
                            let row = [];
                            row.push(x.dir);
                            columns.forEach(y => {
                              if (y !== '') {
                                row.push(x.opts.indexOf(y) > -1 ? 'yes' : 'no');
                              }
                            });
                            row.push(x.recursion_level);
                            rows.push(row);
                          });
                          columns.forEach((x, idx) => {
                            columns[idx] = section.opts[x];
                          });
                          columns.push('RL');
                          tables.push({
                            title: 'Monitored directories',
                            type: 'table',
                            columns,
                            rows
                          });
                        } else {
                          tables.push(...this.getConfigTables(agentConfig[agentConfigKey], section, idx));
                        }
                      }
                    }
                  } else {
                    // Print no configured module and link to the documentation
                    printer.addContent({
                      text: ['This module is not configured. Please take a look on how to configure it in ', {
                        text: `${section.subtitle.toLowerCase()} configuration.`,
                        link: section.docuLink,
                        style: {
                          fontSize: 12,
                          color: '#1a0dab'
                        }
                      }],
                      margin: [0, 0, 0, 20]
                    });
                  }
                } catch (error) {
                  (0, _logger.log)('reporting:report', error.message || error, 'debug');
                }

                idx++;
              }

              for (const table of tables) {
                printer.addConfigTables([table]);
              }
            }

            idxComponent++;
            tables = [];
          }
        }

        await printer.print(context.wazuhEndpointParams.pathFilename);
        return response.ok({
          body: {
            success: true,
            message: `Report ${context.wazuhEndpointParams.filename} was created`
          }
        });
      } catch (error) {
        (0, _logger.log)('reporting:createReportsAgentsConfiguration', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
      }
    }, ({
      params: {
        agentID
      }
    }) => `wazuh-agent-configuration-${agentID}-${this.generateReportTimestamp()}.pdf`));
    (0, _defineProperty2.default)(this, "createReportsAgentsInventory", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:createReportsAgentsInventory', `Report started`, 'info');
        const {
          searchBar,
          filters,
          time,
          indexPatternTitle,
          apiId
        } = request.body;
        const {
          agentID
        } = request.params;
        const {
          from,
          to
        } = time || {}; // Init

        const printer = new _printer.ReportPrinter();
        const {
          hashUsername
        } = await context.wazuh.security.getCurrentUser(request, context);
        (0, _filesystem.createDataDirectoryIfNotExists)();
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);
        (0, _filesystem.createDirectoryIfNotExists)(_path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, hashUsername));
        (0, _logger.log)('reporting:createReportsAgentsInventory', `Syscollector report`, 'debug');
        const [sanitizedFilters, agentsFilter] = filters ? this.sanitizeKibanaFilters(filters, searchBar) : [false, null]; // Get the agent OS

        let agentOs = '';

        try {
          const agentResponse = await context.wazuh.api.client.asCurrentUser.request('GET', '/agents', {
            params: {
              q: `id=${agentID}`
            }
          }, {
            apiHostID: apiId
          });
          agentOs = agentResponse.data.data.affected_items[0].os.platform;
        } catch (error) {
          (0, _logger.log)('reporting:createReportsAgentsInventory', error.message || error, 'debug');
        } // Add title


        printer.addContentWithNewLine({
          text: 'Inventory data report',
          style: 'h1'
        }); // Add table with the agent info

        await (0, _extendedInformation.buildAgentsTable)(context, printer, [agentID], apiId); // Get syscollector packages and processes

        const agentRequestsInventory = [{
          endpoint: `/syscollector/${agentID}/packages`,
          loggerMessage: `Fetching packages for agent ${agentID}`,
          table: {
            title: 'Packages',
            columns: agentOs === 'windows' ? [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'architecture',
              label: 'Architecture'
            }, {
              id: 'version',
              label: 'Version'
            }, {
              id: 'vendor',
              label: 'Vendor'
            }] : [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'architecture',
              label: 'Architecture'
            }, {
              id: 'version',
              label: 'Version'
            }, {
              id: 'vendor',
              label: 'Vendor'
            }, {
              id: 'description',
              label: 'Description'
            }]
          }
        }, {
          endpoint: `/syscollector/${agentID}/processes`,
          loggerMessage: `Fetching processes for agent ${agentID}`,
          table: {
            title: 'Processes',
            columns: agentOs === 'windows' ? [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'cmd',
              label: 'CMD'
            }, {
              id: 'priority',
              label: 'Priority'
            }, {
              id: 'nlwp',
              label: 'NLWP'
            }] : [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'euser',
              label: 'Effective user'
            }, {
              id: 'nice',
              label: 'Priority'
            }, {
              id: 'state',
              label: 'State'
            }]
          },
          mapResponseItems: item => agentOs === 'windows' ? item : { ...item,
            state: _processStateEquivalence.default[item.state]
          }
        }, {
          endpoint: `/syscollector/${agentID}/ports`,
          loggerMessage: `Fetching ports for agent ${agentID}`,
          table: {
            title: 'Network ports',
            columns: agentOs === 'windows' ? [{
              id: 'local_ip',
              label: 'Local IP address'
            }, {
              id: 'local_port',
              label: 'Local port'
            }, {
              id: 'process',
              label: 'Process'
            }, {
              id: 'state',
              label: 'State'
            }, {
              id: 'protocol',
              label: 'Protocol'
            }] : [{
              id: 'local_ip',
              label: 'Local IP address'
            }, {
              id: 'local_port',
              label: 'Local port'
            }, {
              id: 'state',
              label: 'State'
            }, {
              id: 'protocol',
              label: 'Protocol'
            }]
          },
          mapResponseItems: item => ({ ...item,
            local_ip: item.local.ip,
            local_port: item.local.port
          })
        }, {
          endpoint: `/syscollector/${agentID}/netiface`,
          loggerMessage: `Fetching netiface for agent ${agentID}`,
          table: {
            title: 'Network interfaces',
            columns: [{
              id: 'name',
              label: 'Name'
            }, {
              id: 'mac',
              label: 'Mac'
            }, {
              id: 'state',
              label: 'State'
            }, {
              id: 'mtu',
              label: 'MTU'
            }, {
              id: 'type',
              label: 'Type'
            }]
          }
        }, {
          endpoint: `/syscollector/${agentID}/netaddr`,
          loggerMessage: `Fetching netaddr for agent ${agentID}`,
          table: {
            title: 'Network settings',
            columns: [{
              id: 'iface',
              label: 'Interface'
            }, {
              id: 'address',
              label: 'Address'
            }, {
              id: 'netmask',
              label: 'Netmask'
            }, {
              id: 'proto',
              label: 'Protocol'
            }, {
              id: 'broadcast',
              label: 'Broadcast'
            }]
          }
        }];
        agentOs === 'windows' && agentRequestsInventory.push({
          endpoint: `/syscollector/${agentID}/hotfixes`,
          loggerMessage: `Fetching hotfixes for agent ${agentID}`,
          table: {
            title: 'Windows updates',
            columns: [{
              id: 'hotfix',
              label: 'Update code'
            }]
          }
        });

        const requestInventory = async agentRequestInventory => {
          try {
            (0, _logger.log)('reporting:createReportsAgentsInventory', agentRequestInventory.loggerMessage, 'debug');
            const inventoryResponse = await context.wazuh.api.client.asCurrentUser.request('GET', agentRequestInventory.endpoint, {}, {
              apiHostID: apiId
            });
            const inventory = inventoryResponse && inventoryResponse.data && inventoryResponse.data.data && inventoryResponse.data.data.affected_items;

            if (inventory) {
              return { ...agentRequestInventory.table,
                items: agentRequestInventory.mapResponseItems ? inventory.map(agentRequestInventory.mapResponseItems) : inventory
              };
            }
          } catch (error) {
            (0, _logger.log)('reporting:createReportsAgentsInventory', error.message || error, 'debug');
          }
        };

        if (time) {
          await (0, _extendedInformation.extendedInformation)(context, printer, 'agents', 'syscollector', apiId, from, to, sanitizedFilters + ' AND rule.groups: "vulnerability-detector"', agentsFilter, indexPatternTitle, agentID);
        } // Add inventory tables


        (await Promise.all(agentRequestsInventory.map(requestInventory))).filter(table => table).forEach(table => printer.addSimpleTable(table)); // Print the document

        await printer.print(context.wazuhEndpointParams.pathFilename);
        return response.ok({
          body: {
            success: true,
            message: `Report ${context.wazuhEndpointParams.filename} was created`
          }
        });
      } catch (error) {
        (0, _logger.log)('reporting:createReportsAgents', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5029, 500, response);
      }
    }, ({
      params: {
        agentID
      }
    }) => `wazuh-agent-inventory-${agentID}-${this.generateReportTimestamp()}.pdf`));
    (0, _defineProperty2.default)(this, "getReportByName", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:getReportByName', `Getting ${context.wazuhEndpointParams.pathFilename} report`, 'debug');

        const reportFileBuffer = _fs.default.readFileSync(context.wazuhEndpointParams.pathFilename);

        return response.ok({
          headers: {
            'Content-Type': 'application/pdf'
          },
          body: reportFileBuffer
        });
      } catch (error) {
        (0, _logger.log)('reporting:getReportByName', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5030, 500, response);
      }
    }, request => request.params.name));
    (0, _defineProperty2.default)(this, "deleteReportByName", this.checkReportsUserDirectoryIsValidRouteDecorator(async (context, request, response) => {
      try {
        (0, _logger.log)('reporting:deleteReportByName', `Deleting ${context.wazuhEndpointParams.pathFilename} report`, 'debug');

        _fs.default.unlinkSync(context.wazuhEndpointParams.pathFilename);

        (0, _logger.log)('reporting:deleteReportByName', `${context.wazuhEndpointParams.pathFilename} report was deleted`, 'info');
        return response.ok({
          body: {
            error: 0
          }
        });
      } catch (error) {
        (0, _logger.log)('reporting:deleteReportByName', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5032, 500, response);
      }
    }, request => request.params.name));
  }
  /**
   * This do format to filters
   * @param {String} filters E.g: cluster.name: wazuh AND rule.groups: vulnerability
   * @param {String} searchBar search term
   */


  sanitizeKibanaFilters(filters, searchBar) {
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `Started to sanitize filters`, 'info');
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `filters: ${filters.length}, searchBar: ${searchBar}`, 'debug');
    let str = '';
    const agentsFilter = {
      query: {},
      agentsText: ''
    };
    const agentsList = []; //separate agents filter

    filters = filters.filter(filter => {
      if (filter.meta.controlledBy === _constants.AUTHORIZED_AGENTS) {
        agentsFilter.query = filter.query;
        agentsList.push(filter);
        return false;
      }

      return filter;
    });
    const len = filters.length;

    for (let i = 0; i < len; i++) {
      const {
        negate,
        key,
        value,
        params,
        type
      } = filters[i].meta;
      str += `${negate ? 'NOT ' : ''}`;
      str += `${key}: `;
      str += `${type === 'range' ? `${params.gte}-${params.lt}` : type === 'phrases' ? '(' + params.join(" OR ") + ')' : type === 'exists' ? '*' : !!value ? value : (params || {}).query}`;
      str += `${i === len - 1 ? '' : ' AND '}`;
    }

    if (searchBar) {
      str += ` AND (${searchBar})`;
    }

    agentsFilter.agentsText = agentsList.map(filter => filter.meta.value).join(',');
    (0, _logger.log)('reporting:sanitizeKibanaFilters', `str: ${str}, agentsFilterStr: ${agentsFilter.agentsText}`, 'debug');
    return [str, agentsFilter];
  }
  /**
   * This performs the rendering of given header
   * @param {String} printer section target
   * @param {String} section section target
   * @param {Object} tab tab target
   * @param {Boolean} isAgents is agents section
   * @param {String} apiId ID of API
   */


  async renderHeader(context, printer, section, tab, isAgents, apiId) {
    try {
      (0, _logger.log)('reporting:renderHeader', `section: ${section}, tab: ${tab}, isAgents: ${isAgents}, apiId: ${apiId}`, 'debug');

      if (section && typeof section === 'string') {
        if (!['agentConfig', 'groupConfig'].includes(section)) {
          printer.addContent({
            text: _wazuhModules.WAZUH_MODULES[tab].title + ' report',
            style: 'h1'
          });
        } else if (section === 'agentConfig') {
          printer.addContent({
            text: `Agent ${isAgents} configuration`,
            style: 'h1'
          });
        } else if (section === 'groupConfig') {
          printer.addContent({
            text: 'Agents in group',
            style: 'h1'
          });
        }

        printer.addNewLine();
      }

      if (isAgents && typeof isAgents === 'object') {
        await (0, _extendedInformation.buildAgentsTable)(context, printer, isAgents, apiId, section === 'groupConfig' ? tab : '');
      }

      if (isAgents && typeof isAgents === 'string') {
        const agentResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents`, {
          params: {
            agents_list: isAgents
          }
        }, {
          apiHostID: apiId
        });
        const agentData = agentResponse.data.data.affected_items[0];

        if (agentData && agentData.status !== _constants.API_NAME_AGENT_STATUS.ACTIVE) {
          printer.addContentWithNewLine({
            text: `Warning. Agent is ${(0, _wz_agent_status.agentStatusLabelByAgentStatus)(agentData.status).toLowerCase()}`,
            style: 'standard'
          });
        }

        await (0, _extendedInformation.buildAgentsTable)(context, printer, [isAgents], apiId);

        if (agentData && agentData.group) {
          const agentGroups = agentData.group.join(', ');
          printer.addContentWithNewLine({
            text: `Group${agentData.group.length > 1 ? 's' : ''}: ${agentGroups}`,
            style: 'standard'
          });
        }
      }

      if (_wazuhModules.WAZUH_MODULES[tab] && _wazuhModules.WAZUH_MODULES[tab].description) {
        printer.addContentWithNewLine({
          text: _wazuhModules.WAZUH_MODULES[tab].description,
          style: 'standard'
        });
      }
    } catch (error) {
      (0, _logger.log)('reporting:renderHeader', error.message || error);
      return Promise.reject(error);
    }
  }

  getConfigRows(data, labels) {
    (0, _logger.log)('reporting:getConfigRows', `Building configuration rows`, 'info');
    const result = [];

    for (let prop in data || []) {
      if (Array.isArray(data[prop])) {
        data[prop].forEach((x, idx) => {
          if (typeof x === 'object') data[prop][idx] = JSON.stringify(x);
        });
      }

      result.push([(labels || {})[prop] || _csvKeyEquivalence.KeyEquivalence[prop] || prop, data[prop] || '-']);
    }

    return result;
  }

  getConfigTables(data, section, tab, array = []) {
    (0, _logger.log)('reporting:getConfigTables', `Building configuration tables`, 'info');
    let plainData = {};
    const nestedData = [];
    const tableData = [];

    if (data.length === 1 && Array.isArray(data)) {
      tableData[section.config[tab].configuration] = data;
    } else {
      for (let key in data) {
        if (typeof data[key] !== 'object' && !Array.isArray(data[key]) || Array.isArray(data[key]) && typeof data[key][0] !== 'object') {
          plainData[key] = Array.isArray(data[key]) && typeof data[key][0] !== 'object' ? data[key].map(x => {
            return typeof x === 'object' ? JSON.stringify(x) : x + '\n';
          }) : data[key];
        } else if (Array.isArray(data[key]) && typeof data[key][0] === 'object') {
          tableData[key] = data[key];
        } else {
          if (section.isGroupConfig && ['pack', 'content'].includes(key)) {
            tableData[key] = [data[key]];
          } else {
            nestedData.push(data[key]);
          }
        }
      }
    }

    array.push({
      title: (section.options || {}).hideHeader ? '' : (section.tabs || [])[tab] || (section.isGroupConfig ? ((section.labels || [])[0] || [])[tab] : ''),
      columns: ['', ''],
      type: 'config',
      rows: this.getConfigRows(plainData, (section.labels || [])[0])
    });

    for (let key in tableData) {
      const columns = Object.keys(tableData[key][0]);
      columns.forEach((col, i) => {
        columns[i] = col[0].toUpperCase() + col.slice(1);
      });
      const rows = tableData[key].map(x => {
        let row = [];

        for (let key in x) {
          row.push(typeof x[key] !== 'object' ? x[key] : Array.isArray(x[key]) ? x[key].map(x => {
            return x + '\n';
          }) : JSON.stringify(x[key]));
        }

        while (row.length < columns.length) {
          row.push('-');
        }

        return row;
      });
      array.push({
        title: ((section.labels || [])[0] || [])[key] || '',
        type: 'table',
        columns,
        rows
      });
    }

    nestedData.forEach(nest => {
      this.getConfigTables(nest, section, tab + 1, array);
    });
    return array;
  }
  /**
   * Create a report for the modules
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {*} reports list or ErrorResponse
   */


  /**
   * Fetch the reports list
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Array<Object>} reports list or ErrorResponse
   */
  async getReports(context, request, response) {
    try {
      (0, _logger.log)('reporting:getReports', `Fetching created reports`, 'info');
      const {
        hashUsername
      } = await context.wazuh.security.getCurrentUser(request, context);
      (0, _filesystem.createDataDirectoryIfNotExists)();
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH);
      (0, _filesystem.createDirectoryIfNotExists)(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH);

      const userReportsDirectoryPath = _path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, hashUsername);

      (0, _filesystem.createDirectoryIfNotExists)(userReportsDirectoryPath);
      (0, _logger.log)('reporting:getReports', `Directory: ${userReportsDirectoryPath}`, 'debug');

      const sortReportsByDate = (a, b) => a.date < b.date ? 1 : a.date > b.date ? -1 : 0;

      const reports = _fs.default.readdirSync(userReportsDirectoryPath).map(file => {
        const stats = _fs.default.statSync(userReportsDirectoryPath + '/' + file); // Get the file creation time (bithtime). It returns the first value that is a truthy value of next file stats: birthtime, mtime, ctime and atime.
        // This solves some OSs can have the bithtimeMs equal to 0 and returns the date like 1970-01-01


        const birthTimeField = ['birthtime', 'mtime', 'ctime', 'atime'].find(time => stats[`${time}Ms`]);
        return {
          name: file,
          size: stats.size,
          date: stats[birthTimeField]
        };
      });

      (0, _logger.log)('reporting:getReports', `Using TimSort for sorting ${reports.length} items`, 'debug');
      TimSort.sort(reports, sortReportsByDate);
      (0, _logger.log)('reporting:getReports', `Total reports: ${reports.length}`, 'debug');
      return response.ok({
        body: {
          reports
        }
      });
    } catch (error) {
      (0, _logger.log)('reporting:getReports', error.message || error);
      return (0, _errorResponse.ErrorResponse)(error.message || error, 5031, 500, response);
    }
  }
  /**
   * Fetch specific report
   * @param {Object} context
   * @param {Object} request
   * @param {Object} response
   * @returns {Object} report or ErrorResponse
   */


  checkReportsUserDirectoryIsValidRouteDecorator(routeHandler, reportFileNameAccessor) {
    return async (context, request, response) => {
      try {
        const {
          username,
          hashUsername
        } = await context.wazuh.security.getCurrentUser(request, context);

        const userReportsDirectoryPath = _path.default.join(_constants.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH, hashUsername);

        const filename = reportFileNameAccessor(request);

        const pathFilename = _path.default.join(userReportsDirectoryPath, filename);

        (0, _logger.log)('reporting:checkReportsUserDirectoryIsValidRouteDecorator', `Checking the user ${username}(${hashUsername}) can do actions in the reports file: ${pathFilename}`, 'debug');

        if (!pathFilename.startsWith(userReportsDirectoryPath) || pathFilename.includes('../')) {
          (0, _logger.log)('security:reporting:checkReportsUserDirectoryIsValidRouteDecorator', `User ${username}(${hashUsername}) tried to access to a non user report file: ${pathFilename}`, 'warn');
          return response.badRequest({
            body: {
              message: '5040 - You shall not pass!'
            }
          });
        }

        ;
        (0, _logger.log)('reporting:checkReportsUserDirectoryIsValidRouteDecorator', 'Checking the user can do actions in the reports file', 'debug');
        return await routeHandler.bind(this)({ ...context,
          wazuhEndpointParams: {
            hashUsername,
            filename,
            pathFilename
          }
        }, request, response);
      } catch (error) {
        (0, _logger.log)('reporting:checkReportsUserDirectoryIsValidRouteDecorator', error.message || error);
        return (0, _errorResponse.ErrorResponse)(error.message || error, 5040, 500, response);
      }
    };
  }

  generateReportTimestamp() {
    return `${Date.now() / 1000 | 0}`;
  }

}

exports.WazuhReportingCtrl = WazuhReportingCtrl;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndhenVoLXJlcG9ydGluZy50cyJdLCJuYW1lcyI6WyJXYXp1aFJlcG9ydGluZ0N0cmwiLCJjb25zdHJ1Y3RvciIsImNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IiLCJjb250ZXh0IiwicmVxdWVzdCIsInJlc3BvbnNlIiwiYXJyYXkiLCJhZ2VudHMiLCJicm93c2VyVGltZXpvbmUiLCJzZWFyY2hCYXIiLCJmaWx0ZXJzIiwidGltZSIsInRhYmxlcyIsInNlY3Rpb24iLCJpbmRleFBhdHRlcm5UaXRsZSIsImFwaUlkIiwiYm9keSIsIm1vZHVsZUlEIiwicGFyYW1zIiwiZnJvbSIsInRvIiwiYWRkaXRpb25hbFRhYmxlcyIsInByaW50ZXIiLCJSZXBvcnRQcmludGVyIiwiV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgiLCJXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRIIiwicGF0aCIsImpvaW4iLCJ3YXp1aEVuZHBvaW50UGFyYW1zIiwiaGFzaFVzZXJuYW1lIiwicmVuZGVySGVhZGVyIiwic2FuaXRpemVkRmlsdGVycyIsImFnZW50c0ZpbHRlciIsInNhbml0aXplS2liYW5hRmlsdGVycyIsImFkZFRpbWVSYW5nZUFuZEZpbHRlcnMiLCJEYXRlIiwiZ2V0VGltZSIsImFkZFZpc3VhbGl6YXRpb25zIiwiYWRkVGFibGVzIiwiYWdlbnRzVGV4dCIsImFkZEFnZW50c0ZpbHRlcnMiLCJwcmludCIsInBhdGhGaWxlbmFtZSIsIm9rIiwic3VjY2VzcyIsIm1lc3NhZ2UiLCJmaWxlbmFtZSIsImVycm9yIiwiZ2VuZXJhdGVSZXBvcnRUaW1lc3RhbXAiLCJjb21wb25lbnRzIiwiZ3JvdXBJRCIsImVxdWl2YWxlbmNlcyIsImxvY2FsZmlsZSIsIm9zcXVlcnkiLCJjb21tYW5kIiwic3lzY2hlY2siLCJzeXNjb2xsZWN0b3IiLCJyb290Y2hlY2siLCJsYWJlbHMiLCJzY2EiLCJhZGRDb250ZW50IiwidGV4dCIsInN0eWxlIiwiZGF0YSIsImNvbmZpZ3VyYXRpb24iLCJ3YXp1aCIsImFwaSIsImNsaWVudCIsImFzQ3VycmVudFVzZXIiLCJhcGlIb3N0SUQiLCJhZmZlY3RlZF9pdGVtcyIsImxlbmd0aCIsIk9iamVjdCIsImtleXMiLCJjb25maWciLCJmb250U2l6ZSIsImNvbG9yIiwibWFyZ2luIiwiaXNHcm91cENvbmZpZyIsImZpbHRlclRpdGxlIiwiaW5kZXgiLCJmaWx0ZXIiLCJjb25jYXQiLCJpZHgiLCJ0YWJzIiwiX2QiLCJjIiwiQWdlbnRDb25maWd1cmF0aW9uIiwiY29uZmlndXJhdGlvbnMiLCJzIiwic2VjdGlvbnMiLCJvcHRzIiwiY24iLCJ3byIsIndvZGxlIiwibmFtZSIsInB1c2giLCJBcnJheSIsImlzQXJyYXkiLCJncm91cHMiLCJmb3JFYWNoIiwib2JqIiwibG9nZm9ybWF0IiwiZ3JvdXAiLCJzYXZlaWR4IiwieCIsImkiLCJjb2x1bW5zIiwicm93cyIsIm1hcCIsInJvdyIsImtleSIsIkpTT04iLCJzdHJpbmdpZnkiLCJjb2wiLCJ0b1VwcGVyQ2FzZSIsInNsaWNlIiwidGl0bGUiLCJ0eXBlIiwibGFiZWwiLCJpbmNsdWRlcyIsIl9kMiIsImdldENvbmZpZ1RhYmxlcyIsImRpcmVjdG9yaWVzIiwiZGlmZk9wdHMiLCJ5IiwicmVjdXJzaW9uX2xldmVsIiwidGFibGUiLCJhZGRDb25maWdUYWJsZXMiLCJhZ2VudElEIiwid21vZHVsZXNSZXNwb25zZSIsImlkeENvbXBvbmVudCIsInRpdGxlT2ZTZWN0aW9uIiwidGl0bGVPZlN1YnNlY3Rpb24iLCJjb25maWdzIiwiY29uZiIsImFnZW50Q29uZmlnUmVzcG9uc2UiLCJjb21wb25lbnQiLCJhZ2VudENvbmZpZyIsInN1YnRpdGxlIiwiZGVzYyIsImFnZW50Q29uZmlnS2V5IiwiZmlsdGVyQnkiLCJtYXRyaXgiLCJkaWZmIiwic3luY2hyb25pemF0aW9uIiwiZmlsZV9saW1pdCIsInJlc3QiLCJkaXNrX3F1b3RhIiwiZmlsZV9zaXplIiwiZGlyIiwiaW5kZXhPZiIsInRvTG93ZXJDYXNlIiwibGluayIsImRvY3VMaW5rIiwic2VjdXJpdHkiLCJnZXRDdXJyZW50VXNlciIsImFnZW50T3MiLCJhZ2VudFJlc3BvbnNlIiwicSIsIm9zIiwicGxhdGZvcm0iLCJhZGRDb250ZW50V2l0aE5ld0xpbmUiLCJhZ2VudFJlcXVlc3RzSW52ZW50b3J5IiwiZW5kcG9pbnQiLCJsb2dnZXJNZXNzYWdlIiwiaWQiLCJtYXBSZXNwb25zZUl0ZW1zIiwiaXRlbSIsInN0YXRlIiwiUHJvY2Vzc0VxdWl2YWxlbmNlIiwibG9jYWxfaXAiLCJsb2NhbCIsImlwIiwibG9jYWxfcG9ydCIsInBvcnQiLCJyZXF1ZXN0SW52ZW50b3J5IiwiYWdlbnRSZXF1ZXN0SW52ZW50b3J5IiwiaW52ZW50b3J5UmVzcG9uc2UiLCJpbnZlbnRvcnkiLCJpdGVtcyIsIlByb21pc2UiLCJhbGwiLCJhZGRTaW1wbGVUYWJsZSIsInJlcG9ydEZpbGVCdWZmZXIiLCJmcyIsInJlYWRGaWxlU3luYyIsImhlYWRlcnMiLCJ1bmxpbmtTeW5jIiwic3RyIiwicXVlcnkiLCJhZ2VudHNMaXN0IiwibWV0YSIsImNvbnRyb2xsZWRCeSIsIkFVVEhPUklaRURfQUdFTlRTIiwibGVuIiwibmVnYXRlIiwidmFsdWUiLCJndGUiLCJsdCIsInRhYiIsImlzQWdlbnRzIiwiV0FaVUhfTU9EVUxFUyIsImFkZE5ld0xpbmUiLCJhZ2VudHNfbGlzdCIsImFnZW50RGF0YSIsInN0YXR1cyIsIkFQSV9OQU1FX0FHRU5UX1NUQVRVUyIsIkFDVElWRSIsImFnZW50R3JvdXBzIiwiZGVzY3JpcHRpb24iLCJyZWplY3QiLCJnZXRDb25maWdSb3dzIiwicmVzdWx0IiwicHJvcCIsIktleUVxdWl2YWxlbmNlIiwicGxhaW5EYXRhIiwibmVzdGVkRGF0YSIsInRhYmxlRGF0YSIsIm9wdGlvbnMiLCJoaWRlSGVhZGVyIiwibmVzdCIsImdldFJlcG9ydHMiLCJ1c2VyUmVwb3J0c0RpcmVjdG9yeVBhdGgiLCJzb3J0UmVwb3J0c0J5RGF0ZSIsImEiLCJiIiwiZGF0ZSIsInJlcG9ydHMiLCJyZWFkZGlyU3luYyIsImZpbGUiLCJzdGF0cyIsInN0YXRTeW5jIiwiYmlydGhUaW1lRmllbGQiLCJmaW5kIiwic2l6ZSIsIlRpbVNvcnQiLCJzb3J0Iiwicm91dGVIYW5kbGVyIiwicmVwb3J0RmlsZU5hbWVBY2Nlc3NvciIsInVzZXJuYW1lIiwic3RhcnRzV2l0aCIsImJhZFJlcXVlc3QiLCJiaW5kIiwibm93Il0sIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7OztBQVdBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUNBOztBQUVBOztBQU1BOztBQUNBOzs7Ozs7QUE5QkE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQTJCTyxNQUFNQSxrQkFBTixDQUF5QjtBQUM5QkMsRUFBQUEsV0FBVyxHQUFHO0FBQUEsZ0VBa1BTLEtBQUtDLDhDQUFMLENBQW9ELE9BQ3pFQyxPQUR5RSxFQUV6RUMsT0FGeUUsRUFHekVDLFFBSHlFLEtBSXRFO0FBQ0gsVUFBSTtBQUNGLHlCQUFJLGdDQUFKLEVBQXVDLGdCQUF2QyxFQUF3RCxNQUF4RDtBQUNBLGNBQU07QUFDSkMsVUFBQUEsS0FESTtBQUVKQyxVQUFBQSxNQUZJO0FBR0pDLFVBQUFBLGVBSEk7QUFJSkMsVUFBQUEsU0FKSTtBQUtKQyxVQUFBQSxPQUxJO0FBTUpDLFVBQUFBLElBTkk7QUFPSkMsVUFBQUEsTUFQSTtBQVFKQyxVQUFBQSxPQVJJO0FBU0pDLFVBQUFBLGlCQVRJO0FBVUpDLFVBQUFBO0FBVkksWUFXRlgsT0FBTyxDQUFDWSxJQVhaO0FBWUEsY0FBTTtBQUFFQyxVQUFBQTtBQUFGLFlBQWViLE9BQU8sQ0FBQ2MsTUFBN0I7QUFDQSxjQUFNO0FBQUVDLFVBQUFBLElBQUY7QUFBUUMsVUFBQUE7QUFBUixZQUFlVCxJQUFJLElBQUksRUFBN0I7QUFDQSxZQUFJVSxnQkFB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QTBFLFFBQU93SCxRQUFTLElBQUduTixZQUFhLGdEQUErQ2EsWUFBYSxFQUF0SyxFQUF5SyxNQUF6SztBQUNBLGlCQUFPckMsUUFBUSxDQUFDNk8sVUFBVCxDQUFvQjtBQUN6QmxPLFlBQUFBLElBQUksRUFBRTtBQUNKNkIsY0FBQUEsT0FBTyxFQUFFO0FBREw7QUFEbUIsV0FBcEIsQ0FBUDtBQUtEOztBQUFBO0FBQ0QseUJBQUksMERBQUosRUFBZ0Usc0RBQWhFLEVBQXdILE9BQXhIO0FBQ0EsZUFBTyxNQUFNaU0sWUFBWSxDQUFDSyxJQUFiLENBQWtCLElBQWxCLEVBQXdCLEVBQUMsR0FBR2hQLE9BQUo7QUFBYXlCLFVBQUFBLG1CQUFtQixFQUFFO0FBQUVDLFlBQUFBLFlBQUY7QUFBZ0JpQixZQUFBQSxRQUFoQjtBQUEwQkosWUFBQUE7QUFBMUI7QUFBbEMsU0FBeEIsRUFBcUd0QyxPQUFyRyxFQUE4R0MsUUFBOUcsQ0FBYjtBQUNELE9BaEJELENBZ0JDLE9BQU0wQyxLQUFOLEVBQVk7QUFDWCx5QkFBSSwwREFBSixFQUFnRUEsS0FBSyxDQUFDRixPQUFOLElBQWlCRSxLQUFqRjtBQUNBLGVBQU8sa0NBQWNBLEtBQUssQ0FBQ0YsT0FBTixJQUFpQkUsS0FBL0IsRUFBc0MsSUFBdEMsRUFBNEMsR0FBNUMsRUFBaUQxQyxRQUFqRCxDQUFQO0FBQ0Q7QUFDRixLQXpCRDtBQTBCRDs7QUFFTzJDLEVBQUFBLHVCQUF1QixHQUFFO0FBQy9CLFdBQVEsR0FBR2IsSUFBSSxDQUFDaU4sR0FBTCxLQUFhLElBQWQsR0FBc0IsQ0FBRSxFQUFsQztBQUNEOztBQXhxQzZCIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIENsYXNzIGZvciBXYXp1aCByZXBvcnRpbmcgY29udHJvbGxlclxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmltcG9ydCBwYXRoIGZyb20gJ3BhdGgnO1xuaW1wb3J0IGZzIGZyb20gJ2ZzJztcbmltcG9ydCB7IFdBWlVIX01PRFVMRVMgfSBmcm9tICcuLi8uLi9jb21tb24vd2F6dWgtbW9kdWxlcyc7XG5pbXBvcnQgKiBhcyBUaW1Tb3J0IGZyb20gJ3RpbXNvcnQnO1xuaW1wb3J0IHsgRXJyb3JSZXNwb25zZSB9IGZyb20gJy4uL2xpYi9lcnJvci1yZXNwb25zZSc7XG5pbXBvcnQgUHJvY2Vzc0VxdWl2YWxlbmNlIGZyb20gJy4uL2xpYi9wcm9jZXNzLXN0YXRlLWVxdWl2YWxlbmNlJztcbmltcG9ydCB7IEtleUVxdWl2YWxlbmNlIH0gZnJvbSAnLi4vLi4vY29tbW9uL2Nzdi1rZXktZXF1aXZhbGVuY2UnO1xuaW1wb3J0IHsgQWdlbnRDb25maWd1cmF0aW9uIH0gZnJvbSAnLi4vbGliL3JlcG9ydGluZy9hZ2VudC1jb25maWd1cmF0aW9uJztcbmltcG9ydCB7IGV4dGVuZGVkSW5mb3JtYXRpb24sIGJ1aWxkQWdlbnRzVGFibGUgfSBmcm9tICcuLi9saWIvcmVwb3J0aW5nL2V4dGVuZGVkLWluZm9ybWF0aW9uJztcbmltcG9ydCB7IFJlcG9ydFByaW50ZXIgfSBmcm9tICcuLi9saWIvcmVwb3J0aW5nL3ByaW50ZXInO1xuaW1wb3J0IHsgbG9nIH0gZnJvbSAnLi4vbGliL2xvZ2dlcic7XG5pbXBvcnQgeyBLaWJhbmFSZXF1ZXN0LCBSZXF1ZXN0SGFuZGxlckNvbnRleHQsIEtpYmFuYVJlc3BvbnNlRmFjdG9yeSB9IGZyb20gJ3NyYy9jb3JlL3NlcnZlcic7XG5pbXBvcnQge1xuICBXQVpVSF9EQVRBX0RPV05MT0FEU19ESVJFQ1RPUllfUEFUSCxcbiAgV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCxcbiAgQVVUSE9SSVpFRF9BR0VOVFMsXG4gIEFQSV9OQU1FX0FHRU5UX1NUQVRVUyxcbn0gZnJvbSAnLi4vLi4vY29tbW9uL2NvbnN0YW50cyc7XG5pbXBvcnQgeyBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cywgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzIH0gZnJvbSAnLi4vbGliL2ZpbGVzeXN0ZW0nO1xuaW1wb3J0IHsgYWdlbnRTdGF0dXNMYWJlbEJ5QWdlbnRTdGF0dXMgfSBmcm9tICcuLi8uLi9jb21tb24vc2VydmljZXMvd3pfYWdlbnRfc3RhdHVzJztcblxuaW50ZXJmYWNlIEFnZW50c0ZpbHRlciB7XG4gIHF1ZXJ5OiBhbnk7XG4gIGFnZW50c1RleHQ6IHN0cmluZztcbn1cblxuZXhwb3J0IGNsYXNzIFdhenVoUmVwb3J0aW5nQ3RybCB7XG4gIGNvbnN0cnVjdG9yKCkge31cbiAgLyoqXG4gICAqIFRoaXMgZG8gZm9ybWF0IHRvIGZpbHRlcnNcbiAgICogQHBhcmFtIHtTdHJpbmd9IGZpbHRlcnMgRS5nOiBjbHVzdGVyLm5hbWU6IHdhenVoIEFORCBydWxlLmdyb3VwczogdnVsbmVyYWJpbGl0eVxuICAgKiBAcGFyYW0ge1N0cmluZ30gc2VhcmNoQmFyIHNlYXJjaCB0ZXJtXG4gICAqL1xuICBwcml2YXRlIHNhbml0aXplS2liYW5hRmlsdGVycyhmaWx0ZXJzOiBhbnksIHNlYXJjaEJhcj86IHN0cmluZyk6IFtzdHJpbmcsIEFnZW50c0ZpbHRlcl0ge1xuICAgIGxvZygncmVwb3J0aW5nOnNhbml0aXplS2liYW5hRmlsdGVycycsIGBTdGFydGVkIHRvIHNhbml0aXplIGZpbHRlcnNgLCAnaW5mbycpO1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6c2FuaXRpemVLaWJhbmFGaWx0ZXJzJyxcbiAgICAgIGBmaWx0ZXJzOiAke2ZpbHRlcnMubGVuZ3RofSwgc2VhcmNoQmFyOiAke3NlYXJjaEJhcn1gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG4gICAgbGV0IHN0ciA9ICcnO1xuXG4gICAgY29uc3QgYWdlbnRzRmlsdGVyOiBBZ2VudHNGaWx0ZXIgPSB7IHF1ZXJ5OiB7fSwgYWdlbnRzVGV4dDogJycgfTtcbiAgICBjb25zdCBhZ2VudHNMaXN0OiBzdHJpbmdbXSA9IFtdO1xuXG4gICAgLy9zZXBhcmF0ZSBhZ2VudHMgZmlsdGVyXG4gICAgZmlsdGVycyA9IGZpbHRlcnMuZmlsdGVyKChmaWx0ZXIpID0+IHtcbiAgICAgIGlmIChmaWx0ZXIubWV0YS5jb250cm9sbGVkQnkgPT09IEFVVEhPUklaRURfQUdFTlRTKSB7XG4gICAgICAgIGFnZW50c0ZpbHRlci5xdWVyeSA9IGZpbHRlci5xdWVyeTtcbiAgICAgICAgYWdlbnRzTGlzdC5wdXNoKGZpbHRlcik7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBmaWx0ZXI7XG4gICAgfSk7XG5cbiAgICBjb25zdCBsZW4gPSBmaWx0ZXJzLmxlbmd0aDtcblxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgbGVuOyBpKyspIHtcbiAgICAgIGNvbnN0IHsgbmVnYXRlLCBrZXksIHZhbHVlLCBwYXJhbXMsIHR5cGUgfSA9IGZpbHRlcnNbaV0ubWV0YTtcbiAgICAgIHN0ciArPSBgJHtuZWdhdGUgPyAnTk9UICcgOiAnJ31gO1xuICAgICAgc3RyICs9IGAke2tleX06IGA7XG4gICAgICBzdHIgKz0gYCR7XG4gICAgICAgIHR5cGUgPT09ICdyYW5nZSdcbiAgICAgICAgICA/IGAke3BhcmFtcy5ndGV9LSR7cGFyYW1zLmx0fWBcbiAgICAgICAgICA6IHR5cGUgPT09ICdwaHJhc2VzJ1xuICAgICAgICAgICAgPyAnKCcgKyBwYXJhbXMuam9pbihcIiBPUiBcIikgKyAnKSdcbiAgICAgICAgICAgIDogdHlwZSA9PT0gJ2V4aXN0cydcbiAgICAgICAgICAgICAgPyAnKidcbiAgICAgICAgICAgICAgOiAhIXZhbHVlXG4gICAgICAgICAgPyB2YWx1ZVxuICAgICAgICAgIDogKHBhcmFtcyB8fCB7fSkucXVlcnlcbiAgICAgIH1gO1xuICAgICAgc3RyICs9IGAke2kgPT09IGxlbiAtIDEgPyAnJyA6ICcgQU5EICd9YDtcbiAgICB9XG5cbiAgICBpZiAoc2VhcmNoQmFyKSB7XG4gICAgICBzdHIgKz0gYCBBTkQgKCR7IHNlYXJjaEJhcn0pYDtcbiAgICB9XG5cbiAgICBhZ2VudHNGaWx0ZXIuYWdlbnRzVGV4dCA9IGFnZW50c0xpc3QubWFwKChmaWx0ZXIpID0+IGZpbHRlci5tZXRhLnZhbHVlKS5qb2luKCcsJyk7XG5cbiAgICBsb2coXG4gICAgICAncmVwb3J0aW5nOnNhbml0aXplS2liYW5hRmlsdGVycycsXG4gICAgICBgc3RyOiAke3N0cn0sIGFnZW50c0ZpbHRlclN0cjogJHthZ2VudHNGaWx0ZXIuYWdlbnRzVGV4dH1gLFxuICAgICAgJ2RlYnVnJ1xuICAgICk7XG5cbiAgICByZXR1cm4gW3N0ciwgYWdlbnRzRmlsdGVyXTtcbiAgfVxuXG4gIC8qKlxuICAgKiBUaGlzIHBlcmZvcm1zIHRoZSByZW5kZXJpbmcgb2YgZ2l2ZW4gaGVhZGVyXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBwcmludGVyIHNlY3Rpb24gdGFyZ2V0XG4gICAqIEBwYXJhbSB7U3RyaW5nfSBzZWN0aW9uIHNlY3Rpb24gdGFyZ2V0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSB0YWIgdGFiIHRhcmdldFxuICAgKiBAcGFyYW0ge0Jvb2xlYW59IGlzQWdlbnRzIGlzIGFnZW50cyBzZWN0aW9uXG4gICAqIEBwYXJhbSB7U3RyaW5nfSBhcGlJZCBJRCBvZiBBUElcbiAgICovXG4gIHByaXZhdGUgYXN5bmMgcmVuZGVySGVhZGVyKGNvbnRleHQsIHByaW50ZXIsIHNlY3Rpb24sIHRhYiwgaXNBZ2VudHMsIGFwaUlkKSB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3JlcG9ydGluZzpyZW5kZXJIZWFkZXInLFxuICAgICAgICBgc2VjdGlvbjogJHtzZWN0aW9ufSwgdGFiOiAke3RhYn0sIGlzQWdlbnRzOiAke2lzQWdlbnRzfSwgYXBpSWQ6ICR7YXBpSWR9YCxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIGlmIChzZWN0aW9uICYmIHR5cGVvZiBzZWN0aW9uID09PSAnc3RyaW5nJykge1xuICAgICAgICBpZiAoIVsnYWdlbnRDb25maWcnLCAnZ3JvdXBDb25maWcnXS5pbmNsdWRlcyhzZWN0aW9uKSkge1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICB0ZXh0OiBXQVpVSF9NT0RVTEVTW3RhYl0udGl0bGUgKyAnIHJlcG9ydCcsXG4gICAgICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfSBlbHNlIGlmIChzZWN0aW9uID09PSAnYWdlbnRDb25maWcnKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6IGBBZ2VudCAke2lzQWdlbnRzfSBjb25maWd1cmF0aW9uYCxcbiAgICAgICAgICAgIHN0eWxlOiAnaDEnLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2UgaWYgKHNlY3Rpb24gPT09ICdncm91cENvbmZpZycpIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgdGV4dDogJ0FnZW50cyBpbiBncm91cCcsXG4gICAgICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGlzQWdlbnRzICYmIHR5cGVvZiBpc0FnZW50cyA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgYXdhaXQgYnVpbGRBZ2VudHNUYWJsZShcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIHByaW50ZXIsXG4gICAgICAgICAgaXNBZ2VudHMsXG4gICAgICAgICAgYXBpSWQsXG4gICAgICAgICAgc2VjdGlvbiA9PT0gJ2dyb3VwQ29uZmlnJyA/IHRhYiA6ICcnXG4gICAgICAgICk7XG4gICAgICB9XG5cbiAgICAgIGlmIChpc0FnZW50cyAmJiB0eXBlb2YgaXNBZ2VudHMgPT09ICdzdHJpbmcnKSB7XG4gICAgICAgIGNvbnN0IGFnZW50UmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICdHRVQnLFxuICAgICAgICAgIGAvYWdlbnRzYCxcbiAgICAgICAgICB7IHBhcmFtczogeyBhZ2VudHNfbGlzdDogaXNBZ2VudHMgfSB9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG4gICAgICAgIGNvbnN0IGFnZW50RGF0YSA9IGFnZW50UmVzcG9uc2UuZGF0YS5kYXRhLmFmZmVjdGVkX2l0ZW1zWzBdO1xuICAgICAgICBpZiAoYWdlbnREYXRhICYmIGFnZW50RGF0YS5zdGF0dXMgIT09IEFQSV9OQU1FX0FHRU5UX1NUQVRVUy5BQ1RJVkUpIHtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgICAgICB0ZXh0OiBgV2FybmluZy4gQWdlbnQgaXMgJHthZ2VudFN0YXR1c0xhYmVsQnlBZ2VudFN0YXR1cyhhZ2VudERhdGEuc3RhdHVzKS50b0xvd2VyQ2FzZSgpfWAsXG4gICAgICAgICAgICBzdHlsZTogJ3N0YW5kYXJkJyxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICBhd2FpdCBidWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIFtpc0FnZW50c10sIGFwaUlkKTtcblxuICAgICAgICBpZiAoYWdlbnREYXRhICYmIGFnZW50RGF0YS5ncm91cCkge1xuICAgICAgICAgIGNvbnN0IGFnZW50R3JvdXBzID0gYWdlbnREYXRhLmdyb3VwLmpvaW4oJywgJyk7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgICAgdGV4dDogYEdyb3VwJHthZ2VudERhdGEuZ3JvdXAubGVuZ3RoID4gMSA/ICdzJyA6ICcnfTogJHthZ2VudEdyb3Vwc31gLFxuICAgICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmIChXQVpVSF9NT0RVTEVTW3RhYl0gJiYgV0FaVUhfTU9EVUxFU1t0YWJdLmRlc2NyaXB0aW9uKSB7XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICB0ZXh0OiBXQVpVSF9NT0RVTEVTW3RhYl0uZGVzY3JpcHRpb24sXG4gICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpyZW5kZXJIZWFkZXInLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBnZXRDb25maWdSb3dzKGRhdGEsIGxhYmVscykge1xuICAgIGxvZygncmVwb3J0aW5nOmdldENvbmZpZ1Jvd3MnLCBgQnVpbGRpbmcgY29uZmlndXJhdGlvbiByb3dzYCwgJ2luZm8nKTtcbiAgICBjb25zdCByZXN1bHQgPSBbXTtcbiAgICBmb3IgKGxldCBwcm9wIGluIGRhdGEgfHwgW10pIHtcbiAgICAgIGlmIChBcnJheS5pc0FycmF5KGRhdGFbcHJvcF0pKSB7XG4gICAgICAgIGRhdGFbcHJvcF0uZm9yRWFjaCgoeCwgaWR4KSA9PiB7XG4gICAgICAgICAgaWYgKHR5cGVvZiB4ID09PSAnb2JqZWN0JykgZGF0YVtwcm9wXVtpZHhdID0gSlNPTi5zdHJpbmdpZnkoeCk7XG4gICAgICAgIH0pO1xuICAgICAgfVxuICAgICAgcmVzdWx0LnB1c2goWyhsYWJlbHMgfHwge30pW3Byb3BdIHx8IEtleUVxdWl2YWxlbmNlW3Byb3BdIHx8IHByb3AsIGRhdGFbcHJvcF0gfHwgJy0nXSk7XG4gICAgfVxuICAgIHJldHVybiByZXN1bHQ7XG4gIH1cblxuICBwcml2YXRlIGdldENvbmZpZ1RhYmxlcyhkYXRhLCBzZWN0aW9uLCB0YWIsIGFycmF5ID0gW10pIHtcbiAgICBsb2coJ3JlcG9ydGluZzpnZXRDb25maWdUYWJsZXMnLCBgQnVpbGRpbmcgY29uZmlndXJhdGlvbiB0YWJsZXNgLCAnaW5mbycpO1xuICAgIGxldCBwbGFpbkRhdGEgPSB7fTtcbiAgICBjb25zdCBuZXN0ZWREYXRhID0gW107XG4gICAgY29uc3QgdGFibGVEYXRhID0gW107XG5cbiAgICBpZiAoZGF0YS5sZW5ndGggPT09IDEgJiYgQXJyYXkuaXNBcnJheShkYXRhKSkge1xuICAgICAgdGFibGVEYXRhW3NlY3Rpb24uY29uZmlnW3RhYl0uY29uZmlndXJhdGlvbl0gPSBkYXRhO1xuICAgIH0gZWxzZSB7XG4gICAgICBmb3IgKGxldCBrZXkgaW4gZGF0YSkge1xuICAgICAgICBpZiAoXG4gICAgICAgICAgKHR5cGVvZiBkYXRhW2tleV0gIT09ICdvYmplY3QnICYmICFBcnJheS5pc0FycmF5KGRhdGFba2V5XSkpIHx8XG4gICAgICAgICAgKEFycmF5LmlzQXJyYXkoZGF0YVtrZXldKSAmJiB0eXBlb2YgZGF0YVtrZXldWzBdICE9PSAnb2JqZWN0JylcbiAgICAgICAgKSB7XG4gICAgICAgICAgcGxhaW5EYXRhW2tleV0gPVxuICAgICAgICAgICAgQXJyYXkuaXNBcnJheShkYXRhW2tleV0pICYmIHR5cGVvZiBkYXRhW2tleV1bMF0gIT09ICdvYmplY3QnXG4gICAgICAgICAgICAgID8gZGF0YVtrZXldLm1hcCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgcmV0dXJuIHR5cGVvZiB4ID09PSAnb2JqZWN0JyA/IEpTT04uc3RyaW5naWZ5KHgpIDogeCArICdcXG4nO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgIDogZGF0YVtrZXldO1xuICAgICAgICB9IGVsc2UgaWYgKEFycmF5LmlzQXJyYXkoZGF0YVtrZXldKSAmJiB0eXBlb2YgZGF0YVtrZXldWzBdID09PSAnb2JqZWN0Jykge1xuICAgICAgICAgIHRhYmxlRGF0YVtrZXldID0gZGF0YVtrZXldO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGlmIChzZWN0aW9uLmlzR3JvdXBDb25maWcgJiYgWydwYWNrJywgJ2NvbnRlbnQnXS5pbmNsdWRlcyhrZXkpKSB7XG4gICAgICAgICAgICB0YWJsZURhdGFba2V5XSA9IFtkYXRhW2tleV1dO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICBuZXN0ZWREYXRhLnB1c2goZGF0YVtrZXldKTtcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgYXJyYXkucHVzaCh7XG4gICAgICB0aXRsZTogKHNlY3Rpb24ub3B0aW9ucyB8fCB7fSkuaGlkZUhlYWRlclxuICAgICAgICA/ICcnXG4gICAgICAgIDogKHNlY3Rpb24udGFicyB8fCBbXSlbdGFiXSB8fFxuICAgICAgICAgIChzZWN0aW9uLmlzR3JvdXBDb25maWcgPyAoKHNlY3Rpb24ubGFiZWxzIHx8IFtdKVswXSB8fCBbXSlbdGFiXSA6ICcnKSxcbiAgICAgIGNvbHVtbnM6IFsnJywgJyddLFxuICAgICAgdHlwZTogJ2NvbmZpZycsXG4gICAgICByb3dzOiB0aGlzLmdldENvbmZpZ1Jvd3MocGxhaW5EYXRhLCAoc2VjdGlvbi5sYWJlbHMgfHwgW10pWzBdKSxcbiAgICB9KTtcbiAgICBmb3IgKGxldCBrZXkgaW4gdGFibGVEYXRhKSB7XG4gICAgICBjb25zdCBjb2x1bW5zID0gT2JqZWN0LmtleXModGFibGVEYXRhW2tleV1bMF0pO1xuICAgICAgY29sdW1ucy5mb3JFYWNoKChjb2wsIGkpID0+IHtcbiAgICAgICAgY29sdW1uc1tpXSA9IGNvbFswXS50b1VwcGVyQ2FzZSgpICsgY29sLnNsaWNlKDEpO1xuICAgICAgfSk7XG5cbiAgICAgIGNvbnN0IHJvd3MgPSB0YWJsZURhdGFba2V5XS5tYXAoKHgpID0+IHtcbiAgICAgICAgbGV0IHJvdyA9IFtdO1xuICAgICAgICBmb3IgKGxldCBrZXkgaW4geCkge1xuICAgICAgICAgIHJvdy5wdXNoKFxuICAgICAgICAgICAgdHlwZW9mIHhba2V5XSAhPT0gJ29iamVjdCdcbiAgICAgICAgICAgICAgPyB4W2tleV1cbiAgICAgICAgICAgICAgOiBBcnJheS5pc0FycmF5KHhba2V5XSlcbiAgICAgICAgICAgICAgPyB4W2tleV0ubWFwKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICByZXR1cm4geCArICdcXG4nO1xuICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgIDogSlNPTi5zdHJpbmdpZnkoeFtrZXldKVxuICAgICAgICAgICk7XG4gICAgICAgIH1cbiAgICAgICAgd2hpbGUgKHJvdy5sZW5ndGggPCBjb2x1bW5zLmxlbmd0aCkge1xuICAgICAgICAgIHJvdy5wdXNoKCctJyk7XG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIHJvdztcbiAgICAgIH0pO1xuICAgICAgYXJyYXkucHVzaCh7XG4gICAgICAgIHRpdGxlOiAoKHNlY3Rpb24ubGFiZWxzIHx8IFtdKVswXSB8fCBbXSlba2V5XSB8fCAnJyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgY29sdW1ucyxcbiAgICAgICAgcm93cyxcbiAgICAgIH0pO1xuICAgIH1cbiAgICBuZXN0ZWREYXRhLmZvckVhY2gobmVzdCA9PiB7XG4gICAgICB0aGlzLmdldENvbmZpZ1RhYmxlcyhuZXN0LCBzZWN0aW9uLCB0YWIgKyAxLCBhcnJheSk7XG4gICAgfSk7XG4gICAgcmV0dXJuIGFycmF5O1xuICB9XG5cbiAgLyoqXG4gICAqIENyZWF0ZSBhIHJlcG9ydCBmb3IgdGhlIG1vZHVsZXNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHsqfSByZXBvcnRzIGxpc3Qgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgY3JlYXRlUmVwb3J0c01vZHVsZXMgPSB0aGlzLmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IoYXN5bmMgKFxuICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LFxuICAgIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnlcbiAgKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNNb2R1bGVzJywgYFJlcG9ydCBzdGFydGVkYCwgJ2luZm8nKTtcbiAgICAgIGNvbnN0IHtcbiAgICAgICAgYXJyYXksXG4gICAgICAgIGFnZW50cyxcbiAgICAgICAgYnJvd3NlclRpbWV6b25lLFxuICAgICAgICBzZWFyY2hCYXIsXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIHRpbWUsXG4gICAgICAgIHRhYmxlcyxcbiAgICAgICAgc2VjdGlvbixcbiAgICAgICAgaW5kZXhQYXR0ZXJuVGl0bGUsXG4gICAgICAgIGFwaUlkXG4gICAgICB9ID0gcmVxdWVzdC5ib2R5O1xuICAgICAgY29uc3QgeyBtb2R1bGVJRCB9ID0gcmVxdWVzdC5wYXJhbXM7XG4gICAgICBjb25zdCB7IGZyb20sIHRvIH0gPSB0aW1lIHx8IHt9O1xuICAgICAgbGV0IGFkZGl0aW9uYWxUYWJsZXMgPSBbXTtcbiAgICAgIC8vIEluaXRcbiAgICAgIGNvbnN0IHByaW50ZXIgPSBuZXcgUmVwb3J0UHJpbnRlcigpO1xuXG4gICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMocGF0aC5qb2luKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgsIGNvbnRleHQud2F6dWhFbmRwb2ludFBhcmFtcy5oYXNoVXNlcm5hbWUpKTtcblxuICAgICAgYXdhaXQgdGhpcy5yZW5kZXJIZWFkZXIoY29udGV4dCwgcHJpbnRlciwgc2VjdGlvbiwgbW9kdWxlSUQsIGFnZW50cywgYXBpSWQpO1xuXG4gICAgICBjb25zdCBbc2FuaXRpemVkRmlsdGVycywgYWdlbnRzRmlsdGVyXSA9IGZpbHRlcnNcbiAgICAgICAgPyB0aGlzLnNhbml0aXplS2liYW5hRmlsdGVycyhmaWx0ZXJzLCBzZWFyY2hCYXIpXG4gICAgICAgIDogW2ZhbHNlLCBudWxsXTtcblxuICAgICAgaWYgKHRpbWUgJiYgc2FuaXRpemVkRmlsdGVycykge1xuICAgICAgICBwcmludGVyLmFkZFRpbWVSYW5nZUFuZEZpbHRlcnMoZnJvbSwgdG8sIHNhbml0aXplZEZpbHRlcnMsIGJyb3dzZXJUaW1lem9uZSk7XG4gICAgICB9XG5cbiAgICAgIGlmICh0aW1lKSB7XG4gICAgICAgIGFkZGl0aW9uYWxUYWJsZXMgPSBhd2FpdCBleHRlbmRlZEluZm9ybWF0aW9uKFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgcHJpbnRlcixcbiAgICAgICAgICBzZWN0aW9uLFxuICAgICAgICAgIG1vZHVsZUlELFxuICAgICAgICAgIGFwaUlkLFxuICAgICAgICAgIG5ldyBEYXRlKGZyb20pLmdldFRpbWUoKSxcbiAgICAgICAgICBuZXcgRGF0ZSh0bykuZ2V0VGltZSgpLFxuICAgICAgICAgIHNhbml0aXplZEZpbHRlcnMsXG4gICAgICAgICAgYWdlbnRzRmlsdGVyLFxuICAgICAgICAgIGluZGV4UGF0dGVyblRpdGxlLFxuICAgICAgICAgIGFnZW50c1xuICAgICAgICApO1xuICAgICAgfVxuXG4gICAgICBwcmludGVyLmFkZFZpc3VhbGl6YXRpb25zKGFycmF5LCBhZ2VudHMsIG1vZHVsZUlEKTtcblxuICAgICAgaWYgKHRhYmxlcykge1xuICAgICAgICBwcmludGVyLmFkZFRhYmxlcyhbLi4udGFibGVzLCAuLi4oYWRkaXRpb25hbFRhYmxlcyB8fCBbXSldKTtcbiAgICAgIH1cblxuICAgICAgLy9hZGQgYXV0aG9yaXplZCBhZ2VudHNcbiAgICAgIGlmIChhZ2VudHNGaWx0ZXI/LmFnZW50c1RleHQpIHtcbiAgICAgICAgcHJpbnRlci5hZGRBZ2VudHNGaWx0ZXJzKGFnZW50c0ZpbHRlci5hZ2VudHNUZXh0KTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgcHJpbnRlci5wcmludChjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMucGF0aEZpbGVuYW1lKTtcblxuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgICAgbWVzc2FnZTogYFJlcG9ydCAke2NvbnRleHQud2F6dWhFbmRwb2ludFBhcmFtcy5maWxlbmFtZX0gd2FzIGNyZWF0ZWRgLFxuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDUwMjksIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfSwoe2JvZHk6eyBhZ2VudHMgfSwgcGFyYW1zOiB7IG1vZHVsZUlEIH19KSA9PiBgd2F6dWgtbW9kdWxlLSR7YWdlbnRzID8gYGFnZW50cy0ke2FnZW50c31gIDogJ292ZXJ2aWV3J30tJHttb2R1bGVJRH0tJHt0aGlzLmdlbmVyYXRlUmVwb3J0VGltZXN0YW1wKCl9LnBkZmApXG5cbiAgLyoqXG4gICAqIENyZWF0ZSBhIHJlcG9ydCBmb3IgdGhlIGdyb3Vwc1xuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMgeyp9IHJlcG9ydHMgbGlzdCBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBjcmVhdGVSZXBvcnRzR3JvdXBzID0gdGhpcy5jaGVja1JlcG9ydHNVc2VyRGlyZWN0b3J5SXNWYWxpZFJvdXRlRGVjb3JhdG9yKGFzeW5jKFxuICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LFxuICAgIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnlcbiAgKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNHcm91cHMnLCBgUmVwb3J0IHN0YXJ0ZWRgLCAnaW5mbycpO1xuICAgICAgY29uc3QgeyBjb21wb25lbnRzLCBhcGlJZCB9ID0gcmVxdWVzdC5ib2R5O1xuICAgICAgY29uc3QgeyBncm91cElEIH0gPSByZXF1ZXN0LnBhcmFtcztcbiAgICAgIC8vIEluaXRcbiAgICAgIGNvbnN0IHByaW50ZXIgPSBuZXcgUmVwb3J0UHJpbnRlcigpO1xuXG4gICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMocGF0aC5qb2luKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgsIGNvbnRleHQud2F6dWhFbmRwb2ludFBhcmFtcy5oYXNoVXNlcm5hbWUpKTtcblxuICAgICAgbGV0IHRhYmxlcyA9IFtdO1xuICAgICAgY29uc3QgZXF1aXZhbGVuY2VzID0ge1xuICAgICAgICBsb2NhbGZpbGU6ICdMb2NhbCBmaWxlcycsXG4gICAgICAgIG9zcXVlcnk6ICdPc3F1ZXJ5JyxcbiAgICAgICAgY29tbWFuZDogJ0NvbW1hbmQnLFxuICAgICAgICBzeXNjaGVjazogJ1N5c2NoZWNrJyxcbiAgICAgICAgJ29wZW4tc2NhcCc6ICdPcGVuU0NBUCcsXG4gICAgICAgICdjaXMtY2F0JzogJ0NJUy1DQVQnLFxuICAgICAgICBzeXNjb2xsZWN0b3I6ICdTeXNjb2xsZWN0b3InLFxuICAgICAgICByb290Y2hlY2s6ICdSb290Y2hlY2snLFxuICAgICAgICBsYWJlbHM6ICdMYWJlbHMnLFxuICAgICAgICBzY2E6ICdTZWN1cml0eSBjb25maWd1cmF0aW9uIGFzc2Vzc21lbnQnLFxuICAgICAgfTtcbiAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgIHRleHQ6IGBHcm91cCAke2dyb3VwSUR9IGNvbmZpZ3VyYXRpb25gLFxuICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgIH0pO1xuXG4gICAgICAvLyBHcm91cCBjb25maWd1cmF0aW9uXG4gICAgICBpZiAoY29tcG9uZW50c1snMCddKSB7XG5cbiAgICAgICAgY29uc3QgeyBkYXRhOiB7IGRhdGE6IGNvbmZpZ3VyYXRpb24gfSB9ID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICBgL2dyb3Vwcy8ke2dyb3VwSUR9L2NvbmZpZ3VyYXRpb25gLFxuICAgICAgICAgIHt9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG5cbiAgICAgICAgaWYgKFxuICAgICAgICAgIGNvbmZpZ3VyYXRpb24uYWZmZWN0ZWRfaXRlbXMubGVuZ3RoID4gMCAmJlxuICAgICAgICAgIE9iamVjdC5rZXlzKGNvbmZpZ3VyYXRpb24uYWZmZWN0ZWRfaXRlbXNbMF0uY29uZmlnKS5sZW5ndGhcbiAgICAgICAgKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6ICdDb25maWd1cmF0aW9ucycsXG4gICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMTQsIGNvbG9yOiAnIzAwMCcgfSxcbiAgICAgICAgICAgIG1hcmdpbjogWzAsIDEwLCAwLCAxNV0sXG4gICAgICAgICAgfSk7XG4gICAgICAgICAgY29uc3Qgc2VjdGlvbiA9IHtcbiAgICAgICAgICAgIGxhYmVsczogW10sXG4gICAgICAgICAgICBpc0dyb3VwQ29uZmlnOiB0cnVlLFxuICAgICAgICAgIH07XG4gICAgICAgICAgZm9yIChsZXQgY29uZmlnIG9mIGNvbmZpZ3VyYXRpb24uYWZmZWN0ZWRfaXRlbXMpIHtcbiAgICAgICAgICAgIGxldCBmaWx0ZXJUaXRsZSA9ICcnO1xuICAgICAgICAgICAgbGV0IGluZGV4ID0gMDtcbiAgICAgICAgICAgIGZvciAobGV0IGZpbHRlciBvZiBPYmplY3Qua2V5cyhjb25maWcuZmlsdGVycykpIHtcbiAgICAgICAgICAgICAgZmlsdGVyVGl0bGUgPSBmaWx0ZXJUaXRsZS5jb25jYXQoYCR7ZmlsdGVyfTogJHtjb25maWcuZmlsdGVyc1tmaWx0ZXJdfWApO1xuICAgICAgICAgICAgICBpZiAoaW5kZXggPCBPYmplY3Qua2V5cyhjb25maWcuZmlsdGVycykubGVuZ3RoIC0gMSkge1xuICAgICAgICAgICAgICAgIGZpbHRlclRpdGxlID0gZmlsdGVyVGl0bGUuY29uY2F0KCcgfCAnKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBpbmRleCsrO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgICAgdGV4dDogZmlsdGVyVGl0bGUsXG4gICAgICAgICAgICAgIHN0eWxlOiAnaDQnLFxuICAgICAgICAgICAgICBtYXJnaW46IFswLCAwLCAwLCAxMF0sXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIGxldCBpZHggPSAwO1xuICAgICAgICAgICAgc2VjdGlvbi50YWJzID0gW107XG4gICAgICAgICAgICBmb3IgKGxldCBfZCBvZiBPYmplY3Qua2V5cyhjb25maWcuY29uZmlnKSkge1xuICAgICAgICAgICAgICBmb3IgKGxldCBjIG9mIEFnZW50Q29uZmlndXJhdGlvbi5jb25maWd1cmF0aW9ucykge1xuICAgICAgICAgICAgICAgIGZvciAobGV0IHMgb2YgYy5zZWN0aW9ucykge1xuICAgICAgICAgICAgICAgICAgc2VjdGlvbi5vcHRzID0gcy5vcHRzIHx8IHt9O1xuICAgICAgICAgICAgICAgICAgZm9yIChsZXQgY24gb2Ygcy5jb25maWcgfHwgW10pIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKGNuLmNvbmZpZ3VyYXRpb24gPT09IF9kKSB7XG4gICAgICAgICAgICAgICAgICAgICAgc2VjdGlvbi5sYWJlbHMgPSBzLmxhYmVscyB8fCBbW11dO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICBmb3IgKGxldCB3byBvZiBzLndvZGxlIHx8IFtdKSB7XG4gICAgICAgICAgICAgICAgICAgIGlmICh3by5uYW1lID09PSBfZCkge1xuICAgICAgICAgICAgICAgICAgICAgIHNlY3Rpb24ubGFiZWxzID0gcy5sYWJlbHMgfHwgW1tdXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBzZWN0aW9uLmxhYmVsc1swXVsncGFjayddID0gJ1BhY2tzJztcbiAgICAgICAgICAgICAgc2VjdGlvbi5sYWJlbHNbMF1bJ2NvbnRlbnQnXSA9ICdFdmFsdWF0aW9ucyc7XG4gICAgICAgICAgICAgIHNlY3Rpb24ubGFiZWxzWzBdWyc3J10gPSAnU2NhbiBsaXN0ZW5pbmcgbmV0d290ayBwb3J0cyc7XG4gICAgICAgICAgICAgIHNlY3Rpb24udGFicy5wdXNoKGVxdWl2YWxlbmNlc1tfZF0pO1xuXG4gICAgICAgICAgICAgIGlmIChBcnJheS5pc0FycmF5KGNvbmZpZy5jb25maWdbX2RdKSkge1xuICAgICAgICAgICAgICAgIC8qIExPRyBDT0xMRUNUT1IgKi9cbiAgICAgICAgICAgICAgICBpZiAoX2QgPT09ICdsb2NhbGZpbGUnKSB7XG4gICAgICAgICAgICAgICAgICBsZXQgZ3JvdXBzID0gW107XG4gICAgICAgICAgICAgICAgICBjb25maWcuY29uZmlnW19kXS5mb3JFYWNoKChvYmopID0+IHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKCFncm91cHNbb2JqLmxvZ2Zvcm1hdF0pIHtcbiAgICAgICAgICAgICAgICAgICAgICBncm91cHNbb2JqLmxvZ2Zvcm1hdF0gPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICBncm91cHNbb2JqLmxvZ2Zvcm1hdF0ucHVzaChvYmopO1xuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBPYmplY3Qua2V5cyhncm91cHMpLmZvckVhY2goKGdyb3VwKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGxldCBzYXZlaWR4ID0gMDtcbiAgICAgICAgICAgICAgICAgICAgZ3JvdXBzW2dyb3VwXS5mb3JFYWNoKCh4LCBpKSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgaWYgKE9iamVjdC5rZXlzKHgpLmxlbmd0aCA+IE9iamVjdC5rZXlzKGdyb3Vwc1tncm91cF1bc2F2ZWlkeF0pLmxlbmd0aCkge1xuICAgICAgICAgICAgICAgICAgICAgICAgc2F2ZWlkeCA9IGk7XG4gICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgY29uc3QgY29sdW1ucyA9IE9iamVjdC5rZXlzKGdyb3Vwc1tncm91cF1bc2F2ZWlkeF0pO1xuICAgICAgICAgICAgICAgICAgICBjb25zdCByb3dzID0gZ3JvdXBzW2dyb3VwXS5tYXAoKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICBsZXQgcm93ID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKChrZXkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKFxuICAgICAgICAgICAgICAgICAgICAgICAgICB0eXBlb2YgeFtrZXldICE9PSAnb2JqZWN0J1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgID8geFtrZXldXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgOiBBcnJheS5pc0FycmF5KHhba2V5XSlcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICA/IHhba2V5XS5tYXAoKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHggKyAnXFxuJztcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgOiBKU09OLnN0cmluZ2lmeSh4W2tleV0pXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgIHJldHVybiByb3c7XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKGNvbCwgaSkgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnNbaV0gPSBjb2xbMF0udG9VcHBlckNhc2UoKSArIGNvbC5zbGljZSgxKTtcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKHtcbiAgICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ0xvY2FsIGZpbGVzJyxcbiAgICAgICAgICAgICAgICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMsXG4gICAgICAgICAgICAgICAgICAgICAgcm93cyxcbiAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKF9kID09PSAnbGFiZWxzJykge1xuICAgICAgICAgICAgICAgICAgY29uc3Qgb2JqID0gY29uZmlnLmNvbmZpZ1tfZF1bMF0ubGFiZWw7XG4gICAgICAgICAgICAgICAgICBjb25zdCBjb2x1bW5zID0gT2JqZWN0LmtleXMob2JqWzBdKTtcbiAgICAgICAgICAgICAgICAgIGlmICghY29sdW1ucy5pbmNsdWRlcygnaGlkZGVuJykpIHtcbiAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5wdXNoKCdoaWRkZW4nKTtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIGNvbnN0IHJvd3MgPSBvYmoubWFwKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgIGxldCByb3cgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKChrZXkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICByb3cucHVzaCh4W2tleV0pO1xuICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJvdztcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKChjb2wsIGkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgY29sdW1uc1tpXSA9IGNvbFswXS50b1VwcGVyQ2FzZSgpICsgY29sLnNsaWNlKDEpO1xuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgICAgIHRpdGxlOiAnTGFiZWxzJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgICAgICAgICAgICAgY29sdW1ucyxcbiAgICAgICAgICAgICAgICAgICAgcm93cyxcbiAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICBmb3IgKGxldCBfZDIgb2YgY29uZmlnLmNvbmZpZ1tfZF0pIHtcbiAgICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goLi4udGhpcy5nZXRDb25maWdUYWJsZXMoX2QyLCBzZWN0aW9uLCBpZHgpKTtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgLypJTlRFR1JJVFkgTU9OSVRPUklORyBNT05JVE9SRUQgRElSRUNUT1JJRVMgKi9cbiAgICAgICAgICAgICAgICBpZiAoY29uZmlnLmNvbmZpZ1tfZF0uZGlyZWN0b3JpZXMpIHtcbiAgICAgICAgICAgICAgICAgIGNvbnN0IGRpcmVjdG9yaWVzID0gY29uZmlnLmNvbmZpZ1tfZF0uZGlyZWN0b3JpZXM7XG4gICAgICAgICAgICAgICAgICBkZWxldGUgY29uZmlnLmNvbmZpZ1tfZF0uZGlyZWN0b3JpZXM7XG4gICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaCguLi50aGlzLmdldENvbmZpZ1RhYmxlcyhjb25maWcuY29uZmlnW19kXSwgc2VjdGlvbiwgaWR4KSk7XG4gICAgICAgICAgICAgICAgICBsZXQgZGlmZk9wdHMgPSBbXTtcbiAgICAgICAgICAgICAgICAgIE9iamVjdC5rZXlzKHNlY3Rpb24ub3B0cykuZm9yRWFjaCgoeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBkaWZmT3B0cy5wdXNoKHgpO1xuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBjb25zdCBjb2x1bW5zID0gW1xuICAgICAgICAgICAgICAgICAgICAnJyxcbiAgICAgICAgICAgICAgICAgICAgLi4uZGlmZk9wdHMuZmlsdGVyKCh4KSA9PiB4ICE9PSAnY2hlY2tfYWxsJyAmJiB4ICE9PSAnY2hlY2tfc3VtJyksXG4gICAgICAgICAgICAgICAgICBdO1xuICAgICAgICAgICAgICAgICAgbGV0IHJvd3MgPSBbXTtcbiAgICAgICAgICAgICAgICAgIGRpcmVjdG9yaWVzLmZvckVhY2goKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgbGV0IHJvdyA9IFtdO1xuICAgICAgICAgICAgICAgICAgICByb3cucHVzaCh4LnBhdGgpO1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKHkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICBpZiAoeSAhPT0gJycpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHkgPSB5ICE9PSAnY2hlY2tfd2hvZGF0YScgPyB5IDogJ3dob2RhdGEnO1xuICAgICAgICAgICAgICAgICAgICAgICAgcm93LnB1c2goeFt5XSA/IHhbeV0gOiAnbm8nKTtcbiAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICByb3cucHVzaCh4LnJlY3Vyc2lvbl9sZXZlbCk7XG4gICAgICAgICAgICAgICAgICAgIHJvd3MucHVzaChyb3cpO1xuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKHgsIGlkeCkgPT4ge1xuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zW2lkeF0gPSBzZWN0aW9uLm9wdHNbeF07XG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIGNvbHVtbnMucHVzaCgnUkwnKTtcbiAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKHtcbiAgICAgICAgICAgICAgICAgICAgdGl0bGU6ICdNb25pdG9yZWQgZGlyZWN0b3JpZXMnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLFxuICAgICAgICAgICAgICAgICAgICByb3dzLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKC4uLnRoaXMuZ2V0Q29uZmlnVGFibGVzKGNvbmZpZy5jb25maWdbX2RdLCBzZWN0aW9uLCBpZHgpKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgZm9yIChjb25zdCB0YWJsZSBvZiB0YWJsZXMpIHtcbiAgICAgICAgICAgICAgICBwcmludGVyLmFkZENvbmZpZ1RhYmxlcyhbdGFibGVdKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBpZHgrKztcbiAgICAgICAgICAgICAgdGFibGVzID0gW107XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB0YWJsZXMgPSBbXTtcbiAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6ICdBIGNvbmZpZ3VyYXRpb24gZm9yIHRoaXMgZ3JvdXAgaGFzIG5vdCB5ZXQgYmVlbiBzZXQgdXAuJyxcbiAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAxMiwgY29sb3I6ICcjMDAwJyB9LFxuICAgICAgICAgICAgbWFyZ2luOiBbMCwgMTAsIDAsIDE1XSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICAvLyBBZ2VudHMgaW4gZ3JvdXBcbiAgICAgIGlmIChjb21wb25lbnRzWycxJ10pIHtcbiAgICAgICAgYXdhaXQgdGhpcy5yZW5kZXJIZWFkZXIoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBwcmludGVyLFxuICAgICAgICAgICdncm91cENvbmZpZycsXG4gICAgICAgICAgZ3JvdXBJRCxcbiAgICAgICAgICBbXSxcbiAgICAgICAgICBhcGlJZFxuICAgICAgICApO1xuICAgICAgfVxuXG4gICAgICBhd2FpdCBwcmludGVyLnByaW50KGNvbnRleHQud2F6dWhFbmRwb2ludFBhcmFtcy5wYXRoRmlsZW5hbWUpO1xuXG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7XG4gICAgICAgICAgc3VjY2VzczogdHJ1ZSxcbiAgICAgICAgICBtZXNzYWdlOiBgUmVwb3J0ICR7Y29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLmZpbGVuYW1lfSB3YXMgY3JlYXRlZGAsXG4gICAgICAgIH0sXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0dyb3VwcycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAyOSwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9LCAoe3BhcmFtczogeyBncm91cElEIH19KSA9PiBgd2F6dWgtZ3JvdXAtY29uZmlndXJhdGlvbi0ke2dyb3VwSUR9LSR7dGhpcy5nZW5lcmF0ZVJlcG9ydFRpbWVzdGFtcCgpfS5wZGZgKVxuXG4gIC8qKlxuICAgKiBDcmVhdGUgYSByZXBvcnQgZm9yIHRoZSBhZ2VudHNcbiAgICogQHBhcmFtIHtPYmplY3R9IGNvbnRleHRcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlcXVlc3RcbiAgICogQHBhcmFtIHtPYmplY3R9IHJlc3BvbnNlXG4gICAqIEByZXR1cm5zIHsqfSByZXBvcnRzIGxpc3Qgb3IgRXJyb3JSZXNwb25zZVxuICAgKi9cbiAgY3JlYXRlUmVwb3J0c0FnZW50c0NvbmZpZ3VyYXRpb24gPSB0aGlzLmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IoIGFzeW5jIChcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogS2liYW5hUmVxdWVzdCxcbiAgICByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5XG4gICkgPT4ge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzQ29uZmlndXJhdGlvbicsIGBSZXBvcnQgc3RhcnRlZGAsICdpbmZvJyk7XG4gICAgICBjb25zdCB7IGNvbXBvbmVudHMsIGFwaUlkIH0gPSByZXF1ZXN0LmJvZHk7XG4gICAgICBjb25zdCB7IGFnZW50SUQgfSA9IHJlcXVlc3QucGFyYW1zO1xuXG4gICAgICBjb25zdCBwcmludGVyID0gbmV3IFJlcG9ydFByaW50ZXIoKTtcbiAgICAgIGNyZWF0ZURhdGFEaXJlY3RvcnlJZk5vdEV4aXN0cygpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY3JlYXRlRGlyZWN0b3J5SWZOb3RFeGlzdHMoV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLmhhc2hVc2VybmFtZSkpO1xuXG4gICAgICBsZXQgd21vZHVsZXNSZXNwb25zZSA9IHt9O1xuICAgICAgbGV0IHRhYmxlcyA9IFtdO1xuICAgICAgdHJ5IHtcbiAgICAgICAgd21vZHVsZXNSZXNwb25zZSA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgYC9hZ2VudHMvJHthZ2VudElEfS9jb25maWcvd21vZHVsZXMvd21vZHVsZXNgLFxuICAgICAgICAgIHt9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpyZXBvcnQnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAnZGVidWcnKTtcbiAgICAgIH1cblxuICAgICAgYXdhaXQgdGhpcy5yZW5kZXJIZWFkZXIoY29udGV4dCwgcHJpbnRlciwgJ2FnZW50Q29uZmlnJywgJ2FnZW50Q29uZmlnJywgYWdlbnRJRCwgYXBpSWQpO1xuXG4gICAgICBsZXQgaWR4Q29tcG9uZW50ID0gMDtcbiAgICAgIGZvciAobGV0IGNvbmZpZyBvZiBBZ2VudENvbmZpZ3VyYXRpb24uY29uZmlndXJhdGlvbnMpIHtcbiAgICAgICAgbGV0IHRpdGxlT2ZTZWN0aW9uID0gZmFsc2U7XG4gICAgICAgIGxvZyhcbiAgICAgICAgICAncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHNDb25maWd1cmF0aW9uJyxcbiAgICAgICAgICBgSXRlcmF0ZSBvdmVyICR7Y29uZmlnLnNlY3Rpb25zLmxlbmd0aH0gY29uZmlndXJhdGlvbiBzZWN0aW9uc2AsXG4gICAgICAgICAgJ2RlYnVnJ1xuICAgICAgICApO1xuICAgICAgICBmb3IgKGxldCBzZWN0aW9uIG9mIGNvbmZpZy5zZWN0aW9ucykge1xuICAgICAgICAgIGxldCB0aXRsZU9mU3Vic2VjdGlvbiA9IGZhbHNlO1xuICAgICAgICAgIGlmIChcbiAgICAgICAgICAgIGNvbXBvbmVudHNbaWR4Q29tcG9uZW50XSAmJlxuICAgICAgICAgICAgKHNlY3Rpb24uY29uZmlnIHx8IHNlY3Rpb24ud29kbGUpXG4gICAgICAgICAgKSB7XG4gICAgICAgICAgICBsZXQgaWR4ID0gMDtcbiAgICAgICAgICAgIGNvbnN0IGNvbmZpZ3MgPSAoc2VjdGlvbi5jb25maWcgfHwgW10pLmNvbmNhdChzZWN0aW9uLndvZGxlIHx8IFtdKTtcbiAgICAgICAgICAgIGxvZyhcbiAgICAgICAgICAgICAgJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzQ29uZmlndXJhdGlvbicsXG4gICAgICAgICAgICAgIGBJdGVyYXRlIG92ZXIgJHtjb25maWdzLmxlbmd0aH0gY29uZmlndXJhdGlvbiBibG9ja3NgLFxuICAgICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgICApO1xuICAgICAgICAgICAgZm9yIChsZXQgY29uZiBvZiBjb25maWdzKSB7XG4gICAgICAgICAgICAgIGxldCBhZ2VudENvbmZpZ1Jlc3BvbnNlID0ge307XG4gICAgICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICAgICAgaWYgKCFjb25mWyduYW1lJ10pIHtcbiAgICAgICAgICAgICAgICAgIGFnZW50Q29uZmlnUmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgICAgICAgICAgYC9hZ2VudHMvJHthZ2VudElEfS9jb25maWcvJHtjb25mLmNvbXBvbmVudH0vJHtjb25mLmNvbmZpZ3VyYXRpb259YCxcbiAgICAgICAgICAgICAgICAgICAge30sXG4gICAgICAgICAgICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICBmb3IgKGxldCB3b2RsZSBvZiB3bW9kdWxlc1Jlc3BvbnNlLmRhdGEuZGF0YVsnd21vZHVsZXMnXSkge1xuICAgICAgICAgICAgICAgICAgICBpZiAoT2JqZWN0LmtleXMod29kbGUpWzBdID09PSBjb25mWyduYW1lJ10pIHtcbiAgICAgICAgICAgICAgICAgICAgICBhZ2VudENvbmZpZ1Jlc3BvbnNlLmRhdGEgPSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBkYXRhOiB3b2RsZSxcbiAgICAgICAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgY29uc3QgYWdlbnRDb25maWcgPVxuICAgICAgICAgICAgICAgICAgYWdlbnRDb25maWdSZXNwb25zZSAmJiBhZ2VudENvbmZpZ1Jlc3BvbnNlLmRhdGEgJiYgYWdlbnRDb25maWdSZXNwb25zZS5kYXRhLmRhdGE7XG4gICAgICAgICAgICAgICAgaWYgKCF0aXRsZU9mU2VjdGlvbikge1xuICAgICAgICAgICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgICAgICAgICAgdGV4dDogY29uZmlnLnRpdGxlLFxuICAgICAgICAgICAgICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbMCwgMCwgMCwgMTVdLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICB0aXRsZU9mU2VjdGlvbiA9IHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghdGl0bGVPZlN1YnNlY3Rpb24pIHtcbiAgICAgICAgICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICAgICAgICAgIHRleHQ6IHNlY3Rpb24uc3VidGl0bGUsXG4gICAgICAgICAgICAgICAgICAgIHN0eWxlOiAnaDQnLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgICAgICAgICAgICB0ZXh0OiBzZWN0aW9uLmRlc2MsXG4gICAgICAgICAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAxMiwgY29sb3I6ICcjMDAwJyB9LFxuICAgICAgICAgICAgICAgICAgICBtYXJnaW46IFswLCAwLCAwLCAxMF0sXG4gICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgIHRpdGxlT2ZTdWJzZWN0aW9uID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgaWYgKGFnZW50Q29uZmlnKSB7XG4gICAgICAgICAgICAgICAgICBmb3IgKGxldCBhZ2VudENvbmZpZ0tleSBvZiBPYmplY3Qua2V5cyhhZ2VudENvbmZpZykpIHtcbiAgICAgICAgICAgICAgICAgICAgaWYgKEFycmF5LmlzQXJyYXkoYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldKSkge1xuICAgICAgICAgICAgICAgICAgICAgIC8qIExPRyBDT0xMRUNUT1IgKi9cbiAgICAgICAgICAgICAgICAgICAgICBpZiAoY29uZi5maWx0ZXJCeSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgbGV0IGdyb3VwcyA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldLmZvckVhY2goKG9iaikgPT4ge1xuICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoIWdyb3Vwc1tvYmoubG9nZm9ybWF0XSkge1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tvYmoubG9nZm9ybWF0XSA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGdyb3Vwc1tvYmoubG9nZm9ybWF0XS5wdXNoKG9iaik7XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIE9iamVjdC5rZXlzKGdyb3VwcykuZm9yRWFjaCgoZ3JvdXApID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgbGV0IHNhdmVpZHggPSAwO1xuICAgICAgICAgICAgICAgICAgICAgICAgICBncm91cHNbZ3JvdXBdLmZvckVhY2goKHgsIGkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICBPYmplY3Qua2V5cyh4KS5sZW5ndGggPiBPYmplY3Qua2V5cyhncm91cHNbZ3JvdXBdW3NhdmVpZHhdKS5sZW5ndGhcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICApIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHNhdmVpZHggPSBpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGNvbnN0IGNvbHVtbnMgPSBPYmplY3Qua2V5cyhncm91cHNbZ3JvdXBdW3NhdmVpZHhdKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc3Qgcm93cyA9IGdyb3Vwc1tncm91cF0ubWFwKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgbGV0IHJvdyA9IFtdO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoa2V5KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICByb3cucHVzaChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdHlwZW9mIHhba2V5XSAhPT0gJ29iamVjdCdcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICA/IHhba2V5XVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogQXJyYXkuaXNBcnJheSh4W2tleV0pXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgPyB4W2tleV0ubWFwKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiB4ICsgJ1xcbic7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDogSlNPTi5zdHJpbmdpZnkoeFtrZXldKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gcm93O1xuICAgICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5mb3JFYWNoKChjb2wsIGkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zW2ldID0gY29sWzBdLnRvVXBwZXJDYXNlKCkgKyBjb2wuc2xpY2UoMSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaCh7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdGl0bGU6IHNlY3Rpb24ubGFiZWxzWzBdW2dyb3VwXSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgcm93cyxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGFnZW50Q29uZmlnS2V5LmNvbmZpZ3VyYXRpb24gIT09ICdzb2NrZXQnKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICB0YWJsZXMucHVzaChcbiAgICAgICAgICAgICAgICAgICAgICAgICAgLi4udGhpcy5nZXRDb25maWdUYWJsZXMoYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldLCBzZWN0aW9uLCBpZHgpXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBmb3IgKGxldCBfZDIgb2YgYWdlbnRDb25maWdbYWdlbnRDb25maWdLZXldKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKC4uLnRoaXMuZ2V0Q29uZmlnVGFibGVzKF9kMiwgc2VjdGlvbiwgaWR4KSk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgIC8qSU5URUdSSVRZIE1PTklUT1JJTkcgTU9OSVRPUkVEIERJUkVDVE9SSUVTICovXG4gICAgICAgICAgICAgICAgICAgICAgaWYgKGNvbmYubWF0cml4KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICBjb25zdCB7ZGlyZWN0b3JpZXMsZGlmZixzeW5jaHJvbml6YXRpb24sZmlsZV9saW1pdCwuLi5yZXN0fSA9IGFnZW50Q29uZmlnW2FnZW50Q29uZmlnS2V5XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIHRhYmxlcy5wdXNoKFxuICAgICAgICAgICAgICAgICAgICAgICAgICAuLi50aGlzLmdldENvbmZpZ1RhYmxlcyhyZXN0LCBzZWN0aW9uLCBpZHgpLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAuLi4oZGlmZiAmJiBkaWZmLmRpc2tfcXVvdGEgPyB0aGlzLmdldENvbmZpZ1RhYmxlcyhkaWZmLmRpc2tfcXVvdGEsIHt0YWJzOlsnRGlzayBxdW90YSddfSwgMCApOiBbXSksXG4gICAgICAgICAgICAgICAgICAgICAgICAgIC4uLihkaWZmICYmIGRpZmYuZmlsZV9zaXplID8gdGhpcy5nZXRDb25maWdUYWJsZXMoZGlmZi5maWxlX3NpemUsIHt0YWJzOlsnRmlsZSBzaXplJ119LCAwICk6IFtdKSxcbiAgICAgICAgICAgICAgICAgICAgICAgICAgLi4uKHN5bmNocm9uaXphdGlvbiA/IHRoaXMuZ2V0Q29uZmlnVGFibGVzKHN5bmNocm9uaXphdGlvbiwge3RhYnM6WydTeW5jaHJvbml6YXRpb24nXX0sIDAgKTogW10pLFxuICAgICAgICAgICAgICAgICAgICAgICAgICAuLi4oZmlsZV9saW1pdCA/IHRoaXMuZ2V0Q29uZmlnVGFibGVzKGZpbGVfbGltaXQsIHt0YWJzOlsnRmlsZSBsaW1pdCddfSwgMCApOiBbXSksXG4gICAgICAgICAgICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgICAgICAgICAgICAgbGV0IGRpZmZPcHRzID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICBPYmplY3Qua2V5cyhzZWN0aW9uLm9wdHMpLmZvckVhY2goKHgpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgZGlmZk9wdHMucHVzaCh4KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgY29uc3QgY29sdW1ucyA9IFtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgJycsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIC4uLmRpZmZPcHRzLmZpbHRlcigoeCkgPT4geCAhPT0gJ2NoZWNrX2FsbCcgJiYgeCAhPT0gJ2NoZWNrX3N1bScpLFxuICAgICAgICAgICAgICAgICAgICAgICAgXTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGxldCByb3dzID0gW107XG4gICAgICAgICAgICAgICAgICAgICAgICBkaXJlY3Rvcmllcy5mb3JFYWNoKCh4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGxldCByb3cgPSBbXTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgcm93LnB1c2goeC5kaXIpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICBjb2x1bW5zLmZvckVhY2goKHkpID0+IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBpZiAoeSAhPT0gJycpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHgub3B0cy5pbmRleE9mKHkpID4gLTEgPyAneWVzJyA6ICdubycpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIHJvdy5wdXNoKHgucmVjdXJzaW9uX2xldmVsKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgcm93cy5wdXNoKHJvdyk7XG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMuZm9yRWFjaCgoeCwgaWR4KSA9PiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnNbaWR4XSA9IHNlY3Rpb24ub3B0c1t4XTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICAgICAgICAgICAgY29sdW1ucy5wdXNoKCdSTCcpO1xuICAgICAgICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goe1xuICAgICAgICAgICAgICAgICAgICAgICAgICB0aXRsZTogJ01vbml0b3JlZCBkaXJlY3RvcmllcycsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIGNvbHVtbnMsXG4gICAgICAgICAgICAgICAgICAgICAgICAgIHJvd3MsXG4gICAgICAgICAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGFibGVzLnB1c2goXG4gICAgICAgICAgICAgICAgICAgICAgICAgIC4uLnRoaXMuZ2V0Q29uZmlnVGFibGVzKGFnZW50Q29uZmlnW2FnZW50Q29uZmlnS2V5XSwgc2VjdGlvbiwgaWR4KVxuICAgICAgICAgICAgICAgICAgICAgICAgKTtcbiAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgLy8gUHJpbnQgbm8gY29uZmlndXJlZCBtb2R1bGUgYW5kIGxpbmsgdG8gdGhlIGRvY3VtZW50YXRpb25cbiAgICAgICAgICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICAgICAgICAgIHRleHQ6IFtcbiAgICAgICAgICAgICAgICAgICAgICAnVGhpcyBtb2R1bGUgaXMgbm90IGNvbmZpZ3VyZWQuIFBsZWFzZSB0YWtlIGEgbG9vayBvbiBob3cgdG8gY29uZmlndXJlIGl0IGluICcsXG4gICAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgICAgdGV4dDogYCR7c2VjdGlvbi5zdWJ0aXRsZS50b0xvd2VyQ2FzZSgpfSBjb25maWd1cmF0aW9uLmAsXG4gICAgICAgICAgICAgICAgICAgICAgICBsaW5rOiBzZWN0aW9uLmRvY3VMaW5rLFxuICAgICAgICAgICAgICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDEyLCBjb2xvcjogJyMxYTBkYWInIH0sXG4gICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgICAgICAgICAgbWFyZ2luOiBbMCwgMCwgMCwgMjBdLFxuICAgICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgICAgIGxvZygncmVwb3J0aW5nOnJlcG9ydCcsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsICdkZWJ1ZycpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGlkeCsrO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgZm9yIChjb25zdCB0YWJsZSBvZiB0YWJsZXMpIHtcbiAgICAgICAgICAgICAgcHJpbnRlci5hZGRDb25maWdUYWJsZXMoW3RhYmxlXSk7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICAgIGlkeENvbXBvbmVudCsrO1xuICAgICAgICAgIHRhYmxlcyA9IFtdO1xuICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGF3YWl0IHByaW50ZXIucHJpbnQoY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLnBhdGhGaWxlbmFtZSk7XG5cbiAgICAgIHJldHVybiByZXNwb25zZS5vayh7XG4gICAgICAgIGJvZHk6IHtcbiAgICAgICAgICBzdWNjZXNzOiB0cnVlLFxuICAgICAgICAgIG1lc3NhZ2U6IGBSZXBvcnQgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMuZmlsZW5hbWV9IHdhcyBjcmVhdGVkYCxcbiAgICAgICAgfSxcbiAgICAgIH0pO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzQ29uZmlndXJhdGlvbicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAyOSwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9LCAoeyBwYXJhbXM6IHsgYWdlbnRJRCB9fSkgPT4gYHdhenVoLWFnZW50LWNvbmZpZ3VyYXRpb24tJHthZ2VudElEfS0ke3RoaXMuZ2VuZXJhdGVSZXBvcnRUaW1lc3RhbXAoKX0ucGRmYClcblxuICAvKipcbiAgICogQ3JlYXRlIGEgcmVwb3J0IGZvciB0aGUgYWdlbnRzXG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7Kn0gcmVwb3J0cyBsaXN0IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnkgPSB0aGlzLmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IoIGFzeW5jIChcbiAgICBjb250ZXh0OiBSZXF1ZXN0SGFuZGxlckNvbnRleHQsXG4gICAgcmVxdWVzdDogS2liYW5hUmVxdWVzdCxcbiAgICByZXNwb25zZTogS2liYW5hUmVzcG9uc2VGYWN0b3J5XG4gICkgPT4ge1xuICAgIHRyeSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzSW52ZW50b3J5JywgYFJlcG9ydCBzdGFydGVkYCwgJ2luZm8nKTtcbiAgICAgIGNvbnN0IHsgc2VhcmNoQmFyLCBmaWx0ZXJzLCB0aW1lLCBpbmRleFBhdHRlcm5UaXRsZSwgYXBpSWQgfSA9IHJlcXVlc3QuYm9keTtcbiAgICAgIGNvbnN0IHsgYWdlbnRJRCB9ID0gcmVxdWVzdC5wYXJhbXM7XG4gICAgICBjb25zdCB7IGZyb20sIHRvIH0gPSB0aW1lIHx8IHt9O1xuICAgICAgLy8gSW5pdFxuICAgICAgY29uc3QgcHJpbnRlciA9IG5ldyBSZXBvcnRQcmludGVyKCk7XG5cbiAgICAgIGNvbnN0IHsgaGFzaFVzZXJuYW1lIH0gPSBhd2FpdCBjb250ZXh0LndhenVoLnNlY3VyaXR5LmdldEN1cnJlbnRVc2VyKHJlcXVlc3QsIGNvbnRleHQpO1xuICAgICAgY3JlYXRlRGF0YURpcmVjdG9yeUlmTm90RXhpc3RzKCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhXQVpVSF9EQVRBX0RPV05MT0FEU19ESVJFQ1RPUllfUEFUSCk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyhXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKHBhdGguam9pbihXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRILCBoYXNoVXNlcm5hbWUpKTtcblxuICAgICAgbG9nKCdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50c0ludmVudG9yeScsIGBTeXNjb2xsZWN0b3IgcmVwb3J0YCwgJ2RlYnVnJyk7XG4gICAgICBjb25zdCBbc2FuaXRpemVkRmlsdGVycywgYWdlbnRzRmlsdGVyXSA9IGZpbHRlcnMgPyB0aGlzLnNhbml0aXplS2liYW5hRmlsdGVycyhmaWx0ZXJzLCBzZWFyY2hCYXIpIDogW2ZhbHNlLCBudWxsXTtcblxuICAgICAgLy8gR2V0IHRoZSBhZ2VudCBPU1xuICAgICAgbGV0IGFnZW50T3MgPSAnJztcbiAgICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGFnZW50UmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICdHRVQnLFxuICAgICAgICAgICcvYWdlbnRzJyxcbiAgICAgICAgICB7IHBhcmFtczogeyBxOiBgaWQ9JHthZ2VudElEfWAgfSB9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG4gICAgICAgIGFnZW50T3MgPSBhZ2VudFJlc3BvbnNlLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXS5vcy5wbGF0Zm9ybTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHNJbnZlbnRvcnknLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yLCAnZGVidWcnKTtcbiAgICAgIH1cblxuICAgICAgLy8gQWRkIHRpdGxlXG4gICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgIHRleHQ6ICdJbnZlbnRvcnkgZGF0YSByZXBvcnQnLFxuICAgICAgICBzdHlsZTogJ2gxJyxcbiAgICAgIH0pO1xuXG4gICAgICAvLyBBZGQgdGFibGUgd2l0aCB0aGUgYWdlbnQgaW5mb1xuICAgICAgYXdhaXQgYnVpbGRBZ2VudHNUYWJsZShjb250ZXh0LCBwcmludGVyLCBbYWdlbnRJRF0sIGFwaUlkKTtcblxuICAgICAgLy8gR2V0IHN5c2NvbGxlY3RvciBwYWNrYWdlcyBhbmQgcHJvY2Vzc2VzXG4gICAgICBjb25zdCBhZ2VudFJlcXVlc3RzSW52ZW50b3J5ID0gW1xuICAgICAgICB7XG4gICAgICAgICAgZW5kcG9pbnQ6IGAvc3lzY29sbGVjdG9yLyR7YWdlbnRJRH0vcGFja2FnZXNgLFxuICAgICAgICAgIGxvZ2dlck1lc3NhZ2U6IGBGZXRjaGluZyBwYWNrYWdlcyBmb3IgYWdlbnQgJHthZ2VudElEfWAsXG4gICAgICAgICAgdGFibGU6IHtcbiAgICAgICAgICAgIHRpdGxlOiAnUGFja2FnZXMnLFxuICAgICAgICAgICAgY29sdW1uczpcbiAgICAgICAgICAgICAgYWdlbnRPcyA9PT0gJ3dpbmRvd3MnXG4gICAgICAgICAgICAgICAgPyBbXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICduYW1lJywgbGFiZWw6ICdOYW1lJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnYXJjaGl0ZWN0dXJlJywgbGFiZWw6ICdBcmNoaXRlY3R1cmUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICd2ZXJzaW9uJywgbGFiZWw6ICdWZXJzaW9uJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAndmVuZG9yJywgbGFiZWw6ICdWZW5kb3InIH0sXG4gICAgICAgICAgICAgICAgICBdXG4gICAgICAgICAgICAgICAgOiBbXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICduYW1lJywgbGFiZWw6ICdOYW1lJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnYXJjaGl0ZWN0dXJlJywgbGFiZWw6ICdBcmNoaXRlY3R1cmUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICd2ZXJzaW9uJywgbGFiZWw6ICdWZXJzaW9uJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAndmVuZG9yJywgbGFiZWw6ICdWZW5kb3InIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdkZXNjcmlwdGlvbicsIGxhYmVsOiAnRGVzY3JpcHRpb24nIH0sXG4gICAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudElEfS9wcm9jZXNzZXNgLFxuICAgICAgICAgIGxvZ2dlck1lc3NhZ2U6IGBGZXRjaGluZyBwcm9jZXNzZXMgZm9yIGFnZW50ICR7YWdlbnRJRH1gLFxuICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICB0aXRsZTogJ1Byb2Nlc3NlcycsXG4gICAgICAgICAgICBjb2x1bW5zOlxuICAgICAgICAgICAgICBhZ2VudE9zID09PSAnd2luZG93cydcbiAgICAgICAgICAgICAgICA/IFtcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ25hbWUnLCBsYWJlbDogJ05hbWUnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdjbWQnLCBsYWJlbDogJ0NNRCcgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3ByaW9yaXR5JywgbGFiZWw6ICdQcmlvcml0eScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ25sd3AnLCBsYWJlbDogJ05MV1AnIH0sXG4gICAgICAgICAgICAgICAgICBdXG4gICAgICAgICAgICAgICAgOiBbXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICduYW1lJywgbGFiZWw6ICdOYW1lJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnZXVzZXInLCBsYWJlbDogJ0VmZmVjdGl2ZSB1c2VyJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbmljZScsIGxhYmVsOiAnUHJpb3JpdHknIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdzdGF0ZScsIGxhYmVsOiAnU3RhdGUnIH0sXG4gICAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgbWFwUmVzcG9uc2VJdGVtczogKGl0ZW0pID0+XG4gICAgICAgICAgICBhZ2VudE9zID09PSAnd2luZG93cycgPyBpdGVtIDogeyAuLi5pdGVtLCBzdGF0ZTogUHJvY2Vzc0VxdWl2YWxlbmNlW2l0ZW0uc3RhdGVdIH0sXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudElEfS9wb3J0c2AsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIHBvcnRzIGZvciBhZ2VudCAke2FnZW50SUR9YCxcbiAgICAgICAgICB0YWJsZToge1xuICAgICAgICAgICAgdGl0bGU6ICdOZXR3b3JrIHBvcnRzJyxcbiAgICAgICAgICAgIGNvbHVtbnM6XG4gICAgICAgICAgICAgIGFnZW50T3MgPT09ICd3aW5kb3dzJ1xuICAgICAgICAgICAgICAgID8gW1xuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbG9jYWxfaXAnLCBsYWJlbDogJ0xvY2FsIElQIGFkZHJlc3MnIH0sXG4gICAgICAgICAgICAgICAgICAgIHsgaWQ6ICdsb2NhbF9wb3J0JywgbGFiZWw6ICdMb2NhbCBwb3J0JyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAncHJvY2VzcycsIGxhYmVsOiAnUHJvY2VzcycgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3N0YXRlJywgbGFiZWw6ICdTdGF0ZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3Byb3RvY29sJywgbGFiZWw6ICdQcm90b2NvbCcgfSxcbiAgICAgICAgICAgICAgICAgIF1cbiAgICAgICAgICAgICAgICA6IFtcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ2xvY2FsX2lwJywgbGFiZWw6ICdMb2NhbCBJUCBhZGRyZXNzJyB9LFxuICAgICAgICAgICAgICAgICAgICB7IGlkOiAnbG9jYWxfcG9ydCcsIGxhYmVsOiAnTG9jYWwgcG9ydCcgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3N0YXRlJywgbGFiZWw6ICdTdGF0ZScgfSxcbiAgICAgICAgICAgICAgICAgICAgeyBpZDogJ3Byb3RvY29sJywgbGFiZWw6ICdQcm90b2NvbCcgfSxcbiAgICAgICAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBtYXBSZXNwb25zZUl0ZW1zOiAoaXRlbSkgPT4gKHtcbiAgICAgICAgICAgIC4uLml0ZW0sXG4gICAgICAgICAgICBsb2NhbF9pcDogaXRlbS5sb2NhbC5pcCxcbiAgICAgICAgICAgIGxvY2FsX3BvcnQ6IGl0ZW0ubG9jYWwucG9ydCxcbiAgICAgICAgICB9KSxcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIGVuZHBvaW50OiBgL3N5c2NvbGxlY3Rvci8ke2FnZW50SUR9L25ldGlmYWNlYCxcbiAgICAgICAgICBsb2dnZXJNZXNzYWdlOiBgRmV0Y2hpbmcgbmV0aWZhY2UgZm9yIGFnZW50ICR7YWdlbnRJRH1gLFxuICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICB0aXRsZTogJ05ldHdvcmsgaW50ZXJmYWNlcycsXG4gICAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICAgIHsgaWQ6ICduYW1lJywgbGFiZWw6ICdOYW1lJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnbWFjJywgbGFiZWw6ICdNYWMnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdzdGF0ZScsIGxhYmVsOiAnU3RhdGUnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdtdHUnLCBsYWJlbDogJ01UVScgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ3R5cGUnLCBsYWJlbDogJ1R5cGUnIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBlbmRwb2ludDogYC9zeXNjb2xsZWN0b3IvJHthZ2VudElEfS9uZXRhZGRyYCxcbiAgICAgICAgICBsb2dnZXJNZXNzYWdlOiBgRmV0Y2hpbmcgbmV0YWRkciBmb3IgYWdlbnQgJHthZ2VudElEfWAsXG4gICAgICAgICAgdGFibGU6IHtcbiAgICAgICAgICAgIHRpdGxlOiAnTmV0d29yayBzZXR0aW5ncycsXG4gICAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICAgIHsgaWQ6ICdpZmFjZScsIGxhYmVsOiAnSW50ZXJmYWNlJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAnYWRkcmVzcycsIGxhYmVsOiAnQWRkcmVzcycgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ25ldG1hc2snLCBsYWJlbDogJ05ldG1hc2snIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdwcm90bycsIGxhYmVsOiAnUHJvdG9jb2wnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdicm9hZGNhc3QnLCBsYWJlbDogJ0Jyb2FkY2FzdCcgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIF07XG5cbiAgICAgIGFnZW50T3MgPT09ICd3aW5kb3dzJyAmJlxuICAgICAgICBhZ2VudFJlcXVlc3RzSW52ZW50b3J5LnB1c2goe1xuICAgICAgICAgIGVuZHBvaW50OiBgL3N5c2NvbGxlY3Rvci8ke2FnZW50SUR9L2hvdGZpeGVzYCxcbiAgICAgICAgICBsb2dnZXJNZXNzYWdlOiBgRmV0Y2hpbmcgaG90Zml4ZXMgZm9yIGFnZW50ICR7YWdlbnRJRH1gLFxuICAgICAgICAgIHRhYmxlOiB7XG4gICAgICAgICAgICB0aXRsZTogJ1dpbmRvd3MgdXBkYXRlcycsXG4gICAgICAgICAgICBjb2x1bW5zOiBbeyBpZDogJ2hvdGZpeCcsIGxhYmVsOiAnVXBkYXRlIGNvZGUnIH1dLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0pO1xuXG4gICAgICBjb25zdCByZXF1ZXN0SW52ZW50b3J5ID0gYXN5bmMgKGFnZW50UmVxdWVzdEludmVudG9yeSkgPT4ge1xuICAgICAgICB0cnkge1xuICAgICAgICAgIGxvZyhcbiAgICAgICAgICAgICdyZXBvcnRpbmc6Y3JlYXRlUmVwb3J0c0FnZW50c0ludmVudG9yeScsXG4gICAgICAgICAgICBhZ2VudFJlcXVlc3RJbnZlbnRvcnkubG9nZ2VyTWVzc2FnZSxcbiAgICAgICAgICAgICdkZWJ1ZydcbiAgICAgICAgICApO1xuXG4gICAgICAgICAgY29uc3QgaW52ZW50b3J5UmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICBhZ2VudFJlcXVlc3RJbnZlbnRvcnkuZW5kcG9pbnQsXG4gICAgICAgICAgICB7fSxcbiAgICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICAgKTtcblxuICAgICAgICAgIGNvbnN0IGludmVudG9yeSA9XG4gICAgICAgICAgICBpbnZlbnRvcnlSZXNwb25zZSAmJlxuICAgICAgICAgICAgaW52ZW50b3J5UmVzcG9uc2UuZGF0YSAmJlxuICAgICAgICAgICAgaW52ZW50b3J5UmVzcG9uc2UuZGF0YS5kYXRhICYmXG4gICAgICAgICAgICBpbnZlbnRvcnlSZXNwb25zZS5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXM7XG4gICAgICAgICAgaWYgKGludmVudG9yeSkge1xuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgLi4uYWdlbnRSZXF1ZXN0SW52ZW50b3J5LnRhYmxlLFxuICAgICAgICAgICAgICBpdGVtczogYWdlbnRSZXF1ZXN0SW52ZW50b3J5Lm1hcFJlc3BvbnNlSXRlbXNcbiAgICAgICAgICAgICAgICA/IGludmVudG9yeS5tYXAoYWdlbnRSZXF1ZXN0SW52ZW50b3J5Lm1hcFJlc3BvbnNlSXRlbXMpXG4gICAgICAgICAgICAgICAgOiBpbnZlbnRvcnksXG4gICAgICAgICAgICB9O1xuICAgICAgICAgIH1cbiAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICBsb2coJ3JlcG9ydGluZzpjcmVhdGVSZXBvcnRzQWdlbnRzSW52ZW50b3J5JywgZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgJ2RlYnVnJyk7XG4gICAgICAgIH1cbiAgICAgIH07XG5cbiAgICAgIGlmICh0aW1lKSB7XG4gICAgICAgIGF3YWl0IGV4dGVuZGVkSW5mb3JtYXRpb24oXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBwcmludGVyLFxuICAgICAgICAgICdhZ2VudHMnLFxuICAgICAgICAgICdzeXNjb2xsZWN0b3InLFxuICAgICAgICAgIGFwaUlkLFxuICAgICAgICAgIGZyb20sXG4gICAgICAgICAgdG8sXG4gICAgICAgICAgc2FuaXRpemVkRmlsdGVycyArICcgQU5EIHJ1bGUuZ3JvdXBzOiBcInZ1bG5lcmFiaWxpdHktZGV0ZWN0b3JcIicsXG4gICAgICAgICAgYWdlbnRzRmlsdGVyLFxuICAgICAgICAgIGluZGV4UGF0dGVyblRpdGxlLFxuICAgICAgICAgIGFnZW50SURcbiAgICAgICAgKTtcbiAgICAgIH1cblxuICAgICAgLy8gQWRkIGludmVudG9yeSB0YWJsZXNcbiAgICAgIChhd2FpdCBQcm9taXNlLmFsbChhZ2VudFJlcXVlc3RzSW52ZW50b3J5Lm1hcChyZXF1ZXN0SW52ZW50b3J5KSkpXG4gICAgICAgIC5maWx0ZXIoKHRhYmxlKSA9PiB0YWJsZSlcbiAgICAgICAgLmZvckVhY2goKHRhYmxlKSA9PiBwcmludGVyLmFkZFNpbXBsZVRhYmxlKHRhYmxlKSk7XG5cbiAgICAgIC8vIFByaW50IHRoZSBkb2N1bWVudFxuICAgICAgYXdhaXQgcHJpbnRlci5wcmludChjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMucGF0aEZpbGVuYW1lKTtcblxuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keToge1xuICAgICAgICAgIHN1Y2Nlc3M6IHRydWUsXG4gICAgICAgICAgbWVzc2FnZTogYFJlcG9ydCAke2NvbnRleHQud2F6dWhFbmRwb2ludFBhcmFtcy5maWxlbmFtZX0gd2FzIGNyZWF0ZWRgLFxuICAgICAgICB9LFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmNyZWF0ZVJlcG9ydHNBZ2VudHMnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDUwMjksIDUwMCwgcmVzcG9uc2UpO1xuICAgIH1cbiAgfSwgKHtwYXJhbXM6IHsgYWdlbnRJRCB9fSkgPT4gYHdhenVoLWFnZW50LWludmVudG9yeS0ke2FnZW50SUR9LSR7dGhpcy5nZW5lcmF0ZVJlcG9ydFRpbWVzdGFtcCgpfS5wZGZgKVxuXG4gIC8qKlxuICAgKiBGZXRjaCB0aGUgcmVwb3J0cyBsaXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSBjb250ZXh0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXF1ZXN0XG4gICAqIEBwYXJhbSB7T2JqZWN0fSByZXNwb25zZVxuICAgKiBAcmV0dXJucyB7QXJyYXk8T2JqZWN0Pn0gcmVwb3J0cyBsaXN0IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGFzeW5jIGdldFJlcG9ydHMoXG4gICAgY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LFxuICAgIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsXG4gICAgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeVxuICApIHtcbiAgICB0cnkge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Z2V0UmVwb3J0cycsIGBGZXRjaGluZyBjcmVhdGVkIHJlcG9ydHNgLCAnaW5mbycpO1xuICAgICAgY29uc3QgeyBoYXNoVXNlcm5hbWUgfSA9IGF3YWl0IGNvbnRleHQud2F6dWguc2VjdXJpdHkuZ2V0Q3VycmVudFVzZXIocmVxdWVzdCwgY29udGV4dCk7XG4gICAgICBjcmVhdGVEYXRhRGlyZWN0b3J5SWZOb3RFeGlzdHMoKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIKTtcbiAgICAgIGNyZWF0ZURpcmVjdG9yeUlmTm90RXhpc3RzKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgpO1xuICAgICAgY29uc3QgdXNlclJlcG9ydHNEaXJlY3RvcnlQYXRoID0gcGF0aC5qb2luKFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEgsIGhhc2hVc2VybmFtZSk7XG4gICAgICBjcmVhdGVEaXJlY3RvcnlJZk5vdEV4aXN0cyh1c2VyUmVwb3J0c0RpcmVjdG9yeVBhdGgpO1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Z2V0UmVwb3J0cycsIGBEaXJlY3Rvcnk6ICR7dXNlclJlcG9ydHNEaXJlY3RvcnlQYXRofWAsICdkZWJ1ZycpO1xuXG4gICAgICBjb25zdCBzb3J0UmVwb3J0c0J5RGF0ZSA9IChhLCBiKSA9PiAoYS5kYXRlIDwgYi5kYXRlID8gMSA6IGEuZGF0ZSA+IGIuZGF0ZSA/IC0xIDogMCk7XG5cbiAgICAgIGNvbnN0IHJlcG9ydHMgPSBmcy5yZWFkZGlyU3luYyh1c2VyUmVwb3J0c0RpcmVjdG9yeVBhdGgpLm1hcCgoZmlsZSkgPT4ge1xuICAgICAgICBjb25zdCBzdGF0cyA9IGZzLnN0YXRTeW5jKHVzZXJSZXBvcnRzRGlyZWN0b3J5UGF0aCArICcvJyArIGZpbGUpO1xuICAgICAgICAvLyBHZXQgdGhlIGZpbGUgY3JlYXRpb24gdGltZSAoYml0aHRpbWUpLiBJdCByZXR1cm5zIHRoZSBmaXJzdCB2YWx1ZSB0aGF0IGlzIGEgdHJ1dGh5IHZhbHVlIG9mIG5leHQgZmlsZSBzdGF0czogYmlydGh0aW1lLCBtdGltZSwgY3RpbWUgYW5kIGF0aW1lLlxuICAgICAgICAvLyBUaGlzIHNvbHZlcyBzb21lIE9TcyBjYW4gaGF2ZSB0aGUgYml0aHRpbWVNcyBlcXVhbCB0byAwIGFuZCByZXR1cm5zIHRoZSBkYXRlIGxpa2UgMTk3MC0wMS0wMVxuICAgICAgICBjb25zdCBiaXJ0aFRpbWVGaWVsZCA9IFsnYmlydGh0aW1lJywgJ210aW1lJywgJ2N0aW1lJywgJ2F0aW1lJ10uZmluZChcbiAgICAgICAgICAodGltZSkgPT4gc3RhdHNbYCR7dGltZX1Nc2BdXG4gICAgICAgICk7XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgbmFtZTogZmlsZSxcbiAgICAgICAgICBzaXplOiBzdGF0cy5zaXplLFxuICAgICAgICAgIGRhdGU6IHN0YXRzW2JpcnRoVGltZUZpZWxkXSxcbiAgICAgICAgfTtcbiAgICAgIH0pO1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Z2V0UmVwb3J0cycsIGBVc2luZyBUaW1Tb3J0IGZvciBzb3J0aW5nICR7cmVwb3J0cy5sZW5ndGh9IGl0ZW1zYCwgJ2RlYnVnJyk7XG4gICAgICBUaW1Tb3J0LnNvcnQocmVwb3J0cywgc29ydFJlcG9ydHNCeURhdGUpO1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Z2V0UmVwb3J0cycsIGBUb3RhbCByZXBvcnRzOiAke3JlcG9ydHMubGVuZ3RofWAsICdkZWJ1ZycpO1xuICAgICAgcmV0dXJuIHJlc3BvbnNlLm9rKHtcbiAgICAgICAgYm9keTogeyByZXBvcnRzIH0sXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Z2V0UmVwb3J0cycsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAzMSwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9XG5cbiAgLyoqXG4gICAqIEZldGNoIHNwZWNpZmljIHJlcG9ydFxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gcmVwb3J0IG9yIEVycm9yUmVzcG9uc2VcbiAgICovXG4gIGdldFJlcG9ydEJ5TmFtZSA9IHRoaXMuY2hlY2tSZXBvcnRzVXNlckRpcmVjdG9yeUlzVmFsaWRSb3V0ZURlY29yYXRvcihhc3luYyAoXG4gICAgY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LFxuICAgIHJlcXVlc3Q6IEtpYmFuYVJlcXVlc3QsXG4gICAgcmVzcG9uc2U6IEtpYmFuYVJlc3BvbnNlRmFjdG9yeVxuICApID0+IHtcbiAgICB0cnkge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6Z2V0UmVwb3J0QnlOYW1lJywgYEdldHRpbmcgJHtjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMucGF0aEZpbGVuYW1lfSByZXBvcnRgLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IHJlcG9ydEZpbGVCdWZmZXIgPSBmcy5yZWFkRmlsZVN5bmMoY29udGV4dC53YXp1aEVuZHBvaW50UGFyYW1zLnBhdGhGaWxlbmFtZSk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBoZWFkZXJzOiB7ICdDb250ZW50LVR5cGUnOiAnYXBwbGljYXRpb24vcGRmJyB9LFxuICAgICAgICBib2R5OiByZXBvcnRGaWxlQnVmZmVyLFxuICAgICAgfSk7XG4gICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmdldFJlcG9ydEJ5TmFtZScsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgcmV0dXJuIEVycm9yUmVzcG9uc2UoZXJyb3IubWVzc2FnZSB8fCBlcnJvciwgNTAzMCwgNTAwLCByZXNwb25zZSk7XG4gICAgfVxuICB9LCAocmVxdWVzdCkgPT4gcmVxdWVzdC5wYXJhbXMubmFtZSlcblxuICAvKipcbiAgICogRGVsZXRlIHNwZWNpZmljIHJlcG9ydFxuICAgKiBAcGFyYW0ge09iamVjdH0gY29udGV4dFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVxdWVzdFxuICAgKiBAcGFyYW0ge09iamVjdH0gcmVzcG9uc2VcbiAgICogQHJldHVybnMge09iamVjdH0gc3RhdHVzIG9iaiBvciBFcnJvclJlc3BvbnNlXG4gICAqL1xuICBkZWxldGVSZXBvcnRCeU5hbWUgPSB0aGlzLmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3IoYXN5bmMgKFxuICAgIGNvbnRleHQ6IFJlcXVlc3RIYW5kbGVyQ29udGV4dCxcbiAgICByZXF1ZXN0OiBLaWJhbmFSZXF1ZXN0LFxuICAgIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnlcbiAgKSA9PiB7XG4gICAgdHJ5IHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmRlbGV0ZVJlcG9ydEJ5TmFtZScsIGBEZWxldGluZyAke2NvbnRleHQud2F6dWhFbmRwb2ludFBhcmFtcy5wYXRoRmlsZW5hbWV9IHJlcG9ydGAsICdkZWJ1ZycpO1xuICAgICAgZnMudW5saW5rU3luYyhjb250ZXh0LndhenVoRW5kcG9pbnRQYXJhbXMucGF0aEZpbGVuYW1lKTtcbiAgICAgIGxvZygncmVwb3J0aW5nOmRlbGV0ZVJlcG9ydEJ5TmFtZScsIGAke2NvbnRleHQud2F6dWhFbmRwb2ludFBhcmFtcy5wYXRoRmlsZW5hbWV9IHJlcG9ydCB3YXMgZGVsZXRlZGAsICdpbmZvJyk7XG4gICAgICByZXR1cm4gcmVzcG9uc2Uub2soe1xuICAgICAgICBib2R5OiB7IGVycm9yOiAwIH0sXG4gICAgICB9KTtcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6ZGVsZXRlUmVwb3J0QnlOYW1lJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICByZXR1cm4gRXJyb3JSZXNwb25zZShlcnJvci5tZXNzYWdlIHx8IGVycm9yLCA1MDMyLCA1MDAsIHJlc3BvbnNlKTtcbiAgICB9XG4gIH0sKHJlcXVlc3QpID0+IHJlcXVlc3QucGFyYW1zLm5hbWUpXG5cbiAgY2hlY2tSZXBvcnRzVXNlckRpcmVjdG9yeUlzVmFsaWRSb3V0ZURlY29yYXRvcihyb3V0ZUhhbmRsZXIsIHJlcG9ydEZpbGVOYW1lQWNjZXNzb3Ipe1xuICAgIHJldHVybiAoYXN5bmMgKFxuICAgICAgY29udGV4dDogUmVxdWVzdEhhbmRsZXJDb250ZXh0LFxuICAgICAgcmVxdWVzdDogS2liYW5hUmVxdWVzdCxcbiAgICAgIHJlc3BvbnNlOiBLaWJhbmFSZXNwb25zZUZhY3RvcnlcbiAgICApID0+IHtcbiAgICAgIHRyeXtcbiAgICAgICAgY29uc3QgeyB1c2VybmFtZSwgaGFzaFVzZXJuYW1lIH0gPSBhd2FpdCBjb250ZXh0LndhenVoLnNlY3VyaXR5LmdldEN1cnJlbnRVc2VyKHJlcXVlc3QsIGNvbnRleHQpO1xuICAgICAgICBjb25zdCB1c2VyUmVwb3J0c0RpcmVjdG9yeVBhdGggPSBwYXRoLmpvaW4oV0FaVUhfREFUQV9ET1dOTE9BRFNfUkVQT1JUU19ESVJFQ1RPUllfUEFUSCwgaGFzaFVzZXJuYW1lKTtcbiAgICAgICAgY29uc3QgZmlsZW5hbWUgPSByZXBvcnRGaWxlTmFtZUFjY2Vzc29yKHJlcXVlc3QpO1xuICAgICAgICBjb25zdCBwYXRoRmlsZW5hbWUgPSBwYXRoLmpvaW4odXNlclJlcG9ydHNEaXJlY3RvcnlQYXRoLCBmaWxlbmFtZSk7XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3InLCBgQ2hlY2tpbmcgdGhlIHVzZXIgJHt1c2VybmFtZX0oJHtoYXNoVXNlcm5hbWV9KSBjYW4gZG8gYWN0aW9ucyBpbiB0aGUgcmVwb3J0cyBmaWxlOiAke3BhdGhGaWxlbmFtZX1gLCAnZGVidWcnKTtcbiAgICAgICAgaWYoIXBhdGhGaWxlbmFtZS5zdGFydHNXaXRoKHVzZXJSZXBvcnRzRGlyZWN0b3J5UGF0aCkgfHwgcGF0aEZpbGVuYW1lLmluY2x1ZGVzKCcuLi8nKSl7XG4gICAgICAgICAgbG9nKCdzZWN1cml0eTpyZXBvcnRpbmc6Y2hlY2tSZXBvcnRzVXNlckRpcmVjdG9yeUlzVmFsaWRSb3V0ZURlY29yYXRvcicsIGBVc2VyICR7dXNlcm5hbWV9KCR7aGFzaFVzZXJuYW1lfSkgdHJpZWQgdG8gYWNjZXNzIHRvIGEgbm9uIHVzZXIgcmVwb3J0IGZpbGU6ICR7cGF0aEZpbGVuYW1lfWAsICd3YXJuJyk7XG4gICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmJhZFJlcXVlc3Qoe1xuICAgICAgICAgICAgYm9keToge1xuICAgICAgICAgICAgICBtZXNzYWdlOiAnNTA0MCAtIFlvdSBzaGFsbCBub3QgcGFzcyEnXG4gICAgICAgICAgICB9XG4gICAgICAgICAgfSk7XG4gICAgICAgIH07XG4gICAgICAgIGxvZygncmVwb3J0aW5nOmNoZWNrUmVwb3J0c1VzZXJEaXJlY3RvcnlJc1ZhbGlkUm91dGVEZWNvcmF0b3InLCAnQ2hlY2tpbmcgdGhlIHVzZXIgY2FuIGRvIGFjdGlvbnMgaW4gdGhlIHJlcG9ydHMgZmlsZScsICdkZWJ1ZycpO1xuICAgICAgICByZXR1cm4gYXdhaXQgcm91dGVIYW5kbGVyLmJpbmQodGhpcykoey4uLmNvbnRleHQsIHdhenVoRW5kcG9pbnRQYXJhbXM6IHsgaGFzaFVzZXJuYW1lLCBmaWxlbmFtZSwgcGF0aEZpbGVuYW1lIH19LCByZXF1ZXN0LCByZXNwb25zZSk7XG4gICAgICB9Y2F0Y2goZXJyb3Ipe1xuICAgICAgICBsb2coJ3JlcG9ydGluZzpjaGVja1JlcG9ydHNVc2VyRGlyZWN0b3J5SXNWYWxpZFJvdXRlRGVjb3JhdG9yJywgZXJyb3IubWVzc2FnZSB8fCBlcnJvcik7XG4gICAgICAgIHJldHVybiBFcnJvclJlc3BvbnNlKGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IsIDUwNDAsIDUwMCwgcmVzcG9uc2UpO1xuICAgICAgfVxuICAgIH0pXG4gIH1cblxuICBwcml2YXRlIGdlbmVyYXRlUmVwb3J0VGltZXN0YW1wKCl7XG4gICAgcmV0dXJuIGAkeyhEYXRlLm5vdygpIC8gMTAwMCkgfCAwfWA7XG4gIH1cbn1cbiJdfQ==