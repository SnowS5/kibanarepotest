"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.buildAgentsTable = buildAgentsTable;
exports.extendedInformation = extendedInformation;

var _logger = require("../logger");

var _summaryTable = _interopRequireDefault(require("./summary-table"));

var _summaryTablesDefinitions = _interopRequireDefault(require("./summary-tables-definitions"));

var VulnerabilityRequest = _interopRequireWildcard(require("./vulnerability-request"));

var OverviewRequest = _interopRequireWildcard(require("./overview-request"));

var RootcheckRequest = _interopRequireWildcard(require("./rootcheck-request"));

var PCIRequest = _interopRequireWildcard(require("./pci-request"));

var GDPRRequest = _interopRequireWildcard(require("./gdpr-request"));

var TSCRequest = _interopRequireWildcard(require("./tsc-request"));

var AuditRequest = _interopRequireWildcard(require("./audit-request"));

var SyscheckRequest = _interopRequireWildcard(require("./syscheck-request"));

var _pciRequirementsPdfmake = _interopRequireDefault(require("../../integration-files/pci-requirements-pdfmake"));

var _gdprRequirementsPdfmake = _interopRequireDefault(require("../../integration-files/gdpr-requirements-pdfmake"));

var _tscRequirementsPdfmake = _interopRequireDefault(require("../../integration-files/tsc-requirements-pdfmake"));

var _moment = _interopRequireDefault(require("moment"));

var _settings = require("../../../common/services/settings");

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

/**
   * This build the agents table
   * @param {Array<Strings>} ids ids of agents
   * @param {String} apiId API id
   */
async function buildAgentsTable(context, printer, agentIDs, apiId, groupID = '') {
  const dateFormat = await context.core.uiSettings.client.get('dateFormat');
  if ((!agentIDs || !agentIDs.length) && !groupID) return;
  (0, _logger.log)('reporting:buildAgentsTable', `${agentIDs.length} agents for API ${apiId}`, 'info');

  try {
    let agentsData = [];

    if (groupID) {
      let totalAgentsInGroup = null;

      do {
        const {
          data: {
            data: {
              affected_items,
              total_affected_items
            }
          }
        } = await context.wazuh.api.client.asCurrentUser.request('GET', `/groups/${groupID}/agents`, {
          params: {
            offset: agentsData.length,
            select: 'dateAdd,id,ip,lastKeepAlive,manager,name,os.name,os.version,version'
          }
        }, {
          apiHostID: apiId
        });
        !totalAgentsInGroup && (totalAgentsInGroup = total_affected_items);
        agentsData = [...agentsData, ...affected_items];
      } while (agentsData.length < totalAgentsInGroup);
    } else {
      for (const agentID of agentIDs) {
        try {
          const {
            data: {
              data: {
                affected_items: [agent]
              }
            }
          } = await context.wazuh.api.client.asCurrentUser.request('GET', `/agents`, {
            params: {
              q: `id=${agentID}`,
              select: 'dateAdd,id,ip,lastKeepAlive,manager,name,os.name,os.version,version'
            }
          }, {
            apiHostID: apiId
          });
          agentsData.push(agent);
        } catch (error) {
          (0, _logger.log)('reporting:buildAgentsTable', `Skip agent due to: ${error.message || error}`, 'debug');
        }
      }
    }

    if (agentsData.length) {
      // Print a table with agent/s information
      printer.addSimpleTable({
        columns: [{
          id: 'id',
          label: 'ID'
        }, {
          id: 'name',
          label: 'Name'
        }, {
          id: 'ip',
          label: 'IP address'
        }, {
          id: 'version',
          label: 'Version'
        }, {
          id: 'manager',
          label: 'Manager'
        }, {
          id: 'os',
          label: 'Operating system'
        }, {
          id: 'dateAdd',
          label: 'Registration date'
        }, {
          id: 'lastKeepAlive',
          label: 'Last keep alive'
        }],
        items: agentsData.filter(agent => agent) // Remove undefined agents when Wazuh API no longer finds and agentID
        .map(agent => {
          return { ...agent,
            os: agent.os && agent.os.name && agent.os.version ? `${agent.os.name} ${agent.os.version}` : '',
            lastKeepAlive: (0, _moment.default)(agent.lastKeepAlive).format(dateFormat),
            dateAdd: (0, _moment.default)(agent.dateAdd).format(dateFormat)
          };
        })
      });
    } else if (!agentsData.length && groupID) {
      // For group reports when there is no agents in the group
      printer.addContent({
        text: 'There are no agents in this group.',
        style: {
          fontSize: 12,
          color: '#000'
        }
      });
    }
  } catch (error) {
    (0, _logger.log)('reporting:buildAgentsTable', error.message || error);
    return Promise.reject(error);
  }
}
/**
 * This load more information
 * @param {*} context Endpoint context
 * @param {*} printer printer instance
 * @param {String} section section target
 * @param {Object} tab tab target
 * @param {String} apiId ID of API
 * @param {Number} from Timestamp (ms) from
 * @param {Number} to Timestamp (ms) to
 * @param {String} filters E.g: cluster.name: wazuh AND rule.groups: vulnerability
 * @param {String} pattern
 * @param {Object} agent agent target
 * @returns {Object} Extended information
 */


async function extendedInformation(context, printer, section, tab, apiId, from, to, filters, allowedAgentsFilter, pattern = (0, _settings.getSettingDefaultValue)('pattern'), agent = null) {
  try {
    (0, _logger.log)('reporting:extendedInformation', `Section ${section} and tab ${tab}, API is ${apiId}. From ${from} to ${to}. Filters ${filters}. Index pattern ${pattern}`, 'info');

    if (section === 'agents' && !agent) {
      throw new Error('Reporting for specific agent needs an agent ID in order to work properly');
    }

    const agents = await context.wazuh.api.client.asCurrentUser.request('GET', '/agents', {
      params: {
        limit: 1
      }
    }, {
      apiHostID: apiId
    });
    const totalAgents = agents.data.data.total_affected_items; //--- OVERVIEW - VULS

    if (section === 'overview' && tab === 'vuls') {
      (0, _logger.log)('reporting:extendedInformation', 'Fetching overview vulnerability detector metrics', 'debug');
      const vulnerabilitiesLevels = ['Low', 'Medium', 'High', 'Critical'];
      const vulnerabilitiesResponsesCount = (await Promise.all(vulnerabilitiesLevels.map(async vulnerabilitiesLevel => {
        try {
          const count = await VulnerabilityRequest.uniqueSeverityCount(context, from, to, vulnerabilitiesLevel, filters, allowedAgentsFilter, pattern);
          return count ? `${count} of ${totalAgents} agents have ${vulnerabilitiesLevel.toLocaleLowerCase()} vulnerabilities.` : undefined;
        } catch (error) {}
      }))).filter(vulnerabilitiesResponse => vulnerabilitiesResponse);
      printer.addList({
        title: {
          text: 'Summary',
          style: 'h2'
        },
        list: vulnerabilitiesResponsesCount
      });
      (0, _logger.log)('reporting:extendedInformation', 'Fetching overview vulnerability detector top 3 agents by category', 'debug');
      const lowRank = await VulnerabilityRequest.topAgentCount(context, from, to, 'Low', filters, allowedAgentsFilter, pattern);
      const mediumRank = await VulnerabilityRequest.topAgentCount(context, from, to, 'Medium', filters, allowedAgentsFilter, pattern);
      const highRank = await VulnerabilityRequest.topAgentCount(context, from, to, 'High', filters, allowedAgentsFilter, pattern);
      const criticalRank = await VulnerabilityRequest.topAgentCount(context, from, to, 'Critical', filters, allowedAgentsFilter, pattern);
      (0, _logger.log)('reporting:extendedInformation', 'Adding overview vulnerability detector top 3 agents by category', 'debug');

      if (criticalRank && criticalRank.length) {
        printer.addContentWithNewLine({
          text: 'Top 3 agents with critical severity vulnerabilities',
          style: 'h3'
        });
        await buildAgentsTable(context, printer, criticalRank, apiId);
        printer.addNewLine();
      }

      if (highRank && highRank.length) {
        printer.addContentWithNewLine({
          text: 'Top 3 agents with high severity vulnerabilities',
          style: 'h3'
        });
        await buildAgentsTable(context, printer, highRank, apiId);
        printer.addNewLine();
      }

      if (mediumRank && mediumRank.length) {
        printer.addContentWithNewLine({
          text: 'Top 3 agents with medium severity vulnerabilities',
          style: 'h3'
        });
        await buildAgentsTable(context, printer, mediumRank, apiId);
        printer.addNewLine();
      }

      if (lowRank && lowRank.length) {
        printer.addContentWithNewLine({
          text: 'Top 3 agents with low severity vulnerabilities',
          style: 'h3'
        });
        await buildAgentsTable(context, printer, lowRank, apiId);
        printer.addNewLine();
      }

      (0, _logger.log)('reporting:extendedInformation', 'Fetching overview vulnerability detector top 3 CVEs', 'debug');
      const cveRank = await VulnerabilityRequest.topCVECount(context, from, to, filters, allowedAgentsFilter, pattern);
      (0, _logger.log)('reporting:extendedInformation', 'Adding overview vulnerability detector top 3 CVEs', 'debug');

      if (cveRank && cveRank.length) {
        printer.addSimpleTable({
          title: {
            text: 'Top 3 CVE',
            style: 'h2'
          },
          columns: [{
            id: 'top',
            label: 'Top'
          }, {
            id: 'cve',
            label: 'CVE'
          }],
          items: cveRank.map(item => ({
            top: cveRank.indexOf(item) + 1,
            cve: item
          }))
        });
      }
    } //--- OVERVIEW - GENERAL


    if (section === 'overview' && tab === 'general') {
      (0, _logger.log)('reporting:extendedInformation', 'Fetching top 3 agents with level 15 alerts', 'debug');
      const level15Rank = await OverviewRequest.topLevel15(context, from, to, filters, allowedAgentsFilter, pattern);
      (0, _logger.log)('reporting:extendedInformation', 'Adding top 3 agents with level 15 alerts', 'debug');

      if (level15Rank.length) {
        printer.addContent({
          text: 'Top 3 agents with level 15 alerts',
          style: 'h2'
        });
        await buildAgentsTable(context, printer, level15Rank, apiId);
      }
    } //--- OVERVIEW - PM


    if (section === 'overview' && tab === 'pm') {
      (0, _logger.log)('reporting:extendedInformation', 'Fetching most common rootkits', 'debug');
      const top5RootkitsRank = await RootcheckRequest.top5RootkitsDetected(context, from, to, filters, allowedAgentsFilter, pattern);
      (0, _logger.log)('reporting:extendedInformation', 'Adding most common rootkits', 'debug');

      if (top5RootkitsRank && top5RootkitsRank.length) {
        printer.addContentWithNewLine({
          text: 'Most common rootkits found among your agents',
          style: 'h2'
        }).addContentWithNewLine({
          text: 'Rootkits are a set of software tools that enable an unauthorized user to gain control of a computer system without being detected.',
          style: 'standard'
        }).addSimpleTable({
          items: top5RootkitsRank.map(item => {
            return {
              top: top5RootkitsRank.indexOf(item) + 1,
              name: item
            };
          }),
          columns: [{
            id: 'top',
            label: 'Top'
          }, {
            id: 'name',
            label: 'Rootkit'
          }]
        });
      }

      (0, _logger.log)('reporting:extendedInformation', 'Fetching hidden pids', 'debug');
      const hiddenPids = await RootcheckRequest.agentsWithHiddenPids(context, from, to, filters, allowedAgentsFilter, pattern);
      hiddenPids && printer.addContent({
        text: `${hiddenPids} of ${totalAgents} agents have hidden processes`,
        style: 'h3'
      });
      !hiddenPids && printer.addContentWithNewLine({
        text: `No agents have hidden processes`,
        style: 'h3'
      });
      const hiddenPorts = await RootcheckRequest.agentsWithHiddenPorts(context, from, to, filters, allowedAgentsFilter, pattern);
      hiddenPorts && printer.addContent({
        text: `${hiddenPorts} of ${totalAgents} agents have hidden ports`,
        style: 'h3'
      });
      !hiddenPorts && printer.addContent({
        text: `No agents have hidden ports`,
        style: 'h3'
      });
      printer.addNewLine();
    } //--- OVERVIEW/AGENTS - PCI


    if (['overview', 'agents'].includes(section) && tab === 'pci') {
      (0, _logger.log)('reporting:extendedInformation', 'Fetching top PCI DSS requirements', 'debug');
      const topPciRequirements = await PCIRequest.topPCIRequirements(context, from, to, filters, allowedAgentsFilter, pattern);
      printer.addContentWithNewLine({
        text: 'Most common PCI DSS requirements alerts found',
        style: 'h2'
      });

      for (const item of topPciRequirements) {
        const rules = await PCIRequest.getRulesByRequirement(context, from, to, filters, allowedAgentsFilter, item, pattern);
        printer.addContentWithNewLine({
          text: `Requirement ${item}`,
          style: 'h3'
        });

        if (_pciRequirementsPdfmake.default[item]) {
          const content = typeof _pciRequirementsPdfmake.default[item] === 'string' ? {
            text: _pciRequirementsPdfmake.default[item],
            style: 'standard'
          } : _pciRequirementsPdfmake.default[item];
          printer.addContentWithNewLine(content);
        }

        rules && rules.length && printer.addSimpleTable({
          columns: [{
            id: 'ruleID',
            label: 'Rule ID'
          }, {
            id: 'ruleDescription',
            label: 'Description'
          }],
          items: rules,
          title: `Top rules for ${item} requirement`
        });
      }
    } //--- OVERVIEW/AGENTS - TSC


    if (['overview', 'agents'].includes(section) && tab === 'tsc') {
      (0, _logger.log)('reporting:extendedInformation', 'Fetching top TSC requirements', 'debug');
      const topTSCRequirements = await TSCRequest.topTSCRequirements(context, from, to, filters, allowedAgentsFilter, pattern);
      printer.addContentWithNewLine({
        text: 'Most common TSC requirements alerts found',
        style: 'h2'
      });

      for (const item of topTSCRequirements) {
        const rules = await TSCRequest.getRulesByRequirement(context, from, to, filters, allowedAgentsFilter, item, pattern);
        printer.addContentWithNewLine({
          text: `Requirement ${item}`,
          style: 'h3'
        });

        if (_tscRequirementsPdfmake.default[item]) {
          const content = typeof _tscRequirementsPdfmake.default[item] === 'string' ? {
            text: _tscRequirementsPdfmake.default[item],
            style: 'standard'
          } : _tscRequirementsPdfmake.default[item];
          printer.addContentWithNewLine(content);
        }

        rules && rules.length && printer.addSimpleTable({
          columns: [{
            id: 'ruleID',
            label: 'Rule ID'
          }, {
            id: 'ruleDescription',
            label: 'Description'
          }],
          items: rules,
          title: `Top rules for ${item} requirement`
        });
      }
    } //--- OVERVIEW/AGENTS - GDPR


    if (['overview', 'agents'].includes(section) && tab === 'gdpr') {
      (0, _logger.log)('reporting:extendedInformation', 'Fetching top GDPR requirements', 'debug');
      const topGdprRequirements = await GDPRRequest.topGDPRRequirements(context, from, to, filters, allowedAgentsFilter, pattern);
      printer.addContentWithNewLine({
        text: 'Most common GDPR requirements alerts found',
        style: 'h2'
      });

      for (const item of topGdprRequirements) {
        const rules = await GDPRRequest.getRulesByRequirement(context, from, to, filters, allowedAgentsFilter, item, pattern);
        printer.addContentWithNewLine({
          text: `Requirement ${item}`,
          style: 'h3'
        });

        if (_gdprRequirementsPdfmake.default && _gdprRequirementsPdfmake.default[item]) {
          const content = typeof _gdprRequirementsPdfmake.default[item] === 'string' ? {
            text: _gdprRequirementsPdfmake.default[item],
            style: 'standard'
          } : _gdprRequirementsPdfmake.default[item];
          printer.addContentWithNewLine(content);
        }

        rules && rules.length && printer.addSimpleTable({
          columns: [{
            id: 'ruleID',
            label: 'Rule ID'
          }, {
            id: 'ruleDescription',
            label: 'Description'
          }],
          items: rules,
          title: `Top rules for ${item} requirement`
        });
      }

      printer.addNewLine();
    } //--- OVERVIEW - AUDIT


    if (section === 'overview' && tab === 'audit') {
      (0, _logger.log)('reporting:extendedInformation', 'Fetching agents with high number of failed sudo commands', 'debug');
      const auditAgentsNonSuccess = await AuditRequest.getTop3AgentsSudoNonSuccessful(context, from, to, filters, allowedAgentsFilter, pattern);

      if (auditAgentsNonSuccess && auditAgentsNonSuccess.length) {
        printer.addContent({
          text: 'Agents with high number of failed sudo commands',
          style: 'h2'
        });
        await buildAgentsTable(context, printer, auditAgentsNonSuccess, apiId);
      }

      const auditAgentsFailedSyscall = await AuditRequest.getTop3AgentsFailedSyscalls(context, from, to, filters, allowedAgentsFilter, pattern);

      if (auditAgentsFailedSyscall && auditAgentsFailedSyscall.length) {
        printer.addSimpleTable({
          columns: [{
            id: 'agent',
            label: 'Agent ID'
          }, {
            id: 'syscall_id',
            label: 'Syscall ID'
          }, {
            id: 'syscall_syscall',
            label: 'Syscall'
          }],
          items: auditAgentsFailedSyscall.map(item => ({
            agent: item.agent,
            syscall_id: item.syscall.id,
            syscall_syscall: item.syscall.syscall
          })),
          title: {
            text: 'Most common failing syscalls',
            style: 'h2'
          }
        });
      }
    } //--- OVERVIEW - FIM


    if (section === 'overview' && tab === 'fim') {
      (0, _logger.log)('reporting:extendedInformation', 'Fetching top 3 rules for FIM', 'debug');
      const rules = await SyscheckRequest.top3Rules(context, from, to, filters, allowedAgentsFilter, pattern);

      if (rules && rules.length) {
        printer.addContentWithNewLine({
          text: 'Top 3 FIM rules',
          style: 'h2'
        }).addSimpleTable({
          columns: [{
            id: 'ruleID',
            label: 'Rule ID'
          }, {
            id: 'ruleDescription',
            label: 'Description'
          }],
          items: rules,
          title: {
            text: 'Top 3 rules that are generating most alerts.',
            style: 'standard'
          }
        });
      }

      (0, _logger.log)('reporting:extendedInformation', 'Fetching top 3 agents for FIM', 'debug');
      const agents = await SyscheckRequest.top3agents(context, from, to, filters, allowedAgentsFilter, pattern);

      if (agents && agents.length) {
        printer.addContentWithNewLine({
          text: 'Agents with suspicious FIM activity',
          style: 'h2'
        });
        printer.addContentWithNewLine({
          text: 'Top 3 agents that have most FIM alerts from level 7 to level 15. Take care about them.',
          style: 'standard'
        });
        await buildAgentsTable(context, printer, agents, apiId);
      }
    } //--- AGENTS - AUDIT


    if (section === 'agents' && tab === 'audit') {
      (0, _logger.log)('reporting:extendedInformation', `Fetching most common failed syscalls`, 'debug');
      const auditFailedSyscall = await AuditRequest.getTopFailedSyscalls(context, from, to, filters, allowedAgentsFilter, pattern);
      auditFailedSyscall && auditFailedSyscall.length && printer.addSimpleTable({
        columns: [{
          id: 'id',
          label: 'id'
        }, {
          id: 'syscall',
          label: 'Syscall'
        }],
        items: auditFailedSyscall,
        title: 'Most common failing syscalls'
      });
    } //--- AGENTS - FIM


    if (section === 'agents' && tab === 'fim') {
      (0, _logger.log)('reporting:extendedInformation', `Fetching syscheck database for agent ${agent}`, 'debug');
      const lastScanResponse = await context.wazuh.api.client.asCurrentUser.request('GET', `/syscheck/${agent}/last_scan`, {}, {
        apiHostID: apiId
      });

      if (lastScanResponse && lastScanResponse.data) {
        const lastScanData = lastScanResponse.data.data.affected_items[0];

        if (lastScanData.start && lastScanData.end) {
          printer.addContent({
            text: `Last file integrity monitoring scan was executed from ${lastScanData.start} to ${lastScanData.end}.`
          });
        } else if (lastScanData.start) {
          printer.addContent({
            text: `File integrity monitoring scan is currently in progress for this agent (started on ${lastScanData.start}).`
          });
        } else {
          printer.addContent({
            text: `File integrity monitoring scan is currently in progress for this agent.`
          });
        }

        printer.addNewLine();
      }

      (0, _logger.log)('reporting:extendedInformation', `Fetching last 10 deleted files for FIM`, 'debug');
      const lastTenDeleted = await SyscheckRequest.lastTenDeletedFiles(context, from, to, filters, allowedAgentsFilter, pattern);
      lastTenDeleted && lastTenDeleted.length && printer.addSimpleTable({
        columns: [{
          id: 'path',
          label: 'Path'
        }, {
          id: 'date',
          label: 'Date'
        }],
        items: lastTenDeleted,
        title: 'Last 10 deleted files'
      });
      (0, _logger.log)('reporting:extendedInformation', `Fetching last 10 modified files`, 'debug');
      const lastTenModified = await SyscheckRequest.lastTenModifiedFiles(context, from, to, filters, allowedAgentsFilter, pattern);
      lastTenModified && lastTenModified.length && printer.addSimpleTable({
        columns: [{
          id: 'path',
          label: 'Path'
        }, {
          id: 'date',
          label: 'Date'
        }],
        items: lastTenModified,
        title: 'Last 10 modified files'
      });
    } //--- AGENTS - SYSCOLLECTOR


    if (section === 'agents' && tab === 'syscollector') {
      (0, _logger.log)('reporting:extendedInformation', `Fetching hardware information for agent ${agent}`, 'debug');
      const requestsSyscollectorLists = [{
        endpoint: `/syscollector/${agent}/hardware`,
        loggerMessage: `Fetching Hardware information for agent ${agent}`,
        list: {
          title: {
            text: 'Hardware information',
            style: 'h2'
          }
        },
        mapResponse: hardware => [hardware.cpu && hardware.cpu.cores && `${hardware.cpu.cores} cores`, hardware.cpu && hardware.cpu.name, hardware.ram && hardware.ram.total && `${Number(hardware.ram.total / 1024 / 1024).toFixed(2)}GB RAM`]
      }, {
        endpoint: `/syscollector/${agent}/os`,
        loggerMessage: `Fetching operating system information for agent ${agent}`,
        list: {
          title: {
            text: 'Operating system information',
            style: 'h2'
          }
        },
        mapResponse: osData => [osData.sysname, osData.version, osData.architecture, osData.release, osData.os && osData.os.name && osData.os.version && `${osData.os.name} ${osData.os.version}`]
      }];
      const syscollectorLists = await Promise.all(requestsSyscollectorLists.map(async requestSyscollector => {
        try {
          (0, _logger.log)('reporting:extendedInformation', requestSyscollector.loggerMessage, 'debug');
          const responseSyscollector = await context.wazuh.api.client.asCurrentUser.request('GET', requestSyscollector.endpoint, {}, {
            apiHostID: apiId
          });
          const [data] = responseSyscollector && responseSyscollector.data && responseSyscollector.data.data && responseSyscollector.data.data.affected_items || [];

          if (data) {
            return { ...requestSyscollector.list,
              list: requestSyscollector.mapResponse(data)
            };
          }
        } catch (error) {
          (0, _logger.log)('reporting:extendedInformation', error.message || error);
        }
      }));

      if (syscollectorLists) {
        syscollectorLists.filter(syscollectorList => syscollectorList).forEach(syscollectorList => printer.addList(syscollectorList));
      }

      const vulnerabilitiesRequests = ['Critical', 'High'];
      const vulnerabilitiesResponsesItems = (await Promise.all(vulnerabilitiesRequests.map(async vulnerabilitiesLevel => {
        try {
          (0, _logger.log)('reporting:extendedInformation', `Fetching top ${vulnerabilitiesLevel} packages`, 'debug');
          return await VulnerabilityRequest.topPackages(context, from, to, vulnerabilitiesLevel, filters, allowedAgentsFilter, pattern);
        } catch (error) {
          (0, _logger.log)('reporting:extendedInformation', error.message || error);
        }
      }))).filter(vulnerabilitiesResponse => vulnerabilitiesResponse).flat();

      if (vulnerabilitiesResponsesItems && vulnerabilitiesResponsesItems.length) {
        printer.addSimpleTable({
          title: {
            text: 'Vulnerable packages found (last 24 hours)',
            style: 'h2'
          },
          columns: [{
            id: 'package',
            label: 'Package'
          }, {
            id: 'severity',
            label: 'Severity'
          }],
          items: vulnerabilitiesResponsesItems
        });
      }
    } //--- AGENTS - VULNERABILITIES


    if (section === 'agents' && tab === 'vuls') {
      const topCriticalPackages = await VulnerabilityRequest.topPackagesWithCVE(context, from, to, 'Critical', filters, allowedAgentsFilter, pattern);

      if (topCriticalPackages && topCriticalPackages.length) {
        printer.addContentWithNewLine({
          text: 'Critical severity',
          style: 'h2'
        });
        printer.addContentWithNewLine({
          text: 'These vulnerabilties are critical, please review your agent. Click on each link to read more about each found vulnerability.',
          style: 'standard'
        });
        const customul = [];

        for (const critical of topCriticalPackages) {
          customul.push({
            text: critical.package,
            style: 'standard'
          });
          customul.push({
            ul: critical.references.map(item => ({
              text: item.substring(0, 80) + '...',
              link: item,
              color: '#1EA5C8'
            }))
          });
        }

        printer.addContentWithNewLine({
          ul: customul
        });
      }

      const topHighPackages = await VulnerabilityRequest.topPackagesWithCVE(context, from, to, 'High', filters, allowedAgentsFilter, pattern);

      if (topHighPackages && topHighPackages.length) {
        printer.addContentWithNewLine({
          text: 'High severity',
          style: 'h2'
        });
        printer.addContentWithNewLine({
          text: 'Click on each link to read more about each found vulnerability.',
          style: 'standard'
        });
        const customul = [];

        for (const critical of topHighPackages) {
          customul.push({
            text: critical.package,
            style: 'standard'
          });
          customul.push({
            ul: critical.references.map(item => ({
              text: item,
              color: '#1EA5C8'
            }))
          });
        }

        customul && customul.length && printer.addContent({
          ul: customul
        });
        printer.addNewLine();
      }
    } //--- SUMMARY TABLES


    let extraSummaryTables = [];

    if (Array.isArray(_summaryTablesDefinitions.default[section][tab])) {
      const tablesPromises = _summaryTablesDefinitions.default[section][tab].map(summaryTable => {
        (0, _logger.log)('reporting:AlertsTable', `Fetching ${summaryTable.title} Table`, 'debug');
        const alertsSummaryTable = new _summaryTable.default(context, from, to, filters, allowedAgentsFilter, summaryTable, pattern);
        return alertsSummaryTable.fetch();
      });

      extraSummaryTables = await Promise.all(tablesPromises);
    }

    return extraSummaryTables;
  } catch (error) {
    (0, _logger.log)('reporting:extendedInformation', error.message || error);
    return Promise.reject(error);
  }
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImV4dGVuZGVkLWluZm9ybWF0aW9uLnRzIl0sIm5hbWVzIjpbImJ1aWxkQWdlbnRzVGFibGUiLCJjb250ZXh0IiwicHJpbnRlciIsImFnZW50SURzIiwiYXBpSWQiLCJncm91cElEIiwiZGF0ZUZvcm1hdCIsImNvcmUiLCJ1aVNldHRpbmdzIiwiY2xpZW50IiwiZ2V0IiwibGVuZ3RoIiwiYWdlbnRzRGF0YSIsInRvdGFsQWdlbnRzSW5Hcm91cCIsImRhdGEiLCJhZmZlY3RlZF9pdGVtcyIsInRvdGFsX2FmZmVjdGVkX2l0ZW1zIiwid2F6dWgiLCJhcGkiLCJhc0N1cnJlbnRVc2VyIiwicmVxdWVzdCIsInBhcmFtcyIsIm9mZnNldCIsInNlbGVjdCIsImFwaUhvc3RJRCIsImFnZW50SUQiLCJhZ2VudCIsInEiLCJwdXNoIiwiZXJyb3IiLCJtZXNzYWdlIiwiYWRkU2ltcGxlVGFibGUiLCJjb2x1bW5zIiwiaWQiLCJsYWJlbCIsIml0ZW1zIiwiZmlsdGVyIiwibWFwIiwib3MiLCJuYW1lIiwidmVyc2lvbiIsImxhc3RLZWVwQWxpdmUiLCJmb3JtYXQiLCJkYXRlQWRkIiwiYWRkQ29udGVudCIsInRleHQiLCJzdHlsZSIsImZvbnRTaXplIiwiY29sb3IiLCJQcm9taXNlIiwicmVqZWN0IiwiZXh0ZW5kZWRJbmZvcm1hdGlvbiIsInNlY3Rpb24iLCJ0YWIiLCJmcm9tIiwidG8iLCJmaWx0ZXJzIiwiYWxsb3dlZEFnZW50c0ZpbHRlciIsInBhdHRlcm4iLCJFcnJvciIsImFnZW50cyIsImxpbWl0IiwidG90YWxBZ2VudHMiLCJ2dWxuZXJhYmlsaXRpZXNMZXZlbHMiLCJ2dWxuZXJhYmlsaXRpZXNSZXNwb25zZXNDb3VudCIsImFsbCIsInZ1bG5lcmFiaWxpdGllc0xldmVsIiwiY291bnQiLCJWdWxuZXJhYmlsaXR5UmVxdWVzdCIsInVuaXF1ZVNldmVyaXR5Q291bnQiLCJ0b0xvY2FsZUxvd2VyQ2FzZSIsInVuZGVmaW5lZCIsInZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlIiwiYWRkTGlzdCIsInRpdGxlIiwibGlzdCIsImxvd1JhbmsiLCJ0b3BBZ2VudENvdW50IiwibWVkaXVtUmFuayIsImhpZ2hSYW5rIiwiY3JpdGljYWxSYW5rIiwiYWRkQ29udGVudFdpdGhOZXdMaW5lIiwiYWRkTmV3TGluZSIsImN2ZVJhbmsiLCJ0b3BDVkVDb3VudCIsIml0ZW0iLCJ0b3AiLCJpbmRleE9mIiwiY3ZlIiwibGV2ZWwxNVJhbmsiLCJPdmVydmlld1JlcXVlc3QiLCJ0b3BMZXZlbDE1IiwidG9wNVJvb3RraXRzUmFuayIsIlJvb3RjaGVja1JlcXVlc3QiLCJ0b3A1Um9vdGtpdHNEZXRlY3RlZCIsImhpZGRlblBpZHMiLCJhZ2VudHNXaXRoSGlkZGVuUGlkcyIsImhpZGRlblBvcnRzIiwiYWdlbnRzV2l0aEhpZGRlblBvcnRzIiwiaW5jbHVkZXMiLCJ0b3BQY2lSZXF1aXJlbWVudHMiLCJQQ0lSZXF1ZXN0IiwidG9wUENJUmVxdWlyZW1lbnRzIiwicnVsZXMiLCJnZXRSdWxlc0J5UmVxdWlyZW1lbnQiLCJQQ0kiLCJjb250ZW50IiwidG9wVFNDUmVxdWlyZW1lbnRzIiwiVFNDUmVxdWVzdCIsIlRTQyIsInRvcEdkcHJSZXF1aXJlbWVudHMiLCJHRFBSUmVxdWVzdCIsInRvcEdEUFJSZXF1aXJlbWVudHMiLCJHRFBSIiwiYXVkaXRBZ2VudHNOb25TdWNjZXNzIiwiQXVkaXRSZXF1ZXN0IiwiZ2V0VG9wM0FnZW50c1N1ZG9Ob25TdWNjZXNzZnVsIiwiYXVkaXRBZ2VudHNGYWlsZWRTeXNjYWxsIiwiZ2V0VG9wM0FnZW50c0ZhaWxlZFN5c2NhbGxzIiwic3lzY2FsbF9pZCIsInN5c2NhbGwiLCJzeXNjYWxsX3N5c2NhbGwiLCJTeXNjaGVja1JlcXVlc3QiLCJ0b3AzUnVsZXMiLCJ0b3AzYWdlbnRzIiwiYXVkaXRGYWlsZWRTeXNjYWxsIiwiZ2V0VG9wRmFpbGVkU3lzY2FsbHMiLCJsYXN0U2NhblJlc3BvbnNlIiwibGFzdFNjYW5EYXRhIiwic3RhcnQiLCJlbmQiLCJsYXN0VGVuRGVsZXRlZCIsImxhc3RUZW5EZWxldGVkRmlsZXMiLCJsYXN0VGVuTW9kaWZpZWQiLCJsYXN0VGVuTW9kaWZpZWRGaWxlcyIsInJlcXVlc3RzU3lzY29sbGVjdG9yTGlzdHMiLCJlbmRwb2ludCIsImxvZ2dlck1lc3NhZ2UiLCJtYXBSZXNwb25zZSIsImhhcmR3YXJlIiwiY3B1IiwiY29yZXMiLCJyYW0iLCJ0b3RhbCIsIk51bWJlciIsInRvRml4ZWQiLCJvc0RhdGEiLCJzeXNuYW1lIiwiYXJjaGl0ZWN0dXJlIiwicmVsZWFzZSIsInN5c2NvbGxlY3Rvckxpc3RzIiwicmVxdWVzdFN5c2NvbGxlY3RvciIsInJlc3BvbnNlU3lzY29sbGVjdG9yIiwic3lzY29sbGVjdG9yTGlzdCIsImZvckVhY2giLCJ2dWxuZXJhYmlsaXRpZXNSZXF1ZXN0cyIsInZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0l0ZW1zIiwidG9wUGFja2FnZXMiLCJmbGF0IiwidG9wQ3JpdGljYWxQYWNrYWdlcyIsInRvcFBhY2thZ2VzV2l0aENWRSIsImN1c3RvbXVsIiwiY3JpdGljYWwiLCJwYWNrYWdlIiwidWwiLCJyZWZlcmVuY2VzIiwic3Vic3RyaW5nIiwibGluayIsInRvcEhpZ2hQYWNrYWdlcyIsImV4dHJhU3VtbWFyeVRhYmxlcyIsIkFycmF5IiwiaXNBcnJheSIsInN1bW1hcnlUYWJsZXNEZWZpbml0aW9ucyIsInRhYmxlc1Byb21pc2VzIiwic3VtbWFyeVRhYmxlIiwiYWxlcnRzU3VtbWFyeVRhYmxlIiwiU3VtbWFyeVRhYmxlIiwiZmV0Y2giXSwibWFwcGluZ3MiOiI7Ozs7Ozs7Ozs7QUFBQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFDQTs7QUFFQTs7QUFDQTs7Ozs7O0FBS0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNRLGVBQWVBLGdCQUFmLENBQWdDQyxPQUFoQyxFQUF5Q0MsT0FBekMsRUFBaUVDLFFBQWpFLEVBQXFGQyxLQUFy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QkMsRUFIeUIsRUFJekJDLE9BSnlCLEVBS3pCQyxtQkFMeUIsRUFNekJxSCxZQU55QixFQU96QnBILE9BUHlCLENBQTNCO0FBU0EsZUFBT3FILGtCQUFrQixDQUFDRSxLQUFuQixFQUFQO0FBQ0QsT0Fac0IsQ0FBdkI7O0FBYUFSLE1BQUFBLGtCQUFrQixHQUFHLE1BQU14SCxPQUFPLENBQUNnQixHQUFSLENBQVk0RyxjQUFaLENBQTNCO0FBQ0Q7O0FBRUQsV0FBT0osa0JBQVA7QUFDRCxHQXB3QkQsQ0Fvd0JFLE9BQU81SSxLQUFQLEVBQWM7QUFDZCxxQkFBSSwrQkFBSixFQUFxQ0EsS0FBSyxDQUFDQyxPQUFOLElBQWlCRCxLQUF0RDtBQUNBLFdBQU9vQixPQUFPLENBQUNDLE1BQVIsQ0FBZXJCLEtBQWYsQ0FBUDtBQUNEO0FBQ0YiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBsb2cgfSBmcm9tICcuLi9sb2dnZXInO1xuaW1wb3J0IFN1bW1hcnlUYWJsZSBmcm9tICcuL3N1bW1hcnktdGFibGUnO1xuaW1wb3J0IHN1bW1hcnlUYWJsZXNEZWZpbml0aW9ucyBmcm9tICcuL3N1bW1hcnktdGFibGVzLWRlZmluaXRpb25zJztcbmltcG9ydCAqIGFzIFZ1bG5lcmFiaWxpdHlSZXF1ZXN0IGZyb20gJy4vdnVsbmVyYWJpbGl0eS1yZXF1ZXN0JztcbmltcG9ydCAqIGFzIE92ZXJ2aWV3UmVxdWVzdCBmcm9tICcuL292ZXJ2aWV3LXJlcXVlc3QnO1xuaW1wb3J0ICogYXMgUm9vdGNoZWNrUmVxdWVzdCBmcm9tICcuL3Jvb3RjaGVjay1yZXF1ZXN0JztcbmltcG9ydCAqIGFzIFBDSVJlcXVlc3QgZnJvbSAnLi9wY2ktcmVxdWVzdCc7XG5pbXBvcnQgKiBhcyBHRFBSUmVxdWVzdCBmcm9tICcuL2dkcHItcmVxdWVzdCc7XG5pbXBvcnQgKiBhcyBUU0NSZXF1ZXN0IGZyb20gJy4vdHNjLXJlcXVlc3QnO1xuaW1wb3J0ICogYXMgQXVkaXRSZXF1ZXN0IGZyb20gJy4vYXVkaXQtcmVxdWVzdCc7XG5pbXBvcnQgKiBhcyBTeXNjaGVja1JlcXVlc3QgZnJvbSAnLi9zeXNjaGVjay1yZXF1ZXN0JztcbmltcG9ydCBQQ0kgZnJvbSAnLi4vLi4vaW50ZWdyYXRpb24tZmlsZXMvcGNpLXJlcXVpcmVtZW50cy1wZGZtYWtlJztcbmltcG9ydCBHRFBSIGZyb20gJy4uLy4uL2ludGVncmF0aW9uLWZpbGVzL2dkcHItcmVxdWlyZW1lbnRzLXBkZm1ha2UnO1xuaW1wb3J0IFRTQyBmcm9tICcuLi8uLi9pbnRlZ3JhdGlvbi1maWxlcy90c2MtcmVxdWlyZW1lbnRzLXBkZm1ha2UnO1xuaW1wb3J0IHsgUmVwb3J0UHJpbnRlciB9IGZyb20gJy4vcHJpbnRlcic7XG5pbXBvcnQgbW9tZW50IGZyb20gJ21vbWVudCc7XG5pbXBvcnQgeyBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlIH0gZnJvbSAnLi4vLi4vLi4vY29tbW9uL3NlcnZpY2VzL3NldHRpbmdzJztcblxuXG5cblxuLyoqXG4gICAqIFRoaXMgYnVpbGQgdGhlIGFnZW50cyB0YWJsZVxuICAgKiBAcGFyYW0ge0FycmF5PFN0cmluZ3M+fSBpZHMgaWRzIG9mIGFnZW50c1xuICAgKiBAcGFyYW0ge1N0cmluZ30gYXBpSWQgQVBJIGlkXG4gICAqL1xuIGV4cG9ydCBhc3luYyBmdW5jdGlvbiBidWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXI6IFJlcG9ydFByaW50ZXIsIGFnZW50SURzOiBzdHJpbmdbXSwgYXBpSWQ6IHN0cmluZywgZ3JvdXBJRDogc3RyaW5nID0gJycpIHtcbiAgY29uc3QgZGF0ZUZvcm1hdCA9IGF3YWl0IGNvbnRleHQuY29yZS51aVNldHRpbmdzLmNsaWVudC5nZXQoJ2RhdGVGb3JtYXQnKTtcbiAgaWYgKCghYWdlbnRJRHMgfHwgIWFnZW50SURzLmxlbmd0aCkgJiYgIWdyb3VwSUQpIHJldHVybjtcbiAgbG9nKCdyZXBvcnRpbmc6YnVpbGRBZ2VudHNUYWJsZScsIGAke2FnZW50SURzLmxlbmd0aH0gYWdlbnRzIGZvciBBUEkgJHthcGlJZH1gLCAnaW5mbycpO1xuICB0cnkge1xuICAgIGxldCBhZ2VudHNEYXRhID0gW107XG4gICAgaWYgKGdyb3VwSUQpIHtcbiAgICAgIGxldCB0b3RhbEFnZW50c0luR3JvdXAgPSBudWxsO1xuICAgICAgZG97XG4gICAgICAgIGNvbnN0IHsgZGF0YTogeyBkYXRhOiB7IGFmZmVjdGVkX2l0ZW1zLCB0b3RhbF9hZmZlY3RlZF9pdGVtcyB9IH0gfSA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgYC9ncm91cHMvJHtncm91cElEfS9hZ2VudHNgLFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBvZmZzZXQ6IGFnZW50c0RhdGEubGVuZ3RoLFxuICAgICAgICAgICAgICBzZWxlY3Q6ICdkYXRlQWRkLGlkLGlwLGxhc3RLZWVwQWxpdmUsbWFuYWdlcixuYW1lLG9zLm5hbWUsb3MudmVyc2lvbix2ZXJzaW9uJyxcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9LFxuICAgICAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgICAgICk7XG4gICAgICAgICF0b3RhbEFnZW50c0luR3JvdXAgJiYgKHRvdGFsQWdlbnRzSW5Hcm91cCA9IHRvdGFsX2FmZmVjdGVkX2l0ZW1zKTtcbiAgICAgICAgYWdlbnRzRGF0YSA9IFsuLi5hZ2VudHNEYXRhLCAuLi5hZmZlY3RlZF9pdGVtc107XG4gICAgICB9d2hpbGUoYWdlbnRzRGF0YS5sZW5ndGggPCB0b3RhbEFnZW50c0luR3JvdXApO1xuICAgIH0gZWxzZSB7XG4gICAgICBmb3IgKGNvbnN0IGFnZW50SUQgb2YgYWdlbnRJRHMpIHtcbiAgICAgICAgdHJ5IHtcbiAgICAgICAgICBjb25zdCB7IGRhdGE6IHsgZGF0YTogeyBhZmZlY3RlZF9pdGVtczogW2FnZW50XSB9IH0gfSA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAgICAgICAnR0VUJyxcbiAgICAgICAgICAgIGAvYWdlbnRzYCxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgcTogYGlkPSR7YWdlbnRJRH1gLFxuICAgICAgICAgICAgICAgIHNlbGVjdDogJ2RhdGVBZGQsaWQsaXAsbGFzdEtlZXBBbGl2ZSxtYW5hZ2VyLG5hbWUsb3MubmFtZSxvcy52ZXJzaW9uLHZlcnNpb24nLFxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgeyBhcGlIb3N0SUQ6IGFwaUlkIH1cbiAgICAgICAgICApO1xuICAgICAgICAgIGFnZW50c0RhdGEucHVzaChhZ2VudCk7XG4gICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgICAgbG9nKFxuICAgICAgICAgICAgJ3JlcG9ydGluZzpidWlsZEFnZW50c1RhYmxlJyxcbiAgICAgICAgICAgIGBTa2lwIGFnZW50IGR1ZSB0bzogJHtlcnJvci5tZXNzYWdlIHx8IGVycm9yfWAsXG4gICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgKTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cblxuICAgIGlmKGFnZW50c0RhdGEubGVuZ3RoKXtcbiAgICAgIC8vIFByaW50IGEgdGFibGUgd2l0aCBhZ2VudC9zIGluZm9ybWF0aW9uXG4gICAgICBwcmludGVyLmFkZFNpbXBsZVRhYmxlKHtcbiAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgIHsgaWQ6ICdpZCcsIGxhYmVsOiAnSUQnIH0sXG4gICAgICAgICAgeyBpZDogJ25hbWUnLCBsYWJlbDogJ05hbWUnIH0sXG4gICAgICAgICAgeyBpZDogJ2lwJywgbGFiZWw6ICdJUCBhZGRyZXNzJyB9LFxuICAgICAgICAgIHsgaWQ6ICd2ZXJzaW9uJywgbGFiZWw6ICdWZXJzaW9uJyB9LFxuICAgICAgICAgIHsgaWQ6ICdtYW5hZ2VyJywgbGFiZWw6ICdNYW5hZ2VyJyB9LFxuICAgICAgICAgIHsgaWQ6ICdvcycsIGxhYmVsOiAnT3BlcmF0aW5nIHN5c3RlbScgfSxcbiAgICAgICAgICB7IGlkOiAnZGF0ZUFkZCcsIGxhYmVsOiAnUmVnaXN0cmF0aW9uIGRhdGUnIH0sXG4gICAgICAgICAgeyBpZDogJ2xhc3RLZWVwQWxpdmUnLCBsYWJlbDogJ0xhc3Qga2VlcCBhbGl2ZScgfSxcbiAgICAgICAgXSxcbiAgICAgICAgaXRlbXM6IGFnZW50c0RhdGFcbiAgICAgICAgICAuZmlsdGVyKGFnZW50ID0+IGFnZW50KSAvLyBSZW1vdmUgdW5kZWZpbmVkIGFnZW50cyB3aGVuIFdhenVoIEFQSSBubyBsb25nZXIgZmluZHMgYW5kIGFnZW50SURcbiAgICAgICAgICAubWFwKChhZ2VudCkgPT4ge1xuICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgLi4uYWdlbnQsXG4gICAgICAgICAgICAgIG9zOiAoYWdlbnQub3MgJiYgYWdlbnQub3MubmFtZSAmJiBhZ2VudC5vcy52ZXJzaW9uKSA/IGAke2FnZW50Lm9zLm5hbWV9ICR7YWdlbnQub3MudmVyc2lvbn1gIDogJycsXG4gICAgICAgICAgICAgIGxhc3RLZWVwQWxpdmU6IG1vbWVudChhZ2VudC5sYXN0S2VlcEFsaXZlKS5mb3JtYXQoZGF0ZUZvcm1hdCksXG4gICAgICAgICAgICAgIGRhdGVBZGQ6IG1vbWVudChhZ2VudC5kYXRlQWRkKS5mb3JtYXQoZGF0ZUZvcm1hdClcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9KSxcbiAgICAgIH0pO1xuICAgIH1lbHNlIGlmKCFhZ2VudHNEYXRhLmxlbmd0aCAmJiBncm91cElEKXtcbiAgICAgIC8vIEZvciBncm91cCByZXBvcnRzIHdoZW4gdGhlcmUgaXMgbm8gYWdlbnRzIGluIHRoZSBncm91cFxuICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgdGV4dDogJ1RoZXJlIGFyZSBubyBhZ2VudHMgaW4gdGhpcyBncm91cC4nLFxuICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMTIsIGNvbG9yOiAnIzAwMCcgfSxcbiAgICAgIH0pO1xuICAgIH1cblxuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGxvZygncmVwb3J0aW5nOmJ1aWxkQWdlbnRzVGFibGUnLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICB9XG59XG5cbi8qKlxuICogVGhpcyBsb2FkIG1vcmUgaW5mb3JtYXRpb25cbiAqIEBwYXJhbSB7Kn0gY29udGV4dCBFbmRwb2ludCBjb250ZXh0XG4gKiBAcGFyYW0geyp9IHByaW50ZXIgcHJpbnRlciBpbnN0YW5jZVxuICogQHBhcmFtIHtTdHJpbmd9IHNlY3Rpb24gc2VjdGlvbiB0YXJnZXRcbiAqIEBwYXJhbSB7T2JqZWN0fSB0YWIgdGFiIHRhcmdldFxuICogQHBhcmFtIHtTdHJpbmd9IGFwaUlkIElEIG9mIEFQSVxuICogQHBhcmFtIHtOdW1iZXJ9IGZyb20gVGltZXN0YW1wIChtcykgZnJvbVxuICogQHBhcmFtIHtOdW1iZXJ9IHRvIFRpbWVzdGFtcCAobXMpIHRvXG4gKiBAcGFyYW0ge1N0cmluZ30gZmlsdGVycyBFLmc6IGNsdXN0ZXIubmFtZTogd2F6dWggQU5EIHJ1bGUuZ3JvdXBzOiB2dWxuZXJhYmlsaXR5XG4gKiBAcGFyYW0ge1N0cmluZ30gcGF0dGVyblxuICogQHBhcmFtIHtPYmplY3R9IGFnZW50IGFnZW50IHRhcmdldFxuICogQHJldHVybnMge09iamVjdH0gRXh0ZW5kZWQgaW5mb3JtYXRpb25cbiAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGV4dGVuZGVkSW5mb3JtYXRpb24oXG4gIGNvbnRleHQsXG4gIHByaW50ZXIsXG4gIHNlY3Rpb24sXG4gIHRhYixcbiAgYXBpSWQsXG4gIGZyb20sXG4gIHRvLFxuICBmaWx0ZXJzLFxuICBhbGxvd2VkQWdlbnRzRmlsdGVyLFxuICBwYXR0ZXJuID0gZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSgncGF0dGVybicpLFxuICBhZ2VudCA9IG51bGxcbikge1xuICB0cnkge1xuICAgIGxvZyhcbiAgICAgICdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsXG4gICAgICBgU2VjdGlvbiAke3NlY3Rpb259IGFuZCB0YWIgJHt0YWJ9LCBBUEkgaXMgJHthcGlJZH0uIEZyb20gJHtmcm9tfSB0byAke3RvfS4gRmlsdGVycyAke2ZpbHRlcnN9LiBJbmRleCBwYXR0ZXJuICR7cGF0dGVybn1gLFxuICAgICAgJ2luZm8nXG4gICAgKTtcbiAgICBpZiAoc2VjdGlvbiA9PT0gJ2FnZW50cycgJiYgIWFnZW50KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1JlcG9ydGluZyBmb3Igc3BlY2lmaWMgYWdlbnQgbmVlZHMgYW4gYWdlbnQgSUQgaW4gb3JkZXIgdG8gd29yayBwcm9wZXJseScpO1xuICAgIH1cblxuICAgIGNvbnN0IGFnZW50cyA9IGF3YWl0IGNvbnRleHQud2F6dWguYXBpLmNsaWVudC5hc0N1cnJlbnRVc2VyLnJlcXVlc3QoXG4gICAgICAnR0VUJyxcbiAgICAgICcvYWdlbnRzJyxcbiAgICAgIHsgcGFyYW1zOiB7IGxpbWl0OiAxIH0gfSxcbiAgICAgIHsgYXBpSG9zdElEOiBhcGlJZCB9XG4gICAgKTtcblxuICAgIGNvbnN0IHRvdGFsQWdlbnRzID0gYWdlbnRzLmRhdGEuZGF0YS50b3RhbF9hZmZlY3RlZF9pdGVtcztcblxuICAgIC8vLS0tIE9WRVJWSUVXIC0gVlVMU1xuICAgIGlmIChzZWN0aW9uID09PSAnb3ZlcnZpZXcnICYmIHRhYiA9PT0gJ3Z1bHMnKSB7XG4gICAgICBsb2coXG4gICAgICAgICdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsXG4gICAgICAgICdGZXRjaGluZyBvdmVydmlldyB2dWxuZXJhYmlsaXR5IGRldGVjdG9yIG1ldHJpY3MnLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgY29uc3QgdnVsbmVyYWJpbGl0aWVzTGV2ZWxzID0gWydMb3cnLCAnTWVkaXVtJywgJ0hpZ2gnLCAnQ3JpdGljYWwnXTtcblxuICAgICAgY29uc3QgdnVsbmVyYWJpbGl0aWVzUmVzcG9uc2VzQ291bnQgPSAoXG4gICAgICAgIGF3YWl0IFByb21pc2UuYWxsKFxuICAgICAgICAgIHZ1bG5lcmFiaWxpdGllc0xldmVscy5tYXAoYXN5bmMgKHZ1bG5lcmFiaWxpdGllc0xldmVsKSA9PiB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBjb25zdCBjb3VudCA9IGF3YWl0IFZ1bG5lcmFiaWxpdHlSZXF1ZXN0LnVuaXF1ZVNldmVyaXR5Q291bnQoXG4gICAgICAgICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICAgICAgICBmcm9tLFxuICAgICAgICAgICAgICAgIHRvLFxuICAgICAgICAgICAgICAgIHZ1bG5lcmFiaWxpdGllc0xldmVsLFxuICAgICAgICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgICAgICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICAgICAgICAgICAgICBwYXR0ZXJuXG4gICAgICAgICAgICAgICk7XG4gICAgICAgICAgICAgIHJldHVybiBjb3VudFxuICAgICAgICAgICAgICAgID8gYCR7Y291bnR9IG9mICR7dG90YWxBZ2VudHN9IGFnZW50cyBoYXZlICR7dnVsbmVyYWJpbGl0aWVzTGV2ZWwudG9Mb2NhbGVMb3dlckNhc2UoKX0gdnVsbmVyYWJpbGl0aWVzLmBcbiAgICAgICAgICAgICAgICA6IHVuZGVmaW5lZDtcbiAgICAgICAgICAgIH0gY2F0Y2ggKGVycm9yKSB7fVxuICAgICAgICAgIH0pXG4gICAgICAgIClcbiAgICAgICkuZmlsdGVyKCh2dWxuZXJhYmlsaXRpZXNSZXNwb25zZSkgPT4gdnVsbmVyYWJpbGl0aWVzUmVzcG9uc2UpO1xuXG4gICAgICBwcmludGVyLmFkZExpc3Qoe1xuICAgICAgICB0aXRsZTogeyB0ZXh0OiAnU3VtbWFyeScsIHN0eWxlOiAnaDInIH0sXG4gICAgICAgIGxpc3Q6IHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0NvdW50LFxuICAgICAgfSk7XG5cbiAgICAgIGxvZyhcbiAgICAgICAgJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJyxcbiAgICAgICAgJ0ZldGNoaW5nIG92ZXJ2aWV3IHZ1bG5lcmFiaWxpdHkgZGV0ZWN0b3IgdG9wIDMgYWdlbnRzIGJ5IGNhdGVnb3J5JyxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIGNvbnN0IGxvd1JhbmsgPSBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC50b3BBZ2VudENvdW50KFxuICAgICAgICBjb250ZXh0LFxuICAgICAgICBmcm9tLFxuICAgICAgICB0byxcbiAgICAgICAgJ0xvdycsXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgIHBhdHRlcm5cbiAgICAgICk7XG4gICAgICBjb25zdCBtZWRpdW1SYW5rID0gYXdhaXQgVnVsbmVyYWJpbGl0eVJlcXVlc3QudG9wQWdlbnRDb3VudChcbiAgICAgICAgY29udGV4dCxcbiAgICAgICAgZnJvbSxcbiAgICAgICAgdG8sXG4gICAgICAgICdNZWRpdW0nLFxuICAgICAgICBmaWx0ZXJzLFxuICAgICAgICBhbGxvd2VkQWdlbnRzRmlsdGVyLFxuICAgICAgICBwYXR0ZXJuXG4gICAgICApO1xuICAgICAgY29uc3QgaGlnaFJhbmsgPSBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC50b3BBZ2VudENvdW50KFxuICAgICAgICBjb250ZXh0LFxuICAgICAgICBmcm9tLFxuICAgICAgICB0byxcbiAgICAgICAgJ0hpZ2gnLFxuICAgICAgICBmaWx0ZXJzLFxuICAgICAgICBhbGxvd2VkQWdlbnRzRmlsdGVyLFxuICAgICAgICBwYXR0ZXJuXG4gICAgICApO1xuICAgICAgY29uc3QgY3JpdGljYWxSYW5rID0gYXdhaXQgVnVsbmVyYWJpbGl0eVJlcXVlc3QudG9wQWdlbnRDb3VudChcbiAgICAgICAgY29udGV4dCxcbiAgICAgICAgZnJvbSxcbiAgICAgICAgdG8sXG4gICAgICAgICdDcml0aWNhbCcsXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgIHBhdHRlcm5cbiAgICAgICk7XG4gICAgICBsb2coXG4gICAgICAgICdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsXG4gICAgICAgICdBZGRpbmcgb3ZlcnZpZXcgdnVsbmVyYWJpbGl0eSBkZXRlY3RvciB0b3AgMyBhZ2VudHMgYnkgY2F0ZWdvcnknLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgaWYgKGNyaXRpY2FsUmFuayAmJiBjcml0aWNhbFJhbmsubGVuZ3RoKSB7XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICB0ZXh0OiAnVG9wIDMgYWdlbnRzIHdpdGggY3JpdGljYWwgc2V2ZXJpdHkgdnVsbmVyYWJpbGl0aWVzJyxcbiAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgfSk7XG4gICAgICAgIGF3YWl0IGJ1aWxkQWdlbnRzVGFibGUoY29udGV4dCwgcHJpbnRlciwgY3JpdGljYWxSYW5rLCBhcGlJZCk7XG4gICAgICAgIHByaW50ZXIuYWRkTmV3TGluZSgpO1xuICAgICAgfVxuXG4gICAgICBpZiAoaGlnaFJhbmsgJiYgaGlnaFJhbmsubGVuZ3RoKSB7XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICB0ZXh0OiAnVG9wIDMgYWdlbnRzIHdpdGggaGlnaCBzZXZlcml0eSB2dWxuZXJhYmlsaXRpZXMnLFxuICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICB9KTtcbiAgICAgICAgYXdhaXQgYnVpbGRBZ2VudHNUYWJsZShjb250ZXh0LCBwcmludGVyLCBoaWdoUmFuaywgYXBpSWQpO1xuICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKG1lZGl1bVJhbmsgJiYgbWVkaXVtUmFuay5sZW5ndGgpIHtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgIHRleHQ6ICdUb3AgMyBhZ2VudHMgd2l0aCBtZWRpdW0gc2V2ZXJpdHkgdnVsbmVyYWJpbGl0aWVzJyxcbiAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgfSk7XG4gICAgICAgIGF3YWl0IGJ1aWxkQWdlbnRzVGFibGUoY29udGV4dCwgcHJpbnRlciwgbWVkaXVtUmFuaywgYXBpSWQpO1xuICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgIH1cblxuICAgICAgaWYgKGxvd1JhbmsgJiYgbG93UmFuay5sZW5ndGgpIHtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgIHRleHQ6ICdUb3AgMyBhZ2VudHMgd2l0aCBsb3cgc2V2ZXJpdHkgdnVsbmVyYWJpbGl0aWVzJyxcbiAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgfSk7XG4gICAgICAgIGF3YWl0IGJ1aWxkQWdlbnRzVGFibGUoY29udGV4dCwgcHJpbnRlciwgbG93UmFuaywgYXBpSWQpO1xuICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgIH1cblxuICAgICAgbG9nKFxuICAgICAgICAncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLFxuICAgICAgICAnRmV0Y2hpbmcgb3ZlcnZpZXcgdnVsbmVyYWJpbGl0eSBkZXRlY3RvciB0b3AgMyBDVkVzJyxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIGNvbnN0IGN2ZVJhbmsgPSBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC50b3BDVkVDb3VudChjb250ZXh0LCBmcm9tLCB0bywgZmlsdGVycywgYWxsb3dlZEFnZW50c0ZpbHRlciwgcGF0dGVybik7XG4gICAgICBsb2coXG4gICAgICAgICdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsXG4gICAgICAgICdBZGRpbmcgb3ZlcnZpZXcgdnVsbmVyYWJpbGl0eSBkZXRlY3RvciB0b3AgMyBDVkVzJyxcbiAgICAgICAgJ2RlYnVnJ1xuICAgICAgKTtcbiAgICAgIGlmIChjdmVSYW5rICYmIGN2ZVJhbmsubGVuZ3RoKSB7XG4gICAgICAgIHByaW50ZXIuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdUb3AgMyBDVkUnLCBzdHlsZTogJ2gyJyB9LFxuICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgIHsgaWQ6ICd0b3AnLCBsYWJlbDogJ1RvcCcgfSxcbiAgICAgICAgICAgIHsgaWQ6ICdjdmUnLCBsYWJlbDogJ0NWRScgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGl0ZW1zOiBjdmVSYW5rLm1hcCgoaXRlbSkgPT4gKHsgdG9wOiBjdmVSYW5rLmluZGV4T2YoaXRlbSkgKyAxLCBjdmU6IGl0ZW0gfSkpLFxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLy0tLSBPVkVSVklFVyAtIEdFTkVSQUxcbiAgICBpZiAoc2VjdGlvbiA9PT0gJ292ZXJ2aWV3JyAmJiB0YWIgPT09ICdnZW5lcmFsJykge1xuICAgICAgbG9nKCdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsICdGZXRjaGluZyB0b3AgMyBhZ2VudHMgd2l0aCBsZXZlbCAxNSBhbGVydHMnLCAnZGVidWcnKTtcblxuICAgICAgY29uc3QgbGV2ZWwxNVJhbmsgPSBhd2FpdCBPdmVydmlld1JlcXVlc3QudG9wTGV2ZWwxNShjb250ZXh0LCBmcm9tLCB0bywgZmlsdGVycywgYWxsb3dlZEFnZW50c0ZpbHRlciwgcGF0dGVybik7XG5cbiAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnQWRkaW5nIHRvcCAzIGFnZW50cyB3aXRoIGxldmVsIDE1IGFsZXJ0cycsICdkZWJ1ZycpO1xuICAgICAgaWYgKGxldmVsMTVSYW5rLmxlbmd0aCkge1xuICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgIHRleHQ6ICdUb3AgMyBhZ2VudHMgd2l0aCBsZXZlbCAxNSBhbGVydHMnLFxuICAgICAgICAgIHN0eWxlOiAnaDInLFxuICAgICAgICB9KTtcbiAgICAgICAgYXdhaXQgYnVpbGRBZ2VudHNUYWJsZShjb250ZXh0LCBwcmludGVyLCBsZXZlbDE1UmFuaywgYXBpSWQpO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vLS0tIE9WRVJWSUVXIC0gUE1cbiAgICBpZiAoc2VjdGlvbiA9PT0gJ292ZXJ2aWV3JyAmJiB0YWIgPT09ICdwbScpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnRmV0Y2hpbmcgbW9zdCBjb21tb24gcm9vdGtpdHMnLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IHRvcDVSb290a2l0c1JhbmsgPSBhd2FpdCBSb290Y2hlY2tSZXF1ZXN0LnRvcDVSb290a2l0c0RldGVjdGVkKFxuICAgICAgICBjb250ZXh0LFxuICAgICAgICBmcm9tLFxuICAgICAgICB0byxcbiAgICAgICAgZmlsdGVycyxcbiAgICAgICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICAgICAgcGF0dGVyblxuICAgICAgKTtcbiAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnQWRkaW5nIG1vc3QgY29tbW9uIHJvb3RraXRzJywgJ2RlYnVnJyk7XG4gICAgICBpZiAodG9wNVJvb3RraXRzUmFuayAmJiB0b3A1Um9vdGtpdHNSYW5rLmxlbmd0aCkge1xuICAgICAgICBwcmludGVyXG4gICAgICAgICAgLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgICAgICB0ZXh0OiAnTW9zdCBjb21tb24gcm9vdGtpdHMgZm91bmQgYW1vbmcgeW91ciBhZ2VudHMnLFxuICAgICAgICAgICAgc3R5bGU6ICdoMicsXG4gICAgICAgICAgfSlcbiAgICAgICAgICAuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICAgIHRleHQ6XG4gICAgICAgICAgICAgICdSb290a2l0cyBhcmUgYSBzZXQgb2Ygc29mdHdhcmUgdG9vbHMgdGhhdCBlbmFibGUgYW4gdW5hdXRob3JpemVkIHVzZXIgdG8gZ2FpbiBjb250cm9sIG9mIGEgY29tcHV0ZXIgc3lzdGVtIHdpdGhvdXQgYmVpbmcgZGV0ZWN0ZWQuJyxcbiAgICAgICAgICAgIHN0eWxlOiAnc3RhbmRhcmQnLFxuICAgICAgICAgIH0pXG4gICAgICAgICAgLmFkZFNpbXBsZVRhYmxlKHtcbiAgICAgICAgICAgIGl0ZW1zOiB0b3A1Um9vdGtpdHNSYW5rLm1hcCgoaXRlbSkgPT4ge1xuICAgICAgICAgICAgICByZXR1cm4geyB0b3A6IHRvcDVSb290a2l0c1JhbmsuaW5kZXhPZihpdGVtKSArIDEsIG5hbWU6IGl0ZW0gfTtcbiAgICAgICAgICAgIH0pLFxuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAndG9wJywgbGFiZWw6ICdUb3AnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICduYW1lJywgbGFiZWw6ICdSb290a2l0JyB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9KTtcbiAgICAgIH1cbiAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnRmV0Y2hpbmcgaGlkZGVuIHBpZHMnLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGhpZGRlblBpZHMgPSBhd2FpdCBSb290Y2hlY2tSZXF1ZXN0LmFnZW50c1dpdGhIaWRkZW5QaWRzKFxuICAgICAgICBjb250ZXh0LFxuICAgICAgICBmcm9tLFxuICAgICAgICB0byxcbiAgICAgICAgZmlsdGVycyxcbiAgICAgICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICAgICAgcGF0dGVyblxuICAgICAgKTtcbiAgICAgIGhpZGRlblBpZHMgJiZcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICB0ZXh0OiBgJHtoaWRkZW5QaWRzfSBvZiAke3RvdGFsQWdlbnRzfSBhZ2VudHMgaGF2ZSBoaWRkZW4gcHJvY2Vzc2VzYCxcbiAgICAgICAgICBzdHlsZTogJ2gzJyxcbiAgICAgICAgfSk7XG4gICAgICAhaGlkZGVuUGlkcyAmJlxuICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgICAgdGV4dDogYE5vIGFnZW50cyBoYXZlIGhpZGRlbiBwcm9jZXNzZXNgLFxuICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICB9KTtcblxuICAgICAgY29uc3QgaGlkZGVuUG9ydHMgPSBhd2FpdCBSb290Y2hlY2tSZXF1ZXN0LmFnZW50c1dpdGhIaWRkZW5Qb3J0cyhcbiAgICAgICAgY29udGV4dCxcbiAgICAgICAgZnJvbSxcbiAgICAgICAgdG8sXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgIHBhdHRlcm5cbiAgICAgICk7XG4gICAgICBoaWRkZW5Qb3J0cyAmJlxuICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgIHRleHQ6IGAke2hpZGRlblBvcnRzfSBvZiAke3RvdGFsQWdlbnRzfSBhZ2VudHMgaGF2ZSBoaWRkZW4gcG9ydHNgLFxuICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICB9KTtcbiAgICAgICFoaWRkZW5Qb3J0cyAmJlxuICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgIHRleHQ6IGBObyBhZ2VudHMgaGF2ZSBoaWRkZW4gcG9ydHNgLFxuICAgICAgICAgIHN0eWxlOiAnaDMnLFxuICAgICAgICB9KTtcbiAgICAgIHByaW50ZXIuYWRkTmV3TGluZSgpO1xuICAgIH1cblxuICAgIC8vLS0tIE9WRVJWSUVXL0FHRU5UUyAtIFBDSVxuICAgIGlmIChbJ292ZXJ2aWV3JywgJ2FnZW50cyddLmluY2x1ZGVzKHNlY3Rpb24pICYmIHRhYiA9PT0gJ3BjaScpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnRmV0Y2hpbmcgdG9wIFBDSSBEU1MgcmVxdWlyZW1lbnRzJywgJ2RlYnVnJyk7XG4gICAgICBjb25zdCB0b3BQY2lSZXF1aXJlbWVudHMgPSBhd2FpdCBQQ0lSZXF1ZXN0LnRvcFBDSVJlcXVpcmVtZW50cyhcbiAgICAgICAgY29udGV4dCxcbiAgICAgICAgZnJvbSxcbiAgICAgICAgdG8sXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgIHBhdHRlcm5cbiAgICAgICk7XG4gICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgIHRleHQ6ICdNb3N0IGNvbW1vbiBQQ0kgRFNTIHJlcXVpcmVtZW50cyBhbGVydHMgZm91bmQnLFxuICAgICAgICBzdHlsZTogJ2gyJyxcbiAgICAgIH0pO1xuICAgICAgZm9yIChjb25zdCBpdGVtIG9mIHRvcFBjaVJlcXVpcmVtZW50cykge1xuICAgICAgICBjb25zdCBydWxlcyA9IGF3YWl0IFBDSVJlcXVlc3QuZ2V0UnVsZXNCeVJlcXVpcmVtZW50KFxuICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgZnJvbSxcbiAgICAgICAgICB0byxcbiAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgICAgaXRlbSxcbiAgICAgICAgICBwYXR0ZXJuXG4gICAgICAgICk7XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHsgdGV4dDogYFJlcXVpcmVtZW50ICR7aXRlbX1gLCBzdHlsZTogJ2gzJyB9KTtcblxuICAgICAgICBpZiAoUENJW2l0ZW1dKSB7XG4gICAgICAgICAgY29uc3QgY29udGVudCA9XG4gICAgICAgICAgICB0eXBlb2YgUENJW2l0ZW1dID09PSAnc3RyaW5nJyA/IHsgdGV4dDogUENJW2l0ZW1dLCBzdHlsZTogJ3N0YW5kYXJkJyB9IDogUENJW2l0ZW1dO1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKGNvbnRlbnQpO1xuICAgICAgICB9XG5cbiAgICAgICAgcnVsZXMgJiZcbiAgICAgICAgICBydWxlcy5sZW5ndGggJiZcbiAgICAgICAgICBwcmludGVyLmFkZFNpbXBsZVRhYmxlKHtcbiAgICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgICAgeyBpZDogJ3J1bGVJRCcsIGxhYmVsOiAnUnVsZSBJRCcgfSxcbiAgICAgICAgICAgICAgeyBpZDogJ3J1bGVEZXNjcmlwdGlvbicsIGxhYmVsOiAnRGVzY3JpcHRpb24nIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgaXRlbXM6IHJ1bGVzLFxuICAgICAgICAgICAgdGl0bGU6IGBUb3AgcnVsZXMgZm9yICR7aXRlbX0gcmVxdWlyZW1lbnRgLFxuICAgICAgICAgIH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vLS0tIE9WRVJWSUVXL0FHRU5UUyAtIFRTQ1xuICAgIGlmIChbJ292ZXJ2aWV3JywgJ2FnZW50cyddLmluY2x1ZGVzKHNlY3Rpb24pICYmIHRhYiA9PT0gJ3RzYycpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnRmV0Y2hpbmcgdG9wIFRTQyByZXF1aXJlbWVudHMnLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IHRvcFRTQ1JlcXVpcmVtZW50cyA9IGF3YWl0IFRTQ1JlcXVlc3QudG9wVFNDUmVxdWlyZW1lbnRzKFxuICAgICAgICBjb250ZXh0LFxuICAgICAgICBmcm9tLFxuICAgICAgICB0byxcbiAgICAgICAgZmlsdGVycyxcbiAgICAgICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICAgICAgcGF0dGVyblxuICAgICAgKTtcbiAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgdGV4dDogJ01vc3QgY29tbW9uIFRTQyByZXF1aXJlbWVudHMgYWxlcnRzIGZvdW5kJyxcbiAgICAgICAgc3R5bGU6ICdoMicsXG4gICAgICB9KTtcbiAgICAgIGZvciAoY29uc3QgaXRlbSBvZiB0b3BUU0NSZXF1aXJlbWVudHMpIHtcbiAgICAgICAgY29uc3QgcnVsZXMgPSBhd2FpdCBUU0NSZXF1ZXN0LmdldFJ1bGVzQnlSZXF1aXJlbWVudChcbiAgICAgICAgICBjb250ZXh0LFxuICAgICAgICAgIGZyb20sXG4gICAgICAgICAgdG8sXG4gICAgICAgICAgZmlsdGVycyxcbiAgICAgICAgICBhbGxvd2VkQWdlbnRzRmlsdGVyLFxuICAgICAgICAgIGl0ZW0sXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7IHRleHQ6IGBSZXF1aXJlbWVudCAke2l0ZW19YCwgc3R5bGU6ICdoMycgfSk7XG5cbiAgICAgICAgaWYgKFRTQ1tpdGVtXSkge1xuICAgICAgICAgIGNvbnN0IGNvbnRlbnQgPVxuICAgICAgICAgICAgdHlwZW9mIFRTQ1tpdGVtXSA9PT0gJ3N0cmluZycgPyB7IHRleHQ6IFRTQ1tpdGVtXSwgc3R5bGU6ICdzdGFuZGFyZCcgfSA6IFRTQ1tpdGVtXTtcbiAgICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZShjb250ZW50KTtcbiAgICAgICAgfVxuXG4gICAgICAgIHJ1bGVzICYmXG4gICAgICAgICAgcnVsZXMubGVuZ3RoICYmXG4gICAgICAgICAgcHJpbnRlci5hZGRTaW1wbGVUYWJsZSh7XG4gICAgICAgICAgICBjb2x1bW5zOiBbXG4gICAgICAgICAgICAgIHsgaWQ6ICdydWxlSUQnLCBsYWJlbDogJ1J1bGUgSUQnIH0sXG4gICAgICAgICAgICAgIHsgaWQ6ICdydWxlRGVzY3JpcHRpb24nLCBsYWJlbDogJ0Rlc2NyaXB0aW9uJyB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIGl0ZW1zOiBydWxlcyxcbiAgICAgICAgICAgIHRpdGxlOiBgVG9wIHJ1bGVzIGZvciAke2l0ZW19IHJlcXVpcmVtZW50YCxcbiAgICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLy0tLSBPVkVSVklFVy9BR0VOVFMgLSBHRFBSXG4gICAgaWYgKFsnb3ZlcnZpZXcnLCAnYWdlbnRzJ10uaW5jbHVkZXMoc2VjdGlvbikgJiYgdGFiID09PSAnZ2RwcicpIHtcbiAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCAnRmV0Y2hpbmcgdG9wIEdEUFIgcmVxdWlyZW1lbnRzJywgJ2RlYnVnJyk7XG4gICAgICBjb25zdCB0b3BHZHByUmVxdWlyZW1lbnRzID0gYXdhaXQgR0RQUlJlcXVlc3QudG9wR0RQUlJlcXVpcmVtZW50cyhcbiAgICAgICAgY29udGV4dCxcbiAgICAgICAgZnJvbSxcbiAgICAgICAgdG8sXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgIHBhdHRlcm5cbiAgICAgICk7XG4gICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgIHRleHQ6ICdNb3N0IGNvbW1vbiBHRFBSIHJlcXVpcmVtZW50cyBhbGVydHMgZm91bmQnLFxuICAgICAgICBzdHlsZTogJ2gyJyxcbiAgICAgIH0pO1xuICAgICAgZm9yIChjb25zdCBpdGVtIG9mIHRvcEdkcHJSZXF1aXJlbWVudHMpIHtcbiAgICAgICAgY29uc3QgcnVsZXMgPSBhd2FpdCBHRFBSUmVxdWVzdC5nZXRSdWxlc0J5UmVxdWlyZW1lbnQoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICAgICAgICBpdGVtLFxuICAgICAgICAgIHBhdHRlcm5cbiAgICAgICAgKTtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoeyB0ZXh0OiBgUmVxdWlyZW1lbnQgJHtpdGVtfWAsIHN0eWxlOiAnaDMnIH0pO1xuXG4gICAgICAgIGlmIChHRFBSICYmIEdEUFJbaXRlbV0pIHtcbiAgICAgICAgICBjb25zdCBjb250ZW50ID1cbiAgICAgICAgICAgIHR5cGVvZiBHRFBSW2l0ZW1dID09PSAnc3RyaW5nJyA/IHsgdGV4dDogR0RQUltpdGVtXSwgc3R5bGU6ICdzdGFuZGFyZCcgfSA6IEdEUFJbaXRlbV07XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoY29udGVudCk7XG4gICAgICAgIH1cblxuICAgICAgICBydWxlcyAmJlxuICAgICAgICAgIHJ1bGVzLmxlbmd0aCAmJlxuICAgICAgICAgIHByaW50ZXIuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgICB7IGlkOiAncnVsZUlEJywgbGFiZWw6ICdSdWxlIElEJyB9LFxuICAgICAgICAgICAgICB7IGlkOiAncnVsZURlc2NyaXB0aW9uJywgbGFiZWw6ICdEZXNjcmlwdGlvbicgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgICBpdGVtczogcnVsZXMsXG4gICAgICAgICAgICB0aXRsZTogYFRvcCBydWxlcyBmb3IgJHtpdGVtfSByZXF1aXJlbWVudGAsXG4gICAgICAgICAgfSk7XG4gICAgICB9XG4gICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICB9XG5cbiAgICAvLy0tLSBPVkVSVklFVyAtIEFVRElUXG4gICAgaWYgKHNlY3Rpb24gPT09ICdvdmVydmlldycgJiYgdGFiID09PSAnYXVkaXQnKSB7XG4gICAgICBsb2coXG4gICAgICAgICdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsXG4gICAgICAgICdGZXRjaGluZyBhZ2VudHMgd2l0aCBoaWdoIG51bWJlciBvZiBmYWlsZWQgc3VkbyBjb21tYW5kcycsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG4gICAgICBjb25zdCBhdWRpdEFnZW50c05vblN1Y2Nlc3MgPSBhd2FpdCBBdWRpdFJlcXVlc3QuZ2V0VG9wM0FnZW50c1N1ZG9Ob25TdWNjZXNzZnVsKFxuICAgICAgICBjb250ZXh0LFxuICAgICAgICBmcm9tLFxuICAgICAgICB0byxcbiAgICAgICAgZmlsdGVycyxcbiAgICAgICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICAgICAgcGF0dGVyblxuICAgICAgKTtcbiAgICAgIGlmIChhdWRpdEFnZW50c05vblN1Y2Nlc3MgJiYgYXVkaXRBZ2VudHNOb25TdWNjZXNzLmxlbmd0aCkge1xuICAgICAgICBwcmludGVyLmFkZENvbnRlbnQoe1xuICAgICAgICAgIHRleHQ6ICdBZ2VudHMgd2l0aCBoaWdoIG51bWJlciBvZiBmYWlsZWQgc3VkbyBjb21tYW5kcycsXG4gICAgICAgICAgc3R5bGU6ICdoMicsXG4gICAgICAgIH0pO1xuICAgICAgICBhd2FpdCBidWlsZEFnZW50c1RhYmxlKGNvbnRleHQsIHByaW50ZXIsIGF1ZGl0QWdlbnRzTm9uU3VjY2VzcywgYXBpSWQpO1xuICAgICAgfVxuICAgICAgY29uc3QgYXVkaXRBZ2VudHNGYWlsZWRTeXNjYWxsID0gYXdhaXQgQXVkaXRSZXF1ZXN0LmdldFRvcDNBZ2VudHNGYWlsZWRTeXNjYWxscyhcbiAgICAgICAgY29udGV4dCxcbiAgICAgICAgZnJvbSxcbiAgICAgICAgdG8sXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgIHBhdHRlcm5cbiAgICAgICk7XG4gICAgICBpZiAoYXVkaXRBZ2VudHNGYWlsZWRTeXNjYWxsICYmIGF1ZGl0QWdlbnRzRmFpbGVkU3lzY2FsbC5sZW5ndGgpIHtcbiAgICAgICAgcHJpbnRlci5hZGRTaW1wbGVUYWJsZSh7XG4gICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgeyBpZDogJ2FnZW50JywgbGFiZWw6ICdBZ2VudCBJRCcgfSxcbiAgICAgICAgICAgIHsgaWQ6ICdzeXNjYWxsX2lkJywgbGFiZWw6ICdTeXNjYWxsIElEJyB9LFxuICAgICAgICAgICAgeyBpZDogJ3N5c2NhbGxfc3lzY2FsbCcsIGxhYmVsOiAnU3lzY2FsbCcgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGl0ZW1zOiBhdWRpdEFnZW50c0ZhaWxlZFN5c2NhbGwubWFwKChpdGVtKSA9PiAoe1xuICAgICAgICAgICAgYWdlbnQ6IGl0ZW0uYWdlbnQsXG4gICAgICAgICAgICBzeXNjYWxsX2lkOiBpdGVtLnN5c2NhbGwuaWQsXG4gICAgICAgICAgICBzeXNjYWxsX3N5c2NhbGw6IGl0ZW0uc3lzY2FsbC5zeXNjYWxsLFxuICAgICAgICAgIH0pKSxcbiAgICAgICAgICB0aXRsZToge1xuICAgICAgICAgICAgdGV4dDogJ01vc3QgY29tbW9uIGZhaWxpbmcgc3lzY2FsbHMnLFxuICAgICAgICAgICAgc3R5bGU6ICdoMicsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8tLS0gT1ZFUlZJRVcgLSBGSU1cbiAgICBpZiAoc2VjdGlvbiA9PT0gJ292ZXJ2aWV3JyAmJiB0YWIgPT09ICdmaW0nKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgJ0ZldGNoaW5nIHRvcCAzIHJ1bGVzIGZvciBGSU0nLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IHJ1bGVzID0gYXdhaXQgU3lzY2hlY2tSZXF1ZXN0LnRvcDNSdWxlcyhjb250ZXh0LCBmcm9tLCB0bywgZmlsdGVycywgYWxsb3dlZEFnZW50c0ZpbHRlciwgcGF0dGVybik7XG5cbiAgICAgIGlmIChydWxlcyAmJiBydWxlcy5sZW5ndGgpIHtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoeyB0ZXh0OiAnVG9wIDMgRklNIHJ1bGVzJywgc3R5bGU6ICdoMicgfSkuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgIHsgaWQ6ICdydWxlSUQnLCBsYWJlbDogJ1J1bGUgSUQnIH0sXG4gICAgICAgICAgICB7IGlkOiAncnVsZURlc2NyaXB0aW9uJywgbGFiZWw6ICdEZXNjcmlwdGlvbicgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGl0ZW1zOiBydWxlcyxcbiAgICAgICAgICB0aXRsZToge1xuICAgICAgICAgICAgdGV4dDogJ1RvcCAzIHJ1bGVzIHRoYXQgYXJlIGdlbmVyYXRpbmcgbW9zdCBhbGVydHMuJyxcbiAgICAgICAgICAgIHN0eWxlOiAnc3RhbmRhcmQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0pO1xuICAgICAgfVxuXG4gICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgJ0ZldGNoaW5nIHRvcCAzIGFnZW50cyBmb3IgRklNJywgJ2RlYnVnJyk7XG4gICAgICBjb25zdCBhZ2VudHMgPSBhd2FpdCBTeXNjaGVja1JlcXVlc3QudG9wM2FnZW50cyhjb250ZXh0LCBmcm9tLCB0bywgZmlsdGVycywgYWxsb3dlZEFnZW50c0ZpbHRlciwgcGF0dGVybik7XG5cbiAgICAgIGlmIChhZ2VudHMgJiYgYWdlbnRzLmxlbmd0aCkge1xuICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgICAgdGV4dDogJ0FnZW50cyB3aXRoIHN1c3BpY2lvdXMgRklNIGFjdGl2aXR5JyxcbiAgICAgICAgICBzdHlsZTogJ2gyJyxcbiAgICAgICAgfSk7XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHtcbiAgICAgICAgICB0ZXh0OlxuICAgICAgICAgICAgJ1RvcCAzIGFnZW50cyB0aGF0IGhhdmUgbW9zdCBGSU0gYWxlcnRzIGZyb20gbGV2ZWwgNyB0byBsZXZlbCAxNS4gVGFrZSBjYXJlIGFib3V0IHRoZW0uJyxcbiAgICAgICAgICBzdHlsZTogJ3N0YW5kYXJkJyxcbiAgICAgICAgfSk7XG4gICAgICAgIGF3YWl0IGJ1aWxkQWdlbnRzVGFibGUoY29udGV4dCwgcHJpbnRlciwgYWdlbnRzLCBhcGlJZCk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8tLS0gQUdFTlRTIC0gQVVESVRcbiAgICBpZiAoc2VjdGlvbiA9PT0gJ2FnZW50cycgJiYgdGFiID09PSAnYXVkaXQnKSB7XG4gICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgYEZldGNoaW5nIG1vc3QgY29tbW9uIGZhaWxlZCBzeXNjYWxsc2AsICdkZWJ1ZycpO1xuICAgICAgY29uc3QgYXVkaXRGYWlsZWRTeXNjYWxsID0gYXdhaXQgQXVkaXRSZXF1ZXN0LmdldFRvcEZhaWxlZFN5c2NhbGxzKFxuICAgICAgICBjb250ZXh0LFxuICAgICAgICBmcm9tLFxuICAgICAgICB0byxcbiAgICAgICAgZmlsdGVycyxcbiAgICAgICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICAgICAgcGF0dGVyblxuICAgICAgKTtcbiAgICAgIGF1ZGl0RmFpbGVkU3lzY2FsbCAmJlxuICAgICAgICBhdWRpdEZhaWxlZFN5c2NhbGwubGVuZ3RoICYmXG4gICAgICAgIHByaW50ZXIuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgIHsgaWQ6ICdpZCcsIGxhYmVsOiAnaWQnIH0sXG4gICAgICAgICAgICB7IGlkOiAnc3lzY2FsbCcsIGxhYmVsOiAnU3lzY2FsbCcgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGl0ZW1zOiBhdWRpdEZhaWxlZFN5c2NhbGwsXG4gICAgICAgICAgdGl0bGU6ICdNb3N0IGNvbW1vbiBmYWlsaW5nIHN5c2NhbGxzJyxcbiAgICAgICAgfSk7XG4gICAgfVxuXG4gICAgLy8tLS0gQUdFTlRTIC0gRklNXG4gICAgaWYgKHNlY3Rpb24gPT09ICdhZ2VudHMnICYmIHRhYiA9PT0gJ2ZpbScpIHtcbiAgICAgIGxvZyhcbiAgICAgICAgJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJyxcbiAgICAgICAgYEZldGNoaW5nIHN5c2NoZWNrIGRhdGFiYXNlIGZvciBhZ2VudCAke2FnZW50fWAsXG4gICAgICAgICdkZWJ1ZydcbiAgICAgICk7XG5cbiAgICAgIGNvbnN0IGxhc3RTY2FuUmVzcG9uc2UgPSBhd2FpdCBjb250ZXh0LndhenVoLmFwaS5jbGllbnQuYXNDdXJyZW50VXNlci5yZXF1ZXN0KFxuICAgICAgICAnR0VUJyxcbiAgICAgICAgYC9zeXNjaGVjay8ke2FnZW50fS9sYXN0X3NjYW5gLFxuICAgICAgICB7fSxcbiAgICAgICAgeyBhcGlIb3N0SUQ6IGFwaUlkIH1cbiAgICAgICk7XG5cbiAgICAgIGlmIChsYXN0U2NhblJlc3BvbnNlICYmIGxhc3RTY2FuUmVzcG9uc2UuZGF0YSkge1xuICAgICAgICBjb25zdCBsYXN0U2NhbkRhdGEgPSBsYXN0U2NhblJlc3BvbnNlLmRhdGEuZGF0YS5hZmZlY3RlZF9pdGVtc1swXTtcbiAgICAgICAgaWYgKGxhc3RTY2FuRGF0YS5zdGFydCAmJiBsYXN0U2NhbkRhdGEuZW5kKSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6IGBMYXN0IGZpbGUgaW50ZWdyaXR5IG1vbml0b3Jpbmcgc2NhbiB3YXMgZXhlY3V0ZWQgZnJvbSAke2xhc3RTY2FuRGF0YS5zdGFydH0gdG8gJHtsYXN0U2NhbkRhdGEuZW5kfS5gLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9IGVsc2UgaWYgKGxhc3RTY2FuRGF0YS5zdGFydCkge1xuICAgICAgICAgIHByaW50ZXIuYWRkQ29udGVudCh7XG4gICAgICAgICAgICB0ZXh0OiBgRmlsZSBpbnRlZ3JpdHkgbW9uaXRvcmluZyBzY2FuIGlzIGN1cnJlbnRseSBpbiBwcm9ncmVzcyBmb3IgdGhpcyBhZ2VudCAoc3RhcnRlZCBvbiAke2xhc3RTY2FuRGF0YS5zdGFydH0pLmAsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgcHJpbnRlci5hZGRDb250ZW50KHtcbiAgICAgICAgICAgIHRleHQ6IGBGaWxlIGludGVncml0eSBtb25pdG9yaW5nIHNjYW4gaXMgY3VycmVudGx5IGluIHByb2dyZXNzIGZvciB0aGlzIGFnZW50LmAsXG4gICAgICAgICAgfSk7XG4gICAgICAgIH1cbiAgICAgICAgcHJpbnRlci5hZGROZXdMaW5lKCk7XG4gICAgICB9XG5cbiAgICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCBgRmV0Y2hpbmcgbGFzdCAxMCBkZWxldGVkIGZpbGVzIGZvciBGSU1gLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGxhc3RUZW5EZWxldGVkID0gYXdhaXQgU3lzY2hlY2tSZXF1ZXN0Lmxhc3RUZW5EZWxldGVkRmlsZXMoXG4gICAgICAgIGNvbnRleHQsXG4gICAgICAgIGZyb20sXG4gICAgICAgIHRvLFxuICAgICAgICBmaWx0ZXJzLFxuICAgICAgICBhbGxvd2VkQWdlbnRzRmlsdGVyLFxuICAgICAgICBwYXR0ZXJuXG4gICAgICApO1xuXG4gICAgICBsYXN0VGVuRGVsZXRlZCAmJlxuICAgICAgICBsYXN0VGVuRGVsZXRlZC5sZW5ndGggJiZcbiAgICAgICAgcHJpbnRlci5hZGRTaW1wbGVUYWJsZSh7XG4gICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgeyBpZDogJ3BhdGgnLCBsYWJlbDogJ1BhdGgnIH0sXG4gICAgICAgICAgICB7IGlkOiAnZGF0ZScsIGxhYmVsOiAnRGF0ZScgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGl0ZW1zOiBsYXN0VGVuRGVsZXRlZCxcbiAgICAgICAgICB0aXRsZTogJ0xhc3QgMTAgZGVsZXRlZCBmaWxlcycsXG4gICAgICAgIH0pO1xuXG4gICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgYEZldGNoaW5nIGxhc3QgMTAgbW9kaWZpZWQgZmlsZXNgLCAnZGVidWcnKTtcbiAgICAgIGNvbnN0IGxhc3RUZW5Nb2RpZmllZCA9IGF3YWl0IFN5c2NoZWNrUmVxdWVzdC5sYXN0VGVuTW9kaWZpZWRGaWxlcyhcbiAgICAgICAgY29udGV4dCxcbiAgICAgICAgZnJvbSxcbiAgICAgICAgdG8sXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgIHBhdHRlcm5cbiAgICAgICk7XG5cbiAgICAgIGxhc3RUZW5Nb2RpZmllZCAmJlxuICAgICAgICBsYXN0VGVuTW9kaWZpZWQubGVuZ3RoICYmXG4gICAgICAgIHByaW50ZXIuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgIGNvbHVtbnM6IFtcbiAgICAgICAgICAgIHsgaWQ6ICdwYXRoJywgbGFiZWw6ICdQYXRoJyB9LFxuICAgICAgICAgICAgeyBpZDogJ2RhdGUnLCBsYWJlbDogJ0RhdGUnIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBpdGVtczogbGFzdFRlbk1vZGlmaWVkLFxuICAgICAgICAgIHRpdGxlOiAnTGFzdCAxMCBtb2RpZmllZCBmaWxlcycsXG4gICAgICAgIH0pO1xuICAgIH1cblxuICAgIC8vLS0tIEFHRU5UUyAtIFNZU0NPTExFQ1RPUlxuICAgIGlmIChzZWN0aW9uID09PSAnYWdlbnRzJyAmJiB0YWIgPT09ICdzeXNjb2xsZWN0b3InKSB7XG4gICAgICBsb2coXG4gICAgICAgICdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsXG4gICAgICAgIGBGZXRjaGluZyBoYXJkd2FyZSBpbmZvcm1hdGlvbiBmb3IgYWdlbnQgJHthZ2VudH1gLFxuICAgICAgICAnZGVidWcnXG4gICAgICApO1xuICAgICAgY29uc3QgcmVxdWVzdHNTeXNjb2xsZWN0b3JMaXN0cyA9IFtcbiAgICAgICAge1xuICAgICAgICAgIGVuZHBvaW50OiBgL3N5c2NvbGxlY3Rvci8ke2FnZW50fS9oYXJkd2FyZWAsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIEhhcmR3YXJlIGluZm9ybWF0aW9uIGZvciBhZ2VudCAke2FnZW50fWAsXG4gICAgICAgICAgbGlzdDoge1xuICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0hhcmR3YXJlIGluZm9ybWF0aW9uJywgc3R5bGU6ICdoMicgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIG1hcFJlc3BvbnNlOiAoaGFyZHdhcmUpID0+IFtcbiAgICAgICAgICAgIGhhcmR3YXJlLmNwdSAmJiBoYXJkd2FyZS5jcHUuY29yZXMgJiYgYCR7aGFyZHdhcmUuY3B1LmNvcmVzfSBjb3Jlc2AsXG4gICAgICAgICAgICBoYXJkd2FyZS5jcHUgJiYgaGFyZHdhcmUuY3B1Lm5hbWUsXG4gICAgICAgICAgICBoYXJkd2FyZS5yYW0gJiZcbiAgICAgICAgICAgIGhhcmR3YXJlLnJhbS50b3RhbCAmJlxuICAgICAgICAgICAgYCR7TnVtYmVyKGhhcmR3YXJlLnJhbS50b3RhbCAvIDEwMjQgLyAxMDI0KS50b0ZpeGVkKDIpfUdCIFJBTWAsXG4gICAgICAgICAgXSxcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIGVuZHBvaW50OiBgL3N5c2NvbGxlY3Rvci8ke2FnZW50fS9vc2AsXG4gICAgICAgICAgbG9nZ2VyTWVzc2FnZTogYEZldGNoaW5nIG9wZXJhdGluZyBzeXN0ZW0gaW5mb3JtYXRpb24gZm9yIGFnZW50ICR7YWdlbnR9YCxcbiAgICAgICAgICBsaXN0OiB7XG4gICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnT3BlcmF0aW5nIHN5c3RlbSBpbmZvcm1hdGlvbicsIHN0eWxlOiAnaDInIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBtYXBSZXNwb25zZTogKG9zRGF0YSkgPT4gW1xuICAgICAgICAgICAgb3NEYXRhLnN5c25hbWUsXG4gICAgICAgICAgICBvc0RhdGEudmVyc2lvbixcbiAgICAgICAgICAgIG9zRGF0YS5hcmNoaXRlY3R1cmUsXG4gICAgICAgICAgICBvc0RhdGEucmVsZWFzZSxcbiAgICAgICAgICAgIG9zRGF0YS5vcyAmJlxuICAgICAgICAgICAgb3NEYXRhLm9zLm5hbWUgJiZcbiAgICAgICAgICAgIG9zRGF0YS5vcy52ZXJzaW9uICYmXG4gICAgICAgICAgICBgJHtvc0RhdGEub3MubmFtZX0gJHtvc0RhdGEub3MudmVyc2lvbn1gLFxuICAgICAgICAgIF0sXG4gICAgICAgIH0sXG4gICAgICBdO1xuXG4gICAgICBjb25zdCBzeXNjb2xsZWN0b3JMaXN0cyA9IGF3YWl0IFByb21pc2UuYWxsKFxuICAgICAgICByZXF1ZXN0c1N5c2NvbGxlY3Rvckxpc3RzLm1hcChhc3luYyAocmVxdWVzdFN5c2NvbGxlY3RvcikgPT4ge1xuICAgICAgICAgIHRyeSB7XG4gICAgICAgICAgICBsb2coJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJywgcmVxdWVzdFN5c2NvbGxlY3Rvci5sb2dnZXJNZXNzYWdlLCAnZGVidWcnKTtcbiAgICAgICAgICAgIGNvbnN0IHJlc3BvbnNlU3lzY29sbGVjdG9yID0gYXdhaXQgY29udGV4dC53YXp1aC5hcGkuY2xpZW50LmFzQ3VycmVudFVzZXIucmVxdWVzdChcbiAgICAgICAgICAgICAgJ0dFVCcsXG4gICAgICAgICAgICAgIHJlcXVlc3RTeXNjb2xsZWN0b3IuZW5kcG9pbnQsXG4gICAgICAgICAgICAgIHt9LFxuICAgICAgICAgICAgICB7IGFwaUhvc3RJRDogYXBpSWQgfVxuICAgICAgICAgICAgKTtcbiAgICAgICAgICAgIGNvbnN0IFtkYXRhXSA9XG4gICAgICAgICAgICAgIChyZXNwb25zZVN5c2NvbGxlY3RvciAmJlxuICAgICAgICAgICAgICAgIHJlc3BvbnNlU3lzY29sbGVjdG9yLmRhdGEgJiZcbiAgICAgICAgICAgICAgICByZXNwb25zZVN5c2NvbGxlY3Rvci5kYXRhLmRhdGEgJiZcbiAgICAgICAgICAgICAgICByZXNwb25zZVN5c2NvbGxlY3Rvci5kYXRhLmRhdGEuYWZmZWN0ZWRfaXRlbXMpIHx8XG4gICAgICAgICAgICAgIFtdO1xuICAgICAgICAgICAgaWYgKGRhdGEpIHtcbiAgICAgICAgICAgICAgcmV0dXJuIHtcbiAgICAgICAgICAgICAgICAuLi5yZXF1ZXN0U3lzY29sbGVjdG9yLmxpc3QsXG4gICAgICAgICAgICAgICAgbGlzdDogcmVxdWVzdFN5c2NvbGxlY3Rvci5tYXBSZXNwb25zZShkYXRhKSxcbiAgICAgICAgICAgICAgfTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICAgICAgbG9nKCdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICAgICk7XG5cbiAgICAgIGlmIChzeXNjb2xsZWN0b3JMaXN0cykge1xuICAgICAgICBzeXNjb2xsZWN0b3JMaXN0c1xuICAgICAgICAgIC5maWx0ZXIoKHN5c2NvbGxlY3Rvckxpc3QpID0+IHN5c2NvbGxlY3Rvckxpc3QpXG4gICAgICAgICAgLmZvckVhY2goKHN5c2NvbGxlY3Rvckxpc3QpID0+IHByaW50ZXIuYWRkTGlzdChzeXNjb2xsZWN0b3JMaXN0KSk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IHZ1bG5lcmFiaWxpdGllc1JlcXVlc3RzID0gWydDcml0aWNhbCcsICdIaWdoJ107XG5cbiAgICAgIGNvbnN0IHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0l0ZW1zID0gKFxuICAgICAgICBhd2FpdCBQcm9taXNlLmFsbChcbiAgICAgICAgICB2dWxuZXJhYmlsaXRpZXNSZXF1ZXN0cy5tYXAoYXN5bmMgKHZ1bG5lcmFiaWxpdGllc0xldmVsKSA9PiB7XG4gICAgICAgICAgICB0cnkge1xuICAgICAgICAgICAgICBsb2coXG4gICAgICAgICAgICAgICAgJ3JlcG9ydGluZzpleHRlbmRlZEluZm9ybWF0aW9uJyxcbiAgICAgICAgICAgICAgICBgRmV0Y2hpbmcgdG9wICR7dnVsbmVyYWJpbGl0aWVzTGV2ZWx9IHBhY2thZ2VzYCxcbiAgICAgICAgICAgICAgICAnZGVidWcnXG4gICAgICAgICAgICAgICk7XG5cbiAgICAgICAgICAgICAgcmV0dXJuIGF3YWl0IFZ1bG5lcmFiaWxpdHlSZXF1ZXN0LnRvcFBhY2thZ2VzKFxuICAgICAgICAgICAgICAgIGNvbnRleHQsXG4gICAgICAgICAgICAgICAgZnJvbSxcbiAgICAgICAgICAgICAgICB0byxcbiAgICAgICAgICAgICAgICB2dWxuZXJhYmlsaXRpZXNMZXZlbCxcbiAgICAgICAgICAgICAgICBmaWx0ZXJzLFxuICAgICAgICAgICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgICAgICAgICAgcGF0dGVyblxuICAgICAgICAgICAgICApO1xuICAgICAgICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgICAgICAgbG9nKCdyZXBvcnRpbmc6ZXh0ZW5kZWRJbmZvcm1hdGlvbicsIGVycm9yLm1lc3NhZ2UgfHwgZXJyb3IpO1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0pXG4gICAgICAgIClcbiAgICAgIClcbiAgICAgICAgLmZpbHRlcigodnVsbmVyYWJpbGl0aWVzUmVzcG9uc2UpID0+IHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlKVxuICAgICAgICAuZmxhdCgpO1xuXG4gICAgICBpZiAodnVsbmVyYWJpbGl0aWVzUmVzcG9uc2VzSXRlbXMgJiYgdnVsbmVyYWJpbGl0aWVzUmVzcG9uc2VzSXRlbXMubGVuZ3RoKSB7XG4gICAgICAgIHByaW50ZXIuYWRkU2ltcGxlVGFibGUoe1xuICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdWdWxuZXJhYmxlIHBhY2thZ2VzIGZvdW5kIChsYXN0IDI0IGhvdXJzKScsIHN0eWxlOiAnaDInIH0sXG4gICAgICAgICAgY29sdW1uczogW1xuICAgICAgICAgICAgeyBpZDogJ3BhY2thZ2UnLCBsYWJlbDogJ1BhY2thZ2UnIH0sXG4gICAgICAgICAgICB7IGlkOiAnc2V2ZXJpdHknLCBsYWJlbDogJ1NldmVyaXR5JyB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgaXRlbXM6IHZ1bG5lcmFiaWxpdGllc1Jlc3BvbnNlc0l0ZW1zLFxuICAgICAgICB9KTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLy0tLSBBR0VOVFMgLSBWVUxORVJBQklMSVRJRVNcbiAgICBpZiAoc2VjdGlvbiA9PT0gJ2FnZW50cycgJiYgdGFiID09PSAndnVscycpIHtcbiAgICAgIGNvbnN0IHRvcENyaXRpY2FsUGFja2FnZXMgPSBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC50b3BQYWNrYWdlc1dpdGhDVkUoXG4gICAgICAgIGNvbnRleHQsXG4gICAgICAgIGZyb20sXG4gICAgICAgIHRvLFxuICAgICAgICAnQ3JpdGljYWwnLFxuICAgICAgICBmaWx0ZXJzLFxuICAgICAgICBhbGxvd2VkQWdlbnRzRmlsdGVyLFxuICAgICAgICBwYXR0ZXJuXG4gICAgICApO1xuICAgICAgaWYgKHRvcENyaXRpY2FsUGFja2FnZXMgJiYgdG9wQ3JpdGljYWxQYWNrYWdlcy5sZW5ndGgpIHtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoeyB0ZXh0OiAnQ3JpdGljYWwgc2V2ZXJpdHknLCBzdHlsZTogJ2gyJyB9KTtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoe1xuICAgICAgICAgIHRleHQ6XG4gICAgICAgICAgICAnVGhlc2UgdnVsbmVyYWJpbHRpZXMgYXJlIGNyaXRpY2FsLCBwbGVhc2UgcmV2aWV3IHlvdXIgYWdlbnQuIENsaWNrIG9uIGVhY2ggbGluayB0byByZWFkIG1vcmUgYWJvdXQgZWFjaCBmb3VuZCB2dWxuZXJhYmlsaXR5LicsXG4gICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgIH0pO1xuICAgICAgICBjb25zdCBjdXN0b211bCA9IFtdO1xuICAgICAgICBmb3IgKGNvbnN0IGNyaXRpY2FsIG9mIHRvcENyaXRpY2FsUGFja2FnZXMpIHtcbiAgICAgICAgICBjdXN0b211bC5wdXNoKHsgdGV4dDogY3JpdGljYWwucGFja2FnZSwgc3R5bGU6ICdzdGFuZGFyZCcgfSk7XG4gICAgICAgICAgY3VzdG9tdWwucHVzaCh7XG4gICAgICAgICAgICB1bDogY3JpdGljYWwucmVmZXJlbmNlcy5tYXAoKGl0ZW0pID0+ICh7XG4gICAgICAgICAgICAgIHRleHQ6IGl0ZW0uc3Vic3RyaW5nKDAsIDgwKSArICcuLi4nLFxuICAgICAgICAgICAgICBsaW5rOiBpdGVtLFxuICAgICAgICAgICAgICBjb2xvcjogJyMxRUE1QzgnLFxuICAgICAgICAgICAgfSkpLFxuICAgICAgICAgIH0pO1xuICAgICAgICB9XG4gICAgICAgIHByaW50ZXIuYWRkQ29udGVudFdpdGhOZXdMaW5lKHsgdWw6IGN1c3RvbXVsIH0pO1xuICAgICAgfVxuXG4gICAgICBjb25zdCB0b3BIaWdoUGFja2FnZXMgPSBhd2FpdCBWdWxuZXJhYmlsaXR5UmVxdWVzdC50b3BQYWNrYWdlc1dpdGhDVkUoXG4gICAgICAgIGNvbnRleHQsXG4gICAgICAgIGZyb20sXG4gICAgICAgIHRvLFxuICAgICAgICAnSGlnaCcsXG4gICAgICAgIGZpbHRlcnMsXG4gICAgICAgIGFsbG93ZWRBZ2VudHNGaWx0ZXIsXG4gICAgICAgIHBhdHRlcm5cbiAgICAgICk7XG4gICAgICBpZiAodG9wSGlnaFBhY2thZ2VzICYmIHRvcEhpZ2hQYWNrYWdlcy5sZW5ndGgpIHtcbiAgICAgICAgcHJpbnRlci5hZGRDb250ZW50V2l0aE5ld0xpbmUoeyB0ZXh0OiAnSGlnaCBzZXZlcml0eScsIHN0eWxlOiAnaDInIH0pO1xuICAgICAgICBwcmludGVyLmFkZENvbnRlbnRXaXRoTmV3TGluZSh7XG4gICAgICAgICAgdGV4dDogJ0NsaWNrIG9uIGVhY2ggbGluayB0byByZWFkIG1vcmUgYWJvdXQgZWFjaCBmb3VuZCB2dWxuZXJhYmlsaXR5LicsXG4gICAgICAgICAgc3R5bGU6ICdzdGFuZGFyZCcsXG4gICAgICAgIH0pO1xuICAgICAgICBjb25zdCBjdXN0b211bCA9IFtdO1xuICAgICAgICBmb3IgKGNvbnN0IGNyaXRpY2FsIG9mIHRvcEhpZ2hQYWNrYWdlcykge1xuICAgICAgICAgIGN1c3RvbXVsLnB1c2goeyB0ZXh0OiBjcml0aWNhbC5wYWNrYWdlLCBzdHlsZTogJ3N0YW5kYXJkJyB9KTtcbiAgICAgICAgICBjdXN0b211bC5wdXNoKHtcbiAgICAgICAgICAgIHVsOiBjcml0aWNhbC5yZWZlcmVuY2VzLm1hcCgoaXRlbSkgPT4gKHtcbiAgICAgICAgICAgICAgdGV4dDogaXRlbSxcbiAgICAgICAgICAgICAgY29sb3I6ICcjMUVBNUM4JyxcbiAgICAgICAgICAgIH0pKSxcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICBjdXN0b211bCAmJiBjdXN0b211bC5sZW5ndGggJiYgcHJpbnRlci5hZGRDb250ZW50KHsgdWw6IGN1c3RvbXVsIH0pO1xuICAgICAgICBwcmludGVyLmFkZE5ld0xpbmUoKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLy0tLSBTVU1NQVJZIFRBQkxFU1xuICAgIGxldCBleHRyYVN1bW1hcnlUYWJsZXMgPSBbXTtcbiAgICBpZiAoQXJyYXkuaXNBcnJheShzdW1tYXJ5VGFibGVzRGVmaW5pdGlvbnNbc2VjdGlvbl1bdGFiXSkpIHtcbiAgICAgIGNvbnN0IHRhYmxlc1Byb21pc2VzID0gc3VtbWFyeVRhYmxlc0RlZmluaXRpb25zW3NlY3Rpb25dW3RhYl0ubWFwKChzdW1tYXJ5VGFibGUpID0+IHtcbiAgICAgICAgbG9nKCdyZXBvcnRpbmc6QWxlcnRzVGFibGUnLCBgRmV0Y2hpbmcgJHtzdW1tYXJ5VGFibGUudGl0bGV9IFRhYmxlYCwgJ2RlYnVnJyk7XG4gICAgICAgIGNvbnN0IGFsZXJ0c1N1bW1hcnlUYWJsZSA9IG5ldyBTdW1tYXJ5VGFibGUoXG4gICAgICAgICAgY29udGV4dCxcbiAgICAgICAgICBmcm9tLFxuICAgICAgICAgIHRvLFxuICAgICAgICAgIGZpbHRlcnMsXG4gICAgICAgICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICAgICAgICBzdW1tYXJ5VGFibGUsXG4gICAgICAgICAgcGF0dGVyblxuICAgICAgICApO1xuICAgICAgICByZXR1cm4gYWxlcnRzU3VtbWFyeVRhYmxlLmZldGNoKCk7XG4gICAgICB9KTtcbiAgICAgIGV4dHJhU3VtbWFyeVRhYmxlcyA9IGF3YWl0IFByb21pc2UuYWxsKHRhYmxlc1Byb21pc2VzKTtcbiAgICB9XG5cbiAgICByZXR1cm4gZXh0cmFTdW1tYXJ5VGFibGVzO1xuICB9IGNhdGNoIChlcnJvcikge1xuICAgIGxvZygncmVwb3J0aW5nOmV4dGVuZGVkSW5mb3JtYXRpb24nLCBlcnJvci5tZXNzYWdlIHx8IGVycm9yKTtcbiAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICB9XG59XG4iXX0=