"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.generateAlert = generateAlert;
exports.generateAlerts = generateAlerts;

var _common = require("./sample-data/common");

var _regulatoryCompliance = require("./sample-data/regulatory-compliance");

var Audit = _interopRequireWildcard(require("./sample-data/audit"));

var Authentication = _interopRequireWildcard(require("./sample-data/authentication"));

var AWS = _interopRequireWildcard(require("./sample-data/aws"));

var IntegrityMonitoring = _interopRequireWildcard(require("./sample-data/integrity-monitoring"));

var CISCAT = _interopRequireWildcard(require("./sample-data/ciscat"));

var GCP = _interopRequireWildcard(require("./sample-data/gcp"));

var Docker = _interopRequireWildcard(require("./sample-data/docker"));

var Mitre = _interopRequireWildcard(require("./sample-data/mitre"));

var Osquery = _interopRequireWildcard(require("./sample-data/osquery"));

var OpenSCAP = _interopRequireWildcard(require("./sample-data/openscap"));

var PolicyMonitoring = _interopRequireWildcard(require("./sample-data/policy-monitoring"));

var Virustotal = _interopRequireWildcard(require("./sample-data/virustotal"));

var Vulnerability = _interopRequireWildcard(require("./sample-data/vulnerabilities"));

var SSH = _interopRequireWildcard(require("./sample-data/ssh"));

var Apache = _interopRequireWildcard(require("./sample-data/apache"));

var Web = _interopRequireWildcard(require("./sample-data/web"));

var GitHub = _interopRequireWildcard(require("./sample-data/github"));

var Office = _interopRequireWildcard(require("./sample-data/office"));

function _getRequireWildcardCache(nodeInterop) { if (typeof WeakMap !== "function") return null; var cacheBabelInterop = new WeakMap(); var cacheNodeInterop = new WeakMap(); return (_getRequireWildcardCache = function (nodeInterop) { return nodeInterop ? cacheNodeInterop : cacheBabelInterop; })(nodeInterop); }

function _interopRequireWildcard(obj, nodeInterop) { if (!nodeInterop && obj && obj.__esModule) { return obj; } if (obj === null || typeof obj !== "object" && typeof obj !== "function") { return { default: obj }; } var cache = _getRequireWildcardCache(nodeInterop); if (cache && cache.has(obj)) { return cache.get(obj); } var newObj = {}; var hasPropertyDescriptor = Object.defineProperty && Object.getOwnPropertyDescriptor; for (var key in obj) { if (key !== "default" && Object.prototype.hasOwnProperty.call(obj, key)) { var desc = hasPropertyDescriptor ? Object.getOwnPropertyDescriptor(obj, key) : null; if (desc && (desc.get || desc.set)) { Object.defineProperty(newObj, key, desc); } else { newObj[key] = obj[key]; } } } newObj.default = obj; if (cache) { cache.set(obj, newObj); } return newObj; }

/*
 * Wazuh app - Script to generate sample alerts
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// General
//Alert
const alertIDMax = 6000; // Rule

const ruleDescription = ['Sample alert 1', 'Sample alert 2', 'Sample alert 3', 'Sample alert 4', 'Sample alert 5'];
const ruleMaxLevel = 14;
/**
 * Generate a alert
 * @param {any} params - params to configure the alert
 * @param {boolean} params.aws - if true, set aws fields
 * @param {boolean} params.audit - if true, set System Auditing fields
 * @param {boolean} params.office - if true, set office fields
 * @param {boolean} params.ciscat - if true, set CIS-CAT fields
 * @param {boolean} params.gcp - if true, set GCP fields
 * @param {boolean} params.docker - if true, set Docker fields
 * @param {boolean} params.mitre - if true, set Mitre att&ck fields
 * @param {boolean} params.openscap - if true, set OpenSCAP fields
 * @param {boolean} params.osquery - if true, set Osquery fields
 * @param {boolean} params.rootcheck - if true, set Policy monitoring fields
 * @param {boolean} params.syscheck - if true, set integrity monitoring fields
 * @param {boolean} params.virustotal - if true, set VirusTotal fields
 * @param {boolean} params.vulnerabilities - if true, set vulnerabilities fields
 * @param {boolean} params.pci_dss - if true, set pci_dss fields
 * @param {boolean} params.gdpr - if true, set gdpr fields
 * @param {boolean} params.gpg13 - if true, set gpg13 fields
 * @param {boolean} params.hipaa - if true, set hipaa fields
 * @param {boolean} params.nist_800_53 - if true, set nist_800_53 fields
 * @param {boolean} params.nist_800_53 - if true, set nist_800_53 fields
 * @param {boolean} params.win_authentication_failed - if true, add win_authentication_failed to rule.groups
 * @param {number} params.probability_win_authentication_failed - probability to add win_authentication_failed to rule.groups. Example: 20 will be 20% of probability to add this to rule.groups
 * @param {boolean} params.authentication_failed - if true, add win_authentication_failed to rule.groups
 * @param {number} params.probability_authentication_failed - probability to add authentication_failed to rule.groups
 * @param {boolean} params.authentication_failures - if true, add win_authentication_failed to rule.groups
 * @param {number} params.probability_authentication_failures - probability to add authentication_failures to rule.groups
 * @return {any} - Alert generated
 */

function generateAlert(params) {
  let alert = {
    ['@sampledata']: true,
    timestamp: '2020-01-27T11:08:47.777+0000',
    rule: {
      level: 3,
      description: 'Sample alert',
      id: '5502',
      mail: false,
      groups: []
    },
    agent: {
      id: '000',
      name: 'master'
    },
    manager: {
      name: 'master'
    },
    cluster: {
      name: 'wazuh'
    },
    id: '1580123327.49031',
    predecoder: {},
    decoder: {},
    data: {},
    location: ''
  };
  alert.agent = (0, _common.randomArrayItem)(_common.Agents);
  alert.rule.description = (0, _common.randomArrayItem)(ruleDescription);
  alert.rule.id = `${randomIntervalInteger(1, alertIDMax)}`;
  alert.rule.level = randomIntervalInteger(1, ruleMaxLevel);
  alert.timestamp = randomDate();

  if (params.manager) {
    if (params.manager.name) {
      alert.manager.name = params.manager.name;
    }
  }

  if (params.cluster) {
    if (params.cluster.name) {
      alert.cluster.name = params.cluster.name;
    }

    if (params.cluster.node) {
      alert.cluster.node = params.cluster.node;
    }
  }

  if (params.aws) {
    let randomType = (0, _common.randomArrayItem)(['guarddutyPortProbe', 'apiCall', 'networkConnection', 'iamPolicyGrantGlobal']);
    const beforeDate = new Date(new Date(alert.timestamp) - 3 * 24 * 60 * 60 * 1000);

    switch (randomType) {
      case 'guarddutyPortProbe':
        {
          const typeAlert = AWS.guarddutyPortProbe;
          alert.data = { ...typeAlert.data
          };
          alert.data.integration = 'aws';
          alert.data.aws.region = (0, _common.randomArrayItem)(AWS.region);
          alert.data.aws.resource.instanceDetails = { ...(0, _common.randomArrayItem)(AWS.instanceDetails)
          };
          alert.data.aws.resource.instanceDetails.iamInstanceProfile.arn = interpolateAlertProps(typeAlert.data.aws.resource.instanceDetails.iamInstanceProfile.arn, alert);
          alert.data.aws.title = interpolateAlertProps(alert.data.aws.title, alert);
          alert.data.aws.accountId = (0, _common.randomArrayItem)(AWS.accountId);
          alert.data.aws.service.eventFirstSeen = formatDate(beforeDate, 'Y-M-DTh:m:s.lZ');
          alert.data.aws.service.eventLastSeen = formatDate(new Date(alert.timestamp), 'Y-M-DTh:m:s.lZ');
          alert.data.aws.service.action.portProbeAction.portProbeDetails.remoteIpDetails = { ...(0, _common.randomArrayItem)(AWS.remoteIpDetails)
          };
          alert.data.aws.log_info = {
            s3bucket: (0, _common.randomArrayItem)(AWS.buckets),
            log_file: `guardduty/${formatDate(new Date(alert.timestamp), 'Y/M/D/h')}/firehose_guardduty-1-${formatDate(new Date(alert.timestamp), 'Y-M-D-h-m-s-l')}b5b9b-ec62-4a07-85d7-b1699b9c031e.zip`
          };
          alert.data.aws.service.count = `${randomIntervalInteger(400, 4000)}`;
          alert.data.aws.createdAt = formatDate(beforeDate, 'Y-M-DTh:m:s.lZ');
          alert.rule = { ...typeAlert.rule
          };
          alert.rule.firedtimes = randomIntervalInteger(1, 50);
          alert.rule.description = interpolateAlertProps(typeAlert.rule.description, alert);
          alert.decoder = { ...typeAlert.decoder
          };
          alert.location = typeAlert.location;
          break;
        }

      case 'apiCall':
        {
          const typeAlert = AWS.apiCall;
          alert.data = { ...typeAlert.data
          };
          alert.data.integration = 'aws';
          alert.data.aws.region = (0, _common.randomArrayItem)(AWS.region);
          alert.data.aws.resource.accessKeyDetails.userName = (0, _common.randomArrayItem)(_common.Users);
          alert.data.aws.log_info = {
            s3bucket: (0, _common.randomArrayItem)(AWS.buckets),
            log_file: `guardduty/${formatDate(new Date(alert.timestamp), 'Y/M/D/h')}/firehose_guardduty-1-${formatDate(new Date(alert.timestamp), 'Y-M-D-h-m-s-l')}b5b9b-ec62-4a07-85d7-b1699b9c031e.zip`
          };
          alert.data.aws.accountId = (0, _common.randomArrayItem)(AWS.accountId);
          alert.data.aws.service.action.awsApiCallAction.remoteIpDetails = { ...(0, _common.randomArrayItem)(AWS.remoteIpDetails)
          };
          alert.data.aws.service.eventFirstSeen = formatDate(beforeDate, 'Y-M-DTh:m:s.lZ');
          alert.data.aws.service.eventLastSeen = formatDate(new Date(alert.timestamp), 'Y-M-DTh:m:s.lZ');
          alert.data.aws.createdAt = formatDate(beforeDate, 'Y-M-DTh:m:s.lZ');
          alert.data.aws.title = interpolateAlertProps(alert.data.aws.title, alert);
          alert.data.aws.description = interpolateAlertProps(alert.data.aws.description, alert);
          const count = `${randomIntervalInteger(400, 4000)}`;
          alert.data.aws.service.additionalInfo.recentApiCalls.count = count;
          alert.data.aws.service.count = count;
          alert.rule = { ...typeAlert.rule
          };
          alert.rule.firedtimes = randomIntervalInteger(1, 50);
          alert.rule.description = interpolateAlertProps(typeAlert.rule.description, alert);
          alert.decoder = { ...typeAlert.decoder
          };
          alert.location = typeAlert.location;
          break;
        }

      case 'networkConnection':
        {
          const typeAlert = AWS.networkConnection;
          alert.data = { ...typeAlert.data
          };
          alert.data.integration = 'aws';
          alert.data.aws.region = (0, _common.randomArrayItem)(AWS.region);
          alert.data.aws.resource.instanceDetails = { ...(0, _common.randomArrayItem)(AWS.instanceDetails)
          };
          alert.data.aws.log_info = {
            s3bucket: (0, _common.randomArrayItem)(AWS.buckets),
            log_file: `guardduty/${formatDate(new Date(alert.timestamp), 'Y/M/D/h')}/firehose_guardduty-1-${formatDate(new Date(alert.timestamp), 'Y-M-D-h-m-s-l')}b5b9b-ec62-4a07-85d7-b1699b9c031e.zip`
          };
          alert.data.aws.description = interpolateAlertProps(alert.data.aws.description, alert);
          alert.data.aws.title = interpolateAlertProps(alert.data.aws.title, alert);
          alert.data.aws.accountId = (0, _common.randomArrayItem)(AWS.accountId);
          alert.data.aws.createdAt = formatDate(beforeDate, 'Y-M-DTh:m:s.lZ');
          alert.data.aws.service.action.networkConnectionAction.remoteIpDetails = { ...(0, _common.randomArrayItem)(AWS.remoteIpDetails)
          };
          alert.data.aws.service.eventFirstSeen = formatDate(beforeDate, 'Y-M-DTh:m:s.lZ');
          alert.data.aws.service.eventLastSeen = formatDate(new Date(alert.timestamp), 'Y-M-DTh:m:s.lZ');
          alert.data.aws.service.additionalInfo = {
            localPort: `${(0, _common.randomArrayItem)(_common.Ports)}`,
            outBytes: `${randomIntervalInteger(1000, 3000)}`,
            inBytes: `${randomIntervalInteger(1000, 10000)}`,
            unusual: `${randomIntervalInteger(1000, 10000)}`
          };
          alert.data.aws.service.count = `${randomIntervalInteger(400, 4000)}`;
          alert.data.aws.service.action.networkConnectionAction.localIpDetails.ipAddressV4 = alert.data.aws.resource.instanceDetails.networkInterfaces.privateIpAddress;
          alert.data.aws.arn = interpolateAlertProps(typeAlert.data.aws.arn, alert);
          alert.rule = { ...typeAlert.rule
          };
          alert.rule.firedtimes = randomIntervalInteger(1, 50);
          alert.rule.description = interpolateAlertProps(typeAlert.rule.description, alert);
          alert.decoder = { ...typeAlert.decoder
          };
          alert.location = typeAlert.location;
          break;
        }

      case 'iamPolicyGrantGlobal':
        {
          const typeAlert = AWS.iamPolicyGrantGlobal;
          alert.data = { ...typeAlert.data
          };
          alert.data.integration = 'aws';
          alert.data.aws.region = (0, _common.randomArrayItem)(AWS.region);
          alert.data.aws.summary.Timestamps = formatDate(beforeDate, 'Y-M-DTh:m:s.lZ');
          alert.data.aws.log_info = {
            s3bucket: (0, _common.randomArrayItem)(AWS.buckets),
            log_file: `macie/${formatDate(new Date(alert.timestamp), 'Y/M/D/h')}/firehose_macie-1-${formatDate(new Date(alert.timestamp), 'Y-M-D-h-m-s')}-0b1ede94-f399-4e54-8815-1c6587eee3b1//firehose_guardduty-1-${formatDate(new Date(alert.timestamp), 'Y-M-D-h-m-s-l')}b5b9b-ec62-4a07-85d7-b1699b9c031e.zip`
          };
          alert.data.aws['created-at'] = formatDate(beforeDate, 'Y-M-DTh:m:s.lZ');
          alert.data.aws.url = interpolateAlertProps(typeAlert.data.aws.url, alert);
          alert.data.aws['alert-arn'] = interpolateAlertProps(typeAlert.data.aws['alert-arn'], alert);
          alert.rule = { ...typeAlert.rule
          };
          alert.rule.firedtimes = randomIntervalInteger(1, 50);
          alert.decoder = { ...typeAlert.decoder
          };
          alert.location = typeAlert.location;
          break;
        }

      default:
        {}
    }

    alert.input = {
      type: 'log'
    };
    alert.GeoLocation = (0, _common.randomArrayItem)(_common.GeoLocation);
  }

  if (params.office) {
    alert.agent = {
      id: '000',
      ip: alert.agent.ip,
      name: alert.agent.name
    };

    if (params.manager && params.manager.name) {
      alert.agent.name = params.manager.name;
    }

    ;
    const beforeDate = new Date(new Date(alert.timestamp) - 3 * 24 * 60 * 60 * 1000);
    const IntraID = (0, _common.randomArrayItem)(Office.arrayUuidOffice);
    const OrgID = (0, _common.randomArrayItem)(Office.arrayUuidOffice);
    const objID = (0, _common.randomArrayItem)(Office.arrayUuidOffice);
    const userKey = (0, _common.randomArrayItem)(Office.arrayUuidOffice);
    const userID = (0, _common.randomArrayItem)(Office.arrayUserId);
    const userType = (0, _common.randomArrayItem)([0, 2, 4]);
    const resultStatus = (0, _common.randomArrayItem)(['Succeeded', 'PartiallySucceeded', 'Failed']);
    const log = (0, _common.randomArrayItem)(Office.arrayLogs);
    const ruleData = Office.officeRules[log.RecordType];
    alert.agent.id = '000';
    alert.rule = ruleData.rule;
    alert.decoder = (0, _common.randomArrayItem)(Office.arrayDecoderOffice);
    alert.GeoLocation = (0, _common.randomArrayItem)(_common.GeoLocation);
    alert.data.integration = 'Office365';
    alert.location = Office.arrayLocationOffice;
    alert.data.office365 = { ...log,
      ...ruleData.data.office365,
      Id: IntraID,
      CreationTime: formatDate(beforeDate, 'Y-M-DTh:m:s.lZ'),
      OrganizationId: OrgID,
      UserType: userType,
      UserKey: userKey,
      ResultStatus: resultStatus,
      ObjectId: objID,
      UserId: userID,
      ClientIP: (0, _common.randomArrayItem)(Office.arrayIp)
    };
  }

  if (params.gcp) {
    alert.rule = (0, _common.randomArrayItem)(GCP.arrayRules);
    alert.data.integration = 'gcp';
    alert.data.gcp = {
      insertId: 'uk1zpe23xcj',
      jsonPayload: {
        authAnswer: GCP.arrayAuthAnswer[Math.floor(GCP.arrayAuthAnswer.length * Math.random())],
        protocol: GCP.arrayProtocol[Math.floor(GCP.arrayProtocol.length * Math.random())],
        queryName: GCP.arrayQueryName[Math.floor(GCP.arrayQueryName.length * Math.random())],
        queryType: GCP.arrayQueryType[Math.floor(GCP.arrayQueryType.length * Math.random())],
        responseCode: GCP.arrayResponseCode[Math.floor(GCP.arrayResponseCode.length * Math.random())],
        sourceIP: GCP.arraySourceIP[Math.floor(GCP.arraySourceIP.length * Math.random())],
        vmInstanceId: '4980113928800839680.000000',
        vmInstanceName: '531339229531.instance-1'
      },
      logName: 'projects/wazuh-dev/logs/dns.googleapis.com%2Fdns_queries',
      receiveTimestamp: '2019-11-11T02:42:05.05853152Z',
      resource: {
        labels: {
          location: GCP.arrayLocation[Math.floor(GCP.arrayLocation.length * Math.random())],
          project_id: GCP.arrayProject[Math.floor(GCP.arrayProject.length * Math.random())],
          source_type: GCP.arraySourceType[Math.floor(GCP.arraySourceType.length * Math.random())],
          target_type: 'external'
        },
        type: GCP.arrayType[Math.floor(GCP.arrayType.length * Math.random())]
      },
      severity: GCP.arraySeverity[Math.floor(GCP.arraySeverity.length * Math.random())],
      timestamp: '2019-11-11T02:42:04.34921449Z'
    };
    alert.GeoLocation = (0, _common.randomArrayItem)(_common.GeoLocation);
  }

  if (params.audit) {
    let dataAudit = (0, _common.randomArrayItem)(Audit.dataAudit);
    alert.data = dataAudit.data;
    alert.data.audit.file ? alert.data.audit.file.name === '' ? alert.data.audit.file.name = (0, _common.randomArrayItem)(Audit.fileName) : null : null;
    alert.rule = dataAudit.rule;
  }

  if (params.ciscat) {
    alert.rule.groups.push('ciscat');
    alert.data.cis = {};
    alert.data.cis.group = (0, _common.randomArrayItem)(CISCAT.group);
    alert.data.cis.fail = randomIntervalInteger(0, 100);
    alert.data.cis.rule_title = (0, _common.randomArrayItem)(CISCAT.ruleTitle);
    alert.data.cis.notchecked = randomIntervalInteger(0, 100);
    alert.data.cis.score = randomIntervalInteger(0, 100);
    alert.data.cis.pass = randomIntervalInteger(0, 100);
    alert.data.cis.timestamp = new Date(randomDate());
    alert.data.cis.error = randomIntervalInteger(0, 1);
    alert.data.cis.benchmark = (0, _common.randomArrayItem)(CISCAT.benchmark);
    alert.data.cis.unknown = randomIntervalInteger(0, 100);
    alert.data.cis.notchecked = randomIntervalInteger(0, 5);
    alert.data.cis.result = (0, _common.randomArrayItem)(CISCAT.result);
  }

  if (params.docker) {
    const dataDocker = (0, _common.randomArrayItem)(Docker.dataDocker);
    alert.data = {};
    alert.data = dataDocker.data;
    alert.rule = dataDocker.rule;
  }

  if (params.mitre) {
    alert.rule = (0, _common.randomArrayItem)(Mitre.arrayMitreRules);
    alert.location = (0, _common.randomArrayItem)(Mitre.arrayLocation);
  }

  if (params.openscap) {
    alert.data = {};
    alert.data.oscap = {};
    const typeAlert = { ...(0, _common.randomArrayItem)(OpenSCAP.data)
    };
    alert.data = { ...typeAlert.data
    };
    alert.rule = { ...typeAlert.rule
    };
    alert.rule.firedtimes = randomIntervalInteger(2, 10);
    alert.input = {
      type: 'log'
    };
    alert.decoder = { ...OpenSCAP.decoder
    };
    alert.location = OpenSCAP.location;

    if (typeAlert.full_log) {
      alert.full_log = interpolateAlertProps(typeAlert.full_log, alert);
    }
  }

  if (params.rootcheck) {
    alert.location = PolicyMonitoring.location;
    alert.decoder = { ...PolicyMonitoring.decoder
    };
    alert.input = {
      type: 'log'
    };
    const alertCategory = (0, _common.randomArrayItem)(['Rootkit', 'Trojan']);

    switch (alertCategory) {
      case 'Rootkit':
        {
          const rootkitCategory = (0, _common.randomArrayItem)(Object.keys(PolicyMonitoring.rootkits));
          const rootkit = (0, _common.randomArrayItem)(PolicyMonitoring.rootkits[rootkitCategory]);
          alert.data = {
            title: interpolateAlertProps(PolicyMonitoring.rootkitsData.data.title, alert, {
              _rootkit_category: rootkitCategory,
              _rootkit_file: rootkit
            })
          };
          alert.rule = { ...PolicyMonitoring.rootkitsData.rule
          };
          alert.rule.firedtimes = randomIntervalInteger(1, 10);
          alert.full_log = alert.data.title;
          break;
        }

      case 'Trojan':
        {
          const trojan = (0, _common.randomArrayItem)(PolicyMonitoring.trojans);
          alert.data = {
            file: trojan.file,
            title: 'Trojaned version of file detected.'
          };
          alert.rule = { ...PolicyMonitoring.trojansData.rule
          };
          alert.rule.firedtimes = randomIntervalInteger(1, 10);
          alert.full_log = interpolateAlertProps(PolicyMonitoring.trojansData.full_log, alert, {
            _trojan_signature: trojan.signature
          });
          break;
        }

      default:
        {}
    }
  }

  if (params.syscheck) {
    alert.rule.groups.push('syscheck');
    alert.syscheck = {};
    alert.syscheck.event = (0, _common.randomArrayItem)(IntegrityMonitoring.events);
    alert.syscheck.path = (0, _common.randomArrayItem)(alert.agent.name === 'Windows' ? IntegrityMonitoring.pathsWindows : IntegrityMonitoring.pathsLinux);
    alert.syscheck.uname_after = (0, _common.randomArrayItem)(_common.Users);
    alert.syscheck.gname_after = 'root';
    alert.syscheck.mtime_after = new Date(randomDate());
    alert.syscheck.size_after = randomIntervalInteger(0, 65);
    alert.syscheck.uid_after = (0, _common.randomArrayItem)(IntegrityMonitoring.uid_after);
    alert.syscheck.gid_after = (0, _common.randomArrayItem)(IntegrityMonitoring.gid_after);
    alert.syscheck.perm_after = 'rw-r--r--';
    alert.syscheck.inode_after = randomIntervalInteger(0, 100000);

    switch (alert.syscheck.event) {
      case 'added':
        alert.rule = IntegrityMonitoring.regulatory[0];
        break;

      case 'modified':
        alert.rule = IntegrityMonitoring.regulatory[1];
        alert.syscheck.mtime_before = new Date(alert.syscheck.mtime_after.getTime() - 1000 * 60);
        alert.syscheck.inode_before = randomIntervalInteger(0, 100000);
        alert.syscheck.sha1_after = (0, _common.randomElements)(40, 'abcdef0123456789');
        alert.syscheck.changed_attributes = [(0, _common.randomArrayItem)(IntegrityMonitoring.attributes)];
        alert.syscheck.md5_after = (0, _common.randomElements)(32, 'abcdef0123456789');
        alert.syscheck.sha256_after = (0, _common.randomElements)(60, 'abcdef0123456789');
        break;

      case 'deleted':
        alert.rule = IntegrityMonitoring.regulatory[2];
        alert.syscheck.tags = [(0, _common.randomArrayItem)(IntegrityMonitoring.tags)];
        alert.syscheck.sha1_after = (0, _common.randomElements)(40, 'abcdef0123456789');
        alert.syscheck.audit = {
          process: {
            name: (0, _common.randomArrayItem)(_common.Paths),
            id: randomIntervalInteger(0, 100000),
            ppid: randomIntervalInteger(0, 100000)
          },
          effective_user: {
            name: (0, _common.randomArrayItem)(_common.Users),
            id: randomIntervalInteger(0, 100)
          },
          user: {
            name: (0, _common.randomArrayItem)(_common.Users),
            id: randomIntervalInteger(0, 100)
          },
          group: {
            name: (0, _common.randomArrayItem)(_common.Users),
            id: randomIntervalInteger(0, 100)
          }
        };
        alert.syscheck.md5_after = (0, _common.randomElements)(32, 'abcdef0123456789');
        alert.syscheck.sha256_after = (0, _common.randomElements)(60, 'abcdef0123456789');
        break;

      default:
        {}
    }
  }

  if (params.virustotal) {
    alert.rule.groups.push('virustotal');
    alert.location = 'virustotal';
    alert.data.virustotal = {};
    alert.data.virustotal.found = (0, _common.randomArrayItem)(['0', '1', '1', '1']);
    alert.data.virustotal.source = {
      sha1: (0, _common.randomElements)(40, 'abcdef0123456789'),
      file: (0, _common.randomArrayItem)(Virustotal.sourceFile),
      alert_id: `${(0, _common.randomElements)(10, '0123456789')}.${(0, _common.randomElements)(7, '0123456789')}`,
      md5: (0, _common.randomElements)(32, 'abcdef0123456789')
    };

    if (alert.data.virustotal.found === '1') {
      alert.data.virustotal.malicious = (0, _common.randomArrayItem)(Virustotal.malicious);
      alert.data.virustotal.positives = `${randomIntervalInteger(0, 65)}`;
      alert.data.virustotal.total = alert.data.virustotal.malicious + alert.data.virustotal.positives;
      alert.rule.description = `VirusTotal: Alert - ${alert.data.virustotal.source.file} - ${alert.data.virustotal.positives} engines detected this file`;
      alert.data.virustotal.permalink = (0, _common.randomArrayItem)(Virustotal.permalink);
      alert.data.virustotal.scan_date = new Date(Date.parse(alert.timestamp) - 4 * 60000);
    } else {
      alert.data.virustotal.malicious = '0';
      alert.rule.description = 'VirusTotal: Alert - No records in VirusTotal database';
    }
  }

  if (params.vulnerabilities) {
    const dataVulnerability = (0, _common.randomArrayItem)(Vulnerability.data);
    alert.rule = { ...dataVulnerability.rule,
      mail: false,
      groups: ['vulnerability-detector'],
      gdpr: ['IV_35.7.d'],
      pci_dss: ['11.2.1', '11.2.3'],
      tsc: ['CC7.1', 'CC7.2']
    };
    alert.location = 'vulnerability-detector';
    alert.decoder = {
      name: 'json'
    };
    alert.data = { ...dataVulnerability.data
    };
  }

  if (params.osquery) {
    alert.rule.groups.push('osquery');
    alert.data.osquery = {};

    if (randomIntervalInteger(0, 5) === 0) {
      alert.rule.description = 'osquery error message';
    } else {
      let dataOsquery = (0, _common.randomArrayItem)(Osquery.dataOsquery);
      alert.data.osquery = dataOsquery.osquery;
      alert.data.osquery.calendarTime = alert.timestamp;
      alert.rule.description = dataOsquery.rule.description;
      randomIntervalInteger(0, 99) === 0 ? alert.data.osquery.action = 'removed' : null;
    }
  } // Regulatory compliance


  if (params.pci_dss || params.regulatory_compliance || params.random_probability_regulatory_compliance && randomProbability(params.random_probability_regulatory_compliance)) {
    alert.rule.pci_dss = [(0, _common.randomArrayItem)(_regulatoryCompliance.PCI_DSS)];
  }

  if (params.gdpr || params.regulatory_compliance || params.random_probability_regulatory_compliance && randomProbability(params.random_probability_regulatory_compliance)) {
    alert.rule.gdpr = [(0, _common.randomArrayItem)(_regulatoryCompliance.GDPR)];
  }

  if (params.gpg13 || params.regulatory_compliance || params.random_probability_regulatory_compliance && randomProbability(params.random_probability_regulatory_compliance)) {
    alert.rule.gpg13 = [(0, _common.randomArrayItem)(_regulatoryCompliance.GPG13)];
  }

  if (params.hipaa || params.regulatory_compliance || params.random_probability_regulatory_compliance && randomIntervalInteger(params.random_probability_regulatory_compliance)) {
    alert.rule.hipaa = [(0, _common.randomArrayItem)(_regulatoryCompliance.HIPAA)];
  }

  if (params.nist_800_83 || params.regulatory_compliance || params.random_probability_regulatory_compliance && randomIntervalInteger(params.random_probability_regulatory_compliance)) {
    alert.rule.nist_800_53 = [(0, _common.randomArrayItem)(_regulatoryCompliance.NIST_800_53)];
  }

  if (params.authentication) {
    alert.data = {
      srcip: (0, _common.randomArrayItem)(_common.IPs),
      srcuser: (0, _common.randomArrayItem)(_common.Users),
      srcport: (0, _common.randomArrayItem)(_common.Ports)
    };
    alert.GeoLocation = (0, _common.randomArrayItem)(_common.GeoLocation);
    alert.decoder = {
      name: 'sshd',
      parent: 'sshd'
    };
    alert.input = {
      type: 'log'
    };
    alert.predecoder = {
      program_name: 'sshd',
      timestamp: formatDate(new Date(alert.timestamp), 'N D h:m:s'),
      hostname: alert.manager.name
    };
    let typeAlert = (0, _common.randomArrayItem)(['invalidLoginPassword', 'invalidLoginUser', 'multipleAuthenticationFailures', 'windowsInvalidLoginPassword', 'userLoginFailed', 'passwordCheckFailed', 'nonExistentUser', 'bruteForceTryingAccessSystem', 'authenticationSuccess', 'maximumAuthenticationAttemptsExceeded']);

    switch (typeAlert) {
      case 'invalidLoginPassword':
        {
          alert.location = Authentication.invalidLoginPassword.location;
          alert.rule = { ...Authentication.invalidLoginPassword.rule
          };
          alert.rule.groups = [...Authentication.invalidLoginPassword.rule.groups];
          alert.full_log = interpolateAlertProps(Authentication.invalidLoginPassword.full_log, alert);
          break;
        }

      case 'invalidLoginUser':
        {
          alert.location = Authentication.invalidLoginUser.location;
          alert.rule = { ...Authentication.invalidLoginUser.rule
          };
          alert.rule.groups = [...Authentication.invalidLoginUser.rule.groups];
          alert.full_log = interpolateAlertProps(Authentication.invalidLoginUser.full_log, alert);
          break;
        }

      case 'multipleAuthenticationFailures':
        {
          alert.location = Authentication.multipleAuthenticationFailures.location;
          alert.rule = { ...Authentication.multipleAuthenticationFailures.rule
          };
          alert.rule.groups = [...Authentication.multipleAuthenticationFailures.rule.groups];
          alert.rule.frequency = randomIntervalInteger(5, 50);
          alert.full_log = interpolateAlertProps(Authentication.multipleAuthenticationFailures.full_log, alert);
          break;
        }

      case 'windowsInvalidLoginPassword':
        {
          alert.location = Authentication.windowsInvalidLoginPassword.location;
          alert.rule = { ...Authentication.windowsInvalidLoginPassword.rule
          };
          alert.rule.groups = [...Authentication.windowsInvalidLoginPassword.rule.groups];
          alert.rule.frequency = randomIntervalInteger(5, 50);
          alert.data.win = { ...Authentication.windowsInvalidLoginPassword.data_win
          };
          alert.data.win.eventdata.ipAddress = (0, _common.randomArrayItem)(_common.IPs);
          alert.data.win.eventdata.ipPort = (0, _common.randomArrayItem)(_common.Ports);
          alert.data.win.system.computer = (0, _common.randomArrayItem)(_common.Win_Hostnames);
          alert.data.win.system.eventID = `${randomIntervalInteger(1, 600)}`;
          alert.data.win.system.eventRecordID = `${randomIntervalInteger(10000, 50000)}`;
          alert.data.win.system.processID = `${randomIntervalInteger(1, 1200)}`;
          alert.data.win.system.systemTime = alert.timestamp;
          alert.data.win.system.processID = `${randomIntervalInteger(1, 1200)}`;
          alert.data.win.system.task = `${randomIntervalInteger(1, 1800)}`;
          alert.data.win.system.threadID = `${randomIntervalInteger(1, 500)}`;
          alert.full_log = interpolateAlertProps(Authentication.windowsInvalidLoginPassword.full_log, alert);
          break;
        }

      case 'userLoginFailed':
        {
          alert.location = Authentication.userLoginFailed.location;
          alert.rule = { ...Authentication.userLoginFailed.rule
          };
          alert.rule.groups = [...Authentication.userLoginFailed.rule.groups];
          alert.data = {
            srcip: (0, _common.randomArrayItem)(_common.IPs),
            dstuser: (0, _common.randomArrayItem)(_common.Users),
            uid: `${randomIntervalInteger(0, 50)}`,
            euid: `${randomIntervalInteger(0, 50)}`,
            tty: 'ssh'
          };
          alert.decoder = { ...Authentication.userLoginFailed.decoder
          };
          alert.full_log = interpolateAlertProps(Authentication.userLoginFailed.full_log, alert);
          break;
        }

      case 'passwordCheckFailed':
        {
          alert.location = Authentication.passwordCheckFailed.location;
          alert.rule = { ...Authentication.passwordCheckFailed.rule
          };
          alert.rule.groups = [...Authentication.passwordCheckFailed.rule.groups];
          alert.data = {
            srcuser: (0, _common.randomArrayItem)(_common.Users)
          };
          alert.predecoder.program_name = 'unix_chkpwd';
          alert.decoder = { ...Authentication.passwordCheckFailed.decoder
          };
          alert.full_log = interpolateAlertProps(Authentication.passwordCheckFailed.full_log, alert);
          break;
        }

      case 'nonExistentUser':
        {
          alert.location = Authentication.nonExistentUser.location;
          alert.rule = { ...Authentication.nonExistentUser.rule
          };
          alert.rule.groups = [...Authentication.nonExistentUser.rule.groups];
          alert.full_log = interpolateAlertProps(Authentication.nonExistentUser.full_log, alert);
          break;
        }

      case 'bruteForceTryingAccessSystem':
        {
          alert.location = Authentication.bruteForceTryingAccessSystem.location;
          alert.rule = { ...Authentication.bruteForceTryingAccessSystem.rule
          };
          alert.rule.groups = [...Authentication.bruteForceTryingAccessSystem.rule.groups];
          alert.full_log = interpolateAlertProps(Authentication.bruteForceTryingAccessSystem.full_log, alert);
          break;
        }

      case 'reverseLoockupError':
        {
          alert.location = Authentication.reverseLoockupError.location;
          alert.rule = { ...Authentication.reverseLoockupError.rule
          };
          alert.rule.groups = [...Authentication.reverseLoockupError.rule.groups];
          alert.data = {
            srcip: (0, _common.randomArrayItem)(_common.IPs)
          };
          alert.full_log = interpolateAlertProps(Authentication.reverseLoockupError.full_log, alert);
        }

      case 'insecureConnectionAttempt':
        {
          alert.location = Authentication.insecureConnectionAttempt.location;
          alert.rule = { ...Authentication.insecureConnectionAttempt.rule
          };
          alert.rule.groups = [...Authentication.insecureConnectionAttempt.rule.groups];
          alert.data = {
            srcip: (0, _common.randomArrayItem)(_common.IPs),
            srcport: (0, _common.randomArrayItem)(_common.Ports)
          };
          alert.full_log = interpolateAlertProps(Authentication.insecureConnectionAttempt.full_log, alert);
        }

      case 'authenticationSuccess':
        {
          alert.location = Authentication.authenticationSuccess.location;
          alert.rule = { ...Authentication.authenticationSuccess.rule
          };
          alert.rule.groups = [...Authentication.authenticationSuccess.rule.groups];
          alert.data = {
            srcip: (0, _common.randomArrayItem)(_common.IPs),
            srcport: (0, _common.randomArrayItem)(_common.Ports),
            dstuser: (0, _common.randomArrayItem)(_common.Users)
          };
          alert.full_log = interpolateAlertProps(Authentication.authenticationSuccess.full_log, alert);
        }

      case 'maximumAuthenticationAttemptsExceeded':
        {
          alert.location = Authentication.maximumAuthenticationAttemptsExceeded.location;
          alert.rule = { ...Authentication.maximumAuthenticationAttemptsExceeded.rule
          };
          alert.rule.groups = [...Authentication.maximumAuthenticationAttemptsExceeded.rule.groups];
          alert.data = {
            srcip: (0, _common.randomArrayItem)(_common.IPs),
            srcport: (0, _common.randomArrayItem)(_common.Ports),
            dstuser: (0, _common.randomArrayItem)(_common.Users)
          };
          alert.full_log = interpolateAlertProps(Authentication.maximumAuthenticationAttemptsExceeded.full_log, alert);
        }

      default:
        {}
    }

    alert.rule.firedtimes = randomIntervalInteger(2, 15);
    alert.rule.tsc = [(0, _common.randomArrayItem)(_regulatoryCompliance.tsc)];
  }

  if (params.ssh) {
    alert.data = {
      srcip: (0, _common.randomArrayItem)(_common.IPs),
      srcuser: (0, _common.randomArrayItem)(_common.Users),
      srcport: (0, _common.randomArrayItem)(_common.Ports)
    };
    alert.GeoLocation = (0, _common.randomArrayItem)(_common.GeoLocation);
    alert.decoder = {
      name: 'sshd',
      parent: 'sshd'
    };
    alert.input = {
      type: 'log'
    };
    alert.predecoder = {
      program_name: 'sshd',
      timestamp: formatDate(new Date(alert.timestamp), 'N D h:m:s'),
      hostname: alert.manager.name
    };
    const typeAlert = (0, _common.randomArrayItem)(SSH.data);
    alert.location = typeAlert.location;
    alert.rule = { ...typeAlert.rule
    };
    alert.rule.groups = [...typeAlert.rule.groups];
    alert.rule.firedtimes = randomIntervalInteger(1, 15);
    alert.full_log = interpolateAlertProps(typeAlert.full_log, alert);
  }

  if (params.windows) {
    alert.rule.groups.push('windows');

    if (params.windows.service_control_manager) {
      alert.predecoder = {
        program_name: 'WinEvtLog',
        timestamp: '2020 Apr 17 05:59:05'
      };
      alert.input = {
        type: 'log'
      };
      alert.data = {
        extra_data: 'Service Control Manager',
        dstuser: 'SYSTEM',
        system_name: (0, _common.randomArrayItem)(_common.Win_Hostnames),
        id: '7040',
        type: 'type',
        status: 'INFORMATION'
      };
      alert.rule.description = 'Windows: Service startup type was changed.';
      alert.rule.firedtimes = randomIntervalInteger(1, 20);
      alert.rule.mail = false;
      alert.rule.level = 3;
      alert.rule.groups.push('windows', 'policy_changed');
      alert.rule.pci = ['10.6'];
      alert.rule.hipaa = ['164.312.b'];
      alert.rule.gdpr = ['IV_35.7.d'];
      alert.rule.nist_800_53 = ['AU.6'];
      alert.rule.info = 'This does not appear to be logged on Windows 2000.';
      alert.location = 'WinEvtLog';
      alert.decoder = {
        parent: 'windows',
        name: 'windows'
      };
      alert.full_log = `2020 Apr 17 05:59:05 WinEvtLog: type: INFORMATION(7040): Service Control Manager: SYSTEM: NT AUTHORITY: ${alert.data.system_name}: Background Intelligent Transfer Service auto start demand start BITS `; //TODO: date

      alert.id = 18145;
      alert.fields = {
        timestamp: alert.timestamp
      };
    }
  }

  if (params.apache) {
    const typeAlert = { ...Apache.data[0]
    }; // there is only one type alert in data array at the moment. Randomize if add more type of alerts to data array

    alert.data = {
      srcip: (0, _common.randomArrayItem)(_common.IPs),
      srcport: (0, _common.randomArrayItem)(_common.Ports),
      id: `AH${randomIntervalInteger(10000, 99999)}`
    };
    alert.GeoLocation = { ...(0, _common.randomArrayItem)(_common.GeoLocation)
    };
    alert.rule = { ...typeAlert.rule
    };
    alert.rule.firedtimes = randomIntervalInteger(2, 10);
    alert.input = {
      type: 'log'
    };
    alert.location = Apache.location;
    alert.decoder = { ...Apache.decoder
    };
    alert.full_log = interpolateAlertProps(typeAlert.full_log, alert, {
      _timestamp_apache: formatDate(new Date(alert.timestamp), 'E N D h:m:s.l Y'),
      _pi_id: randomIntervalInteger(10000, 30000)
    });
  }

  if (params.web) {
    alert.input = {
      type: 'log'
    };
    alert.data = {
      protocol: 'GET',
      srcip: (0, _common.randomArrayItem)(_common.IPs),
      id: '404',
      url: (0, _common.randomArrayItem)(Web.urls)
    };
    alert.GeoLocation = { ...(0, _common.randomArrayItem)(_common.GeoLocation)
    };
    const typeAlert = (0, _common.randomArrayItem)(Web.data);
    const userAgent = (0, _common.randomArrayItem)(Web.userAgents);
    alert.rule = { ...typeAlert.rule
    };
    alert.rule.firedtimes = randomIntervalInteger(1, 10);
    alert.decoder = { ...typeAlert.decoder
    };
    alert.location = typeAlert.location;
    alert.full_log = interpolateAlertProps(typeAlert.full_log, alert, {
      _user_agent: userAgent,
      _date: formatDate(new Date(alert.timestamp), 'D/N/Y:h:m:s +0000')
    });

    if (typeAlert.previous_output) {
      const previousOutput = [];
      const beforeSeconds = 4;

      for (let i = beforeSeconds; i > 0; i--) {
        const beforeDate = new Date(new Date(alert.timestamp) - (2 + i) * 1000);
        previousOutput.push(interpolateAlertProps(typeAlert.full_log, alert, {
          _user_agent: userAgent,
          _date: formatDate(new Date(beforeDate), 'D/N/Y:h:m:s +0000')
        }));
      }

      alert.previous_output = previousOutput.join('\n');
    }
  }

  if (params.github) {
    alert.location = GitHub.LOCATION;
    alert.decoder = GitHub.DECODER;
    const alertType = (0, _common.randomArrayItem)(GitHub.ALERT_TYPES);
    const actor = (0, _common.randomArrayItem)(GitHub.ACTORS);
    alert.data = {
      github: { ...alertType.data.github
      }
    };
    alert.data.github.org = (0, _common.randomArrayItem)(GitHub.ORGANIZATION_NAMES);
    alert.data.github.repo && (alert.data.github.repo = `${alert.data.github.org}/${(0, _common.randomArrayItem)(GitHub.REPOSITORY_NAMES)}`);
    alert.data.github.repository && (alert.data.github.repository = `${alert.data.github.org}/${(0, _common.randomArrayItem)(GitHub.REPOSITORY_NAMES)}`);
    alert.data.github.actor = actor.name;
    alert.data.github.actor_location && alert.data.github.actor_location.country_code && (alert.data.github.actor_location.country_code = actor.country_code);
    alert.data.github.user && (alert.data.github.user = (0, _common.randomArrayItem)(GitHub.USER_NAMES));
    alert.data.github.config && alert.data.github.config.url && (alert.data.github.config.url = (0, _common.randomArrayItem)(GitHub.SERVER_ADDRESS_WEBHOOK));
    alert.data.github['@timestamp'] = alert.timestamp;
    alert.data.github.created_at && (alert.data.github.created_at = alert.timestamp);
    alert.rule = { ...alertType.rule
    };
  }

  return alert;
}
/**
 * Get a random array with unique values
 * @param {[]} array Array to extract the values
 * @param {*} randomMaxRepetitions Number max of random extractions
 * @param {function} sort Funciton to seort elements
 * @return {*} Array with random values extracted of paramater array passed
 */


function randomUniqueValuesFromArray(array, randomMaxRepetitions = 1, sort) {
  const repetitions = randomIntervalInteger(1, randomMaxRepetitions);
  const set = new Set();

  for (let i = 0; i < repetitions; i++) {
    set.add(array[randomIntervalInteger(0, array.length - 1)]);
  }

  return sort ? Array.from(set).sort(sort) : Array.from(set);
}
/**
 * Get a integer within a range
 * @param {number} min - Minimum limit
 * @param {number} max - Maximum limit
 * @returns {number} - Randomized number in interval
 */


function randomIntervalInteger(min, max) {
  return Math.floor(Math.random() * (max - (min - 1))) + min;
}
/**
 * Generate random alerts
 * @param {*} params
 * @param {number} numAlerts - Define number of alerts
 * @return {*} - Random generated alerts defined with params
 */


function generateAlerts(params, numAlerts = 1) {
  const alerts = [];

  for (let i = 0; i < numAlerts; i++) {
    alerts.push(generateAlert(params));
  }

  return alerts;
}
/**
 * Get a random Date in range(7 days ago - now)
 * @returns {date} - Random date in range (7 days ago - now)
 */


function randomDate(inf, sup) {
  const nowTimestamp = Date.now();
  const time = randomIntervalInteger(0, 604800000); // Random 7 days in miliseconds

  const unix_timestamp = nowTimestamp - time; // Last 7 days from now

  const lastWeek = new Date(unix_timestamp);
  return formatDate(lastWeek, 'Y-M-DTh:m:s.l+0000');
}

const formatterNumber = (number, zeros = 0) => ('0'.repeat(zeros) + `${number}`).slice(-zeros);

const monthNames = {
  long: ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'],
  short: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
};
const dayNames = {
  long: ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'],
  short: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
};

function formatDate(date, format) {
  // It could use "moment" library to format strings too
  const tokens = {
    D: d => formatterNumber(d.getDate(), 2),
    // 01-31
    A: d => dayNames.long[d.getDay()],
    // 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'
    E: d => dayNames.short[d.getDay()],
    // 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'
    M: d => formatterNumber(d.getMonth() + 1, 2),
    // 01-12
    J: d => monthNames.long[d.getMonth()],
    // 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'
    N: d => monthNames.short[d.getMonth()],
    // 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
    Y: d => d.getFullYear(),
    // 2020
    h: d => formatterNumber(d.getHours(), 2),
    // 00-23
    m: d => formatterNumber(d.getMinutes(), 2),
    // 00-59
    s: d => formatterNumber(d.getSeconds(), 2),
    // 00-59
    l: d => formatterNumber(d.getMilliseconds(), 3) // 000-999

  };
  return format.split('').reduce((accum, token) => {
    if (tokens[token]) {
      return accum + tokens[token](date);
    }

    return accum + token;
  }, '');
}
/**
 *
 * @param {string} str String with interpolations
 * @param {*} alert Alert object
 * @param {*} extra Extra parameters to interpolate what aren't in alert objet. Only admit one level of depth
 */


function interpolateAlertProps(str, alert, extra = {}) {
  const matches = str.match(/{([\w\._]+)}/g);
  return matches && matches.reduce((accum, cur) => {
    const match = cur.match(/{([\w\._]+)}/);
    const items = match[1].split('.');
    const value = items.reduce((a, c) => a && a[c] || extra[c] || undefined, alert) || cur;
    return accum.replace(cur, value);
  }, str) || str;
}
/**
 * Return a random probability
 * @param {number} probability
 * @param {number[=100]} maximum
 */


function randomProbability(probability, maximum = 100) {
  return randomIntervalInteger(0, maximum) <= probability;
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImdlbmVyYXRlLWFsZXJ0cy1zY3JpcHQuanMiXSwibmFtZXMiOlsiYWxlcnRJRE1heCIsInJ1bGVEZXNjcmlwdGlvbiIsInJ1bGVNYXhMZXZlbCIsImdlbmVyYXRlQWxlcnQiLCJwYXJhbXMiLCJhbGVydCIsInRpbWVzdGFtcCIsInJ1bGUiLCJsZXZlbCIsImRlc2NyaXB0aW9uIiwiaWQiLCJtYWlsIiwiZ3JvdXBzIiwiYWdlbnQiLCJuYW1lIiwibWFuYWdlciIsImNsdXN0ZXIiLCJwcmVkZWNvZGVyIiwiZGVjb2RlciIsImRhdGEiLCJsb2NhdGlvbiIsIkFnZW50cyIsInJhbmRvbUludGVydmFsSW50ZWdlciIsInJhbmRvbURhdGUiLCJub2RlIiwiYXdzIiwicmFuZG9tVHlwZSIsImJlZm9yZURhdGUiLCJEYXRlIiwidHlwZUFsZXJ0IiwiQVdTIiwiZ3VhcmRkdXR5UG9ydFByb2JlIiwiaW50ZWdyYXRpb24iLCJyZWdpb24iLCJyZXNvdXJjZSIsImluc3RhbmNlRGV0YWlscyIsImlhbUluc3RhbmNlUHJvZmlsZSIsImFybiIsImludGVycG9sYXRlQWxlcnRQcm9wcyIsInRpdGxlIiwiYWNjb3VudElkIiwic2VydmljZSIsImV2ZW50Rmlyc3RTZWVuIiwiZm9ybWF0RGF0ZSIsImV2ZW50TGFzdFNlZW4iLCJhY3Rpb24iLCJwb3J0UHJvYmVBY3Rpb24iLCJwb3J0UHJvYmVEZXRhaWxzIiwicmVtb3RlSXBEZXRhaWxzIiwibG9nX2luZm8iLCJzM2J1Y2tldCIsImJ1Y2tldHMiLCJsb2dfZmlsZSIsImNvdW50IiwiY3JlYXRlZEF0IiwiZmlyZWR0aW1lcyIsImFwaUNhbGwiLCJhY2Nlc3NLZXlEZXRhaWxzIiwidXNlck5hbWUiLCJVc2VycyIsImF3c0FwaUNhbGxBY3Rpb24iLCJhZGRpdGlvbmFsSW5mbyIsInJlY2VudEFwaUNhbGxzIiwibmV0d29ya0Nvbm5lY3Rpb24iLCJuZXR3b3JrQ29ubmVjdGlvbkFjdGlvbiIsImxvY2FsUG9ydCIsIlBvcnRzIiwib3V0Qnl0ZXMiLCJpbkJ5dGVzIiwidW51c3VhbCIsImxvY2FsSXBEZXRhaWxzIiwiaXBBZGRyZXNzVjQiLCJuZXR3b3JrSW50ZXJmYWNlcyIsInByaXZhdGVJcEFkZHJlc3MiLCJpYW1Qb2xpY3lHcmFudEdsb2JhbCIsInN1bW1hcnkiLCJUaW1lc3RhbXBzIiwidXJsIiwiaW5wdXQiLCJ0eXBlIiwiR2VvTG9jYXRpb24iLCJvZmZpY2UiLCJpcCIsIkludHJhSUQiLCJPZmZpY2UiLCJhcnJheVV1aWRPZmZpY2UiLCJPcmdJRCIsIm9iaklEIiwidXNlcktleSIsInVzZXJJRCIsImFycmF5VXNlcklkIiwidXNlclR5cGUiLCJyZXN1bHRTdGF0dXMiLCJsb2ciLCJhcnJheUxvZ3MiLCJydWxlRGF0YSIsIm9mZmljZVJ1bGVzIiwiUmVjb3JkVHlwZSIsImFycmF5RGVjb2Rlck9mZmljZSIsImFycmF5TG9jYXRpb25PZmZpY2UiLCJvZmZpY2UzNjUiLCJJZCIsIkNyZWF0aW9uVGltZSIsIk9yZ2FuaXphdGlvbklkIiwiVXNlclR5cGUiLCJVc2VyS2V5IiwiUmVzdWx0U3RhdHVzIiwiT2JqZWN0SWQiLCJVc2VySWQiLCJDbGllbnRJUCIsImFycmF5SXAiLCJnY3AiLCJHQ1AiLCJhcnJheVJ1bGVzIiwiaW5zZXJ0SWQiLCJqc29uUGF5bG9hZCIsImF1dGhBbnN3ZXIiLCJhcnJheUF1dGhBbnN3ZXIiLCJNYXRoIiwiZmxvb3IiLCJsZW5ndGgiLCJyYW5kb20iLCJwcm90b2NvbCIsImFycmF5UHJvdG9jb2wiLCJxdWVyeU5hbWUiLCJhcnJheVF1ZXJ5TmFtZSIsInF1ZXJ5VHlwZSIsImFycmF5UXVlcnlUeXBlIiwicmVzcG9uc2VDb2RlIiwiYXJyYXlSZXNwb25zZUNvZGUiLCJzb3VyY2VJUCIsImFycmF5U291cmNlSVAiLCJ2bUluc3RhbmNlSWQiLCJ2bUluc3RhbmNlTmFtZSIsImxvZ05hbWUiLCJyZWNlaXZlVGltZXN0YW1wIiwibGFiZWxzIiwiYXJyYXlMb2NhdGlvbiIsInByb2plY3RfaWQiLCJhcnJheVByb2plY3QiLCJzb3VyY2VfdHlwZSIsImFycmF5U291cmNlVHlwZSIsInRhcmdldF90eXBlIiwiYXJyYXlUeXBlIiwic2V2ZXJpdHkiLCJhcnJheVNldmVyaXR5IiwiYXVkaXQiLCJkYXRhQXVkaXQiLCJBdWRpdCIsImZpbGUiLCJmaWxlTmFtZSIsImNpc2NhdCIsInB1c2giLCJjaXMiLCJncm91cCIsIkNJU0NBVCIsImZhaWwiLCJydWxlX3RpdGxlIiwicnVsZVRpdGxlIiwibm90Y2hlY2tlZCIsInNjb3JlIiwicGFzcyIsImVycm9yIiwiYmVuY2htYXJrIiwidW5rbm93biIsInJlc3VsdCIsImRvY2tlciIsImRhdGFEb2NrZXIiLCJEb2NrZXIiLCJtaXRyZSIsIk1pdHJlIiwiYXJyYXlNaXRyZVJ1bGVzIiwib3BlbnNjYXAiLCJvc2NhcCIsIk9wZW5TQ0FQIiwiZnVsbF9sb2ciLCJyb290Y2hlY2siLCJQb2xpY3lNb25pdG9yaW5nIiwiYWxlcnRDYXRlZ29yeSIsInJvb3RraXRDYXRlZ29yeSIsIk9iamVjdCIsImtleXMiLCJyb290a2l0cyIsInJvb3RraXQiLCJyb290a2l0c0RhdGEiLCJfcm9vdGtpdF9jYXRlZ29yeSIsIl9yb290a2l0X2ZpbGUiLCJ0cm9qYW4iLCJ0cm9qYW5zIiwidHJvamFuc0RhdGEiLCJfdHJvamFuX3NpZ25hdHVyZSIsInNpZ25hdHVyZSIsInN5c2NoZWNrIiwiZXZlbnQiLCJJbnRlZ3JpdHlNb25pdG9yaW5nIiwiZXZlbnRzIiwicGF0aCIsInBhdGhzV2luZG93cyIsInBhdGhzTGludXgiLCJ1bmFtZV9hZnRlciIsImduYW1lX2FmdGVyIiwibXRpbWVfYWZ0ZXIiLCJzaXplX2FmdGVyIiwidWlkX2FmdGVyIiwiZ2lkX2FmdGVyIiwicGVybV9hZnRlciIsImlub2RlX2FmdGVyIiwicmVndWxhdG9yeSIsIm10aW1lX2JlZm9yZSIsImdldFRpbWUiLCJpbm9kZV9iZWZvcmUiLCJzaGExX2FmdGVyIiwiY2hhbmdlZF9hdHRyaWJ1dGVzIiwiYXR0cmlidXRlcyIsIm1kNV9hZnRlciIsInNoYTI1Nl9hZnRlciIsInRhZ3MiLCJwcm9jZXNzIiwiUGF0aHMiLCJwcGlkIiwiZWZmZWN0aXZlX3VzZXIiLCJ1c2VyIiwidmlydXN0b3RhbCIsImZvdW5kIiwic291cmNlIiwic2hhMSIsIlZpcnVzdG90YWwiLCJzb3VyY2VGaWxlIiwiYWxlcnRfaWQiLCJtZDUiLCJtYWxpY2lvdXMiLCJwb3NpdGl2ZXMiLCJ0b3RhbCIsInBlcm1hbGluayIsInNjYW5fZGF0ZSIsInBhcnNlIiwidnVsbmVyYWJpbGl0aWVzIiwiZGF0YVZ1bG5lcmFiaWxpdHkiLCJWdWxuZXJhYmlsaXR5IiwiZ2RwciIsInBjaV9kc3MiLCJ0c2MiLCJvc3F1ZXJ5IiwiZGF0YU9zcXVlcnkiLCJPc3F1ZXJ5IiwiY2FsZW5kYXJUaW1lIiwicmVndWxhdG9yeV9jb21wbGlhbmNlIiwicmFuZG9tX3Byb2JhYmlsaXR5X3JlZ3VsYXRvcnlfY29tcGxpYW5jZSIsInJhbmRvbVByb2JhYmlsaXR5IiwiUENJX0RTUyIsIkdEUFIiLCJncGcxMyIsIkdQRzEzIiwiaGlwYWEiLCJISVBBQSIsIm5pc3RfODAwXzgzIiwibmlzdF84MDBfNTMiLCJOSVNUXzgwMF81MyIsImF1dGhlbnRpY2F0aW9uIiwic3JjaXAiLCJJUHMiLCJzcmN1c2VyIiwic3JjcG9ydCIsInBhcmVudCIsInByb2dyYW1fbmFtZSIsImhvc3RuYW1lIiwiQXV0aGVudGljYXRpb24iLCJpbnZhbGlkTG9naW5QYXNzd29yZCIsImludmFsaWRMb2dpblVzZXIiLCJtdWx0aXBsZUF1dGhlbnRpY2F0aW9uRmFpbHVyZXMiLCJmcmVxdWVuY3kiLCJ3aW5kb3dzSW52YWxpZExvZ2luUGFzc3dvcmQiLCJ3aW4iLCJkYXRhX3dpbiIsImV2ZW50ZGF0YSIsImlwQWRkcmVzcyIsImlwUG9ydCIsInN5c3RlbSIsImNvbXB1dGVyIiwiV2luX0hvc3RuYW1lcyIsImV2ZW50SUQiLCJldmVudFJlY29yZElEIiwicHJvY2Vzc0lEIiwic3lzdGVtVGltZSIsInRhc2siLCJ0aHJlYWRJRCIsInVzZXJMb2dpbkZhaWxlZCIsImRzdHVzZXIiLCJ1aWQiLCJldWlkIiwidHR5IiwicGFzc3dvcmRDaGVja0ZhaWxlZCIsIm5vbkV4aXN0ZW50VXNlciIsImJydXRlRm9yY2VUcnlpbmdBY2Nlc3NTeXN0ZW0iLCJyZXZlcnNlTG9vY2t1cEVycm9yIiwiaW5zZWN1cmVDb25uZWN0aW9uQXR0ZW1wdCIsImF1dGhlbnRpY2F0aW9uU3VjY2VzcyIsIm1heGltdW1BdXRoZW50aWNhdGlvbkF0dGVtcHRzRXhjZWVkZWQiLCJzc2giLCJTU0giLCJ3aW5kb3dzIiwic2VydmljZV9jb250cm9sX21hbmFnZXIiLCJleHRyYV9kYXRhIiwic3lzdGVtX25hbWUiLCJzdGF0dXMiLCJwY2kiLCJpbmZvIiwiZmllbGRzIiwiYXBhY2hlIiwiQXBhY2hlIiwiX3RpbWVzdGFtcF9hcGFjaGUiLCJfcGlfaWQiLCJ3ZWIiLCJXZWIiLCJ1cmxzIiwidXNlckFnZW50IiwidXNlckFnZW50cyIsIl91c2VyX2FnZW50IiwiX2RhdGUiLCJwcmV2aW91c19vdXRwdXQiLCJwcmV2aW91c091dHB1dCIsImJlZm9yZVNlY29uZHMiLCJpIiwiam9pbiIsImdpdGh1YiIsIkdpdEh1YiIsIkxPQ0FUSU9OIiwiREVDT0RFUiIsImFsZXJ0VHlwZSIsIkFMRVJUX1RZUEVTIiwiYWN0b3IiLCJBQ1RPUlMiLCJvcmciLCJPUkdBTklaQVRJT05fTkFNRVMiLCJyZXBvIiwiUkVQT1NJVE9SWV9OQU1FUyIsInJlcG9zaXRvcnkiLCJhY3Rvcl9sb2NhdGlvbiIsImNvdW50cnlfY29kZSIsIlVTRVJfTkFNRVMiLCJjb25maWciLCJTRVJWRVJfQUREUkVTU19XRUJIT09LIiwiY3JlYXRlZF9hdCIsInJhbmRvbVVuaXF1ZVZhbHVlc0Zyb21BcnJheSIsImFycmF5IiwicmFuZG9tTWF4UmVwZXRpdGlvbnMiLCJzb3J0IiwicmVwZXRpdGlvbnMiLCJzZXQiLCJTZXQiLCJhZGQiLCJBcnJheSIsImZyb20iLCJtaW4iLCJtYXgiLCJnZW5lcmF0ZUFsZXJ0cyIsIm51bUFsZXJ0cyIsImFsZXJ0cyIsImluZiIsInN1cCIsIm5vd1RpbWVzdGFtcCIsIm5vdyIsInRpbWUiLCJ1bml4X3RpbWVzdGFtcCIsImxhc3RXZWVrIiwiZm9ybWF0dGVyTnVtYmVyIiwibnVtYmVyIiwiemVyb3MiLCJyZXBlYXQiLCJzbGljZSIsIm1vbnRoTmFtZXMiLCJsb25nIiwic2hvcnQiLCJkYXlOYW1lcyIsImRhdGUiLCJmb3JtYXQiLCJ0b2tlbnMiLCJEIiwiZCIsImdldERhdGUiLCJBIiwiZ2V0RGF5IiwiRSIsIk0iLCJnZXRNb250aCIsIkoiLCJOIiwiWSIsImdldEZ1bGxZZWFyIiwiaCIsImdldEhvdXJzIiwibSIsImdldE1pbnV0ZXMiLCJzIiwiZ2V0U2Vjb25kcyIsImwiLCJnZXRNaWxsaXNlY29uZHMiLCJzcGxpdCIsInJlZHVjZSIsImFjY3VtIiwidG9rZW4iLCJzdHIiLCJleHRyYSIsIm1hdGNoZXMiLCJtYXRjaCIsImN1ciIsIml0ZW1zIiwidmFsdWUiLCJhIiwiYyIsInVuZGVmaW5lZCIsInJlcGxhY2UiLCJwcm9iYWJpbGl0eSIsIm1heGltdW0iXSwibWFwcGluZ3MiOiI7Ozs7Ozs7O0FBYUE7O0FBV0E7O0FBRUE7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7O0FBQ0E7Ozs7OztBQTNDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBRUE7QUFpQ0E7QUFDQSxNQUFNQSxVQUFVLEdBQUcsSUFBbkIsQyxDQUVBOztBQUNBLE1BQU1DLGVBQWUsR0FBRyxDQUN0QixnQkFEc0IsRUFFdEIsZ0JBRnNCLEVBR3RCLGdCQUhzQixFQUl0QixnQkFKc0IsRUFLdEIsZ0JBTHNCLENBQXhCO0FBT0EsTUFBTUMsWUFBWSxHQUFHLEVBQXJCO0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7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S0FBSyxDQUFDUixNQUFOLENBQWEsQ0FBQ1UsQ0FBRCxFQUFJQyxDQUFKLEtBQVdELENBQUMsSUFBSUEsQ0FBQyxDQUFDQyxDQUFELENBQVAsSUFBZVAsS0FBSyxDQUFDTyxDQUFELENBQXBCLElBQTJCQyxTQUFsRCxFQUE2RHJaLEtBQTdELEtBQXVFZ1osR0FBckY7QUFDQSxXQUFPTixLQUFLLENBQUNZLE9BQU4sQ0FBY04sR0FBZCxFQUFtQkUsS0FBbkIsQ0FBUDtBQUNELEdBTEQsRUFLR04sR0FMSCxDQURGLElBT0FBLEdBUkY7QUFVRDtBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7OztBQUNBLFNBQVN6SixpQkFBVCxDQUEyQm9LLFdBQTNCLEVBQXdDQyxPQUFPLEdBQUcsR0FBbEQsRUFBdUQ7QUFDckQsU0FBT3ZZLHFCQUFxQixDQUFDLENBQUQsRUFBSXVZLE9BQUosQ0FBckIsSUFBcUNELFdBQTVDO0FBQ0QiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gU2NyaXB0IHRvIGdlbmVyYXRlIHNhbXBsZSBhbGVydHNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5cbi8vIEdlbmVyYWxcbmltcG9ydCB7XG4gIElQcyxcbiAgVXNlcnMsXG4gIFBvcnRzLFxuICBQYXRocyxcbiAgV2luX0hvc3RuYW1lcyxcbiAgR2VvTG9jYXRpb24sXG4gIEFnZW50cyxcbiAgcmFuZG9tRWxlbWVudHMsXG4gIHJhbmRvbUFycmF5SXRlbSxcbn0gZnJvbSAnLi9zYW1wbGUtZGF0YS9jb21tb24nO1xuaW1wb3J0IHsgUENJX0RTUywgR0RQUiwgSElQQUEsIEdQRzEzLCBOSVNUXzgwMF81MywgdHNjIH0gZnJvbSAnLi9zYW1wbGUtZGF0YS9yZWd1bGF0b3J5LWNvbXBsaWFuY2UnO1xuXG5pbXBvcnQgKiBhcyBBdWRpdCBmcm9tICcuL3NhbXBsZS1kYXRhL2F1ZGl0JztcbmltcG9ydCAqIGFzIEF1dGhlbnRpY2F0aW9uIGZyb20gJy4vc2FtcGxlLWRhdGEvYXV0aGVudGljYXRpb24nO1xuaW1wb3J0ICogYXMgQVdTIGZyb20gJy4vc2FtcGxlLWRhdGEvYXdzJztcbmltcG9ydCAqIGFzIEludGVncml0eU1vbml0b3JpbmcgZnJvbSAnLi9zYW1wbGUtZGF0YS9pbnRlZ3JpdHktbW9uaXRvcmluZyc7XG5pbXBvcnQgKiBhcyBDSVNDQVQgZnJvbSAnLi9zYW1wbGUtZGF0YS9jaXNjYXQnO1xuaW1wb3J0ICogYXMgR0NQIGZyb20gJy4vc2FtcGxlLWRhdGEvZ2NwJztcbmltcG9ydCAqIGFzIERvY2tlciBmcm9tICcuL3NhbXBsZS1kYXRhL2RvY2tlcic7XG5pbXBvcnQgKiBhcyBNaXRyZSBmcm9tICcuL3NhbXBsZS1kYXRhL21pdHJlJztcbmltcG9ydCAqIGFzIE9zcXVlcnkgZnJvbSAnLi9zYW1wbGUtZGF0YS9vc3F1ZXJ5JztcbmltcG9ydCAqIGFzIE9wZW5TQ0FQIGZyb20gJy4vc2FtcGxlLWRhdGEvb3BlbnNjYXAnO1xuaW1wb3J0ICogYXMgUG9saWN5TW9uaXRvcmluZyBmcm9tICcuL3NhbXBsZS1kYXRhL3BvbGljeS1tb25pdG9yaW5nJztcbmltcG9ydCAqIGFzIFZpcnVzdG90YWwgZnJvbSAnLi9zYW1wbGUtZGF0YS92aXJ1c3RvdGFsJztcbmltcG9ydCAqIGFzIFZ1bG5lcmFiaWxpdHkgZnJvbSAnLi9zYW1wbGUtZGF0YS92dWxuZXJhYmlsaXRpZXMnO1xuaW1wb3J0ICogYXMgU1NIIGZyb20gJy4vc2FtcGxlLWRhdGEvc3NoJztcbmltcG9ydCAqIGFzIEFwYWNoZSBmcm9tICcuL3NhbXBsZS1kYXRhL2FwYWNoZSc7XG5pbXBvcnQgKiBhcyBXZWIgZnJvbSAnLi9zYW1wbGUtZGF0YS93ZWInO1xuaW1wb3J0ICogYXMgR2l0SHViIGZyb20gJy4vc2FtcGxlLWRhdGEvZ2l0aHViJztcbmltcG9ydCAqIGFzIE9mZmljZSBmcm9tICcuL3NhbXBsZS1kYXRhL29mZmljZSc7XG5cbi8vQWxlcnRcbmNvbnN0IGFsZXJ0SURNYXggPSA2MDAwO1xuXG4vLyBSdWxlXG5jb25zdCBydWxlRGVzY3JpcHRpb24gPSBbXG4gICdTYW1wbGUgYWxlcnQgMScsXG4gICdTYW1wbGUgYWxlcnQgMicsXG4gICdTYW1wbGUgYWxlcnQgMycsXG4gICdTYW1wbGUgYWxlcnQgNCcsXG4gICdTYW1wbGUgYWxlcnQgNScsXG5dO1xuY29uc3QgcnVsZU1heExldmVsID0gMTQ7XG5cbi8qKlxuICogR2VuZXJhdGUgYSBhbGVydFxuICogQHBhcmFtIHthbnl9IHBhcmFtcyAtIHBhcmFtcyB0byBjb25maWd1cmUgdGhlIGFsZXJ0XG4gKiBAcGFyYW0ge2Jvb2xlYW59IHBhcmFtcy5hd3MgLSBpZiB0cnVlLCBzZXQgYXdzIGZpZWxkc1xuICogQHBhcmFtIHtib29sZWFufSBwYXJhbXMuYXVkaXQgLSBpZiB0cnVlLCBzZXQgU3lzdGVtIEF1ZGl0aW5nIGZpZWxkc1xuICogQHBhcmFtIHtib29sZWFufSBwYXJhbXMub2ZmaWNlIC0gaWYgdHJ1ZSwgc2V0IG9mZmljZSBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLmNpc2NhdCAtIGlmIHRydWUsIHNldCBDSVMtQ0FUIGZpZWxkc1xuICogQHBhcmFtIHtib29sZWFufSBwYXJhbXMuZ2NwIC0gaWYgdHJ1ZSwgc2V0IEdDUCBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLmRvY2tlciAtIGlmIHRydWUsIHNldCBEb2NrZXIgZmllbGRzXG4gKiBAcGFyYW0ge2Jvb2xlYW59IHBhcmFtcy5taXRyZSAtIGlmIHRydWUsIHNldCBNaXRyZSBhdHQmY2sgZmllbGRzXG4gKiBAcGFyYW0ge2Jvb2xlYW59IHBhcmFtcy5vcGVuc2NhcCAtIGlmIHRydWUsIHNldCBPcGVuU0NBUCBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLm9zcXVlcnkgLSBpZiB0cnVlLCBzZXQgT3NxdWVyeSBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLnJvb3RjaGVjayAtIGlmIHRydWUsIHNldCBQb2xpY3kgbW9uaXRvcmluZyBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLnN5c2NoZWNrIC0gaWYgdHJ1ZSwgc2V0IGludGVncml0eSBtb25pdG9yaW5nIGZpZWxkc1xuICogQHBhcmFtIHtib29sZWFufSBwYXJhbXMudmlydXN0b3RhbCAtIGlmIHRydWUsIHNldCBWaXJ1c1RvdGFsIGZpZWxkc1xuICogQHBhcmFtIHtib29sZWFufSBwYXJhbXMudnVsbmVyYWJpbGl0aWVzIC0gaWYgdHJ1ZSwgc2V0IHZ1bG5lcmFiaWxpdGllcyBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLnBjaV9kc3MgLSBpZiB0cnVlLCBzZXQgcGNpX2RzcyBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLmdkcHIgLSBpZiB0cnVlLCBzZXQgZ2RwciBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLmdwZzEzIC0gaWYgdHJ1ZSwgc2V0IGdwZzEzIGZpZWxkc1xuICogQHBhcmFtIHtib29sZWFufSBwYXJhbXMuaGlwYWEgLSBpZiB0cnVlLCBzZXQgaGlwYWEgZmllbGRzXG4gKiBAcGFyYW0ge2Jvb2xlYW59IHBhcmFtcy5uaXN0XzgwMF81MyAtIGlmIHRydWUsIHNldCBuaXN0XzgwMF81MyBmaWVsZHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLm5pc3RfODAwXzUzIC0gaWYgdHJ1ZSwgc2V0IG5pc3RfODAwXzUzIGZpZWxkc1xuICogQHBhcmFtIHtib29sZWFufSBwYXJhbXMud2luX2F1dGhlbnRpY2F0aW9uX2ZhaWxlZCAtIGlmIHRydWUsIGFkZCB3aW5fYXV0aGVudGljYXRpb25fZmFpbGVkIHRvIHJ1bGUuZ3JvdXBzXG4gKiBAcGFyYW0ge251bWJlcn0gcGFyYW1zLnByb2JhYmlsaXR5X3dpbl9hdXRoZW50aWNhdGlvbl9mYWlsZWQgLSBwcm9iYWJpbGl0eSB0byBhZGQgd2luX2F1dGhlbnRpY2F0aW9uX2ZhaWxlZCB0byBydWxlLmdyb3Vwcy4gRXhhbXBsZTogMjAgd2lsbCBiZSAyMCUgb2YgcHJvYmFiaWxpdHkgdG8gYWRkIHRoaXMgdG8gcnVsZS5ncm91cHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLmF1dGhlbnRpY2F0aW9uX2ZhaWxlZCAtIGlmIHRydWUsIGFkZCB3aW5fYXV0aGVudGljYXRpb25fZmFpbGVkIHRvIHJ1bGUuZ3JvdXBzXG4gKiBAcGFyYW0ge251bWJlcn0gcGFyYW1zLnByb2JhYmlsaXR5X2F1dGhlbnRpY2F0aW9uX2ZhaWxlZCAtIHByb2JhYmlsaXR5IHRvIGFkZCBhdXRoZW50aWNhdGlvbl9mYWlsZWQgdG8gcnVsZS5ncm91cHNcbiAqIEBwYXJhbSB7Ym9vbGVhbn0gcGFyYW1zLmF1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzIC0gaWYgdHJ1ZSwgYWRkIHdpbl9hdXRoZW50aWNhdGlvbl9mYWlsZWQgdG8gcnVsZS5ncm91cHNcbiAqIEBwYXJhbSB7bnVtYmVyfSBwYXJhbXMucHJvYmFiaWxpdHlfYXV0aGVudGljYXRpb25fZmFpbHVyZXMgLSBwcm9iYWJpbGl0eSB0byBhZGQgYXV0aGVudGljYXRpb25fZmFpbHVyZXMgdG8gcnVsZS5ncm91cHNcbiAqIEByZXR1cm4ge2FueX0gLSBBbGVydCBnZW5lcmF0ZWRcbiAqL1xuZnVuY3Rpb24gZ2VuZXJhdGVBbGVydChwYXJhbXMpIHtcbiAgbGV0IGFsZXJ0ID0ge1xuICAgIFsnQHNhbXBsZWRhdGEnXTogdHJ1ZSxcbiAgICB0aW1lc3RhbXA6ICcyMDIwLTAxLTI3VDExOjA4OjQ3Ljc3NyswMDAwJyxcbiAgICBydWxlOiB7XG4gICAgICBsZXZlbDogMyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnU2FtcGxlIGFsZXJ0JyxcbiAgICAgIGlkOiAnNTUwMicsXG4gICAgICBtYWlsOiBmYWxzZSxcbiAgICAgIGdyb3VwczogW10sXG4gICAgfSxcbiAgICBhZ2VudDoge1xuICAgICAgaWQ6ICcwMDAnLFxuICAgICAgbmFtZTogJ21hc3RlcicsXG4gICAgfSxcbiAgICBtYW5hZ2VyOiB7XG4gICAgICBuYW1lOiAnbWFzdGVyJyxcbiAgICB9LFxuICAgIGNsdXN0ZXI6IHtcbiAgICAgIG5hbWU6ICd3YXp1aCcsXG4gICAgfSxcbiAgICBpZDogJzE1ODAxMjMzMjcuNDkwMzEnLFxuICAgIHByZWRlY29kZXI6IHt9LFxuICAgIGRlY29kZXI6IHt9LFxuICAgIGRhdGE6IHt9LFxuICAgIGxvY2F0aW9uOiAnJyxcbiAgfTtcbiAgYWxlcnQuYWdlbnQgPSByYW5kb21BcnJheUl0ZW0oQWdlbnRzKTtcbiAgYWxlcnQucnVsZS5kZXNjcmlwdGlvbiA9IHJhbmRvbUFycmF5SXRlbShydWxlRGVzY3JpcHRpb24pO1xuICBhbGVydC5ydWxlLmlkID0gYCR7cmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDEsIGFsZXJ0SURNYXgpfWA7XG4gIGFsZXJ0LnJ1bGUubGV2ZWwgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMSwgcnVsZU1heExldmVsKTtcblxuICBhbGVydC50aW1lc3RhbXAgPSByYW5kb21EYXRlKCk7XG5cbiAgaWYgKHBhcmFtcy5tYW5hZ2VyKSB7XG4gICAgaWYgKHBhcmFtcy5tYW5hZ2VyLm5hbWUpIHtcbiAgICAgIGFsZXJ0Lm1hbmFnZXIubmFtZSA9IHBhcmFtcy5tYW5hZ2VyLm5hbWU7XG4gICAgfVxuICB9XG5cbiAgaWYgKHBhcmFtcy5jbHVzdGVyKSB7XG4gICAgaWYgKHBhcmFtcy5jbHVzdGVyLm5hbWUpIHtcbiAgICAgIGFsZXJ0LmNsdXN0ZXIubmFtZSA9IHBhcmFtcy5jbHVzdGVyLm5hbWU7XG4gICAgfVxuICAgIGlmIChwYXJhbXMuY2x1c3Rlci5ub2RlKSB7XG4gICAgICBhbGVydC5jbHVzdGVyLm5vZGUgPSBwYXJhbXMuY2x1c3Rlci5ub2RlO1xuICAgIH1cbiAgfVxuXG4gIGlmIChwYXJhbXMuYXdzKSB7XG4gICAgbGV0IHJhbmRvbVR5cGUgPSByYW5kb21BcnJheUl0ZW0oW1xuICAgICAgJ2d1YXJkZHV0eVBvcnRQcm9iZScsXG4gICAgICAnYXBpQ2FsbCcsXG4gICAgICAnbmV0d29ya0Nvbm5lY3Rpb24nLFxuICAgICAgJ2lhbVBvbGljeUdyYW50R2xvYmFsJyxcbiAgICBdKTtcblxuICAgIGNvbnN0IGJlZm9yZURhdGUgPSBuZXcgRGF0ZShuZXcgRGF0ZShhbGVydC50aW1lc3RhbXApIC0gMyAqIDI0ICogNjAgKiA2MCAqIDEwMDApO1xuICAgIHN3aXRjaCAocmFuZG9tVHlwZSkge1xuICAgICAgY2FzZSAnZ3VhcmRkdXR5UG9ydFByb2JlJzoge1xuICAgICAgICBjb25zdCB0eXBlQWxlcnQgPSBBV1MuZ3VhcmRkdXR5UG9ydFByb2JlO1xuXG4gICAgICAgIGFsZXJ0LmRhdGEgPSB7IC4uLnR5cGVBbGVydC5kYXRhIH07XG4gICAgICAgIGFsZXJ0LmRhdGEuaW50ZWdyYXRpb24gPSAnYXdzJztcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MucmVnaW9uID0gcmFuZG9tQXJyYXlJdGVtKEFXUy5yZWdpb24pO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5yZXNvdXJjZS5pbnN0YW5jZURldGFpbHMgPSB7IC4uLnJhbmRvbUFycmF5SXRlbShBV1MuaW5zdGFuY2VEZXRhaWxzKSB9O1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5yZXNvdXJjZS5pbnN0YW5jZURldGFpbHMuaWFtSW5zdGFuY2VQcm9maWxlLmFybiA9IGludGVycG9sYXRlQWxlcnRQcm9wcyhcbiAgICAgICAgICB0eXBlQWxlcnQuZGF0YS5hd3MucmVzb3VyY2UuaW5zdGFuY2VEZXRhaWxzLmlhbUluc3RhbmNlUHJvZmlsZS5hcm4sXG4gICAgICAgICAgYWxlcnRcbiAgICAgICAgKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MudGl0bGUgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoYWxlcnQuZGF0YS5hd3MudGl0bGUsIGFsZXJ0KTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MuYWNjb3VudElkID0gcmFuZG9tQXJyYXlJdGVtKEFXUy5hY2NvdW50SWQpO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5zZXJ2aWNlLmV2ZW50Rmlyc3RTZWVuID0gZm9ybWF0RGF0ZShiZWZvcmVEYXRlLCAnWS1NLURUaDptOnMubFonKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3Muc2VydmljZS5ldmVudExhc3RTZWVuID0gZm9ybWF0RGF0ZShcbiAgICAgICAgICBuZXcgRGF0ZShhbGVydC50aW1lc3RhbXApLFxuICAgICAgICAgICdZLU0tRFRoOm06cy5sWidcbiAgICAgICAgKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3Muc2VydmljZS5hY3Rpb24ucG9ydFByb2JlQWN0aW9uLnBvcnRQcm9iZURldGFpbHMucmVtb3RlSXBEZXRhaWxzID0ge1xuICAgICAgICAgIC4uLnJhbmRvbUFycmF5SXRlbShBV1MucmVtb3RlSXBEZXRhaWxzKSxcbiAgICAgICAgfTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MubG9nX2luZm8gPSB7XG4gICAgICAgICAgczNidWNrZXQ6IHJhbmRvbUFycmF5SXRlbShBV1MuYnVja2V0cyksXG4gICAgICAgICAgbG9nX2ZpbGU6IGBndWFyZGR1dHkvJHtmb3JtYXREYXRlKFxuICAgICAgICAgICAgbmV3IERhdGUoYWxlcnQudGltZXN0YW1wKSxcbiAgICAgICAgICAgICdZL00vRC9oJ1xuICAgICAgICAgICl9L2ZpcmVob3NlX2d1YXJkZHV0eS0xLSR7Zm9ybWF0RGF0ZShcbiAgICAgICAgICAgIG5ldyBEYXRlKGFsZXJ0LnRpbWVzdGFtcCksXG4gICAgICAgICAgICAnWS1NLUQtaC1tLXMtbCdcbiAgICAgICAgICApfWI1YjliLWVjNjItNGEwNy04NWQ3LWIxNjk5YjljMDMxZS56aXBgLFxuICAgICAgICB9O1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5zZXJ2aWNlLmNvdW50ID0gYCR7cmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDQwMCwgNDAwMCl9YDtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MuY3JlYXRlZEF0ID0gZm9ybWF0RGF0ZShiZWZvcmVEYXRlLCAnWS1NLURUaDptOnMubFonKTtcblxuICAgICAgICBhbGVydC5ydWxlID0geyAuLi50eXBlQWxlcnQucnVsZSB9O1xuICAgICAgICBhbGVydC5ydWxlLmZpcmVkdGltZXMgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMSwgNTApO1xuICAgICAgICBhbGVydC5ydWxlLmRlc2NyaXB0aW9uID0gaW50ZXJwb2xhdGVBbGVydFByb3BzKHR5cGVBbGVydC5ydWxlLmRlc2NyaXB0aW9uLCBhbGVydCk7XG5cbiAgICAgICAgYWxlcnQuZGVjb2RlciA9IHsgLi4udHlwZUFsZXJ0LmRlY29kZXIgfTtcbiAgICAgICAgYWxlcnQubG9jYXRpb24gPSB0eXBlQWxlcnQubG9jYXRpb247XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnYXBpQ2FsbCc6IHtcbiAgICAgICAgY29uc3QgdHlwZUFsZXJ0ID0gQVdTLmFwaUNhbGw7XG5cbiAgICAgICAgYWxlcnQuZGF0YSA9IHsgLi4udHlwZUFsZXJ0LmRhdGEgfTtcbiAgICAgICAgYWxlcnQuZGF0YS5pbnRlZ3JhdGlvbiA9ICdhd3MnO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5yZWdpb24gPSByYW5kb21BcnJheUl0ZW0oQVdTLnJlZ2lvbik7XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzLnJlc291cmNlLmFjY2Vzc0tleURldGFpbHMudXNlck5hbWUgPSByYW5kb21BcnJheUl0ZW0oVXNlcnMpO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5sb2dfaW5mbyA9IHtcbiAgICAgICAgICBzM2J1Y2tldDogcmFuZG9tQXJyYXlJdGVtKEFXUy5idWNrZXRzKSxcbiAgICAgICAgICBsb2dfZmlsZTogYGd1YXJkZHV0eS8ke2Zvcm1hdERhdGUoXG4gICAgICAgICAgICBuZXcgRGF0ZShhbGVydC50aW1lc3RhbXApLFxuICAgICAgICAgICAgJ1kvTS9EL2gnXG4gICAgICAgICAgKX0vZmlyZWhvc2VfZ3VhcmRkdXR5LTEtJHtmb3JtYXREYXRlKFxuICAgICAgICAgICAgbmV3IERhdGUoYWxlcnQudGltZXN0YW1wKSxcbiAgICAgICAgICAgICdZLU0tRC1oLW0tcy1sJ1xuICAgICAgICAgICl9YjViOWItZWM2Mi00YTA3LTg1ZDctYjE2OTliOWMwMzFlLnppcGAsXG4gICAgICAgIH07XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzLmFjY291bnRJZCA9IHJhbmRvbUFycmF5SXRlbShBV1MuYWNjb3VudElkKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3Muc2VydmljZS5hY3Rpb24uYXdzQXBpQ2FsbEFjdGlvbi5yZW1vdGVJcERldGFpbHMgPSB7XG4gICAgICAgICAgLi4ucmFuZG9tQXJyYXlJdGVtKEFXUy5yZW1vdGVJcERldGFpbHMpLFxuICAgICAgICB9O1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5zZXJ2aWNlLmV2ZW50Rmlyc3RTZWVuID0gZm9ybWF0RGF0ZShiZWZvcmVEYXRlLCAnWS1NLURUaDptOnMubFonKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3Muc2VydmljZS5ldmVudExhc3RTZWVuID0gZm9ybWF0RGF0ZShcbiAgICAgICAgICBuZXcgRGF0ZShhbGVydC50aW1lc3RhbXApLFxuICAgICAgICAgICdZLU0tRFRoOm06cy5sWidcbiAgICAgICAgKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MuY3JlYXRlZEF0ID0gZm9ybWF0RGF0ZShiZWZvcmVEYXRlLCAnWS1NLURUaDptOnMubFonKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MudGl0bGUgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoYWxlcnQuZGF0YS5hd3MudGl0bGUsIGFsZXJ0KTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MuZGVzY3JpcHRpb24gPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoYWxlcnQuZGF0YS5hd3MuZGVzY3JpcHRpb24sIGFsZXJ0KTtcbiAgICAgICAgY29uc3QgY291bnQgPSBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoNDAwLCA0MDAwKX1gO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5zZXJ2aWNlLmFkZGl0aW9uYWxJbmZvLnJlY2VudEFwaUNhbGxzLmNvdW50ID0gY291bnQ7XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzLnNlcnZpY2UuY291bnQgPSBjb3VudDtcblxuICAgICAgICBhbGVydC5ydWxlID0geyAuLi50eXBlQWxlcnQucnVsZSB9O1xuICAgICAgICBhbGVydC5ydWxlLmZpcmVkdGltZXMgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMSwgNTApO1xuICAgICAgICBhbGVydC5ydWxlLmRlc2NyaXB0aW9uID0gaW50ZXJwb2xhdGVBbGVydFByb3BzKHR5cGVBbGVydC5ydWxlLmRlc2NyaXB0aW9uLCBhbGVydCk7XG5cbiAgICAgICAgYWxlcnQuZGVjb2RlciA9IHsgLi4udHlwZUFsZXJ0LmRlY29kZXIgfTtcbiAgICAgICAgYWxlcnQubG9jYXRpb24gPSB0eXBlQWxlcnQubG9jYXRpb247XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnbmV0d29ya0Nvbm5lY3Rpb24nOiB7XG4gICAgICAgIGNvbnN0IHR5cGVBbGVydCA9IEFXUy5uZXR3b3JrQ29ubmVjdGlvbjtcblxuICAgICAgICBhbGVydC5kYXRhID0geyAuLi50eXBlQWxlcnQuZGF0YSB9O1xuICAgICAgICBhbGVydC5kYXRhLmludGVncmF0aW9uID0gJ2F3cyc7XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzLnJlZ2lvbiA9IHJhbmRvbUFycmF5SXRlbShBV1MucmVnaW9uKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MucmVzb3VyY2UuaW5zdGFuY2VEZXRhaWxzID0geyAuLi5yYW5kb21BcnJheUl0ZW0oQVdTLmluc3RhbmNlRGV0YWlscykgfTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MubG9nX2luZm8gPSB7XG4gICAgICAgICAgczNidWNrZXQ6IHJhbmRvbUFycmF5SXRlbShBV1MuYnVja2V0cyksXG4gICAgICAgICAgbG9nX2ZpbGU6IGBndWFyZGR1dHkvJHtmb3JtYXREYXRlKFxuICAgICAgICAgICAgbmV3IERhdGUoYWxlcnQudGltZXN0YW1wKSxcbiAgICAgICAgICAgICdZL00vRC9oJ1xuICAgICAgICAgICl9L2ZpcmVob3NlX2d1YXJkZHV0eS0xLSR7Zm9ybWF0RGF0ZShcbiAgICAgICAgICAgIG5ldyBEYXRlKGFsZXJ0LnRpbWVzdGFtcCksXG4gICAgICAgICAgICAnWS1NLUQtaC1tLXMtbCdcbiAgICAgICAgICApfWI1YjliLWVjNjItNGEwNy04NWQ3LWIxNjk5YjljMDMxZS56aXBgLFxuICAgICAgICB9O1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5kZXNjcmlwdGlvbiA9IGludGVycG9sYXRlQWxlcnRQcm9wcyhhbGVydC5kYXRhLmF3cy5kZXNjcmlwdGlvbiwgYWxlcnQpO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy50aXRsZSA9IGludGVycG9sYXRlQWxlcnRQcm9wcyhhbGVydC5kYXRhLmF3cy50aXRsZSwgYWxlcnQpO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5hY2NvdW50SWQgPSByYW5kb21BcnJheUl0ZW0oQVdTLmFjY291bnRJZCk7XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzLmNyZWF0ZWRBdCA9IGZvcm1hdERhdGUoYmVmb3JlRGF0ZSwgJ1ktTS1EVGg6bTpzLmxaJyk7XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzLnNlcnZpY2UuYWN0aW9uLm5ldHdvcmtDb25uZWN0aW9uQWN0aW9uLnJlbW90ZUlwRGV0YWlscyA9IHtcbiAgICAgICAgICAuLi5yYW5kb21BcnJheUl0ZW0oQVdTLnJlbW90ZUlwRGV0YWlscyksXG4gICAgICAgIH07XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzLnNlcnZpY2UuZXZlbnRGaXJzdFNlZW4gPSBmb3JtYXREYXRlKGJlZm9yZURhdGUsICdZLU0tRFRoOm06cy5sWicpO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5zZXJ2aWNlLmV2ZW50TGFzdFNlZW4gPSBmb3JtYXREYXRlKFxuICAgICAgICAgIG5ldyBEYXRlKGFsZXJ0LnRpbWVzdGFtcCksXG4gICAgICAgICAgJ1ktTS1EVGg6bTpzLmxaJ1xuICAgICAgICApO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5zZXJ2aWNlLmFkZGl0aW9uYWxJbmZvID0ge1xuICAgICAgICAgIGxvY2FsUG9ydDogYCR7cmFuZG9tQXJyYXlJdGVtKFBvcnRzKX1gLFxuICAgICAgICAgIG91dEJ5dGVzOiBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoMTAwMCwgMzAwMCl9YCxcbiAgICAgICAgICBpbkJ5dGVzOiBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoMTAwMCwgMTAwMDApfWAsXG4gICAgICAgICAgdW51c3VhbDogYCR7cmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDEwMDAsIDEwMDAwKX1gLFxuICAgICAgICB9O1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5zZXJ2aWNlLmNvdW50ID0gYCR7cmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDQwMCwgNDAwMCl9YDtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3Muc2VydmljZS5hY3Rpb24ubmV0d29ya0Nvbm5lY3Rpb25BY3Rpb24ubG9jYWxJcERldGFpbHMuaXBBZGRyZXNzVjQgPVxuICAgICAgICAgIGFsZXJ0LmRhdGEuYXdzLnJlc291cmNlLmluc3RhbmNlRGV0YWlscy5uZXR3b3JrSW50ZXJmYWNlcy5wcml2YXRlSXBBZGRyZXNzO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy5hcm4gPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHModHlwZUFsZXJ0LmRhdGEuYXdzLmFybiwgYWxlcnQpO1xuICAgICAgICBhbGVydC5ydWxlID0geyAuLi50eXBlQWxlcnQucnVsZSB9O1xuICAgICAgICBhbGVydC5ydWxlLmZpcmVkdGltZXMgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMSwgNTApO1xuICAgICAgICBhbGVydC5ydWxlLmRlc2NyaXB0aW9uID0gaW50ZXJwb2xhdGVBbGVydFByb3BzKHR5cGVBbGVydC5ydWxlLmRlc2NyaXB0aW9uLCBhbGVydCk7XG5cbiAgICAgICAgYWxlcnQuZGVjb2RlciA9IHsgLi4udHlwZUFsZXJ0LmRlY29kZXIgfTtcbiAgICAgICAgYWxlcnQubG9jYXRpb24gPSB0eXBlQWxlcnQubG9jYXRpb247XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnaWFtUG9saWN5R3JhbnRHbG9iYWwnOiB7XG4gICAgICAgIGNvbnN0IHR5cGVBbGVydCA9IEFXUy5pYW1Qb2xpY3lHcmFudEdsb2JhbDtcblxuICAgICAgICBhbGVydC5kYXRhID0geyAuLi50eXBlQWxlcnQuZGF0YSB9O1xuICAgICAgICBhbGVydC5kYXRhLmludGVncmF0aW9uID0gJ2F3cyc7XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzLnJlZ2lvbiA9IHJhbmRvbUFycmF5SXRlbShBV1MucmVnaW9uKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3Muc3VtbWFyeS5UaW1lc3RhbXBzID0gZm9ybWF0RGF0ZShiZWZvcmVEYXRlLCAnWS1NLURUaDptOnMubFonKTtcbiAgICAgICAgYWxlcnQuZGF0YS5hd3MubG9nX2luZm8gPSB7XG4gICAgICAgICAgczNidWNrZXQ6IHJhbmRvbUFycmF5SXRlbShBV1MuYnVja2V0cyksXG4gICAgICAgICAgbG9nX2ZpbGU6IGBtYWNpZS8ke2Zvcm1hdERhdGUoXG4gICAgICAgICAgICBuZXcgRGF0ZShhbGVydC50aW1lc3RhbXApLFxuICAgICAgICAgICAgJ1kvTS9EL2gnXG4gICAgICAgICAgKX0vZmlyZWhvc2VfbWFjaWUtMS0ke2Zvcm1hdERhdGUoXG4gICAgICAgICAgICBuZXcgRGF0ZShhbGVydC50aW1lc3RhbXApLFxuICAgICAgICAgICAgJ1ktTS1ELWgtbS1zJ1xuICAgICAgICAgICl9LTBiMWVkZTk0LWYzOTktNGU1NC04ODE1LTFjNjU4N2VlZTNiMS8vZmlyZWhvc2VfZ3VhcmRkdXR5LTEtJHtmb3JtYXREYXRlKFxuICAgICAgICAgICAgbmV3IERhdGUoYWxlcnQudGltZXN0YW1wKSxcbiAgICAgICAgICAgICdZLU0tRC1oLW0tcy1sJ1xuICAgICAgICAgICl9YjViOWItZWM2Mi00YTA3LTg1ZDctYjE2OTliOWMwMzFlLnppcGAsXG4gICAgICAgIH07XG4gICAgICAgIGFsZXJ0LmRhdGEuYXdzWydjcmVhdGVkLWF0J10gPSBmb3JtYXREYXRlKGJlZm9yZURhdGUsICdZLU0tRFRoOm06cy5sWicpO1xuICAgICAgICBhbGVydC5kYXRhLmF3cy51cmwgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHModHlwZUFsZXJ0LmRhdGEuYXdzLnVybCwgYWxlcnQpO1xuICAgICAgICBhbGVydC5kYXRhLmF3c1snYWxlcnQtYXJuJ10gPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHModHlwZUFsZXJ0LmRhdGEuYXdzWydhbGVydC1hcm4nXSwgYWxlcnQpO1xuXG4gICAgICAgIGFsZXJ0LnJ1bGUgPSB7IC4uLnR5cGVBbGVydC5ydWxlIH07XG4gICAgICAgIGFsZXJ0LnJ1bGUuZmlyZWR0aW1lcyA9IHJhbmRvbUludGVydmFsSW50ZWdlcigxLCA1MCk7XG5cbiAgICAgICAgYWxlcnQuZGVjb2RlciA9IHsgLi4udHlwZUFsZXJ0LmRlY29kZXIgfTtcbiAgICAgICAgYWxlcnQubG9jYXRpb24gPSB0eXBlQWxlcnQubG9jYXRpb247XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgZGVmYXVsdDoge1xuICAgICAgfVxuICAgIH1cbiAgICBhbGVydC5pbnB1dCA9IHsgdHlwZTogJ2xvZycgfTtcbiAgICBhbGVydC5HZW9Mb2NhdGlvbiA9IHJhbmRvbUFycmF5SXRlbShHZW9Mb2NhdGlvbik7XG4gIH1cblxuICBpZiAocGFyYW1zLm9mZmljZSkge1xuICAgIGFsZXJ0LmFnZW50ID0ge1xuICAgICAgaWQ6ICcwMDAnLFxuICAgICAgaXA6IGFsZXJ0LmFnZW50LmlwLFxuICAgICAgbmFtZTogYWxlcnQuYWdlbnQubmFtZVxuICAgIH07XG5cbiAgICBpZiAocGFyYW1zLm1hbmFnZXIgJiYgcGFyYW1zLm1hbmFnZXIubmFtZSkge1xuICAgICAgYWxlcnQuYWdlbnQubmFtZSA9IHBhcmFtcy5tYW5hZ2VyLm5hbWU7XG4gICAgfTtcblxuICAgIGNvbnN0IGJlZm9yZURhdGUgPSBuZXcgRGF0ZShuZXcgRGF0ZShhbGVydC50aW1lc3RhbXApIC0gMyAqIDI0ICogNjAgKiA2MCAqIDEwMDApO1xuICAgIGNvbnN0IEludHJhSUQgPSByYW5kb21BcnJheUl0ZW0oT2ZmaWNlLmFycmF5VXVpZE9mZmljZSk7XG4gICAgY29uc3QgT3JnSUQgPSByYW5kb21BcnJheUl0ZW0oT2ZmaWNlLmFycmF5VXVpZE9mZmljZSk7XG4gICAgY29uc3Qgb2JqSUQgPSByYW5kb21BcnJheUl0ZW0oT2ZmaWNlLmFycmF5VXVpZE9mZmljZSk7XG4gICAgY29uc3QgdXNlcktleSA9IHJhbmRvbUFycmF5SXRlbShPZmZpY2UuYXJyYXlVdWlkT2ZmaWNlKTtcbiAgICBjb25zdCB1c2VySUQgPSByYW5kb21BcnJheUl0ZW0oT2ZmaWNlLmFycmF5VXNlcklkKTtcbiAgICBjb25zdCB1c2VyVHlwZSA9IHJhbmRvbUFycmF5SXRlbShbMCwgMiwgNF0pO1xuICAgIGNvbnN0IHJlc3VsdFN0YXR1cyA9IHJhbmRvbUFycmF5SXRlbShbJ1N1Y2NlZWRlZCcsICdQYXJ0aWFsbHlTdWNjZWVkZWQnLCAnRmFpbGVkJ10pO1xuICAgIGNvbnN0IGxvZyA9IHJhbmRvbUFycmF5SXRlbShPZmZpY2UuYXJyYXlMb2dzKTtcbiAgICBjb25zdCBydWxlRGF0YSA9IE9mZmljZS5vZmZpY2VSdWxlc1tsb2cuUmVjb3JkVHlwZV07XG5cbiAgICBhbGVydC5hZ2VudC5pZCA9ICcwMDAnXG4gICAgYWxlcnQucnVsZSA9IHJ1bGVEYXRhLnJ1bGU7XG4gICAgYWxlcnQuZGVjb2RlciA9IHJhbmRvbUFycmF5SXRlbShPZmZpY2UuYXJyYXlEZWNvZGVyT2ZmaWNlKTtcbiAgICBhbGVydC5HZW9Mb2NhdGlvbiA9IHJhbmRvbUFycmF5SXRlbShHZW9Mb2NhdGlvbik7XG4gICAgYWxlcnQuZGF0YS5pbnRlZ3JhdGlvbiA9ICdPZmZpY2UzNjUnO1xuICAgIGFsZXJ0LmxvY2F0aW9uID0gT2ZmaWNlLmFycmF5TG9jYXRpb25PZmZpY2U7XG4gICAgYWxlcnQuZGF0YS5vZmZpY2UzNjUgPSB7XG4gICAgICAuLi5sb2csXG4gICAgICAuLi5ydWxlRGF0YS5kYXRhLm9mZmljZTM2NSxcbiAgICAgIElkOiBJbnRyYUlELFxuICAgICAgQ3JlYXRpb25UaW1lOiBmb3JtYXREYXRlKGJlZm9yZURhdGUsICdZLU0tRFRoOm06cy5sWicpLFxuICAgICAgT3JnYW5pemF0aW9uSWQ6IE9yZ0lELFxuICAgICAgVXNlclR5cGU6IHVzZXJUeXBlLFxuICAgICAgVXNlcktleTogdXNlcktleSxcbiAgICAgIFJlc3VsdFN0YXR1czogcmVzdWx0U3RhdHVzLFxuICAgICAgT2JqZWN0SWQ6IG9iaklELFxuICAgICAgVXNlcklkOiB1c2VySUQsXG4gICAgICBDbGllbnRJUDogcmFuZG9tQXJyYXlJdGVtKE9mZmljZS5hcnJheUlwKSxcbiAgICB9O1xuICB9XG5cbiAgaWYgKHBhcmFtcy5nY3ApIHtcbiAgICBhbGVydC5ydWxlID0gcmFuZG9tQXJyYXlJdGVtKEdDUC5hcnJheVJ1bGVzKTtcbiAgICBhbGVydC5kYXRhLmludGVncmF0aW9uID0gJ2djcCc7XG4gICAgYWxlcnQuZGF0YS5nY3AgPSB7XG4gICAgICBpbnNlcnRJZDogJ3VrMXpwZTIzeGNqJyxcbiAgICAgIGpzb25QYXlsb2FkOiB7XG4gICAgICAgIGF1dGhBbnN3ZXI6IEdDUC5hcnJheUF1dGhBbnN3ZXJbTWF0aC5mbG9vcihHQ1AuYXJyYXlBdXRoQW5zd2VyLmxlbmd0aCAqIE1hdGgucmFuZG9tKCkpXSxcbiAgICAgICAgcHJvdG9jb2w6IEdDUC5hcnJheVByb3RvY29sW01hdGguZmxvb3IoR0NQLmFycmF5UHJvdG9jb2wubGVuZ3RoICogTWF0aC5yYW5kb20oKSldLFxuICAgICAgICBxdWVyeU5hbWU6IEdDUC5hcnJheVF1ZXJ5TmFtZVtNYXRoLmZsb29yKEdDUC5hcnJheVF1ZXJ5TmFtZS5sZW5ndGggKiBNYXRoLnJhbmRvbSgpKV0sXG4gICAgICAgIHF1ZXJ5VHlwZTogR0NQLmFycmF5UXVlcnlUeXBlW01hdGguZmxvb3IoR0NQLmFycmF5UXVlcnlUeXBlLmxlbmd0aCAqIE1hdGgucmFuZG9tKCkpXSxcbiAgICAgICAgcmVzcG9uc2VDb2RlOlxuICAgICAgICAgIEdDUC5hcnJheVJlc3BvbnNlQ29kZVtNYXRoLmZsb29yKEdDUC5hcnJheVJlc3BvbnNlQ29kZS5sZW5ndGggKiBNYXRoLnJhbmRvbSgpKV0sXG4gICAgICAgIHNvdXJjZUlQOiBHQ1AuYXJyYXlTb3VyY2VJUFtNYXRoLmZsb29yKEdDUC5hcnJheVNvdXJjZUlQLmxlbmd0aCAqIE1hdGgucmFuZG9tKCkpXSxcbiAgICAgICAgdm1JbnN0YW5jZUlkOiAnNDk4MDExMzkyODgwMDgzOTY4MC4wMDAwMDAnLFxuICAgICAgICB2bUluc3RhbmNlTmFtZTogJzUzMTMzOTIyOTUzMS5pbnN0YW5jZS0xJyxcbiAgICAgIH0sXG4gICAgICBsb2dOYW1lOiAncHJvamVjdHMvd2F6dWgtZGV2L2xvZ3MvZG5zLmdvb2dsZWFwaXMuY29tJTJGZG5zX3F1ZXJpZXMnLFxuICAgICAgcmVjZWl2ZVRpbWVzdGFtcDogJzIwMTktMTEtMTFUMDI6NDI6MDUuMDU4NTMxNTJaJyxcbiAgICAgIHJlc291cmNlOiB7XG4gICAgICAgIGxhYmVsczoge1xuICAgICAgICAgIGxvY2F0aW9uOiBHQ1AuYXJyYXlMb2NhdGlvbltNYXRoLmZsb29yKEdDUC5hcnJheUxvY2F0aW9uLmxlbmd0aCAqIE1hdGgucmFuZG9tKCkpXSxcbiAgICAgICAgICBwcm9qZWN0X2lkOiBHQ1AuYXJyYXlQcm9qZWN0W01hdGguZmxvb3IoR0NQLmFycmF5UHJvamVjdC5sZW5ndGggKiBNYXRoLnJhbmRvbSgpKV0sXG4gICAgICAgICAgc291cmNlX3R5cGU6IEdDUC5hcnJheVNvdXJjZVR5cGVbTWF0aC5mbG9vcihHQ1AuYXJyYXlTb3VyY2VUeXBlLmxlbmd0aCAqIE1hdGgucmFuZG9tKCkpXSxcbiAgICAgICAgICB0YXJnZXRfdHlwZTogJ2V4dGVybmFsJyxcbiAgICAgICAgfSxcbiAgICAgICAgdHlwZTogR0NQLmFycmF5VHlwZVtNYXRoLmZsb29yKEdDUC5hcnJheVR5cGUubGVuZ3RoICogTWF0aC5yYW5kb20oKSldLFxuICAgICAgfSxcbiAgICAgIHNldmVyaXR5OiBHQ1AuYXJyYXlTZXZlcml0eVtNYXRoLmZsb29yKEdDUC5hcnJheVNldmVyaXR5Lmxlbmd0aCAqIE1hdGgucmFuZG9tKCkpXSxcbiAgICAgIHRpbWVzdGFtcDogJzIwMTktMTEtMTFUMDI6NDI6MDQuMzQ5MjE0NDlaJyxcbiAgICB9O1xuXG4gICAgYWxlcnQuR2VvTG9jYXRpb24gPSByYW5kb21BcnJheUl0ZW0oR2VvTG9jYXRpb24pO1xuICB9XG5cbiAgaWYgKHBhcmFtcy5hdWRpdCkge1xuICAgIGxldCBkYXRhQXVkaXQgPSByYW5kb21BcnJheUl0ZW0oQXVkaXQuZGF0YUF1ZGl0KTtcbiAgICBhbGVydC5kYXRhID0gZGF0YUF1ZGl0LmRhdGE7XG4gICAgYWxlcnQuZGF0YS5hdWRpdC5maWxlXG4gICAgICA/IGFsZXJ0LmRhdGEuYXVkaXQuZmlsZS5uYW1lID09PSAnJ1xuICAgICAgICA/IChhbGVydC5kYXRhLmF1ZGl0LmZpbGUubmFtZSA9IHJhbmRvbUFycmF5SXRlbShBdWRpdC5maWxlTmFtZSkpXG4gICAgICAgIDogbnVsbFxuICAgICAgOiBudWxsO1xuICAgIGFsZXJ0LnJ1bGUgPSBkYXRhQXVkaXQucnVsZTtcbiAgfVxuXG4gIGlmIChwYXJhbXMuY2lzY2F0KSB7XG4gICAgYWxlcnQucnVsZS5ncm91cHMucHVzaCgnY2lzY2F0Jyk7XG4gICAgYWxlcnQuZGF0YS5jaXMgPSB7fTtcblxuICAgIGFsZXJ0LmRhdGEuY2lzLmdyb3VwID0gcmFuZG9tQXJyYXlJdGVtKENJU0NBVC5ncm91cCk7XG4gICAgYWxlcnQuZGF0YS5jaXMuZmFpbCA9IHJhbmRvbUludGVydmFsSW50ZWdlcigwLCAxMDApO1xuICAgIGFsZXJ0LmRhdGEuY2lzLnJ1bGVfdGl0bGUgPSByYW5kb21BcnJheUl0ZW0oQ0lTQ0FULnJ1bGVUaXRsZSk7XG4gICAgYWxlcnQuZGF0YS5jaXMubm90Y2hlY2tlZCA9IHJhbmRvbUludGVydmFsSW50ZWdlcigwLCAxMDApO1xuICAgIGFsZXJ0LmRhdGEuY2lzLnNjb3JlID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDEwMCk7XG4gICAgYWxlcnQuZGF0YS5jaXMucGFzcyA9IHJhbmRvbUludGVydmFsSW50ZWdlcigwLCAxMDApO1xuICAgIGFsZXJ0LmRhdGEuY2lzLnRpbWVzdGFtcCA9IG5ldyBEYXRlKHJhbmRvbURhdGUoKSk7XG4gICAgYWxlcnQuZGF0YS5jaXMuZXJyb3IgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMCwgMSk7XG4gICAgYWxlcnQuZGF0YS5jaXMuYmVuY2htYXJrID0gcmFuZG9tQXJyYXlJdGVtKENJU0NBVC5iZW5jaG1hcmspO1xuICAgIGFsZXJ0LmRhdGEuY2lzLnVua25vd24gPSByYW5kb21JbnRlcnZhbEludGVnZXIoMCwgMTAwKTtcbiAgICBhbGVydC5kYXRhLmNpcy5ub3RjaGVja2VkID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDUpO1xuICAgIGFsZXJ0LmRhdGEuY2lzLnJlc3VsdCA9IHJhbmRvbUFycmF5SXRlbShDSVNDQVQucmVzdWx0KTtcbiAgfVxuXG4gIGlmIChwYXJhbXMuZG9ja2VyKSB7XG4gICAgY29uc3QgZGF0YURvY2tlciA9IHJhbmRvbUFycmF5SXRlbShEb2NrZXIuZGF0YURvY2tlcik7XG4gICAgYWxlcnQuZGF0YSA9IHt9O1xuICAgIGFsZXJ0LmRhdGEgPSBkYXRhRG9ja2VyLmRhdGE7XG4gICAgYWxlcnQucnVsZSA9IGRhdGFEb2NrZXIucnVsZTtcbiAgfVxuXG4gIGlmIChwYXJhbXMubWl0cmUpIHtcbiAgICBhbGVydC5ydWxlID0gcmFuZG9tQXJyYXlJdGVtKE1pdHJlLmFycmF5TWl0cmVSdWxlcyk7XG4gICAgYWxlcnQubG9jYXRpb24gPSByYW5kb21BcnJheUl0ZW0oTWl0cmUuYXJyYXlMb2NhdGlvbik7XG4gIH1cblxuICBpZiAocGFyYW1zLm9wZW5zY2FwKSB7XG4gICAgYWxlcnQuZGF0YSA9IHt9O1xuICAgIGFsZXJ0LmRhdGEub3NjYXAgPSB7fTtcbiAgICBjb25zdCB0eXBlQWxlcnQgPSB7IC4uLnJhbmRvbUFycmF5SXRlbShPcGVuU0NBUC5kYXRhKSB9O1xuICAgIGFsZXJ0LmRhdGEgPSB7IC4uLnR5cGVBbGVydC5kYXRhIH07XG4gICAgYWxlcnQucnVsZSA9IHsgLi4udHlwZUFsZXJ0LnJ1bGUgfTtcbiAgICBhbGVydC5ydWxlLmZpcmVkdGltZXMgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMiwgMTApO1xuICAgIGFsZXJ0LmlucHV0ID0ge1xuICAgICAgdHlwZTogJ2xvZycsXG4gICAgfTtcbiAgICBhbGVydC5kZWNvZGVyID0geyAuLi5PcGVuU0NBUC5kZWNvZGVyIH07XG4gICAgYWxlcnQubG9jYXRpb24gPSBPcGVuU0NBUC5sb2NhdGlvbjtcbiAgICBpZiAodHlwZUFsZXJ0LmZ1bGxfbG9nKSB7XG4gICAgICBhbGVydC5mdWxsX2xvZyA9IGludGVycG9sYXRlQWxlcnRQcm9wcyh0eXBlQWxlcnQuZnVsbF9sb2csIGFsZXJ0KTtcbiAgICB9XG4gIH1cblxuICBpZiAocGFyYW1zLnJvb3RjaGVjaykge1xuICAgIGFsZXJ0LmxvY2F0aW9uID0gUG9saWN5TW9uaXRvcmluZy5sb2NhdGlvbjtcbiAgICBhbGVydC5kZWNvZGVyID0geyAuLi5Qb2xpY3lNb25pdG9yaW5nLmRlY29kZXIgfTtcbiAgICBhbGVydC5pbnB1dCA9IHtcbiAgICAgIHR5cGU6ICdsb2cnLFxuICAgIH07XG5cbiAgICBjb25zdCBhbGVydENhdGVnb3J5ID0gcmFuZG9tQXJyYXlJdGVtKFsnUm9vdGtpdCcsICdUcm9qYW4nXSk7XG5cbiAgICBzd2l0Y2ggKGFsZXJ0Q2F0ZWdvcnkpIHtcbiAgICAgIGNhc2UgJ1Jvb3RraXQnOiB7XG4gICAgICAgIGNvbnN0IHJvb3RraXRDYXRlZ29yeSA9IHJhbmRvbUFycmF5SXRlbShPYmplY3Qua2V5cyhQb2xpY3lNb25pdG9yaW5nLnJvb3RraXRzKSk7XG4gICAgICAgIGNvbnN0IHJvb3RraXQgPSByYW5kb21BcnJheUl0ZW0oUG9saWN5TW9uaXRvcmluZy5yb290a2l0c1tyb290a2l0Q2F0ZWdvcnldKTtcbiAgICAgICAgYWxlcnQuZGF0YSA9IHtcbiAgICAgICAgICB0aXRsZTogaW50ZXJwb2xhdGVBbGVydFByb3BzKFBvbGljeU1vbml0b3Jpbmcucm9vdGtpdHNEYXRhLmRhdGEudGl0bGUsIGFsZXJ0LCB7XG4gICAgICAgICAgICBfcm9vdGtpdF9jYXRlZ29yeTogcm9vdGtpdENhdGVnb3J5LFxuICAgICAgICAgICAgX3Jvb3RraXRfZmlsZTogcm9vdGtpdCxcbiAgICAgICAgICB9KSxcbiAgICAgICAgfTtcbiAgICAgICAgYWxlcnQucnVsZSA9IHsgLi4uUG9saWN5TW9uaXRvcmluZy5yb290a2l0c0RhdGEucnVsZSB9O1xuICAgICAgICBhbGVydC5ydWxlLmZpcmVkdGltZXMgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMSwgMTApO1xuICAgICAgICBhbGVydC5mdWxsX2xvZyA9IGFsZXJ0LmRhdGEudGl0bGU7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnVHJvamFuJzoge1xuICAgICAgICBjb25zdCB0cm9qYW4gPSByYW5kb21BcnJheUl0ZW0oUG9saWN5TW9uaXRvcmluZy50cm9qYW5zKTtcbiAgICAgICAgYWxlcnQuZGF0YSA9IHtcbiAgICAgICAgICBmaWxlOiB0cm9qYW4uZmlsZSxcbiAgICAgICAgICB0aXRsZTogJ1Ryb2phbmVkIHZlcnNpb24gb2YgZmlsZSBkZXRlY3RlZC4nLFxuICAgICAgICB9O1xuICAgICAgICBhbGVydC5ydWxlID0geyAuLi5Qb2xpY3lNb25pdG9yaW5nLnRyb2phbnNEYXRhLnJ1bGUgfTtcbiAgICAgICAgYWxlcnQucnVsZS5maXJlZHRpbWVzID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDEsIDEwKTtcbiAgICAgICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoUG9saWN5TW9uaXRvcmluZy50cm9qYW5zRGF0YS5mdWxsX2xvZywgYWxlcnQsIHtcbiAgICAgICAgICBfdHJvamFuX3NpZ25hdHVyZTogdHJvamFuLnNpZ25hdHVyZSxcbiAgICAgICAgfSk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgZGVmYXVsdDoge1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGlmIChwYXJhbXMuc3lzY2hlY2spIHtcbiAgICBhbGVydC5ydWxlLmdyb3Vwcy5wdXNoKCdzeXNjaGVjaycpO1xuICAgIGFsZXJ0LnN5c2NoZWNrID0ge307XG4gICAgYWxlcnQuc3lzY2hlY2suZXZlbnQgPSByYW5kb21BcnJheUl0ZW0oSW50ZWdyaXR5TW9uaXRvcmluZy5ldmVudHMpO1xuICAgIGFsZXJ0LnN5c2NoZWNrLnBhdGggPSByYW5kb21BcnJheUl0ZW0oXG4gICAgICBhbGVydC5hZ2VudC5uYW1lID09PSAnV2luZG93cydcbiAgICAgICAgPyBJbnRlZ3JpdHlNb25pdG9yaW5nLnBhdGhzV2luZG93c1xuICAgICAgICA6IEludGVncml0eU1vbml0b3JpbmcucGF0aHNMaW51eFxuICAgICk7XG4gICAgYWxlcnQuc3lzY2hlY2sudW5hbWVfYWZ0ZXIgPSByYW5kb21BcnJheUl0ZW0oVXNlcnMpO1xuICAgIGFsZXJ0LnN5c2NoZWNrLmduYW1lX2FmdGVyID0gJ3Jvb3QnO1xuICAgIGFsZXJ0LnN5c2NoZWNrLm10aW1lX2FmdGVyID0gbmV3IERhdGUocmFuZG9tRGF0ZSgpKTtcbiAgICBhbGVydC5zeXNjaGVjay5zaXplX2FmdGVyID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDY1KTtcbiAgICBhbGVydC5zeXNjaGVjay51aWRfYWZ0ZXIgPSByYW5kb21BcnJheUl0ZW0oSW50ZWdyaXR5TW9uaXRvcmluZy51aWRfYWZ0ZXIpO1xuICAgIGFsZXJ0LnN5c2NoZWNrLmdpZF9hZnRlciA9IHJhbmRvbUFycmF5SXRlbShJbnRlZ3JpdHlNb25pdG9yaW5nLmdpZF9hZnRlcik7XG4gICAgYWxlcnQuc3lzY2hlY2sucGVybV9hZnRlciA9ICdydy1yLS1yLS0nO1xuICAgIGFsZXJ0LnN5c2NoZWNrLmlub2RlX2FmdGVyID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDEwMDAwMCk7XG4gICAgc3dpdGNoIChhbGVydC5zeXNjaGVjay5ldmVudCkge1xuICAgICAgY2FzZSAnYWRkZWQnOlxuICAgICAgICBhbGVydC5ydWxlID0gSW50ZWdyaXR5TW9uaXRvcmluZy5yZWd1bGF0b3J5WzBdO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ21vZGlmaWVkJzpcbiAgICAgICAgYWxlcnQucnVsZSA9IEludGVncml0eU1vbml0b3JpbmcucmVndWxhdG9yeVsxXTtcbiAgICAgICAgYWxlcnQuc3lzY2hlY2subXRpbWVfYmVmb3JlID0gbmV3IERhdGUoYWxlcnQuc3lzY2hlY2subXRpbWVfYWZ0ZXIuZ2V0VGltZSgpIC0gMTAwMCAqIDYwKTtcbiAgICAgICAgYWxlcnQuc3lzY2hlY2suaW5vZGVfYmVmb3JlID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDEwMDAwMCk7XG4gICAgICAgIGFsZXJ0LnN5c2NoZWNrLnNoYTFfYWZ0ZXIgPSByYW5kb21FbGVtZW50cyg0MCwgJ2FiY2RlZjAxMjM0NTY3ODknKTtcbiAgICAgICAgYWxlcnQuc3lzY2hlY2suY2hhbmdlZF9hdHRyaWJ1dGVzID0gW3JhbmRvbUFycmF5SXRlbShJbnRlZ3JpdHlNb25pdG9yaW5nLmF0dHJpYnV0ZXMpXTtcbiAgICAgICAgYWxlcnQuc3lzY2hlY2subWQ1X2FmdGVyID0gcmFuZG9tRWxlbWVudHMoMzIsICdhYmNkZWYwMTIzNDU2Nzg5Jyk7XG4gICAgICAgIGFsZXJ0LnN5c2NoZWNrLnNoYTI1Nl9hZnRlciA9IHJhbmRvbUVsZW1lbnRzKDYwLCAnYWJjZGVmMDEyMzQ1Njc4OScpO1xuICAgICAgICBicmVhaztcbiAgICAgIGNhc2UgJ2RlbGV0ZWQnOlxuICAgICAgICBhbGVydC5ydWxlID0gSW50ZWdyaXR5TW9uaXRvcmluZy5yZWd1bGF0b3J5WzJdO1xuICAgICAgICBhbGVydC5zeXNjaGVjay50YWdzID0gW3JhbmRvbUFycmF5SXRlbShJbnRlZ3JpdHlNb25pdG9yaW5nLnRhZ3MpXTtcbiAgICAgICAgYWxlcnQuc3lzY2hlY2suc2hhMV9hZnRlciA9IHJhbmRvbUVsZW1lbnRzKDQwLCAnYWJjZGVmMDEyMzQ1Njc4OScpO1xuICAgICAgICBhbGVydC5zeXNjaGVjay5hdWRpdCA9IHtcbiAgICAgICAgICBwcm9jZXNzOiB7XG4gICAgICAgICAgICBuYW1lOiByYW5kb21BcnJheUl0ZW0oUGF0aHMpLFxuICAgICAgICAgICAgaWQ6IHJhbmRvbUludGVydmFsSW50ZWdlcigwLCAxMDAwMDApLFxuICAgICAgICAgICAgcHBpZDogcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDEwMDAwMCksXG4gICAgICAgICAgfSxcbiAgICAgICAgICBlZmZlY3RpdmVfdXNlcjoge1xuICAgICAgICAgICAgbmFtZTogcmFuZG9tQXJyYXlJdGVtKFVzZXJzKSxcbiAgICAgICAgICAgIGlkOiByYW5kb21JbnRlcnZhbEludGVnZXIoMCwgMTAwKSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHVzZXI6IHtcbiAgICAgICAgICAgIG5hbWU6IHJhbmRvbUFycmF5SXRlbShVc2VycyksXG4gICAgICAgICAgICBpZDogcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDEwMCksXG4gICAgICAgICAgfSxcbiAgICAgICAgICBncm91cDoge1xuICAgICAgICAgICAgbmFtZTogcmFuZG9tQXJyYXlJdGVtKFVzZXJzKSxcbiAgICAgICAgICAgIGlkOiByYW5kb21JbnRlcnZhbEludGVnZXIoMCwgMTAwKSxcbiAgICAgICAgICB9LFxuICAgICAgICB9O1xuICAgICAgICBhbGVydC5zeXNjaGVjay5tZDVfYWZ0ZXIgPSByYW5kb21FbGVtZW50cygzMiwgJ2FiY2RlZjAxMjM0NTY3ODknKTtcbiAgICAgICAgYWxlcnQuc3lzY2hlY2suc2hhMjU2X2FmdGVyID0gcmFuZG9tRWxlbWVudHMoNjAsICdhYmNkZWYwMTIzNDU2Nzg5Jyk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgZGVmYXVsdDoge1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIGlmIChwYXJhbXMudmlydXN0b3RhbCkge1xuICAgIGFsZXJ0LnJ1bGUuZ3JvdXBzLnB1c2goJ3ZpcnVzdG90YWwnKTtcbiAgICBhbGVydC5sb2NhdGlvbiA9ICd2aXJ1c3RvdGFsJztcbiAgICBhbGVydC5kYXRhLnZpcnVzdG90YWwgPSB7fTtcbiAgICBhbGVydC5kYXRhLnZpcnVzdG90YWwuZm91bmQgPSByYW5kb21BcnJheUl0ZW0oWycwJywgJzEnLCAnMScsICcxJ10pO1xuXG4gICAgYWxlcnQuZGF0YS52aXJ1c3RvdGFsLnNvdXJjZSA9IHtcbiAgICAgIHNoYTE6IHJhbmRvbUVsZW1lbnRzKDQwLCAnYWJjZGVmMDEyMzQ1Njc4OScpLFxuICAgICAgZmlsZTogcmFuZG9tQXJyYXlJdGVtKFZpcnVzdG90YWwuc291cmNlRmlsZSksXG4gICAgICBhbGVydF9pZDogYCR7cmFuZG9tRWxlbWVudHMoMTAsICcwMTIzNDU2Nzg5Jyl9LiR7cmFuZG9tRWxlbWVudHMoNywgJzAxMjM0NTY3ODknKX1gLFxuICAgICAgbWQ1OiByYW5kb21FbGVtZW50cygzMiwgJ2FiY2RlZjAxMjM0NTY3ODknKSxcbiAgICB9O1xuXG4gICAgaWYgKGFsZXJ0LmRhdGEudmlydXN0b3RhbC5mb3VuZCA9PT0gJzEnKSB7XG4gICAgICBhbGVydC5kYXRhLnZpcnVzdG90YWwubWFsaWNpb3VzID0gcmFuZG9tQXJyYXlJdGVtKFZpcnVzdG90YWwubWFsaWNpb3VzKTtcbiAgICAgIGFsZXJ0LmRhdGEudmlydXN0b3RhbC5wb3NpdGl2ZXMgPSBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoMCwgNjUpfWA7XG4gICAgICBhbGVydC5kYXRhLnZpcnVzdG90YWwudG90YWwgPVxuICAgICAgICBhbGVydC5kYXRhLnZpcnVzdG90YWwubWFsaWNpb3VzICsgYWxlcnQuZGF0YS52aXJ1c3RvdGFsLnBvc2l0aXZlcztcbiAgICAgIGFsZXJ0LnJ1bGUuZGVzY3JpcHRpb24gPSBgVmlydXNUb3RhbDogQWxlcnQgLSAke2FsZXJ0LmRhdGEudmlydXN0b3RhbC5zb3VyY2UuZmlsZX0gLSAke2FsZXJ0LmRhdGEudmlydXN0b3RhbC5wb3NpdGl2ZXN9IGVuZ2luZXMgZGV0ZWN0ZWQgdGhpcyBmaWxlYDtcbiAgICAgIGFsZXJ0LmRhdGEudmlydXN0b3RhbC5wZXJtYWxpbmsgPSByYW5kb21BcnJheUl0ZW0oVmlydXN0b3RhbC5wZXJtYWxpbmspO1xuICAgICAgYWxlcnQuZGF0YS52aXJ1c3RvdGFsLnNjYW5fZGF0ZSA9IG5ldyBEYXRlKERhdGUucGFyc2UoYWxlcnQudGltZXN0YW1wKSAtIDQgKiA2MDAwMCk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGFsZXJ0LmRhdGEudmlydXN0b3RhbC5tYWxpY2lvdXMgPSAnMCc7XG4gICAgICBhbGVydC5ydWxlLmRlc2NyaXB0aW9uID0gJ1ZpcnVzVG90YWw6IEFsZXJ0IC0gTm8gcmVjb3JkcyBpbiBWaXJ1c1RvdGFsIGRhdGFiYXNlJztcbiAgICB9XG4gIH1cblxuICBpZiAocGFyYW1zLnZ1bG5lcmFiaWxpdGllcykge1xuICAgIGNvbnN0IGRhdGFWdWxuZXJhYmlsaXR5ID0gcmFuZG9tQXJyYXlJdGVtKFZ1bG5lcmFiaWxpdHkuZGF0YSk7XG4gICAgYWxlcnQucnVsZSA9IHtcbiAgICAgIC4uLmRhdGFWdWxuZXJhYmlsaXR5LnJ1bGUsXG4gICAgICBtYWlsOiBmYWxzZSxcbiAgICAgIGdyb3VwczogWyd2dWxuZXJhYmlsaXR5LWRldGVjdG9yJ10sXG4gICAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgICAgcGNpX2RzczogWycxMS4yLjEnLCAnMTEuMi4zJ10sXG4gICAgICB0c2M6IFsnQ0M3LjEnLCAnQ0M3LjInXSxcbiAgICB9O1xuICAgIGFsZXJ0LmxvY2F0aW9uID0gJ3Z1bG5lcmFiaWxpdHktZGV0ZWN0b3InO1xuICAgIGFsZXJ0LmRlY29kZXIgPSB7IG5hbWU6ICdqc29uJyB9O1xuICAgIGFsZXJ0LmRhdGEgPSB7XG4gICAgICAuLi5kYXRhVnVsbmVyYWJpbGl0eS5kYXRhLFxuICAgIH07XG4gIH1cblxuICBpZiAocGFyYW1zLm9zcXVlcnkpIHtcbiAgICBhbGVydC5ydWxlLmdyb3Vwcy5wdXNoKCdvc3F1ZXJ5Jyk7XG4gICAgYWxlcnQuZGF0YS5vc3F1ZXJ5ID0ge307XG4gICAgaWYgKHJhbmRvbUludGVydmFsSW50ZWdlcigwLCA1KSA9PT0gMCkge1xuICAgICAgYWxlcnQucnVsZS5kZXNjcmlwdGlvbiA9ICdvc3F1ZXJ5IGVycm9yIG1lc3NhZ2UnO1xuICAgIH0gZWxzZSB7XG4gICAgICBsZXQgZGF0YU9zcXVlcnkgPSByYW5kb21BcnJheUl0ZW0oT3NxdWVyeS5kYXRhT3NxdWVyeSk7XG4gICAgICBhbGVydC5kYXRhLm9zcXVlcnkgPSBkYXRhT3NxdWVyeS5vc3F1ZXJ5O1xuICAgICAgYWxlcnQuZGF0YS5vc3F1ZXJ5LmNhbGVuZGFyVGltZSA9IGFsZXJ0LnRpbWVzdGFtcDtcbiAgICAgIGFsZXJ0LnJ1bGUuZGVzY3JpcHRpb24gPSBkYXRhT3NxdWVyeS5ydWxlLmRlc2NyaXB0aW9uO1xuICAgICAgcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDk5KSA9PT0gMCA/IChhbGVydC5kYXRhLm9zcXVlcnkuYWN0aW9uID0gJ3JlbW92ZWQnKSA6IG51bGw7XG4gICAgfVxuICB9XG5cbiAgLy8gUmVndWxhdG9yeSBjb21wbGlhbmNlXG4gIGlmIChcbiAgICBwYXJhbXMucGNpX2RzcyB8fFxuICAgIHBhcmFtcy5yZWd1bGF0b3J5X2NvbXBsaWFuY2UgfHxcbiAgICAocGFyYW1zLnJhbmRvbV9wcm9iYWJpbGl0eV9yZWd1bGF0b3J5X2NvbXBsaWFuY2UgJiZcbiAgICAgIHJhbmRvbVByb2JhYmlsaXR5KHBhcmFtcy5yYW5kb21fcHJvYmFiaWxpdHlfcmVndWxhdG9yeV9jb21wbGlhbmNlKSlcbiAgKSB7XG4gICAgYWxlcnQucnVsZS5wY2lfZHNzID0gW3JhbmRvbUFycmF5SXRlbShQQ0lfRFNTKV07XG4gIH1cbiAgaWYgKFxuICAgIHBhcmFtcy5nZHByIHx8XG4gICAgcGFyYW1zLnJlZ3VsYXRvcnlfY29tcGxpYW5jZSB8fFxuICAgIChwYXJhbXMucmFuZG9tX3Byb2JhYmlsaXR5X3JlZ3VsYXRvcnlfY29tcGxpYW5jZSAmJlxuICAgICAgcmFuZG9tUHJvYmFiaWxpdHkocGFyYW1zLnJhbmRvbV9wcm9iYWJpbGl0eV9yZWd1bGF0b3J5X2NvbXBsaWFuY2UpKVxuICApIHtcbiAgICBhbGVydC5ydWxlLmdkcHIgPSBbcmFuZG9tQXJyYXlJdGVtKEdEUFIpXTtcbiAgfVxuICBpZiAoXG4gICAgcGFyYW1zLmdwZzEzIHx8XG4gICAgcGFyYW1zLnJlZ3VsYXRvcnlfY29tcGxpYW5jZSB8fFxuICAgIChwYXJhbXMucmFuZG9tX3Byb2JhYmlsaXR5X3JlZ3VsYXRvcnlfY29tcGxpYW5jZSAmJlxuICAgICAgcmFuZG9tUHJvYmFiaWxpdHkocGFyYW1zLnJhbmRvbV9wcm9iYWJpbGl0eV9yZWd1bGF0b3J5X2NvbXBsaWFuY2UpKVxuICApIHtcbiAgICBhbGVydC5ydWxlLmdwZzEzID0gW3JhbmRvbUFycmF5SXRlbShHUEcxMyldO1xuICB9XG4gIGlmIChcbiAgICBwYXJhbXMuaGlwYWEgfHxcbiAgICBwYXJhbXMucmVndWxhdG9yeV9jb21wbGlhbmNlIHx8XG4gICAgKHBhcmFtcy5yYW5kb21fcHJvYmFiaWxpdHlfcmVndWxhdG9yeV9jb21wbGlhbmNlICYmXG4gICAgICByYW5kb21JbnRlcnZhbEludGVnZXIocGFyYW1zLnJhbmRvbV9wcm9iYWJpbGl0eV9yZWd1bGF0b3J5X2NvbXBsaWFuY2UpKVxuICApIHtcbiAgICBhbGVydC5ydWxlLmhpcGFhID0gW3JhbmRvbUFycmF5SXRlbShISVBBQSldO1xuICB9XG4gIGlmIChcbiAgICBwYXJhbXMubmlzdF84MDBfODMgfHxcbiAgICBwYXJhbXMucmVndWxhdG9yeV9jb21wbGlhbmNlIHx8XG4gICAgKHBhcmFtcy5yYW5kb21fcHJvYmFiaWxpdHlfcmVndWxhdG9yeV9jb21wbGlhbmNlICYmXG4gICAgICByYW5kb21JbnRlcnZhbEludGVnZXIocGFyYW1zLnJhbmRvbV9wcm9iYWJpbGl0eV9yZWd1bGF0b3J5X2NvbXBsaWFuY2UpKVxuICApIHtcbiAgICBhbGVydC5ydWxlLm5pc3RfODAwXzUzID0gW3JhbmRvbUFycmF5SXRlbShOSVNUXzgwMF81MyldO1xuICB9XG5cbiAgaWYgKHBhcmFtcy5hdXRoZW50aWNhdGlvbikge1xuICAgIGFsZXJ0LmRhdGEgPSB7XG4gICAgICBzcmNpcDogcmFuZG9tQXJyYXlJdGVtKElQcyksXG4gICAgICBzcmN1c2VyOiByYW5kb21BcnJheUl0ZW0oVXNlcnMpLFxuICAgICAgc3JjcG9ydDogcmFuZG9tQXJyYXlJdGVtKFBvcnRzKSxcbiAgICB9O1xuICAgIGFsZXJ0Lkdlb0xvY2F0aW9uID0gcmFuZG9tQXJyYXlJdGVtKEdlb0xvY2F0aW9uKTtcbiAgICBhbGVydC5kZWNvZGVyID0ge1xuICAgICAgbmFtZTogJ3NzaGQnLFxuICAgICAgcGFyZW50OiAnc3NoZCcsXG4gICAgfTtcbiAgICBhbGVydC5pbnB1dCA9IHtcbiAgICAgIHR5cGU6ICdsb2cnLFxuICAgIH07XG4gICAgYWxlcnQucHJlZGVjb2RlciA9IHtcbiAgICAgIHByb2dyYW1fbmFtZTogJ3NzaGQnLFxuICAgICAgdGltZXN0YW1wOiBmb3JtYXREYXRlKG5ldyBEYXRlKGFsZXJ0LnRpbWVzdGFtcCksICdOIEQgaDptOnMnKSxcbiAgICAgIGhvc3RuYW1lOiBhbGVydC5tYW5hZ2VyLm5hbWUsXG4gICAgfTtcbiAgICBsZXQgdHlwZUFsZXJ0ID0gcmFuZG9tQXJyYXlJdGVtKFtcbiAgICAgICdpbnZhbGlkTG9naW5QYXNzd29yZCcsXG4gICAgICAnaW52YWxpZExvZ2luVXNlcicsXG4gICAgICAnbXVsdGlwbGVBdXRoZW50aWNhdGlvbkZhaWx1cmVzJyxcbiAgICAgICd3aW5kb3dzSW52YWxpZExvZ2luUGFzc3dvcmQnLFxuICAgICAgJ3VzZXJMb2dpbkZhaWxlZCcsXG4gICAgICAncGFzc3dvcmRDaGVja0ZhaWxlZCcsXG4gICAgICAnbm9uRXhpc3RlbnRVc2VyJyxcbiAgICAgICdicnV0ZUZvcmNlVHJ5aW5nQWNjZXNzU3lzdGVtJyxcbiAgICAgICdhdXRoZW50aWNhdGlvblN1Y2Nlc3MnLFxuICAgICAgJ21heGltdW1BdXRoZW50aWNhdGlvbkF0dGVtcHRzRXhjZWVkZWQnLFxuICAgIF0pO1xuXG4gICAgc3dpdGNoICh0eXBlQWxlcnQpIHtcbiAgICAgIGNhc2UgJ2ludmFsaWRMb2dpblBhc3N3b3JkJzoge1xuICAgICAgICBhbGVydC5sb2NhdGlvbiA9IEF1dGhlbnRpY2F0aW9uLmludmFsaWRMb2dpblBhc3N3b3JkLmxvY2F0aW9uO1xuICAgICAgICBhbGVydC5ydWxlID0geyAuLi5BdXRoZW50aWNhdGlvbi5pbnZhbGlkTG9naW5QYXNzd29yZC5ydWxlIH07XG4gICAgICAgIGFsZXJ0LnJ1bGUuZ3JvdXBzID0gWy4uLkF1dGhlbnRpY2F0aW9uLmludmFsaWRMb2dpblBhc3N3b3JkLnJ1bGUuZ3JvdXBzXTtcbiAgICAgICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoQXV0aGVudGljYXRpb24uaW52YWxpZExvZ2luUGFzc3dvcmQuZnVsbF9sb2csIGFsZXJ0KTtcbiAgICAgICAgYnJlYWs7XG4gICAgICB9XG4gICAgICBjYXNlICdpbnZhbGlkTG9naW5Vc2VyJzoge1xuICAgICAgICBhbGVydC5sb2NhdGlvbiA9IEF1dGhlbnRpY2F0aW9uLmludmFsaWRMb2dpblVzZXIubG9jYXRpb247XG4gICAgICAgIGFsZXJ0LnJ1bGUgPSB7IC4uLkF1dGhlbnRpY2F0aW9uLmludmFsaWRMb2dpblVzZXIucnVsZSB9O1xuICAgICAgICBhbGVydC5ydWxlLmdyb3VwcyA9IFsuLi5BdXRoZW50aWNhdGlvbi5pbnZhbGlkTG9naW5Vc2VyLnJ1bGUuZ3JvdXBzXTtcbiAgICAgICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoQXV0aGVudGljYXRpb24uaW52YWxpZExvZ2luVXNlci5mdWxsX2xvZywgYWxlcnQpO1xuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICAgIGNhc2UgJ211bHRpcGxlQXV0aGVudGljYXRpb25GYWlsdXJlcyc6IHtcbiAgICAgICAgYWxlcnQubG9jYXRpb24gPSBBdXRoZW50aWNhdGlvbi5tdWx0aXBsZUF1dGhlbnRpY2F0aW9uRmFpbHVyZXMubG9jYXRpb247XG4gICAgICAgIGFsZXJ0LnJ1bGUgPSB7IC4uLkF1dGhlbnRpY2F0aW9uLm11bHRpcGxlQXV0aGVudGljYXRpb25GYWlsdXJlcy5ydWxlIH07XG4gICAgICAgIGFsZXJ0LnJ1bGUuZ3JvdXBzID0gWy4uLkF1dGhlbnRpY2F0aW9uLm11bHRpcGxlQXV0aGVudGljYXRpb25GYWlsdXJlcy5ydWxlLmdyb3Vwc107XG4gICAgICAgIGFsZXJ0LnJ1bGUuZnJlcXVlbmN5ID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDUsIDUwKTtcbiAgICAgICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoXG4gICAgICAgICAgQXV0aGVudGljYXRpb24ubXVsdGlwbGVBdXRoZW50aWNhdGlvbkZhaWx1cmVzLmZ1bGxfbG9nLFxuICAgICAgICAgIGFsZXJ0XG4gICAgICAgICk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAnd2luZG93c0ludmFsaWRMb2dpblBhc3N3b3JkJzoge1xuICAgICAgICBhbGVydC5sb2NhdGlvbiA9IEF1dGhlbnRpY2F0aW9uLndpbmRvd3NJbnZhbGlkTG9naW5QYXNzd29yZC5sb2NhdGlvbjtcbiAgICAgICAgYWxlcnQucnVsZSA9IHsgLi4uQXV0aGVudGljYXRpb24ud2luZG93c0ludmFsaWRMb2dpblBhc3N3b3JkLnJ1bGUgfTtcbiAgICAgICAgYWxlcnQucnVsZS5ncm91cHMgPSBbLi4uQXV0aGVudGljYXRpb24ud2luZG93c0ludmFsaWRMb2dpblBhc3N3b3JkLnJ1bGUuZ3JvdXBzXTtcbiAgICAgICAgYWxlcnQucnVsZS5mcmVxdWVuY3kgPSByYW5kb21JbnRlcnZhbEludGVnZXIoNSwgNTApO1xuICAgICAgICBhbGVydC5kYXRhLndpbiA9IHsgLi4uQXV0aGVudGljYXRpb24ud2luZG93c0ludmFsaWRMb2dpblBhc3N3b3JkLmRhdGFfd2luIH07XG4gICAgICAgIGFsZXJ0LmRhdGEud2luLmV2ZW50ZGF0YS5pcEFkZHJlc3MgPSByYW5kb21BcnJheUl0ZW0oSVBzKTtcbiAgICAgICAgYWxlcnQuZGF0YS53aW4uZXZlbnRkYXRhLmlwUG9ydCA9IHJhbmRvbUFycmF5SXRlbShQb3J0cyk7XG4gICAgICAgIGFsZXJ0LmRhdGEud2luLnN5c3RlbS5jb21wdXRlciA9IHJhbmRvbUFycmF5SXRlbShXaW5fSG9zdG5hbWVzKTtcbiAgICAgICAgYWxlcnQuZGF0YS53aW4uc3lzdGVtLmV2ZW50SUQgPSBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoMSwgNjAwKX1gO1xuICAgICAgICBhbGVydC5kYXRhLndpbi5zeXN0ZW0uZXZlbnRSZWNvcmRJRCA9IGAke3JhbmRvbUludGVydmFsSW50ZWdlcigxMDAwMCwgNTAwMDApfWA7XG4gICAgICAgIGFsZXJ0LmRhdGEud2luLnN5c3RlbS5wcm9jZXNzSUQgPSBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoMSwgMTIwMCl9YDtcbiAgICAgICAgYWxlcnQuZGF0YS53aW4uc3lzdGVtLnN5c3RlbVRpbWUgPSBhbGVydC50aW1lc3RhbXA7XG4gICAgICAgIGFsZXJ0LmRhdGEud2luLnN5c3RlbS5wcm9jZXNzSUQgPSBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoMSwgMTIwMCl9YDtcbiAgICAgICAgYWxlcnQuZGF0YS53aW4uc3lzdGVtLnRhc2sgPSBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoMSwgMTgwMCl9YDtcbiAgICAgICAgYWxlcnQuZGF0YS53aW4uc3lzdGVtLnRocmVhZElEID0gYCR7cmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDEsIDUwMCl9YDtcbiAgICAgICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoXG4gICAgICAgICAgQXV0aGVudGljYXRpb24ud2luZG93c0ludmFsaWRMb2dpblBhc3N3b3JkLmZ1bGxfbG9nLFxuICAgICAgICAgIGFsZXJ0XG4gICAgICAgICk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAndXNlckxvZ2luRmFpbGVkJzoge1xuICAgICAgICBhbGVydC5sb2NhdGlvbiA9IEF1dGhlbnRpY2F0aW9uLnVzZXJMb2dpbkZhaWxlZC5sb2NhdGlvbjtcbiAgICAgICAgYWxlcnQucnVsZSA9IHsgLi4uQXV0aGVudGljYXRpb24udXNlckxvZ2luRmFpbGVkLnJ1bGUgfTtcbiAgICAgICAgYWxlcnQucnVsZS5ncm91cHMgPSBbLi4uQXV0aGVudGljYXRpb24udXNlckxvZ2luRmFpbGVkLnJ1bGUuZ3JvdXBzXTtcbiAgICAgICAgYWxlcnQuZGF0YSA9IHtcbiAgICAgICAgICBzcmNpcDogcmFuZG9tQXJyYXlJdGVtKElQcyksXG4gICAgICAgICAgZHN0dXNlcjogcmFuZG9tQXJyYXlJdGVtKFVzZXJzKSxcbiAgICAgICAgICB1aWQ6IGAke3JhbmRvbUludGVydmFsSW50ZWdlcigwLCA1MCl9YCxcbiAgICAgICAgICBldWlkOiBgJHtyYW5kb21JbnRlcnZhbEludGVnZXIoMCwgNTApfWAsXG4gICAgICAgICAgdHR5OiAnc3NoJyxcbiAgICAgICAgfTtcbiAgICAgICAgYWxlcnQuZGVjb2RlciA9IHsgLi4uQXV0aGVudGljYXRpb24udXNlckxvZ2luRmFpbGVkLmRlY29kZXIgfTtcbiAgICAgICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoQXV0aGVudGljYXRpb24udXNlckxvZ2luRmFpbGVkLmZ1bGxfbG9nLCBhbGVydCk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAncGFzc3dvcmRDaGVja0ZhaWxlZCc6IHtcbiAgICAgICAgYWxlcnQubG9jYXRpb24gPSBBdXRoZW50aWNhdGlvbi5wYXNzd29yZENoZWNrRmFpbGVkLmxvY2F0aW9uO1xuICAgICAgICBhbGVydC5ydWxlID0geyAuLi5BdXRoZW50aWNhdGlvbi5wYXNzd29yZENoZWNrRmFpbGVkLnJ1bGUgfTtcbiAgICAgICAgYWxlcnQucnVsZS5ncm91cHMgPSBbLi4uQXV0aGVudGljYXRpb24ucGFzc3dvcmRDaGVja0ZhaWxlZC5ydWxlLmdyb3Vwc107XG4gICAgICAgIGFsZXJ0LmRhdGEgPSB7XG4gICAgICAgICAgc3JjdXNlcjogcmFuZG9tQXJyYXlJdGVtKFVzZXJzKSxcbiAgICAgICAgfTtcbiAgICAgICAgYWxlcnQucHJlZGVjb2Rlci5wcm9ncmFtX25hbWUgPSAndW5peF9jaGtwd2QnO1xuICAgICAgICBhbGVydC5kZWNvZGVyID0geyAuLi5BdXRoZW50aWNhdGlvbi5wYXNzd29yZENoZWNrRmFpbGVkLmRlY29kZXIgfTtcbiAgICAgICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoQXV0aGVudGljYXRpb24ucGFzc3dvcmRDaGVja0ZhaWxlZC5mdWxsX2xvZywgYWxlcnQpO1xuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICAgIGNhc2UgJ25vbkV4aXN0ZW50VXNlcic6IHtcbiAgICAgICAgYWxlcnQubG9jYXRpb24gPSBBdXRoZW50aWNhdGlvbi5ub25FeGlzdGVudFVzZXIubG9jYXRpb247XG4gICAgICAgIGFsZXJ0LnJ1bGUgPSB7IC4uLkF1dGhlbnRpY2F0aW9uLm5vbkV4aXN0ZW50VXNlci5ydWxlIH07XG4gICAgICAgIGFsZXJ0LnJ1bGUuZ3JvdXBzID0gWy4uLkF1dGhlbnRpY2F0aW9uLm5vbkV4aXN0ZW50VXNlci5ydWxlLmdyb3Vwc107XG4gICAgICAgIGFsZXJ0LmZ1bGxfbG9nID0gaW50ZXJwb2xhdGVBbGVydFByb3BzKEF1dGhlbnRpY2F0aW9uLm5vbkV4aXN0ZW50VXNlci5mdWxsX2xvZywgYWxlcnQpO1xuICAgICAgICBicmVhaztcbiAgICAgIH1cbiAgICAgIGNhc2UgJ2JydXRlRm9yY2VUcnlpbmdBY2Nlc3NTeXN0ZW0nOiB7XG4gICAgICAgIGFsZXJ0LmxvY2F0aW9uID0gQXV0aGVudGljYXRpb24uYnJ1dGVGb3JjZVRyeWluZ0FjY2Vzc1N5c3RlbS5sb2NhdGlvbjtcbiAgICAgICAgYWxlcnQucnVsZSA9IHsgLi4uQXV0aGVudGljYXRpb24uYnJ1dGVGb3JjZVRyeWluZ0FjY2Vzc1N5c3RlbS5ydWxlIH07XG4gICAgICAgIGFsZXJ0LnJ1bGUuZ3JvdXBzID0gWy4uLkF1dGhlbnRpY2F0aW9uLmJydXRlRm9yY2VUcnlpbmdBY2Nlc3NTeXN0ZW0ucnVsZS5ncm91cHNdO1xuICAgICAgICBhbGVydC5mdWxsX2xvZyA9IGludGVycG9sYXRlQWxlcnRQcm9wcyhcbiAgICAgICAgICBBdXRoZW50aWNhdGlvbi5icnV0ZUZvcmNlVHJ5aW5nQWNjZXNzU3lzdGVtLmZ1bGxfbG9nLFxuICAgICAgICAgIGFsZXJ0XG4gICAgICAgICk7XG4gICAgICAgIGJyZWFrO1xuICAgICAgfVxuICAgICAgY2FzZSAncmV2ZXJzZUxvb2NrdXBFcnJvcic6IHtcbiAgICAgICAgYWxlcnQubG9jYXRpb24gPSBBdXRoZW50aWNhdGlvbi5yZXZlcnNlTG9vY2t1cEVycm9yLmxvY2F0aW9uO1xuICAgICAgICBhbGVydC5ydWxlID0geyAuLi5BdXRoZW50aWNhdGlvbi5yZXZlcnNlTG9vY2t1cEVycm9yLnJ1bGUgfTtcbiAgICAgICAgYWxlcnQucnVsZS5ncm91cHMgPSBbLi4uQXV0aGVudGljYXRpb24ucmV2ZXJzZUxvb2NrdXBFcnJvci5ydWxlLmdyb3Vwc107XG4gICAgICAgIGFsZXJ0LmRhdGEgPSB7XG4gICAgICAgICAgc3JjaXA6IHJhbmRvbUFycmF5SXRlbShJUHMpLFxuICAgICAgICB9O1xuICAgICAgICBhbGVydC5mdWxsX2xvZyA9IGludGVycG9sYXRlQWxlcnRQcm9wcyhBdXRoZW50aWNhdGlvbi5yZXZlcnNlTG9vY2t1cEVycm9yLmZ1bGxfbG9nLCBhbGVydCk7XG4gICAgICB9XG4gICAgICBjYXNlICdpbnNlY3VyZUNvbm5lY3Rpb25BdHRlbXB0Jzoge1xuICAgICAgICBhbGVydC5sb2NhdGlvbiA9IEF1dGhlbnRpY2F0aW9uLmluc2VjdXJlQ29ubmVjdGlvbkF0dGVtcHQubG9jYXRpb247XG4gICAgICAgIGFsZXJ0LnJ1bGUgPSB7IC4uLkF1dGhlbnRpY2F0aW9uLmluc2VjdXJlQ29ubmVjdGlvbkF0dGVtcHQucnVsZSB9O1xuICAgICAgICBhbGVydC5ydWxlLmdyb3VwcyA9IFsuLi5BdXRoZW50aWNhdGlvbi5pbnNlY3VyZUNvbm5lY3Rpb25BdHRlbXB0LnJ1bGUuZ3JvdXBzXTtcbiAgICAgICAgYWxlcnQuZGF0YSA9IHtcbiAgICAgICAgICBzcmNpcDogcmFuZG9tQXJyYXlJdGVtKElQcyksXG4gICAgICAgICAgc3JjcG9ydDogcmFuZG9tQXJyYXlJdGVtKFBvcnRzKSxcbiAgICAgICAgfTtcbiAgICAgICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHMoXG4gICAgICAgICAgQXV0aGVudGljYXRpb24uaW5zZWN1cmVDb25uZWN0aW9uQXR0ZW1wdC5mdWxsX2xvZyxcbiAgICAgICAgICBhbGVydFxuICAgICAgICApO1xuICAgICAgfVxuICAgICAgY2FzZSAnYXV0aGVudGljYXRpb25TdWNjZXNzJzoge1xuICAgICAgICBhbGVydC5sb2NhdGlvbiA9IEF1dGhlbnRpY2F0aW9uLmF1dGhlbnRpY2F0aW9uU3VjY2Vzcy5sb2NhdGlvbjtcbiAgICAgICAgYWxlcnQucnVsZSA9IHsgLi4uQXV0aGVudGljYXRpb24uYXV0aGVudGljYXRpb25TdWNjZXNzLnJ1bGUgfTtcbiAgICAgICAgYWxlcnQucnVsZS5ncm91cHMgPSBbLi4uQXV0aGVudGljYXRpb24uYXV0aGVudGljYXRpb25TdWNjZXNzLnJ1bGUuZ3JvdXBzXTtcbiAgICAgICAgYWxlcnQuZGF0YSA9IHtcbiAgICAgICAgICBzcmNpcDogcmFuZG9tQXJyYXlJdGVtKElQcyksXG4gICAgICAgICAgc3JjcG9ydDogcmFuZG9tQXJyYXlJdGVtKFBvcnRzKSxcbiAgICAgICAgICBkc3R1c2VyOiByYW5kb21BcnJheUl0ZW0oVXNlcnMpLFxuICAgICAgICB9O1xuICAgICAgICBhbGVydC5mdWxsX2xvZyA9IGludGVycG9sYXRlQWxlcnRQcm9wcyhcbiAgICAgICAgICBBdXRoZW50aWNhdGlvbi5hdXRoZW50aWNhdGlvblN1Y2Nlc3MuZnVsbF9sb2csXG4gICAgICAgICAgYWxlcnRcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGNhc2UgJ21heGltdW1BdXRoZW50aWNhdGlvbkF0dGVtcHRzRXhjZWVkZWQnOiB7XG4gICAgICAgIGFsZXJ0LmxvY2F0aW9uID0gQXV0aGVudGljYXRpb24ubWF4aW11bUF1dGhlbnRpY2F0aW9uQXR0ZW1wdHNFeGNlZWRlZC5sb2NhdGlvbjtcbiAgICAgICAgYWxlcnQucnVsZSA9IHsgLi4uQXV0aGVudGljYXRpb24ubWF4aW11bUF1dGhlbnRpY2F0aW9uQXR0ZW1wdHNFeGNlZWRlZC5ydWxlIH07XG4gICAgICAgIGFsZXJ0LnJ1bGUuZ3JvdXBzID0gWy4uLkF1dGhlbnRpY2F0aW9uLm1heGltdW1BdXRoZW50aWNhdGlvbkF0dGVtcHRzRXhjZWVkZWQucnVsZS5ncm91cHNdO1xuICAgICAgICBhbGVydC5kYXRhID0ge1xuICAgICAgICAgIHNyY2lwOiByYW5kb21BcnJheUl0ZW0oSVBzKSxcbiAgICAgICAgICBzcmNwb3J0OiByYW5kb21BcnJheUl0ZW0oUG9ydHMpLFxuICAgICAgICAgIGRzdHVzZXI6IHJhbmRvbUFycmF5SXRlbShVc2VycyksXG4gICAgICAgIH07XG4gICAgICAgIGFsZXJ0LmZ1bGxfbG9nID0gaW50ZXJwb2xhdGVBbGVydFByb3BzKFxuICAgICAgICAgIEF1dGhlbnRpY2F0aW9uLm1heGltdW1BdXRoZW50aWNhdGlvbkF0dGVtcHRzRXhjZWVkZWQuZnVsbF9sb2csXG4gICAgICAgICAgYWxlcnRcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGRlZmF1bHQ6IHtcbiAgICAgIH1cbiAgICB9XG4gICAgYWxlcnQucnVsZS5maXJlZHRpbWVzID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDIsIDE1KTtcbiAgICBhbGVydC5ydWxlLnRzYyA9IFtyYW5kb21BcnJheUl0ZW0odHNjKV07XG4gIH1cblxuICBpZiAocGFyYW1zLnNzaCkge1xuICAgIGFsZXJ0LmRhdGEgPSB7XG4gICAgICBzcmNpcDogcmFuZG9tQXJyYXlJdGVtKElQcyksXG4gICAgICBzcmN1c2VyOiByYW5kb21BcnJheUl0ZW0oVXNlcnMpLFxuICAgICAgc3JjcG9ydDogcmFuZG9tQXJyYXlJdGVtKFBvcnRzKSxcbiAgICB9O1xuICAgIGFsZXJ0Lkdlb0xvY2F0aW9uID0gcmFuZG9tQXJyYXlJdGVtKEdlb0xvY2F0aW9uKTtcbiAgICBhbGVydC5kZWNvZGVyID0ge1xuICAgICAgbmFtZTogJ3NzaGQnLFxuICAgICAgcGFyZW50OiAnc3NoZCcsXG4gICAgfTtcbiAgICBhbGVydC5pbnB1dCA9IHtcbiAgICAgIHR5cGU6ICdsb2cnLFxuICAgIH07XG4gICAgYWxlcnQucHJlZGVjb2RlciA9IHtcbiAgICAgIHByb2dyYW1fbmFtZTogJ3NzaGQnLFxuICAgICAgdGltZXN0YW1wOiBmb3JtYXREYXRlKG5ldyBEYXRlKGFsZXJ0LnRpbWVzdGFtcCksICdOIEQgaDptOnMnKSxcbiAgICAgIGhvc3RuYW1lOiBhbGVydC5tYW5hZ2VyLm5hbWUsXG4gICAgfTtcbiAgICBjb25zdCB0eXBlQWxlcnQgPSByYW5kb21BcnJheUl0ZW0oU1NILmRhdGEpO1xuICAgIGFsZXJ0LmxvY2F0aW9uID0gdHlwZUFsZXJ0LmxvY2F0aW9uO1xuICAgIGFsZXJ0LnJ1bGUgPSB7IC4uLnR5cGVBbGVydC5ydWxlIH07XG4gICAgYWxlcnQucnVsZS5ncm91cHMgPSBbLi4udHlwZUFsZXJ0LnJ1bGUuZ3JvdXBzXTtcbiAgICBhbGVydC5ydWxlLmZpcmVkdGltZXMgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMSwgMTUpO1xuICAgIGFsZXJ0LmZ1bGxfbG9nID0gaW50ZXJwb2xhdGVBbGVydFByb3BzKHR5cGVBbGVydC5mdWxsX2xvZywgYWxlcnQpO1xuICB9XG5cbiAgaWYgKHBhcmFtcy53aW5kb3dzKSB7XG4gICAgYWxlcnQucnVsZS5ncm91cHMucHVzaCgnd2luZG93cycpO1xuICAgIGlmIChwYXJhbXMud2luZG93cy5zZXJ2aWNlX2NvbnRyb2xfbWFuYWdlcikge1xuICAgICAgYWxlcnQucHJlZGVjb2RlciA9IHtcbiAgICAgICAgcHJvZ3JhbV9uYW1lOiAnV2luRXZ0TG9nJyxcbiAgICAgICAgdGltZXN0YW1wOiAnMjAyMCBBcHIgMTcgMDU6NTk6MDUnLFxuICAgICAgfTtcbiAgICAgIGFsZXJ0LmlucHV0ID0ge1xuICAgICAgICB0eXBlOiAnbG9nJyxcbiAgICAgIH07XG4gICAgICBhbGVydC5kYXRhID0ge1xuICAgICAgICBleHRyYV9kYXRhOiAnU2VydmljZSBDb250cm9sIE1hbmFnZXInLFxuICAgICAgICBkc3R1c2VyOiAnU1lTVEVNJyxcbiAgICAgICAgc3lzdGVtX25hbWU6IHJhbmRvbUFycmF5SXRlbShXaW5fSG9zdG5hbWVzKSxcbiAgICAgICAgaWQ6ICc3MDQwJyxcbiAgICAgICAgdHlwZTogJ3R5cGUnLFxuICAgICAgICBzdGF0dXM6ICdJTkZPUk1BVElPTicsXG4gICAgICB9O1xuICAgICAgYWxlcnQucnVsZS5kZXNjcmlwdGlvbiA9ICdXaW5kb3dzOiBTZXJ2aWNlIHN0YXJ0dXAgdHlwZSB3YXMgY2hhbmdlZC4nO1xuICAgICAgYWxlcnQucnVsZS5maXJlZHRpbWVzID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDEsIDIwKTtcbiAgICAgIGFsZXJ0LnJ1bGUubWFpbCA9IGZhbHNlO1xuICAgICAgYWxlcnQucnVsZS5sZXZlbCA9IDM7XG4gICAgICBhbGVydC5ydWxlLmdyb3Vwcy5wdXNoKCd3aW5kb3dzJywgJ3BvbGljeV9jaGFuZ2VkJyk7XG4gICAgICBhbGVydC5ydWxlLnBjaSA9IFsnMTAuNiddO1xuICAgICAgYWxlcnQucnVsZS5oaXBhYSA9IFsnMTY0LjMxMi5iJ107XG4gICAgICBhbGVydC5ydWxlLmdkcHIgPSBbJ0lWXzM1LjcuZCddO1xuICAgICAgYWxlcnQucnVsZS5uaXN0XzgwMF81MyA9IFsnQVUuNiddO1xuICAgICAgYWxlcnQucnVsZS5pbmZvID0gJ1RoaXMgZG9lcyBub3QgYXBwZWFyIHRvIGJlIGxvZ2dlZCBvbiBXaW5kb3dzIDIwMDAuJztcbiAgICAgIGFsZXJ0LmxvY2F0aW9uID0gJ1dpbkV2dExvZyc7XG4gICAgICBhbGVydC5kZWNvZGVyID0ge1xuICAgICAgICBwYXJlbnQ6ICd3aW5kb3dzJyxcbiAgICAgICAgbmFtZTogJ3dpbmRvd3MnLFxuICAgICAgfTtcbiAgICAgIGFsZXJ0LmZ1bGxfbG9nID0gYDIwMjAgQXByIDE3IDA1OjU5OjA1IFdpbkV2dExvZzogdHlwZTogSU5GT1JNQVRJT04oNzA0MCk6IFNlcnZpY2UgQ29udHJvbCBNYW5hZ2VyOiBTWVNURU06IE5UIEFVVEhPUklUWTogJHthbGVydC5kYXRhLnN5c3RlbV9uYW1lfTogQmFja2dyb3VuZCBJbnRlbGxpZ2VudCBUcmFuc2ZlciBTZXJ2aWNlIGF1dG8gc3RhcnQgZGVtYW5kIHN0YXJ0IEJJVFMgYDsgLy9UT0RPOiBkYXRlXG4gICAgICBhbGVydC5pZCA9IDE4MTQ1O1xuICAgICAgYWxlcnQuZmllbGRzID0ge1xuICAgICAgICB0aW1lc3RhbXA6IGFsZXJ0LnRpbWVzdGFtcCxcbiAgICAgIH07XG4gICAgfVxuICB9XG5cbiAgaWYgKHBhcmFtcy5hcGFjaGUpIHtcbiAgICBjb25zdCB0eXBlQWxlcnQgPSB7IC4uLkFwYWNoZS5kYXRhWzBdIH07IC8vIHRoZXJlIGlzIG9ubHkgb25lIHR5cGUgYWxlcnQgaW4gZGF0YSBhcnJheSBhdCB0aGUgbW9tZW50LiBSYW5kb21pemUgaWYgYWRkIG1vcmUgdHlwZSBvZiBhbGVydHMgdG8gZGF0YSBhcnJheVxuICAgIGFsZXJ0LmRhdGEgPSB7XG4gICAgICBzcmNpcDogcmFuZG9tQXJyYXlJdGVtKElQcyksXG4gICAgICBzcmNwb3J0OiByYW5kb21BcnJheUl0ZW0oUG9ydHMpLFxuICAgICAgaWQ6IGBBSCR7cmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDEwMDAwLCA5OTk5OSl9YCxcbiAgICB9O1xuICAgIGFsZXJ0Lkdlb0xvY2F0aW9uID0geyAuLi5yYW5kb21BcnJheUl0ZW0oR2VvTG9jYXRpb24pIH07XG4gICAgYWxlcnQucnVsZSA9IHsgLi4udHlwZUFsZXJ0LnJ1bGUgfTtcbiAgICBhbGVydC5ydWxlLmZpcmVkdGltZXMgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMiwgMTApO1xuICAgIGFsZXJ0LmlucHV0ID0geyB0eXBlOiAnbG9nJyB9O1xuICAgIGFsZXJ0LmxvY2F0aW9uID0gQXBhY2hlLmxvY2F0aW9uO1xuICAgIGFsZXJ0LmRlY29kZXIgPSB7IC4uLkFwYWNoZS5kZWNvZGVyIH07XG5cbiAgICBhbGVydC5mdWxsX2xvZyA9IGludGVycG9sYXRlQWxlcnRQcm9wcyh0eXBlQWxlcnQuZnVsbF9sb2csIGFsZXJ0LCB7XG4gICAgICBfdGltZXN0YW1wX2FwYWNoZTogZm9ybWF0RGF0ZShuZXcgRGF0ZShhbGVydC50aW1lc3RhbXApLCAnRSBOIEQgaDptOnMubCBZJyksXG4gICAgICBfcGlfaWQ6IHJhbmRvbUludGVydmFsSW50ZWdlcigxMDAwMCwgMzAwMDApLFxuICAgIH0pO1xuICB9XG5cbiAgaWYgKHBhcmFtcy53ZWIpIHtcbiAgICBhbGVydC5pbnB1dCA9IHtcbiAgICAgIHR5cGU6ICdsb2cnLFxuICAgIH07XG4gICAgYWxlcnQuZGF0YSA9IHtcbiAgICAgIHByb3RvY29sOiAnR0VUJyxcbiAgICAgIHNyY2lwOiByYW5kb21BcnJheUl0ZW0oSVBzKSxcbiAgICAgIGlkOiAnNDA0JyxcbiAgICAgIHVybDogcmFuZG9tQXJyYXlJdGVtKFdlYi51cmxzKSxcbiAgICB9O1xuICAgIGFsZXJ0Lkdlb0xvY2F0aW9uID0geyAuLi5yYW5kb21BcnJheUl0ZW0oR2VvTG9jYXRpb24pIH07XG5cbiAgICBjb25zdCB0eXBlQWxlcnQgPSByYW5kb21BcnJheUl0ZW0oV2ViLmRhdGEpO1xuICAgIGNvbnN0IHVzZXJBZ2VudCA9IHJhbmRvbUFycmF5SXRlbShXZWIudXNlckFnZW50cyk7XG4gICAgYWxlcnQucnVsZSA9IHsgLi4udHlwZUFsZXJ0LnJ1bGUgfTtcbiAgICBhbGVydC5ydWxlLmZpcmVkdGltZXMgPSByYW5kb21JbnRlcnZhbEludGVnZXIoMSwgMTApO1xuICAgIGFsZXJ0LmRlY29kZXIgPSB7IC4uLnR5cGVBbGVydC5kZWNvZGVyIH07XG4gICAgYWxlcnQubG9jYXRpb24gPSB0eXBlQWxlcnQubG9jYXRpb247XG4gICAgYWxlcnQuZnVsbF9sb2cgPSBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHModHlwZUFsZXJ0LmZ1bGxfbG9nLCBhbGVydCwge1xuICAgICAgX3VzZXJfYWdlbnQ6IHVzZXJBZ2VudCxcbiAgICAgIF9kYXRlOiBmb3JtYXREYXRlKG5ldyBEYXRlKGFsZXJ0LnRpbWVzdGFtcCksICdEL04vWTpoOm06cyArMDAwMCcpLFxuICAgIH0pO1xuICAgIGlmICh0eXBlQWxlcnQucHJldmlvdXNfb3V0cHV0KSB7XG4gICAgICBjb25zdCBwcmV2aW91c091dHB1dCA9IFtdO1xuICAgICAgY29uc3QgYmVmb3JlU2Vjb25kcyA9IDQ7XG4gICAgICBmb3IgKGxldCBpID0gYmVmb3JlU2Vjb25kczsgaSA+IDA7IGktLSkge1xuICAgICAgICBjb25zdCBiZWZvcmVEYXRlID0gbmV3IERhdGUobmV3IERhdGUoYWxlcnQudGltZXN0YW1wKSAtICgyICsgaSkgKiAxMDAwKTtcbiAgICAgICAgcHJldmlvdXNPdXRwdXQucHVzaChcbiAgICAgICAgICBpbnRlcnBvbGF0ZUFsZXJ0UHJvcHModHlwZUFsZXJ0LmZ1bGxfbG9nLCBhbGVydCwge1xuICAgICAgICAgICAgX3VzZXJfYWdlbnQ6IHVzZXJBZ2VudCxcbiAgICAgICAgICAgIF9kYXRlOiBmb3JtYXREYXRlKG5ldyBEYXRlKGJlZm9yZURhdGUpLCAnRC9OL1k6aDptOnMgKzAwMDAnKSxcbiAgICAgICAgICB9KVxuICAgICAgICApO1xuICAgICAgfVxuICAgICAgYWxlcnQucHJldmlvdXNfb3V0cHV0ID0gcHJldmlvdXNPdXRwdXQuam9pbignXFxuJyk7XG4gICAgfVxuICB9XG5cbiAgaWYgKHBhcmFtcy5naXRodWIpe1xuICAgIGFsZXJ0LmxvY2F0aW9uID0gR2l0SHViLkxPQ0FUSU9OO1xuICAgIGFsZXJ0LmRlY29kZXIgPSBHaXRIdWIuREVDT0RFUjtcbiAgICBjb25zdCBhbGVydFR5cGUgPSByYW5kb21BcnJheUl0ZW0oR2l0SHViLkFMRVJUX1RZUEVTKTtcbiAgICBjb25zdCBhY3RvciA9IHJhbmRvbUFycmF5SXRlbShHaXRIdWIuQUNUT1JTKTtcbiAgICBhbGVydC5kYXRhID0ge1xuICAgICAgZ2l0aHViIDogeyAuLi5hbGVydFR5cGUuZGF0YS5naXRodWIgfVxuICAgIH07XG4gICAgYWxlcnQuZGF0YS5naXRodWIub3JnID0gcmFuZG9tQXJyYXlJdGVtKEdpdEh1Yi5PUkdBTklaQVRJT05fTkFNRVMpO1xuICAgIGFsZXJ0LmRhdGEuZ2l0aHViLnJlcG8gJiYgKGFsZXJ0LmRhdGEuZ2l0aHViLnJlcG8gPSBgJHthbGVydC5kYXRhLmdpdGh1Yi5vcmd9LyR7cmFuZG9tQXJyYXlJdGVtKEdpdEh1Yi5SRVBPU0lUT1JZX05BTUVTKX1gKTtcbiAgICBhbGVydC5kYXRhLmdpdGh1Yi5yZXBvc2l0b3J5ICYmIChhbGVydC5kYXRhLmdpdGh1Yi5yZXBvc2l0b3J5ID0gYCR7YWxlcnQuZGF0YS5naXRodWIub3JnfS8ke3JhbmRvbUFycmF5SXRlbShHaXRIdWIuUkVQT1NJVE9SWV9OQU1FUyl9YCk7XG4gICAgYWxlcnQuZGF0YS5naXRodWIuYWN0b3IgPSBhY3Rvci5uYW1lO1xuICAgIGFsZXJ0LmRhdGEuZ2l0aHViLmFjdG9yX2xvY2F0aW9uICYmIGFsZXJ0LmRhdGEuZ2l0aHViLmFjdG9yX2xvY2F0aW9uLmNvdW50cnlfY29kZSAmJiAoYWxlcnQuZGF0YS5naXRodWIuYWN0b3JfbG9jYXRpb24uY291bnRyeV9jb2RlID0gYWN0b3IuY291bnRyeV9jb2RlKTtcbiAgICBhbGVydC5kYXRhLmdpdGh1Yi51c2VyICYmIChhbGVydC5kYXRhLmdpdGh1Yi51c2VyID0gcmFuZG9tQXJyYXlJdGVtKEdpdEh1Yi5VU0VSX05BTUVTKSk7XG4gICAgYWxlcnQuZGF0YS5naXRodWIuY29uZmlnICYmIGFsZXJ0LmRhdGEuZ2l0aHViLmNvbmZpZy51cmwgJiYgKGFsZXJ0LmRhdGEuZ2l0aHViLmNvbmZpZy51cmwgPSByYW5kb21BcnJheUl0ZW0oR2l0SHViLlNFUlZFUl9BRERSRVNTX1dFQkhPT0spKTtcbiAgICBhbGVydC5kYXRhLmdpdGh1YlsnQHRpbWVzdGFtcCddID0gYWxlcnQudGltZXN0YW1wO1xuICAgIGFsZXJ0LmRhdGEuZ2l0aHViLmNyZWF0ZWRfYXQgJiYgKGFsZXJ0LmRhdGEuZ2l0aHViLmNyZWF0ZWRfYXQgPSBhbGVydC50aW1lc3RhbXApO1xuICAgIGFsZXJ0LnJ1bGUgPSB7XG4gICAgICAuLi5hbGVydFR5cGUucnVsZVxuICAgIH07XG4gIH1cbiAgXG4gIHJldHVybiBhbGVydDtcbn1cblxuLyoqXG4gKiBHZXQgYSByYW5kb20gYXJyYXkgd2l0aCB1bmlxdWUgdmFsdWVzXG4gKiBAcGFyYW0ge1tdfSBhcnJheSBBcnJheSB0byBleHRyYWN0IHRoZSB2YWx1ZXNcbiAqIEBwYXJhbSB7Kn0gcmFuZG9tTWF4UmVwZXRpdGlvbnMgTnVtYmVyIG1heCBvZiByYW5kb20gZXh0cmFjdGlvbnNcbiAqIEBwYXJhbSB7ZnVuY3Rpb259IHNvcnQgRnVuY2l0b24gdG8gc2VvcnQgZWxlbWVudHNcbiAqIEByZXR1cm4geyp9IEFycmF5IHdpdGggcmFuZG9tIHZhbHVlcyBleHRyYWN0ZWQgb2YgcGFyYW1hdGVyIGFycmF5IHBhc3NlZFxuICovXG5mdW5jdGlvbiByYW5kb21VbmlxdWVWYWx1ZXNGcm9tQXJyYXkoYXJyYXksIHJhbmRvbU1heFJlcGV0aXRpb25zID0gMSwgc29ydCkge1xuICBjb25zdCByZXBldGl0aW9ucyA9IHJhbmRvbUludGVydmFsSW50ZWdlcigxLCByYW5kb21NYXhSZXBldGl0aW9ucyk7XG4gIGNvbnN0IHNldCA9IG5ldyBTZXQoKTtcbiAgZm9yIChsZXQgaSA9IDA7IGkgPCByZXBldGl0aW9uczsgaSsrKSB7XG4gICAgc2V0LmFkZChhcnJheVtyYW5kb21JbnRlcnZhbEludGVnZXIoMCwgYXJyYXkubGVuZ3RoIC0gMSldKTtcbiAgfVxuICByZXR1cm4gc29ydCA/IEFycmF5LmZyb20oc2V0KS5zb3J0KHNvcnQpIDogQXJyYXkuZnJvbShzZXQpO1xufVxuXG4vKipcbiAqIEdldCBhIGludGVnZXIgd2l0aGluIGEgcmFuZ2VcbiAqIEBwYXJhbSB7bnVtYmVyfSBtaW4gLSBNaW5pbXVtIGxpbWl0XG4gKiBAcGFyYW0ge251bWJlcn0gbWF4IC0gTWF4aW11bSBsaW1pdFxuICogQHJldHVybnMge251bWJlcn0gLSBSYW5kb21pemVkIG51bWJlciBpbiBpbnRlcnZhbFxuICovXG5mdW5jdGlvbiByYW5kb21JbnRlcnZhbEludGVnZXIobWluLCBtYXgpIHtcbiAgcmV0dXJuIE1hdGguZmxvb3IoTWF0aC5yYW5kb20oKSAqIChtYXggLSAobWluIC0gMSkpKSArIG1pbjtcbn1cblxuLyoqXG4gKiBHZW5lcmF0ZSByYW5kb20gYWxlcnRzXG4gKiBAcGFyYW0geyp9IHBhcmFtc1xuICogQHBhcmFtIHtudW1iZXJ9IG51bUFsZXJ0cyAtIERlZmluZSBudW1iZXIgb2YgYWxlcnRzXG4gKiBAcmV0dXJuIHsqfSAtIFJhbmRvbSBnZW5lcmF0ZWQgYWxlcnRzIGRlZmluZWQgd2l0aCBwYXJhbXNcbiAqL1xuZnVuY3Rpb24gZ2VuZXJhdGVBbGVydHMocGFyYW1zLCBudW1BbGVydHMgPSAxKSB7XG4gIGNvbnN0IGFsZXJ0cyA9IFtdO1xuICBmb3IgKGxldCBpID0gMDsgaSA8IG51bUFsZXJ0czsgaSsrKSB7XG4gICAgYWxlcnRzLnB1c2goZ2VuZXJhdGVBbGVydChwYXJhbXMpKTtcbiAgfVxuICByZXR1cm4gYWxlcnRzO1xufVxuXG4vKipcbiAqIEdldCBhIHJhbmRvbSBEYXRlIGluIHJhbmdlKDcgZGF5cyBhZ28gLSBub3cpXG4gKiBAcmV0dXJucyB7ZGF0ZX0gLSBSYW5kb20gZGF0ZSBpbiByYW5nZSAoNyBkYXlzIGFnbyAtIG5vdylcbiAqL1xuZnVuY3Rpb24gcmFuZG9tRGF0ZShpbmYsIHN1cCkge1xuICBjb25zdCBub3dUaW1lc3RhbXAgPSBEYXRlLm5vdygpO1xuICBjb25zdCB0aW1lID0gcmFuZG9tSW50ZXJ2YWxJbnRlZ2VyKDAsIDYwNDgwMDAwMCk7IC8vIFJhbmRvbSA3IGRheXMgaW4gbWlsaXNlY29uZHNcblxuICBjb25zdCB1bml4X3RpbWVzdGFtcCA9IG5vd1RpbWVzdGFtcCAtIHRpbWU7IC8vIExhc3QgNyBkYXlzIGZyb20gbm93XG5cbiAgY29uc3QgbGFzdFdlZWsgPSBuZXcgRGF0ZSh1bml4X3RpbWVzdGFtcCk7XG4gIHJldHVybiBmb3JtYXREYXRlKGxhc3RXZWVrLCAnWS1NLURUaDptOnMubCswMDAwJyk7XG59XG5cbmNvbnN0IGZvcm1hdHRlck51bWJlciA9IChudW1iZXIsIHplcm9zID0gMCkgPT4gKCcwJy5yZXBlYXQoemVyb3MpICsgYCR7bnVtYmVyfWApLnNsaWNlKC16ZXJvcyk7XG5jb25zdCBtb250aE5hbWVzID0ge1xuICBsb25nOiBbXG4gICAgJ0phbnVhcnknLFxuICAgICdGZWJydWFyeScsXG4gICAgJ01hcmNoJyxcbiAgICAnQXByaWwnLFxuICAgICdNYXknLFxuICAgICdKdW5lJyxcbiAgICAnSnVseScsXG4gICAgJ0F1Z3VzdCcsXG4gICAgJ1NlcHRlbWJlcicsXG4gICAgJ09jdG9iZXInLFxuICAgICdOb3ZlbWJlcicsXG4gICAgJ0RlY2VtYmVyJyxcbiAgXSxcbiAgc2hvcnQ6IFsnSmFuJywgJ0ZlYicsICdNYXInLCAnQXByJywgJ01heScsICdKdW4nLCAnSnVsJywgJ0F1ZycsICdTZXAnLCAnT2N0JywgJ05vdicsICdEZWMnXSxcbn07XG5cbmNvbnN0IGRheU5hbWVzID0ge1xuICBsb25nOiBbJ1N1bmRheScsICdNb25kYXknLCAnVHVlc2RheScsICdXZWRuZXNkYXknLCAnVGh1cnNkYXknLCAnRnJpZGF5JywgJ1NhdHVyZGF5J10sXG4gIHNob3J0OiBbJ1N1bicsICdNb24nLCAnVHVlJywgJ1dlZCcsICdUaHUnLCAnRnJpJywgJ1NhdCddLFxufTtcblxuZnVuY3Rpb24gZm9ybWF0RGF0ZShkYXRlLCBmb3JtYXQpIHtcbiAgLy8gSXQgY291bGQgdXNlIFwibW9tZW50XCIgbGlicmFyeSB0byBmb3JtYXQgc3RyaW5ncyB0b29cbiAgY29uc3QgdG9rZW5zID0ge1xuICAgIEQ6IChkKSA9PiBmb3JtYXR0ZXJOdW1iZXIoZC5nZXREYXRlKCksIDIpLCAvLyAwMS0zMVxuICAgIEE6IChkKSA9PiBkYXlOYW1lcy5sb25nW2QuZ2V0RGF5KCldLCAvLyAnU3VuZGF5JywgJ01vbmRheScsICdUdWVzZGF5JywgJ1dlZG5lc2RheScsICdUaHVyc2RheScsICdGcmlkYXknLCAnU2F0dXJkYXknXG4gICAgRTogKGQpID0+IGRheU5hbWVzLnNob3J0W2QuZ2V0RGF5KCldLCAvLyAnU3VuJywgJ01vbicsICdUdWUnLCAnV2VkJywgJ1RodScsICdGcmknLCAnU2F0J1xuICAgIE06IChkKSA9PiBmb3JtYXR0ZXJOdW1iZXIoZC5nZXRNb250aCgpICsgMSwgMiksIC8vIDAxLTEyXG4gICAgSjogKGQpID0+IG1vbnRoTmFtZXMubG9uZ1tkLmdldE1vbnRoKCldLCAvLyAnSmFudWFyeScsICdGZWJydWFyeScsICdNYXJjaCcsICdBcHJpbCcsICdNYXknLCAnSnVuZScsICdKdWx5JywgJ0F1Z3VzdCcsICdTZXB0ZW1iZXInLCAnT2N0b2JlcicsICdOb3ZlbWJlcicsICdEZWNlbWJlcidcbiAgICBOOiAoZCkgPT4gbW9udGhOYW1lcy5zaG9ydFtkLmdldE1vbnRoKCldLCAvLyAnSmFuJywgJ0ZlYicsICdNYXInLCAnQXByJywgJ01heScsICdKdW4nLCAnSnVsJywgJ0F1ZycsICdTZXAnLCAnT2N0JywgJ05vdicsICdEZWMnXG4gICAgWTogKGQpID0+IGQuZ2V0RnVsbFllYXIoKSwgLy8gMjAyMFxuICAgIGg6IChkKSA9PiBmb3JtYXR0ZXJOdW1iZXIoZC5nZXRIb3VycygpLCAyKSwgLy8gMDAtMjNcbiAgICBtOiAoZCkgPT4gZm9ybWF0dGVyTnVtYmVyKGQuZ2V0TWludXRlcygpLCAyKSwgLy8gMDAtNTlcbiAgICBzOiAoZCkgPT4gZm9ybWF0dGVyTnVtYmVyKGQuZ2V0U2Vjb25kcygpLCAyKSwgLy8gMDAtNTlcbiAgICBsOiAoZCkgPT4gZm9ybWF0dGVyTnVtYmVyKGQuZ2V0TWlsbGlzZWNvbmRzKCksIDMpLCAvLyAwMDAtOTk5XG4gIH07XG5cbiAgcmV0dXJuIGZvcm1hdC5zcGxpdCgnJykucmVkdWNlKChhY2N1bSwgdG9rZW4pID0+IHtcbiAgICBpZiAodG9rZW5zW3Rva2VuXSkge1xuICAgICAgcmV0dXJuIGFjY3VtICsgdG9rZW5zW3Rva2VuXShkYXRlKTtcbiAgICB9XG4gICAgcmV0dXJuIGFjY3VtICsgdG9rZW47XG4gIH0sICcnKTtcbn1cblxuLyoqXG4gKlxuICogQHBhcmFtIHtzdHJpbmd9IHN0ciBTdHJpbmcgd2l0aCBpbnRlcnBvbGF0aW9uc1xuICogQHBhcmFtIHsqfSBhbGVydCBBbGVydCBvYmplY3RcbiAqIEBwYXJhbSB7Kn0gZXh0cmEgRXh0cmEgcGFyYW1ldGVycyB0byBpbnRlcnBvbGF0ZSB3aGF0IGFyZW4ndCBpbiBhbGVydCBvYmpldC4gT25seSBhZG1pdCBvbmUgbGV2ZWwgb2YgZGVwdGhcbiAqL1xuZnVuY3Rpb24gaW50ZXJwb2xhdGVBbGVydFByb3BzKHN0ciwgYWxlcnQsIGV4dHJhID0ge30pIHtcbiAgY29uc3QgbWF0Y2hlcyA9IHN0ci5tYXRjaCgveyhbXFx3XFwuX10rKX0vZyk7XG4gIHJldHVybiAoXG4gICAgKG1hdGNoZXMgJiZcbiAgICAgIG1hdGNoZXMucmVkdWNlKChhY2N1bSwgY3VyKSA9PiB7XG4gICAgICAgIGNvbnN0IG1hdGNoID0gY3VyLm1hdGNoKC97KFtcXHdcXC5fXSspfS8pO1xuICAgICAgICBjb25zdCBpdGVtcyA9IG1hdGNoWzFdLnNwbGl0KCcuJyk7XG4gICAgICAgIGNvbnN0IHZhbHVlID0gaXRlbXMucmVkdWNlKChhLCBjKSA9PiAoYSAmJiBhW2NdKSB8fCBleHRyYVtjXSB8fCB1bmRlZmluZWQsIGFsZXJ0KSB8fCBjdXI7XG4gICAgICAgIHJldHVybiBhY2N1bS5yZXBsYWNlKGN1ciwgdmFsdWUpO1xuICAgICAgfSwgc3RyKSkgfHxcbiAgICBzdHJcbiAgKTtcbn1cblxuLyoqXG4gKiBSZXR1cm4gYSByYW5kb20gcHJvYmFiaWxpdHlcbiAqIEBwYXJhbSB7bnVtYmVyfSBwcm9iYWJpbGl0eVxuICogQHBhcmFtIHtudW1iZXJbPTEwMF19IG1heGltdW1cbiAqL1xuZnVuY3Rpb24gcmFuZG9tUHJvYmFiaWxpdHkocHJvYmFiaWxpdHksIG1heGltdW0gPSAxMDApIHtcbiAgcmV0dXJuIHJhbmRvbUludGVydmFsSW50ZWdlcigwLCBtYXhpbXVtKSA8PSBwcm9iYWJpbGl0eTtcbn1cblxuZXhwb3J0IHsgZ2VuZXJhdGVBbGVydCwgZ2VuZXJhdGVBbGVydHMgfTtcbiJdfQ==