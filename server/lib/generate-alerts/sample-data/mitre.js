"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.arrayMitreRules = exports.arrayLocation = void 0;

/*
 * Wazuh app - Mitre sample alerts
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// Mitre
const arrayMitreRules = [{
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 504,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '500',
    match: 'Agent disconnected'
  },
  pci_dss: ['10.6.1', '10.2.6'],
  gpg13: ['10.1'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'AU.14', 'AU.5'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.8'],
  mitre: {
    tactic: ['Defense Evasion'],
    id: ['T1089'],
    technique: ['Disabling Security Tools']
  },
  groups: ['wazuh'],
  description: 'Ossec agent disconnected.'
}, {
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 505,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '500',
    match: 'Agent removed'
  },
  pci_dss: ['10.6.1', '10.2.6'],
  gpg13: ['10.1'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'AU.14', 'AU.5'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.8'],
  mitre: {
    tactic: ['Defense Evasion'],
    id: ['T1089'],
    technique: ['Disabling Security Tools']
  },
  groups: ['wazuh'],
  description: 'Ossec agent removed.'
}, {
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 518,
  level: 9,
  status: 'enabled',
  details: {
    if_sid: '514',
    match: 'Adware|Spyware'
  },
  gpg13: ['4.2'],
  gdpr: ['IV_35.7.d'],
  mitre: {
    tactic: ['Lateral Movement'],
    id: ['T1017'],
    technique: ['Application Deployment Software']
  },
  groups: ['rootcheck', 'wazuh'],
  description: 'Windows Adware/Spyware application found.'
}, {
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 550,
  level: 7,
  status: 'enabled',
  details: {
    category: 'wazuh',
    decoded_as: 'syscheck_integrity_changed'
  },
  pci_dss: ['11.5'],
  gpg13: ['4.11'],
  gdpr: ['II_5.1.f'],
  hipaa: ['164.312.c.1', '164.312.c.2'],
  nist_800_53: ['SI.7'],
  tsc: ['PI1.4', 'PI1.5', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1492'],
    technique: ['Stored Data Manipulation']
  },
  groups: ['syscheck', 'wazuh'],
  description: 'Integrity checksum changed.'
}, {
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 553,
  level: 7,
  status: 'enabled',
  details: {
    category: 'wazuh',
    decoded_as: 'syscheck_deleted'
  },
  pci_dss: ['11.5'],
  gpg13: ['4.11'],
  gdpr: ['II_5.1.f'],
  hipaa: ['164.312.c.1', '164.312.c.2'],
  nist_800_53: ['SI.7'],
  tsc: ['PI1.4', 'PI1.5', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Defense Evasion', 'Impact'],
    id: ['T1107', 'T1485'],
    technique: ['File Deletion', 'Data Destruction']
  },
  groups: ['syscheck', 'wazuh'],
  description: 'File deleted.'
}, {
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 592,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '500',
    match: '^ossec: File size reduced'
  },
  pci_dss: ['10.5.2', '11.4'],
  gpg13: ['10.1'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.9', 'SI.4'],
  tsc: ['CC6.1', 'CC7.2', 'CC7.3', 'CC6.8'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1492'],
    technique: ['Stored Data Manipulation']
  },
  groups: ['attacks', 'wazuh'],
  description: 'Log file size reduced.'
}, {
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 593,
  level: 9,
  status: 'enabled',
  details: {
    if_sid: '500',
    match: '^ossec: Event log cleared'
  },
  pci_dss: ['10.5.2'],
  gpg13: ['10.1'],
  gdpr: ['II_5.1.f', 'IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.9'],
  tsc: ['CC6.1', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Defense Evasion'],
    id: ['T1070'],
    technique: ['Indicator Removal on Host']
  },
  groups: ['logs_cleared', 'wazuh'],
  description: 'Microsoft Event log cleared.'
}, {
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 594,
  level: 5,
  status: 'enabled',
  details: {
    category: 'wazuh',
    if_sid: '550',
    hostname: 'syscheck-registry'
  },
  pci_dss: ['11.5'],
  gpg13: ['4.13'],
  gdpr: ['II_5.1.f'],
  hipaa: ['164.312.c.1', '164.312.c.2'],
  nist_800_53: ['SI.7'],
  tsc: ['PI1.4', 'PI1.5', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1492'],
    technique: ['Stored Data Manipulation']
  },
  groups: ['syscheck', 'wazuh'],
  description: 'Registry Integrity Checksum Changed'
}, {
  filename: '0015-ossec_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 597,
  level: 5,
  status: 'enabled',
  details: {
    category: 'wazuh',
    if_sid: '553',
    hostname: 'syscheck-registry'
  },
  pci_dss: ['11.5'],
  gpg13: ['4.13'],
  gdpr: ['II_5.1.f'],
  hipaa: ['164.312.c.1', '164.312.c.2'],
  nist_800_53: ['SI.7'],
  tsc: ['PI1.4', 'PI1.5', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Defense Evasion', 'Impact'],
    id: ['T1107', 'T1485'],
    technique: ['File Deletion', 'Data Destruction']
  },
  groups: ['syscheck', 'wazuh'],
  description: 'Registry Entry Deleted.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 1003,
  level: 13,
  status: 'enabled',
  details: {
    maxsize: '1025',
    noalert: '1'
  },
  gpg13: ['4.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['syslog', 'errors'],
  description: 'Non standard syslog message (size too large).'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2301,
  level: 10,
  status: 'enabled',
  details: {
    match: '^Deactivating service '
  },
  pci_dss: ['10.6.1'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['syslog', 'xinetd'],
  description: 'xinetd: Excessive number connections to a service.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2502,
  level: 10,
  status: 'enabled',
  details: {
    match: 'more authentication failures;|REPEATED login failures'
  },
  pci_dss: ['10.2.4', '10.2.5'],
  gpg13: ['7.8'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Credential Access'],
    id: ['T1110'],
    technique: ['Brute Force']
  },
  groups: ['authentication_failed', 'syslog', 'access_control'],
  description: 'syslog: User missed the password more than one time'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2503,
  level: 5,
  status: 'enabled',
  details: {
    regex: ['^refused connect from|', '^libwrap refused connection|', 'Connection from S+ denied']
  },
  pci_dss: ['10.2.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Command and Control'],
    id: ['T1095'],
    technique: ['Standard Non-Application Layer Protocol']
  },
  groups: ['access_denied', 'syslog', 'access_control'],
  description: 'syslog: Connection blocked by Tcp Wrappers.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2504,
  level: 9,
  status: 'enabled',
  details: {
    match: 'ILLEGAL ROOT LOGIN|ROOT LOGIN REFUSED'
  },
  pci_dss: ['10.2.4', '10.2.5', '10.2.2'],
  gpg13: ['7.8'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7', 'AC.6'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['invalid_login', 'syslog', 'access_control'],
  description: 'syslog: Illegal root login.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2551,
  level: 10,
  status: 'enabled',
  details: {
    if_sid: '2550',
    regex: '^Connection from S+ on illegal port$'
  },
  pci_dss: ['10.6.1'],
  gpg13: ['7.1'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Discovery'],
    id: ['T1046'],
    technique: ['Network Service Scanning']
  },
  groups: ['connection_attempt', 'syslog', 'access_control'],
  description: 'Connection to rshd from unprivileged port. Possible network scan.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2833,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '2832',
    match: '^(root)'
  },
  pci_dss: ['10.2.7', '10.6.1', '10.2.2'],
  gpg13: ['4.13'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AU.6', 'AC.6'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['syslog', 'cron'],
  description: "Root's crontab entry changed."
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2960,
  level: 2,
  status: 'enabled',
  details: {
    decoded_as: 'gpasswd',
    match: 'added by'
  },
  gpg13: ['7.9', '4.13'],
  gdpr: ['IV_32.2'],
  mitre: {
    tactic: ['Persistence'],
    id: ['T1136'],
    technique: ['Create Account']
  },
  groups: ['syslog', 'yum'],
  description: 'User added to group.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2961,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '2960',
    group: 'sudo'
  },
  gpg13: ['7.9', '4.13'],
  gdpr: ['IV_32.2'],
  mitre: {
    tactic: ['Persistence'],
    id: ['T1136'],
    technique: ['Create Account']
  },
  groups: ['syslog', 'yum'],
  description: 'User added to group sudo.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 2964,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '4',
    timeframe: '30',
    if_matched_sid: '2963',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['recon', 'syslog', 'perdition'],
  description: 'perdition: Multiple connection attempts from same source.'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3102,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '3101',
    match: 'reject=451 4.1.8 '
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'sendmail'],
  description: 'sendmail: Sender domain does not have any valid MX record (Requested action aborted).'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3103,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3101',
    match: 'reject=550 5.0.0 |reject=553 5.3.0'
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'sendmail'],
  description: 'sendmail: Rejected by access list (55x: Requested action not taken).'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3104,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3101',
    match: 'reject=550 5.7.1 '
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'sendmail'],
  description: 'sendmail: Attempt to use mail server as relay (550: Requested action not taken).'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3105,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '3101',
    match: 'reject=553 5.1.8 '
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'sendmail'],
  description: 'sendmail: Sender domain is not found  (553: Requested action not taken).'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3106,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '3101',
    match: 'reject=553 5.5.4 '
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'sendmail'],
  description: 'sendmail: Sender address does not have domain (553: Requested action not taken).'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3108,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3100',
    match: 'rejecting commands from'
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'sendmail'],
  description: 'sendmail: Sendmail rejected due to pre-greeting.'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3151,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '120',
    if_matched_sid: '3102',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'sendmail'],
  description: 'sendmail: Sender domain has bogus MX record. It should not be sending e-mail.'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3152,
  level: 6,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '120',
    if_matched_sid: '3103',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'sendmail'],
  description: 'sendmail: Multiple attempts to send e-mail from a previously rejected sender (access).'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3153,
  level: 6,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '120',
    if_matched_sid: '3104',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'sendmail'],
  description: 'sendmail: Multiple relaying attempts of spam.'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3154,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '120',
    if_matched_sid: '3105',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'sendmail'],
  description: 'sendmail: Multiple attempts to send e-mail from invalid/unknown sender domain.'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3155,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '120',
    if_matched_sid: '3106',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'sendmail'],
  description: 'sendmail: Multiple attempts to send e-mail from invalid/unknown sender.'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3156,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '12',
    timeframe: '120',
    if_matched_sid: '3107',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'sendmail'],
  description: 'sendmail: Multiple rejected e-mails from same source ip.'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3158,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '120',
    if_matched_sid: '3108',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'sendmail'],
  description: 'sendmail: Multiple pre-greetings rejects.'
}, {
  filename: '0025-sendmail_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3191,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3190',
    match: '^sender check failed|^sender check tempfailed'
  },
  pci_dss: ['11.4'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['smf-sav', 'spam', 'syslog', 'sendmail'],
  description: 'sendmail: SMF-SAV sendmail milter unable to verify address (REJECTED).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3301,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3300',
    id: '^554$'
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: Attempt to use mail server as relay (client host rejected).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3302,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3300',
    id: '^550$'
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: Rejected by access list (Requested action not taken).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3303,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '3300',
    id: '^450$'
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: Sender domain is not found (450: Requested mail action not taken).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3304,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '3300',
    id: '^503$'
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: Improper use of SMTP command pipelining (503: Bad sequence of commands).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3305,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '3300',
    id: '^504$'
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: Recipient address must contain FQDN (504: Command parameter not implemented).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3306,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3301, 3302',
    match: ' blocked using '
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: IP Address black-listed by anti-spam (blocked).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3330,
  level: 10,
  status: 'enabled',
  details: {
    ignore: '240',
    if_sid: '3320',
    match: ['defer service failure|Resource temporarily unavailable|', '^fatal: the Postfix mail system is not running']
  },
  pci_dss: ['10.6.1'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['service_availability', 'syslog', 'postfix'],
  description: 'Postfix process error.'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3335,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3320',
    match: '^too many '
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: too many errors after RCPT from unknown'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3351,
  level: 6,
  status: 'enabled',
  details: {
    frequency: '$POSTFIX_FREQ',
    timeframe: '90',
    if_matched_sid: '3301',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'postfix'],
  description: 'Postfix: Multiple relaying attempts of spam.'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3352,
  level: 6,
  status: 'enabled',
  details: {
    frequency: '$POSTFIX_FREQ',
    timeframe: '120',
    if_matched_sid: '3302',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1', '11.4'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'postfix'],
  description: 'Postfix: Multiple attempts to send e-mail from a rejected sender IP (access).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3353,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '$POSTFIX_FREQ',
    timeframe: '120',
    if_matched_sid: '3303',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'postfix'],
  description: 'Postfix: Multiple attempts to send e-mail from invalid/unknown sender domain.'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3354,
  level: 12,
  status: 'enabled',
  details: {
    frequency: '$POSTFIX_FREQ',
    timeframe: '120',
    if_matched_sid: '3304',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['multiple_spam', 'syslog', 'postfix'],
  description: 'Postfix: Multiple misuse of SMTP service (bad sequence of commands).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3355,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '$POSTFIX_FREQ',
    timeframe: '120',
    if_matched_sid: '3305',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'postfix'],
  description: 'Postfix: Multiple attempts to send e-mail to invalid recipient or from unknown sender domain.'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3356,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '$POSTFIX_FREQ',
    timeframe: '120',
    ignore: '30',
    if_matched_sid: '3306',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'syslog', 'postfix'],
  description: 'Postfix: Multiple attempts to send e-mail from black-listed IP address (blocked).'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3357,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '120',
    ignore: '60',
    if_matched_sid: '3332',
    same_source_ip: ''
  },
  pci_dss: ['10.2.4', '10.2.5', '11.4'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7', 'SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Credential Access'],
    id: ['T1110'],
    technique: ['Brute Force']
  },
  groups: ['authentication_failures', 'syslog', 'postfix'],
  description: 'Postfix: Multiple SASL authentication failures.'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3396,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3395',
    match: 'verification'
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: hostname verification failed'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3397,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3395',
    match: 'RBL'
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: RBL lookup error: Host or domain name not found'
}, {
  filename: '0030-postfix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3398,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '3395',
    match: 'MAIL|does not resolve to address'
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Collection'],
    id: ['T1114'],
    technique: ['Email Collection']
  },
  groups: ['spam', 'syslog', 'postfix'],
  description: 'Postfix: Illegal address from unknown sender'
}, {
  filename: '0040-imapd_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3602,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '3600',
    match: 'Authenticated user='
  },
  pci_dss: ['10.2.5'],
  gpg13: ['7.1'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'syslog', 'imapd'],
  description: 'Imapd user login.'
}, {
  filename: '0040-imapd_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3651,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '$IMAPD_FREQ',
    timeframe: '120',
    if_matched_sid: '3601',
    same_source_ip: ''
  },
  pci_dss: ['10.2.4', '10.2.5', '11.4'],
  gpg13: ['7.1'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7', 'SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Credential Access'],
    id: ['T1110'],
    technique: ['Brute Force']
  },
  groups: ['authentication_failures', 'syslog', 'imapd'],
  description: 'Imapd Multiple failed logins from same source ip.'
}, {
  filename: '0045-mailscanner_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3751,
  level: 6,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '180',
    if_matched_sid: '3702',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Credential Access', 'Collection'],
    id: ['T1110', 'T1114'],
    technique: ['Brute Force', 'Email Collection']
  },
  groups: ['multiple_spam', 'syslog', 'mailscanner'],
  description: 'mailscanner: Multiple attempts of spam.'
}, {
  filename: '0050-ms-exchange_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3851,
  level: 9,
  status: 'enabled',
  details: {
    frequency: '12',
    timeframe: '120',
    ignore: '120',
    if_matched_sid: '3801',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'ms', 'exchange'],
  description: 'ms-exchange: Multiple e-mail attempts to an invalid account.'
}, {
  filename: '0050-ms-exchange_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3852,
  level: 9,
  status: 'enabled',
  details: {
    frequency: '14',
    timeframe: '120',
    ignore: '240',
    if_matched_sid: '3802',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Collection', 'Impact'],
    id: ['T1114', 'T1499'],
    technique: ['Email Collection', 'Endpoint Denial of Service']
  },
  groups: ['multiple_spam', 'ms', 'exchange'],
  description: 'ms-exchange: Multiple e-mail 500 error code (spam).'
}, {
  filename: '0055-courier_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3904,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '3900',
    match: '^LOGIN,'
  },
  pci_dss: ['10.2.5'],
  gpg13: ['7.1', '7.2'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'syslog', 'courier'],
  description: 'Courier (imap/pop3) authentication success.'
}, {
  filename: '0055-courier_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3910,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '12',
    timeframe: '30',
    if_matched_sid: '3902',
    same_source_ip: ''
  },
  pci_dss: ['10.2.4', '10.2.5', '11.4'],
  gpg13: ['7.1'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7', 'SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Credential Access'],
    id: ['T1110'],
    technique: ['Brute Force']
  },
  groups: ['authentication_failures', 'syslog', 'courier'],
  description: 'Courier brute force (multiple failed logins).'
}, {
  filename: '0055-courier_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 3911,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '17',
    timeframe: '30',
    if_matched_sid: '3901',
    same_source_ip: ''
  },
  pci_dss: ['10.6.1', '11.4'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Credential Access'],
    id: ['T1110'],
    technique: ['Brute Force']
  },
  groups: ['recon', 'syslog', 'courier'],
  description: 'Courier: Multiple connection attempts from same source.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4323,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '4314',
    id: '^6-605005'
  },
  pci_dss: ['10.2.5'],
  gpg13: ['7.8'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'syslog', 'pix'],
  description: 'PIX: Successful login.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4325,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4313',
    id: '^4-405001'
  },
  pci_dss: ['10.6.1'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Command and Control'],
    id: ['T1095'],
    technique: ['Standard Non-Application Layer Protocol']
  },
  groups: ['syslog', 'pix'],
  description: 'PIX: ARP collision detected.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4335,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '4314',
    id: '^6-113004'
  },
  pci_dss: ['10.2.5'],
  gpg13: ['7.1', '7.2'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'syslog', 'pix'],
  description: 'PIX: AAA (VPN) authentication successful.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4336,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4314',
    id: '^6-113006'
  },
  pci_dss: ['10.2.4', '10.2.5'],
  gpg13: ['7.1', '7.5'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1133'],
    technique: ['External Remote Services']
  },
  groups: ['authentication_failed', 'syslog', 'pix'],
  description: 'PIX: AAA (VPN) user locked out.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4337,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4312',
    id: '^3-201008'
  },
  pci_dss: ['10.6.1'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1133'],
    technique: ['External Remote Services']
  },
  groups: ['service_availability', 'syslog', 'pix'],
  description: 'PIX: The PIX is disallowing new connections.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4339,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4314',
    id: '^5-111003'
  },
  pci_dss: ['1.1.1', '10.4'],
  gpg13: ['4.13'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.a.1', '164.312.b'],
  nist_800_53: ['CM.3', 'CM.5', 'AU.8'],
  tsc: ['CC8.1', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Defense Evasion'],
    id: ['T1089'],
    technique: ['Disabling Security Tools']
  },
  groups: ['config_changed', 'syslog', 'pix'],
  description: 'PIX: Firewall configuration deleted.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4340,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4314',
    id: '^5-111005|^5-111004|^5-111002|^5-111007'
  },
  pci_dss: ['1.1.1', '10.4'],
  gpg13: ['4.13'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.a.1', '164.312.b'],
  nist_800_53: ['CM.3', 'CM.5', 'AU.8'],
  tsc: ['CC8.1', 'CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Defense Evasion'],
    id: ['T1089'],
    technique: ['Disabling Security Tools']
  },
  groups: ['config_changed', 'syslog', 'pix'],
  description: 'PIX: Firewall configuration changed.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4342,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4314',
    id: '^5-502101|^5-502102'
  },
  pci_dss: ['8.1.2', '10.2.5'],
  gpg13: ['4.13'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.a.2.I', '164.312.a.2.II', '164.312.b'],
  nist_800_53: ['AC.2', 'IA.4', 'AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Defense Evasion', 'Initial Access'],
    id: ['T1089', 'T1133'],
    technique: ['Disabling Security Tools', 'External Remote Services']
  },
  groups: ['adduser', 'account_changed', 'syslog', 'pix'],
  description: 'PIX: User created or modified on the Firewall.'
}, {
  filename: '0065-pix_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4386,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '10',
    timeframe: '240',
    if_matched_sid: '4334',
    same_source_ip: ''
  },
  pci_dss: ['11.4', '10.2.4', '10.2.5'],
  gpg13: ['7.1'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['SI.4', 'AU.14', 'AC.7'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Credential Access', 'Initial Access'],
    id: ['T1110', 'T1133'],
    technique: ['Brute Force', 'External Remote Services']
  },
  groups: ['authentication_failures', 'syslog', 'pix'],
  description: 'PIX: Multiple AAA (VPN) authentication failures.'
}, {
  filename: '0070-netscreenfw_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4505,
  level: 11,
  status: 'enabled',
  details: {
    if_sid: '4503',
    id: '^00027'
  },
  pci_dss: ['1.4', '10.6.1'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.a.1', '164.312.b'],
  nist_800_53: ['SC.7', 'AU.6'],
  tsc: ['CC6.7', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1485'],
    technique: ['Data Destruction']
  },
  groups: ['service_availability', 'netscreenfw'],
  description: 'Netscreen Erase sequence started.'
}, {
  filename: '0070-netscreenfw_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4506,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4501',
    id: '^00002'
  },
  pci_dss: ['10.2.5', '10.2.2'],
  gpg13: ['7.8'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7', 'AC.6'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'netscreenfw'],
  description: 'Netscreen firewall: Successfull admin login'
}, {
  filename: '0070-netscreenfw_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4507,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4502',
    id: '^00515'
  },
  pci_dss: ['10.2.5', '10.2.2'],
  gpg13: ['7.8'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7', 'AC.6'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'netscreenfw'],
  description: 'Netscreen firewall: Successfull admin login'
}, {
  filename: '0070-netscreenfw_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4509,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '4504',
    id: '^00767'
  },
  pci_dss: ['1.1.1'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.a.1'],
  nist_800_53: ['CM.3', 'CM.5'],
  tsc: ['CC8.1'],
  mitre: {
    tactic: ['Defense Evasion'],
    id: ['T1089'],
    technique: ['Disabling Security Tools']
  },
  groups: ['config_changed', 'netscreenfw'],
  description: 'Netscreen firewall: configuration changed.'
}, {
  filename: '0070-netscreenfw_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4550,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '6',
    timeframe: '180',
    ignore: '60',
    if_matched_sid: '4503',
    same_source_ip: ''
  },
  pci_dss: ['1.4', '10.6.1', '11.4'],
  gpg13: ['4.1'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.a.1', '164.312.b'],
  nist_800_53: ['SC.7', 'AU.6', 'SI.4'],
  tsc: ['CC6.7', 'CC6.8', 'CC7.2', 'CC7.3', 'CC6.1'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['netscreenfw'],
  description: 'Netscreen firewall: Multiple critical messages from same source IP.'
}, {
  filename: '0070-netscreenfw_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4551,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '180',
    ignore: '60',
    if_matched_sid: '4503'
  },
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['netscreenfw'],
  description: 'Netscreen firewall: Multiple critical messages.'
}, {
  filename: '0075-cisco-ios_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4722,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '4715',
    id: '^%SEC_LOGIN-5-LOGIN_SUCCESS'
  },
  pci_dss: ['10.2.5'],
  gpg13: ['3.6'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'syslog', 'cisco_ios'],
  description: 'Cisco IOS: Successful login to the router.'
}, {
  filename: '0080-sonicwall_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4810,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '4806',
    id: '^236$'
  },
  pci_dss: ['10.2.5'],
  gpg13: ['3.6'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'syslog', 'sonicwall'],
  description: 'SonicWall: Firewall administrator login.'
}, {
  filename: '0080-sonicwall_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 4851,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '120',
    ignore: '60',
    if_matched_sid: '4803'
  },
  pci_dss: ['10.6.1'],
  gpg13: ['3.5'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['service_availability', 'syslog', 'sonicwall'],
  description: 'SonicWall: Multiple firewall error messages.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5103,
  level: 9,
  status: 'enabled',
  details: {
    if_sid: '5100',
    match: 'Oversized packet received from'
  },
  gdpr: ['IV_35.7.d'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['syslog', 'linuxkernel'],
  description: 'Error message from the kernel. Ping of death attack.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5104,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '5100',
    regex: ['Promiscuous mode enabled|', 'device S+ entered promiscuous mode']
  },
  pci_dss: ['10.6.1', '11.4'],
  gpg13: ['4.13'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6', 'SI.4'],
  tsc: ['CC7.2', 'CC7.3', 'CC6.1', 'CC6.8'],
  mitre: {
    tactic: ['Discovery'],
    id: ['T1040'],
    technique: ['Network Sniffing']
  },
  groups: ['promisc', 'syslog', 'linuxkernel'],
  description: 'Interface entered in promiscuous(sniffing) mode.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5108,
  level: 12,
  status: 'enabled',
  details: {
    if_sid: '5100',
    match: 'Out of Memory: '
  },
  pci_dss: ['10.6.1'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1499'],
    technique: ['Endpoint Denial of Service']
  },
  groups: ['service_availability', 'syslog', 'linuxkernel'],
  description: 'System running out of memory. Availability of the system is in risk.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5113,
  level: 7,
  status: 'enabled',
  details: {
    if_sid: '5100',
    match: 'Kernel log daemon terminating'
  },
  pci_dss: ['10.6.1'],
  gpg13: ['4.14'],
  gdpr: ['IV_35.7.d'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.6'],
  tsc: ['CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Impact'],
    id: ['T1529'],
    technique: ['System Shutdown/Reboot']
  },
  groups: ['system_shutdown', 'syslog', 'linuxkernel'],
  description: 'System is shutting down.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5132,
  level: 11,
  status: 'enabled',
  details: {
    if_sid: '5100',
    match: 'module verification failed'
  },
  mitre: {
    tactic: ['Persistence'],
    id: ['T1215'],
    technique: ['Kernel Modules and Extensions']
  },
  groups: ['syslog', 'linuxkernel'],
  description: 'Unsigned kernel module was loaded'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5133,
  level: 11,
  status: 'enabled',
  details: {
    if_sid: '5100',
    match: 'PKCS#7 signature not signed with a trusted key'
  },
  mitre: {
    tactic: ['Persistence'],
    id: ['T1215'],
    technique: ['Kernel Modules and Extensions']
  },
  groups: ['syslog', 'linuxkernel'],
  description: 'Signed but untrusted kernel module was loaded'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5302,
  level: 9,
  status: 'enabled',
  details: {
    if_sid: '5301',
    user: '^root'
  },
  pci_dss: ['10.2.4', '10.2.5'],
  gpg13: ['7.8'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3', 'CC7.4'],
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['authentication_failed', 'syslog', 'su'],
  description: 'User missed the password to change UID to root.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5303,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '5300',
    regex: ["session opened for user root|^'su root'|", '^+ S+ S+proot$|^S+ to root on|^SU S+ S+ + S+ S+-root$']
  },
  pci_dss: ['10.2.5'],
  gpg13: ['7.6', '7.8', '7.9'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'syslog', 'su'],
  description: 'User successfully changed UID to root.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5304,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '5300',
    regex: ['session opened for user|succeeded for|', '^+|^S+ to |^SU S+ S+ + ']
  },
  pci_dss: ['10.2.5'],
  gpg13: ['7.6', '7.8'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'syslog', 'su'],
  description: 'User successfully changed UID.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5401,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '5400',
    match: 'incorrect password attempt'
  },
  pci_dss: ['10.2.4', '10.2.5'],
  gpg13: ['7.8'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['syslog', 'sudo'],
  description: 'Failed attempt to run sudo.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5402,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '5400',
    regex: ' ; USER=root ; COMMAND=| ; USER=root ; TSID=S+ ; COMMAND='
  },
  pci_dss: ['10.2.5', '10.2.2'],
  gpg13: ['7.6', '7.8', '7.13'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7', 'AC.6'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['syslog', 'sudo'],
  description: 'Successful sudo to ROOT executed.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5403,
  level: 4,
  status: 'enabled',
  details: {
    if_sid: '5400',
    if_fts: ''
  },
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['syslog', 'sudo'],
  description: 'First time user executed sudo.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5404,
  level: 10,
  status: 'enabled',
  details: {
    if_sid: '5401',
    match: '3 incorrect password attempts'
  },
  pci_dss: ['10.2.4', '10.2.5'],
  gpg13: ['7.8'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['syslog', 'sudo'],
  description: 'Three failed attempts to run sudo'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5405,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '5400',
    match: 'user NOT in sudoers'
  },
  pci_dss: ['10.2.2', '10.2.5'],
  gpg13: ['7.8'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.6', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['syslog', 'sudo'],
  description: 'Unauthorized user attempted to use sudo.'
}, {
  filename: '0020-syslog_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5407,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '5400',
    regex: ' ; USER=S+ ; COMMAND=| ; USER=S+ ; TSID=S+ ; COMMAND='
  },
  pci_dss: ['10.2.5', '10.2.2'],
  gpg13: ['7.6', '7.8', '7.13'],
  gdpr: ['IV_32.2'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Privilege Escalation'],
    id: ['T1169'],
    technique: ['Sudo']
  },
  groups: ['syslog', 'sudo'],
  description: 'Successful sudo executed.'
}, {
  filename: '0085-pam_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5501,
  level: 3,
  status: 'enabled',
  details: {
    if_sid: '5500',
    match: 'session opened for user '
  },
  pci_dss: ['10.2.5'],
  gpg13: ['7.8', '7.9'],
  gdpr: ['IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7'],
  tsc: ['CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1078'],
    technique: ['Valid Accounts']
  },
  groups: ['authentication_success', 'pam', 'syslog'],
  description: 'PAM: Login session opened.'
}, {
  filename: '0085-pam_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5551,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '8',
    timeframe: '180',
    if_matched_sid: '5503',
    same_source_ip: ''
  },
  pci_dss: ['10.2.4', '10.2.5', '11.4'],
  gpg13: ['7.8'],
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  hipaa: ['164.312.b'],
  nist_800_53: ['AU.14', 'AC.7', 'SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Credential Access'],
    id: ['T1110'],
    technique: ['Brute Force']
  },
  groups: ['authentication_failures', 'pam', 'syslog'],
  description: 'PAM: Multiple failed logins in a small period of time.'
}, {
  filename: '0090-telnetd_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5601,
  level: 5,
  status: 'enabled',
  details: {
    if_sid: '5600',
    match: 'refused connect from '
  },
  gdpr: ['IV_35.7.d'],
  mitre: {
    tactic: ['Command and Control'],
    id: ['T1095'],
    technique: ['Standard Non-Application Layer Protocol']
  },
  groups: ['syslog', 'telnetd'],
  description: 'telnetd: Connection refused by TCP Wrappers.'
}, {
  filename: '0090-telnetd_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5631,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '6',
    timeframe: '120',
    if_matched_sid: '5602',
    same_source_ip: ''
  },
  gdpr: ['IV_35.7.d', 'IV_32.2'],
  mitre: {
    tactic: ['Credential Access'],
    id: ['T1110'],
    technique: ['Brute Force']
  },
  groups: ['syslog', 'telnetd'],
  description: 'telnetd: Multiple connection attempts from same source (possible scan).'
}, {
  filename: '0095-sshd_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5701,
  level: 8,
  status: 'enabled',
  details: {
    if_sid: '5700',
    match: 'Bad protocol version identification'
  },
  pci_dss: ['11.4'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access'],
    id: ['T1190'],
    technique: ['Exploit Public-Facing Application']
  },
  groups: ['recon', 'syslog', 'sshd'],
  description: 'sshd: Possible attack on the ssh server (or version gathering).'
}, {
  filename: '0095-sshd_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5703,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '6',
    timeframe: '360',
    if_matched_sid: '5702',
    same_source_ip: ''
  },
  pci_dss: ['11.4'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Credential Access'],
    id: ['T1110'],
    technique: ['Brute Force']
  },
  groups: ['syslog', 'sshd'],
  description: 'sshd: Possible breakin attempt (high number of reverse lookup errors).'
}, {
  filename: '0095-sshd_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5705,
  level: 10,
  status: 'enabled',
  details: {
    frequency: '6',
    timeframe: '360',
    if_matched_sid: '5704'
  },
  pci_dss: ['11.4'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Initial Access', 'Credential Access'],
    id: ['T1190', 'T1110'],
    technique: ['Exploit Public-Facing Application', 'Brute Force']
  },
  groups: ['syslog', 'sshd'],
  description: 'sshd: Possible scan or breakin attempt (high number of login timeouts).'
}, {
  filename: '0095-sshd_rules.xml',
  relative_dirname: 'ruleset/rules',
  id: 5706,
  level: 6,
  status: 'enabled',
  details: {
    if_sid: '5700',
    match: 'Did not receive identification string from'
  },
  pci_dss: ['11.4'],
  gpg13: ['4.12'],
  gdpr: ['IV_35.7.d'],
  nist_800_53: ['SI.4'],
  tsc: ['CC6.1', 'CC6.8', 'CC7.2', 'CC7.3'],
  mitre: {
    tactic: ['Command and Control'],
    id: ['T1043'],
    technique: ['Commonly Used Port']
  },
  groups: ['recon', 'syslog', 'sshd'],
  description: 'sshd: insecure connection attempt (scan).'
}];
exports.arrayMitreRules = arrayMitreRules;
const arrayLocation = ['EventChannel', '/var/log/auth.log', '/var/log/secure'];
exports.arrayLocation = arrayLocation;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1pdHJlLmpzIl0sIm5hbWVzIjpbImFycmF5TWl0cmVSdWxlcyIsImZpbGVuYW1lIiwicmVsYXRpdmVfZGlybmFtZSIsImlkIiwibGV2ZWwiLCJzdGF0dXMiLCJkZXRhaWxzIiwiaWZfc2lkIiwibWF0Y2giLCJwY2lfZHNzIiwiZ3BnMTMiLCJnZHByIiwiaGlwYWEiLCJuaXN0XzgwMF81MyIsInRzYyIsIm1pdHJlIiwidGFjdGljIiwidGVjaG5pcXVlIiwiZ3JvdXBzIiwiZGVzY3JpcHRpb24iLCJjYXRlZ29yeSIsImRlY29kZWRfYXMiLCJob3N0bmFtZSIsIm1heHNpemUiLCJub2FsZXJ0IiwicmVnZXgiLCJncm91cCIsImZyZXF1ZW5jeSIsInRpbWVmcmFtZSIsImlmX21hdGNoZWRfc2lkIiwic2FtZV9zb3VyY2VfaXAiLCJpZ25vcmUiLCJ1c2VyIiwiaWZfZnRzIiwiYXJyYXlMb2NhdGlvbiJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFFQTtBQUNPLE1BQU1BLGVBQWUsR0FBRyxDQUM3QjtBQUNFQyxFQUFBQSxRQUFRLEVBQUUsc0JBRFo7QUFFRUMsRUFBQUEsZ0JBQWdCLEVBQUUsZUFGcEI7QUFHRUMsRUFBQUEsRUFBRSxFQUFFLEdBSE47QUFJRUMsRUFBQUEsS0FBSyxFQUFFLENBSlQ7QUFLRUMsRUFBQUEsTUFBTSxFQUFFLFNBTFY7QUFNRUMsRUFBQUEsT0FBTyxFQUFFO0FBQUVDLElBQUFBLE1BQU0sRUFBRSxLQUFWO0FBQWlCQyxJQUFBQSxLQUFLLEVBQUU7QUFBeEIsR0FOWDtBQU9FQyxFQUFBQSxPQUFPLEVBQUUsQ0FBQyxRQUFELEVBQVcsUUFBWCxDQVBYO0FBUUVDLEVBQUFBLEtBQUssRUFBRSxDQUFDLE1BQUQsQ0FSVDtBQVNFQyxFQUFBQSxJQUFJLEVBQUUsQ0FBQyxXQUFELENBVFI7QUFVRUMsRUFBQUEsS0FBSyxFQUFFLENBQUMsV0FBRCxD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LFFBQUQsRUFBVyxNQUFYLENBakJWO0FBa0JFQyxFQUFBQSxXQUFXLEVBQUU7QUFsQmYsQ0F2c0Q2QixFQTJ0RDdCO0FBQ0VsQixFQUFBQSxRQUFRLEVBQUUscUJBRFo7QUFFRUMsRUFBQUEsZ0JBQWdCLEVBQUUsZUFGcEI7QUFHRUMsRUFBQUEsRUFBRSxFQUFFLElBSE47QUFJRUMsRUFBQUEsS0FBSyxFQUFFLENBSlQ7QUFLRUMsRUFBQUEsTUFBTSxFQUFFLFNBTFY7QUFNRUMsRUFBQUEsT0FBTyxFQUFFO0FBQUVDLElBQUFBLE1BQU0sRUFBRSxNQUFWO0FBQWtCQyxJQUFBQSxLQUFLLEVBQUU7QUFBekIsR0FOWDtBQU9FQyxFQUFBQSxPQUFPLEVBQUUsQ0FBQyxNQUFELENBUFg7QUFRRUMsRUFBQUEsS0FBSyxFQUFFLENBQUMsTUFBRCxDQVJUO0FBU0VDLEVBQUFBLElBQUksRUFBRSxDQUFDLFdBQUQsQ0FUUjtBQVVFRSxFQUFBQSxXQUFXLEVBQUUsQ0FBQyxNQUFELENBVmY7QUFXRUMsRUFBQUEsR0FBRyxFQUFFLENBQUMsT0FBRCxFQUFVLE9BQVYsRUFBbUIsT0FBbkIsRUFBNEIsT0FBNUIsQ0FYUDtBQVlFQyxFQUFBQSxLQUFLLEVBQUU7QUFBRUMsSUFBQUEsTUFBTSxFQUFFLENBQUMscUJBQUQsQ0FBVjtBQUFtQ2IsSUFBQUEsRUFBRSxFQUFFLENBQUMsT0FBRCxDQUF2QztBQUFrRGMsSUFBQUEsU0FBUyxFQUFFLENBQUMsb0JBQUQ7QUFBN0QsR0FaVDtBQWFFQyxFQUFBQSxNQUFNLEVBQUUsQ0FBQyxPQUFELEVBQVUsUUFBVixFQUFvQixNQUFwQixDQWJWO0FBY0VDLEVBQUFBLFdBQVcsRUFBRTtBQWRmLENBM3RENkIsQ0FBeEI7O0FBNnVEQSxNQUFNZSxhQUFhLEdBQUcsQ0FBQyxjQUFELEVBQWlCLG1CQUFqQixFQUFzQyxpQkFBdEMsQ0FBdEIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTWl0cmUgc2FtcGxlIGFsZXJ0c1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuLy8gTWl0cmVcbmV4cG9ydCBjb25zdCBhcnJheU1pdHJlUnVsZXMgPSBbXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMTUtb3NzZWNfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDUwNCxcbiAgICBsZXZlbDogMyxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzUwMCcsIG1hdGNoOiAnQWdlbnQgZGlzY29ubmVjdGVkJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJywgJzEwLjIuNiddLFxuICAgIGdwZzEzOiBbJzEwLjEnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnLCAnQVUuMTQnLCAnQVUuNSddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMycsICdDQzYuOCddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydEZWZlbnNlIEV2YXNpb24nXSwgaWQ6IFsnVDEwODknXSwgdGVjaG5pcXVlOiBbJ0Rpc2FibGluZyBTZWN1cml0eSBUb29scyddIH0sXG4gICAgZ3JvdXBzOiBbJ3dhenVoJ10sXG4gICAgZGVzY3JpcHRpb246ICdPc3NlYyBhZ2VudCBkaXNjb25uZWN0ZWQuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAxNS1vc3NlY19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTA1LFxuICAgIGxldmVsOiAzLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNTAwJywgbWF0Y2g6ICdBZ2VudCByZW1vdmVkJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJywgJzEwLjIuNiddLFxuICAgIGdwZzEzOiBbJzEwLjEnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnLCAnQVUuMTQnLCAnQVUuNSddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMycsICdDQzYuOCddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydEZWZlbnNlIEV2YXNpb24nXSwgaWQ6IFsnVDEwODknXSwgdGVjaG5pcXVlOiBbJ0Rpc2FibGluZyBTZWN1cml0eSBUb29scyddIH0sXG4gICAgZ3JvdXBzOiBbJ3dhenVoJ10sXG4gICAgZGVzY3JpcHRpb246ICdPc3NlYyBhZ2VudCByZW1vdmVkLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMTUtb3NzZWNfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDUxOCxcbiAgICBsZXZlbDogOSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzUxNCcsIG1hdGNoOiAnQWR3YXJlfFNweXdhcmUnIH0sXG4gICAgZ3BnMTM6IFsnNC4yJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBtaXRyZToge1xuICAgICAgdGFjdGljOiBbJ0xhdGVyYWwgTW92ZW1lbnQnXSxcbiAgICAgIGlkOiBbJ1QxMDE3J10sXG4gICAgICB0ZWNobmlxdWU6IFsnQXBwbGljYXRpb24gRGVwbG95bWVudCBTb2Z0d2FyZSddLFxuICAgIH0sXG4gICAgZ3JvdXBzOiBbJ3Jvb3RjaGVjaycsICd3YXp1aCddLFxuICAgIGRlc2NyaXB0aW9uOiAnV2luZG93cyBBZHdhcmUvU3B5d2FyZSBhcHBsaWNhdGlvbiBmb3VuZC4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDE1LW9zc2VjX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA1NTAsXG4gICAgbGV2ZWw6IDcsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBjYXRlZ29yeTogJ3dhenVoJywgZGVjb2RlZF9hczogJ3N5c2NoZWNrX2ludGVncml0eV9jaGFuZ2VkJyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNSddLFxuICAgIGdwZzEzOiBbJzQuMTEnXSxcbiAgICBnZHByOiBbJ0lJXzUuMS5mJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5jLjEnLCAnMTY0LjMxMi5jLjInXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS43J10sXG4gICAgdHNjOiBbJ1BJMS40JywgJ1BJMS41JywgJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0ltcGFjdCddLCBpZDogWydUMTQ5MiddLCB0ZWNobmlxdWU6IFsnU3RvcmVkIERhdGEgTWFuaXB1bGF0aW9uJ10gfSxcbiAgICBncm91cHM6IFsnc3lzY2hlY2snLCAnd2F6dWgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ0ludGVncml0eSBjaGVja3N1bSBjaGFuZ2VkLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMTUtb3NzZWNfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDU1MyxcbiAgICBsZXZlbDogNyxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGNhdGVnb3J5OiAnd2F6dWgnLCBkZWNvZGVkX2FzOiAnc3lzY2hlY2tfZGVsZXRlZCcgfSxcbiAgICBwY2lfZHNzOiBbJzExLjUnXSxcbiAgICBncGcxMzogWyc0LjExJ10sXG4gICAgZ2RwcjogWydJSV81LjEuZiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYy4xJywgJzE2NC4zMTIuYy4yJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNyddLFxuICAgIHRzYzogWydQSTEuNCcsICdQSTEuNScsICdDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnRGVmZW5zZSBFdmFzaW9uJywgJ0ltcGFjdCddLFxuICAgICAgaWQ6IFsnVDExMDcnLCAnVDE0ODUnXSxcbiAgICAgIHRlY2huaXF1ZTogWydGaWxlIERlbGV0aW9uJywgJ0RhdGEgRGVzdHJ1Y3Rpb24nXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydzeXNjaGVjaycsICd3YXp1aCddLFxuICAgIGRlc2NyaXB0aW9uOiAnRmlsZSBkZWxldGVkLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMTUtb3NzZWNfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDU5MixcbiAgICBsZXZlbDogOCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzUwMCcsIG1hdGNoOiAnXm9zc2VjOiBGaWxlIHNpemUgcmVkdWNlZCcgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjUuMicsICcxMS40J10sXG4gICAgZ3BnMTM6IFsnMTAuMSddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuOScsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0ltcGFjdCddLCBpZDogWydUMTQ5MiddLCB0ZWNobmlxdWU6IFsnU3RvcmVkIERhdGEgTWFuaXB1bGF0aW9uJ10gfSxcbiAgICBncm91cHM6IFsnYXR0YWNrcycsICd3YXp1aCddLFxuICAgIGRlc2NyaXB0aW9uOiAnTG9nIGZpbGUgc2l6ZSByZWR1Y2VkLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMTUtb3NzZWNfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDU5MyxcbiAgICBsZXZlbDogOSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzUwMCcsIG1hdGNoOiAnXm9zc2VjOiBFdmVudCBsb2cgY2xlYXJlZCcgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjUuMiddLFxuICAgIGdwZzEzOiBbJzEwLjEnXSxcbiAgICBnZHByOiBbJ0lJXzUuMS5mJywgJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjknXSxcbiAgICB0c2M6IFsnQ0M2LjEnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnRGVmZW5zZSBFdmFzaW9uJ10sIGlkOiBbJ1QxMDcwJ10sIHRlY2huaXF1ZTogWydJbmRpY2F0b3IgUmVtb3ZhbCBvbiBIb3N0J10gfSxcbiAgICBncm91cHM6IFsnbG9nc19jbGVhcmVkJywgJ3dhenVoJ10sXG4gICAgZGVzY3JpcHRpb246ICdNaWNyb3NvZnQgRXZlbnQgbG9nIGNsZWFyZWQuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAxNS1vc3NlY19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTk0LFxuICAgIGxldmVsOiA1LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgY2F0ZWdvcnk6ICd3YXp1aCcsIGlmX3NpZDogJzU1MCcsIGhvc3RuYW1lOiAnc3lzY2hlY2stcmVnaXN0cnknIH0sXG4gICAgcGNpX2RzczogWycxMS41J10sXG4gICAgZ3BnMTM6IFsnNC4xMyddLFxuICAgIGdkcHI6IFsnSUlfNS4xLmYnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmMuMScsICcxNjQuMzEyLmMuMiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ1NJLjcnXSxcbiAgICB0c2M6IFsnUEkxLjQnLCAnUEkxLjUnLCAnQ0M2LjEnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnSW1wYWN0J10sIGlkOiBbJ1QxNDkyJ10sIHRlY2huaXF1ZTogWydTdG9yZWQgRGF0YSBNYW5pcHVsYXRpb24nXSB9LFxuICAgIGdyb3VwczogWydzeXNjaGVjaycsICd3YXp1aCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUmVnaXN0cnkgSW50ZWdyaXR5IENoZWNrc3VtIENoYW5nZWQnLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDE1LW9zc2VjX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA1OTcsXG4gICAgbGV2ZWw6IDUsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBjYXRlZ29yeTogJ3dhenVoJywgaWZfc2lkOiAnNTUzJywgaG9zdG5hbWU6ICdzeXNjaGVjay1yZWdpc3RyeScgfSxcbiAgICBwY2lfZHNzOiBbJzExLjUnXSxcbiAgICBncGcxMzogWyc0LjEzJ10sXG4gICAgZ2RwcjogWydJSV81LjEuZiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYy4xJywgJzE2NC4zMTIuYy4yJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNyddLFxuICAgIHRzYzogWydQSTEuNCcsICdQSTEuNScsICdDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnRGVmZW5zZSBFdmFzaW9uJywgJ0ltcGFjdCddLFxuICAgICAgaWQ6IFsnVDExMDcnLCAnVDE0ODUnXSxcbiAgICAgIHRlY2huaXF1ZTogWydGaWxlIERlbGV0aW9uJywgJ0RhdGEgRGVzdHJ1Y3Rpb24nXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydzeXNjaGVjaycsICd3YXp1aCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUmVnaXN0cnkgRW50cnkgRGVsZXRlZC4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDIwLXN5c2xvZ19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMTAwMyxcbiAgICBsZXZlbDogMTMsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBtYXhzaXplOiAnMTAyNScsIG5vYWxlcnQ6ICcxJyB9LFxuICAgIGdwZzEzOiBbJzQuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbXBhY3QnXSwgaWQ6IFsnVDE0OTknXSwgdGVjaG5pcXVlOiBbJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10gfSxcbiAgICBncm91cHM6IFsnc3lzbG9nJywgJ2Vycm9ycyddLFxuICAgIGRlc2NyaXB0aW9uOiAnTm9uIHN0YW5kYXJkIHN5c2xvZyBtZXNzYWdlIChzaXplIHRvbyBsYXJnZSkuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDIzMDEsXG4gICAgbGV2ZWw6IDEwLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgbWF0Y2g6ICdeRGVhY3RpdmF0aW5nIHNlcnZpY2UgJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS42J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0ltcGFjdCddLCBpZDogWydUMTQ5OSddLCB0ZWNobmlxdWU6IFsnRW5kcG9pbnQgRGVuaWFsIG9mIFNlcnZpY2UnXSB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAneGluZXRkJ10sXG4gICAgZGVzY3JpcHRpb246ICd4aW5ldGQ6IEV4Y2Vzc2l2ZSBudW1iZXIgY29ubmVjdGlvbnMgdG8gYSBzZXJ2aWNlLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAyNTAyLFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IG1hdGNoOiAnbW9yZSBhdXRoZW50aWNhdGlvbiBmYWlsdXJlczt8UkVQRUFURUQgbG9naW4gZmFpbHVyZXMnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjQnLCAnMTAuMi41J10sXG4gICAgZ3BnMTM6IFsnNy44J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnLCAnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjE0JywgJ0FDLjcnXSxcbiAgICB0c2M6IFsnQ0M2LjEnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnQ3JlZGVudGlhbCBBY2Nlc3MnXSwgaWQ6IFsnVDExMTAnXSwgdGVjaG5pcXVlOiBbJ0JydXRlIEZvcmNlJ10gfSxcbiAgICBncm91cHM6IFsnYXV0aGVudGljYXRpb25fZmFpbGVkJywgJ3N5c2xvZycsICdhY2Nlc3NfY29udHJvbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnc3lzbG9nOiBVc2VyIG1pc3NlZCB0aGUgcGFzc3dvcmQgbW9yZSB0aGFuIG9uZSB0aW1lJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDI1MDMsXG4gICAgbGV2ZWw6IDUsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczoge1xuICAgICAgcmVnZXg6IFtcbiAgICAgICAgJ15yZWZ1c2VkIGNvbm5lY3QgZnJvbXwnLFxuICAgICAgICAnXmxpYndyYXAgcmVmdXNlZCBjb25uZWN0aW9ufCcsXG4gICAgICAgICdDb25uZWN0aW9uIGZyb20gUysgZGVuaWVkJyxcbiAgICAgIF0sXG4gICAgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjIuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNyddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnQ29tbWFuZCBhbmQgQ29udHJvbCddLFxuICAgICAgaWQ6IFsnVDEwOTUnXSxcbiAgICAgIHRlY2huaXF1ZTogWydTdGFuZGFyZCBOb24tQXBwbGljYXRpb24gTGF5ZXIgUHJvdG9jb2wnXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydhY2Nlc3NfZGVuaWVkJywgJ3N5c2xvZycsICdhY2Nlc3NfY29udHJvbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnc3lzbG9nOiBDb25uZWN0aW9uIGJsb2NrZWQgYnkgVGNwIFdyYXBwZXJzLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAyNTA0LFxuICAgIGxldmVsOiA5LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgbWF0Y2g6ICdJTExFR0FMIFJPT1QgTE9HSU58Uk9PVCBMT0dJTiBSRUZVU0VEJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuMi40JywgJzEwLjIuNScsICcxMC4yLjInXSxcbiAgICBncGcxMzogWyc3LjgnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCcsICdJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNycsICdBQy42J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ1ByaXZpbGVnZSBFc2NhbGF0aW9uJ10sIGlkOiBbJ1QxMTY5J10sIHRlY2huaXF1ZTogWydTdWRvJ10gfSxcbiAgICBncm91cHM6IFsnaW52YWxpZF9sb2dpbicsICdzeXNsb2cnLCAnYWNjZXNzX2NvbnRyb2wnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3N5c2xvZzogSWxsZWdhbCByb290IGxvZ2luLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAyNTUxLFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzI1NTAnLCByZWdleDogJ15Db25uZWN0aW9uIGZyb20gUysgb24gaWxsZWdhbCBwb3J0JCcgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMSddLFxuICAgIGdwZzEzOiBbJzcuMSddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNiddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydEaXNjb3ZlcnknXSwgaWQ6IFsnVDEwNDYnXSwgdGVjaG5pcXVlOiBbJ05ldHdvcmsgU2VydmljZSBTY2FubmluZyddIH0sXG4gICAgZ3JvdXBzOiBbJ2Nvbm5lY3Rpb25fYXR0ZW1wdCcsICdzeXNsb2cnLCAnYWNjZXNzX2NvbnRyb2wnXSxcbiAgICBkZXNjcmlwdGlvbjogJ0Nvbm5lY3Rpb24gdG8gcnNoZCBmcm9tIHVucHJpdmlsZWdlZCBwb3J0LiBQb3NzaWJsZSBuZXR3b3JrIHNjYW4uJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDI4MzMsXG4gICAgbGV2ZWw6IDgsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICcyODMyJywgbWF0Y2g6ICdeKHJvb3QpJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuMi43JywgJzEwLjYuMScsICcxMC4yLjInXSxcbiAgICBncGcxMzogWyc0LjEzJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnLCAnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjE0JywgJ0FVLjYnLCAnQUMuNiddLFxuICAgIHRzYzogWydDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydQcml2aWxlZ2UgRXNjYWxhdGlvbiddLCBpZDogWydUMTE2OSddLCB0ZWNobmlxdWU6IFsnU3VkbyddIH0sXG4gICAgZ3JvdXBzOiBbJ3N5c2xvZycsICdjcm9uJ10sXG4gICAgZGVzY3JpcHRpb246IFwiUm9vdCdzIGNyb250YWIgZW50cnkgY2hhbmdlZC5cIixcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDI5NjAsXG4gICAgbGV2ZWw6IDIsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBkZWNvZGVkX2FzOiAnZ3Bhc3N3ZCcsIG1hdGNoOiAnYWRkZWQgYnknIH0sXG4gICAgZ3BnMTM6IFsnNy45JywgJzQuMTMnXSxcbiAgICBnZHByOiBbJ0lWXzMyLjInXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnUGVyc2lzdGVuY2UnXSwgaWQ6IFsnVDExMzYnXSwgdGVjaG5pcXVlOiBbJ0NyZWF0ZSBBY2NvdW50J10gfSxcbiAgICBncm91cHM6IFsnc3lzbG9nJywgJ3l1bSddLFxuICAgIGRlc2NyaXB0aW9uOiAnVXNlciBhZGRlZCB0byBncm91cC4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDIwLXN5c2xvZ19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMjk2MSxcbiAgICBsZXZlbDogNSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzI5NjAnLCBncm91cDogJ3N1ZG8nIH0sXG4gICAgZ3BnMTM6IFsnNy45JywgJzQuMTMnXSxcbiAgICBnZHByOiBbJ0lWXzMyLjInXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnUGVyc2lzdGVuY2UnXSwgaWQ6IFsnVDExMzYnXSwgdGVjaG5pcXVlOiBbJ0NyZWF0ZSBBY2NvdW50J10gfSxcbiAgICBncm91cHM6IFsnc3lzbG9nJywgJ3l1bSddLFxuICAgIGRlc2NyaXB0aW9uOiAnVXNlciBhZGRlZCB0byBncm91cCBzdWRvLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAyOTY0LFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGZyZXF1ZW5jeTogJzQnLCB0aW1lZnJhbWU6ICczMCcsIGlmX21hdGNoZWRfc2lkOiAnMjk2MycsIHNhbWVfc291cmNlX2lwOiAnJyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbXBhY3QnXSwgaWQ6IFsnVDE0OTknXSwgdGVjaG5pcXVlOiBbJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10gfSxcbiAgICBncm91cHM6IFsncmVjb24nLCAnc3lzbG9nJywgJ3BlcmRpdGlvbiddLFxuICAgIGRlc2NyaXB0aW9uOiAncGVyZGl0aW9uOiBNdWx0aXBsZSBjb25uZWN0aW9uIGF0dGVtcHRzIGZyb20gc2FtZSBzb3VyY2UuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyNS1zZW5kbWFpbF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzEwMixcbiAgICBsZXZlbDogNSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzMxMDEnLCBtYXRjaDogJ3JlamVjdD00NTEgNC4xLjggJyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydDb2xsZWN0aW9uJ10sIGlkOiBbJ1QxMTE0J10sIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJ10gfSxcbiAgICBncm91cHM6IFsnc3BhbScsICdzeXNsb2cnLCAnc2VuZG1haWwnXSxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdzZW5kbWFpbDogU2VuZGVyIGRvbWFpbiBkb2VzIG5vdCBoYXZlIGFueSB2YWxpZCBNWCByZWNvcmQgKFJlcXVlc3RlZCBhY3Rpb24gYWJvcnRlZCkuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyNS1zZW5kbWFpbF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzEwMyxcbiAgICBsZXZlbDogNixcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzMxMDEnLCBtYXRjaDogJ3JlamVjdD01NTAgNS4wLjAgfHJlamVjdD01NTMgNS4zLjAnIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbGxlY3Rpb24nXSwgaWQ6IFsnVDExMTQnXSwgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nXSB9LFxuICAgIGdyb3VwczogWydzcGFtJywgJ3N5c2xvZycsICdzZW5kbWFpbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnc2VuZG1haWw6IFJlamVjdGVkIGJ5IGFjY2VzcyBsaXN0ICg1NXg6IFJlcXVlc3RlZCBhY3Rpb24gbm90IHRha2VuKS4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDI1LXNlbmRtYWlsX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMTA0LFxuICAgIGxldmVsOiA2LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnMzEwMScsIG1hdGNoOiAncmVqZWN0PTU1MCA1LjcuMSAnIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbGxlY3Rpb24nXSwgaWQ6IFsnVDExMTQnXSwgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nXSB9LFxuICAgIGdyb3VwczogWydzcGFtJywgJ3N5c2xvZycsICdzZW5kbWFpbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnc2VuZG1haWw6IEF0dGVtcHQgdG8gdXNlIG1haWwgc2VydmVyIGFzIHJlbGF5ICg1NTA6IFJlcXVlc3RlZCBhY3Rpb24gbm90IHRha2VuKS4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDI1LXNlbmRtYWlsX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMTA1LFxuICAgIGxldmVsOiA1LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnMzEwMScsIG1hdGNoOiAncmVqZWN0PTU1MyA1LjEuOCAnIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbGxlY3Rpb24nXSwgaWQ6IFsnVDExMTQnXSwgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nXSB9LFxuICAgIGdyb3VwczogWydzcGFtJywgJ3N5c2xvZycsICdzZW5kbWFpbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnc2VuZG1haWw6IFNlbmRlciBkb21haW4gaXMgbm90IGZvdW5kICAoNTUzOiBSZXF1ZXN0ZWQgYWN0aW9uIG5vdCB0YWtlbikuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyNS1zZW5kbWFpbF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzEwNixcbiAgICBsZXZlbDogNSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzMxMDEnLCBtYXRjaDogJ3JlamVjdD01NTMgNS41LjQgJyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydDb2xsZWN0aW9uJ10sIGlkOiBbJ1QxMTE0J10sIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJ10gfSxcbiAgICBncm91cHM6IFsnc3BhbScsICdzeXNsb2cnLCAnc2VuZG1haWwnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3NlbmRtYWlsOiBTZW5kZXIgYWRkcmVzcyBkb2VzIG5vdCBoYXZlIGRvbWFpbiAoNTUzOiBSZXF1ZXN0ZWQgYWN0aW9uIG5vdCB0YWtlbikuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyNS1zZW5kbWFpbF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzEwOCxcbiAgICBsZXZlbDogNixcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzMxMDAnLCBtYXRjaDogJ3JlamVjdGluZyBjb21tYW5kcyBmcm9tJyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydDb2xsZWN0aW9uJ10sIGlkOiBbJ1QxMTE0J10sIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJ10gfSxcbiAgICBncm91cHM6IFsnc3BhbScsICdzeXNsb2cnLCAnc2VuZG1haWwnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3NlbmRtYWlsOiBTZW5kbWFpbCByZWplY3RlZCBkdWUgdG8gcHJlLWdyZWV0aW5nLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjUtc2VuZG1haWxfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMxNTEsXG4gICAgbGV2ZWw6IDEwLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgZnJlcXVlbmN5OiAnOCcsIHRpbWVmcmFtZTogJzEyMCcsIGlmX21hdGNoZWRfc2lkOiAnMzEwMicsIHNhbWVfc291cmNlX2lwOiAnJyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnQ29sbGVjdGlvbicsICdJbXBhY3QnXSxcbiAgICAgIGlkOiBbJ1QxMTE0JywgJ1QxNDk5J10sXG4gICAgICB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbicsICdFbmRwb2ludCBEZW5pYWwgb2YgU2VydmljZSddLFxuICAgIH0sXG4gICAgZ3JvdXBzOiBbJ211bHRpcGxlX3NwYW0nLCAnc3lzbG9nJywgJ3NlbmRtYWlsJ10sXG4gICAgZGVzY3JpcHRpb246ICdzZW5kbWFpbDogU2VuZGVyIGRvbWFpbiBoYXMgYm9ndXMgTVggcmVjb3JkLiBJdCBzaG91bGQgbm90IGJlIHNlbmRpbmcgZS1tYWlsLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjUtc2VuZG1haWxfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMxNTIsXG4gICAgbGV2ZWw6IDYsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICc4JywgdGltZWZyYW1lOiAnMTIwJywgaWZfbWF0Y2hlZF9zaWQ6ICczMTAzJywgc2FtZV9zb3VyY2VfaXA6ICcnIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogWydDb2xsZWN0aW9uJywgJ0ltcGFjdCddLFxuICAgICAgaWQ6IFsnVDExMTQnLCAnVDE0OTknXSxcbiAgICAgIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJywgJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10sXG4gICAgfSxcbiAgICBncm91cHM6IFsnbXVsdGlwbGVfc3BhbScsICdzeXNsb2cnLCAnc2VuZG1haWwnXSxcbiAgICBkZXNjcmlwdGlvbjpcbiAgICAgICdzZW5kbWFpbDogTXVsdGlwbGUgYXR0ZW1wdHMgdG8gc2VuZCBlLW1haWwgZnJvbSBhIHByZXZpb3VzbHkgcmVqZWN0ZWQgc2VuZGVyIChhY2Nlc3MpLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjUtc2VuZG1haWxfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMxNTMsXG4gICAgbGV2ZWw6IDYsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICc4JywgdGltZWZyYW1lOiAnMTIwJywgaWZfbWF0Y2hlZF9zaWQ6ICczMTA0Jywgc2FtZV9zb3VyY2VfaXA6ICcnIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogWydDb2xsZWN0aW9uJywgJ0ltcGFjdCddLFxuICAgICAgaWQ6IFsnVDExMTQnLCAnVDE0OTknXSxcbiAgICAgIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJywgJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10sXG4gICAgfSxcbiAgICBncm91cHM6IFsnbXVsdGlwbGVfc3BhbScsICdzeXNsb2cnLCAnc2VuZG1haWwnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3NlbmRtYWlsOiBNdWx0aXBsZSByZWxheWluZyBhdHRlbXB0cyBvZiBzcGFtLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjUtc2VuZG1haWxfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMxNTQsXG4gICAgbGV2ZWw6IDEwLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgZnJlcXVlbmN5OiAnOCcsIHRpbWVmcmFtZTogJzEyMCcsIGlmX21hdGNoZWRfc2lkOiAnMzEwNScsIHNhbWVfc291cmNlX2lwOiAnJyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnQ29sbGVjdGlvbicsICdJbXBhY3QnXSxcbiAgICAgIGlkOiBbJ1QxMTE0JywgJ1QxNDk5J10sXG4gICAgICB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbicsICdFbmRwb2ludCBEZW5pYWwgb2YgU2VydmljZSddLFxuICAgIH0sXG4gICAgZ3JvdXBzOiBbJ211bHRpcGxlX3NwYW0nLCAnc3lzbG9nJywgJ3NlbmRtYWlsJ10sXG4gICAgZGVzY3JpcHRpb246ICdzZW5kbWFpbDogTXVsdGlwbGUgYXR0ZW1wdHMgdG8gc2VuZCBlLW1haWwgZnJvbSBpbnZhbGlkL3Vua25vd24gc2VuZGVyIGRvbWFpbi4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDI1LXNlbmRtYWlsX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMTU1LFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGZyZXF1ZW5jeTogJzgnLCB0aW1lZnJhbWU6ICcxMjAnLCBpZl9tYXRjaGVkX3NpZDogJzMxMDYnLCBzYW1lX3NvdXJjZV9pcDogJycgfSxcbiAgICBwY2lfZHNzOiBbJzExLjQnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIG5pc3RfODAwXzUzOiBbJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M2LjEnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZToge1xuICAgICAgdGFjdGljOiBbJ0NvbGxlY3Rpb24nLCAnSW1wYWN0J10sXG4gICAgICBpZDogWydUMTExNCcsICdUMTQ5OSddLFxuICAgICAgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nLCAnRW5kcG9pbnQgRGVuaWFsIG9mIFNlcnZpY2UnXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydtdWx0aXBsZV9zcGFtJywgJ3N5c2xvZycsICdzZW5kbWFpbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnc2VuZG1haWw6IE11bHRpcGxlIGF0dGVtcHRzIHRvIHNlbmQgZS1tYWlsIGZyb20gaW52YWxpZC91bmtub3duIHNlbmRlci4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDI1LXNlbmRtYWlsX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMTU2LFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGZyZXF1ZW5jeTogJzEyJywgdGltZWZyYW1lOiAnMTIwJywgaWZfbWF0Y2hlZF9zaWQ6ICczMTA3Jywgc2FtZV9zb3VyY2VfaXA6ICcnIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogWydDb2xsZWN0aW9uJywgJ0ltcGFjdCddLFxuICAgICAgaWQ6IFsnVDExMTQnLCAnVDE0OTknXSxcbiAgICAgIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJywgJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10sXG4gICAgfSxcbiAgICBncm91cHM6IFsnbXVsdGlwbGVfc3BhbScsICdzeXNsb2cnLCAnc2VuZG1haWwnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3NlbmRtYWlsOiBNdWx0aXBsZSByZWplY3RlZCBlLW1haWxzIGZyb20gc2FtZSBzb3VyY2UgaXAuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyNS1zZW5kbWFpbF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzE1OCxcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICc4JywgdGltZWZyYW1lOiAnMTIwJywgaWZfbWF0Y2hlZF9zaWQ6ICczMTA4Jywgc2FtZV9zb3VyY2VfaXA6ICcnIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogWydDb2xsZWN0aW9uJywgJ0ltcGFjdCddLFxuICAgICAgaWQ6IFsnVDExMTQnLCAnVDE0OTknXSxcbiAgICAgIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJywgJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10sXG4gICAgfSxcbiAgICBncm91cHM6IFsnbXVsdGlwbGVfc3BhbScsICdzeXNsb2cnLCAnc2VuZG1haWwnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3NlbmRtYWlsOiBNdWx0aXBsZSBwcmUtZ3JlZXRpbmdzIHJlamVjdHMuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyNS1zZW5kbWFpbF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzE5MSxcbiAgICBsZXZlbDogNixcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzMxOTAnLCBtYXRjaDogJ15zZW5kZXIgY2hlY2sgZmFpbGVkfF5zZW5kZXIgY2hlY2sgdGVtcGZhaWxlZCcgfSxcbiAgICBwY2lfZHNzOiBbJzExLjQnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIG5pc3RfODAwXzUzOiBbJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M2LjEnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnQ29sbGVjdGlvbiddLCBpZDogWydUMTExNCddLCB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbiddIH0sXG4gICAgZ3JvdXBzOiBbJ3NtZi1zYXYnLCAnc3BhbScsICdzeXNsb2cnLCAnc2VuZG1haWwnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3NlbmRtYWlsOiBTTUYtU0FWIHNlbmRtYWlsIG1pbHRlciB1bmFibGUgdG8gdmVyaWZ5IGFkZHJlc3MgKFJFSkVDVEVEKS4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDMwLXBvc3RmaXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMzMDEsXG4gICAgbGV2ZWw6IDYsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICczMzAwJywgaWQ6ICdeNTU0JCcgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMScsICcxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS42JywgJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnLCAnQ0M2LjEnLCAnQ0M2LjgnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnQ29sbGVjdGlvbiddLCBpZDogWydUMTExNCddLCB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbiddIH0sXG4gICAgZ3JvdXBzOiBbJ3NwYW0nLCAnc3lzbG9nJywgJ3Bvc3RmaXgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1Bvc3RmaXg6IEF0dGVtcHQgdG8gdXNlIG1haWwgc2VydmVyIGFzIHJlbGF5IChjbGllbnQgaG9zdCByZWplY3RlZCkuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAzMC1wb3N0Zml4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMzAyLFxuICAgIGxldmVsOiA2LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnMzMwMCcsIGlkOiAnXjU1MCQnIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNicsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi4xJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbGxlY3Rpb24nXSwgaWQ6IFsnVDExMTQnXSwgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nXSB9LFxuICAgIGdyb3VwczogWydzcGFtJywgJ3N5c2xvZycsICdwb3N0Zml4J10sXG4gICAgZGVzY3JpcHRpb246ICdQb3N0Zml4OiBSZWplY3RlZCBieSBhY2Nlc3MgbGlzdCAoUmVxdWVzdGVkIGFjdGlvbiBub3QgdGFrZW4pLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMzAtcG9zdGZpeF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzMwMyxcbiAgICBsZXZlbDogNSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzMzMDAnLCBpZDogJ140NTAkJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJywgJzExLjQnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnLCAnU0kuNCddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMycsICdDQzYuMScsICdDQzYuOCddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydDb2xsZWN0aW9uJ10sIGlkOiBbJ1QxMTE0J10sIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJ10gfSxcbiAgICBncm91cHM6IFsnc3BhbScsICdzeXNsb2cnLCAncG9zdGZpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUG9zdGZpeDogU2VuZGVyIGRvbWFpbiBpcyBub3QgZm91bmQgKDQ1MDogUmVxdWVzdGVkIG1haWwgYWN0aW9uIG5vdCB0YWtlbikuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAzMC1wb3N0Zml4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMzA0LFxuICAgIGxldmVsOiA1LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnMzMwMCcsIGlkOiAnXjUwMyQnIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNicsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi4xJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbGxlY3Rpb24nXSwgaWQ6IFsnVDExMTQnXSwgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nXSB9LFxuICAgIGdyb3VwczogWydzcGFtJywgJ3N5c2xvZycsICdwb3N0Zml4J10sXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnUG9zdGZpeDogSW1wcm9wZXIgdXNlIG9mIFNNVFAgY29tbWFuZCBwaXBlbGluaW5nICg1MDM6IEJhZCBzZXF1ZW5jZSBvZiBjb21tYW5kcykuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAzMC1wb3N0Zml4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMzA1LFxuICAgIGxldmVsOiA1LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnMzMwMCcsIGlkOiAnXjUwNCQnIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNicsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi4xJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbGxlY3Rpb24nXSwgaWQ6IFsnVDExMTQnXSwgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nXSB9LFxuICAgIGdyb3VwczogWydzcGFtJywgJ3N5c2xvZycsICdwb3N0Zml4J10sXG4gICAgZGVzY3JpcHRpb246XG4gICAgICAnUG9zdGZpeDogUmVjaXBpZW50IGFkZHJlc3MgbXVzdCBjb250YWluIEZRRE4gKDUwNDogQ29tbWFuZCBwYXJhbWV0ZXIgbm90IGltcGxlbWVudGVkKS4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDMwLXBvc3RmaXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMzMDYsXG4gICAgbGV2ZWw6IDYsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICczMzAxLCAzMzAyJywgbWF0Y2g6ICcgYmxvY2tlZCB1c2luZyAnIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNicsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi4xJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbGxlY3Rpb24nXSwgaWQ6IFsnVDExMTQnXSwgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nXSB9LFxuICAgIGdyb3VwczogWydzcGFtJywgJ3N5c2xvZycsICdwb3N0Zml4J10sXG4gICAgZGVzY3JpcHRpb246ICdQb3N0Zml4OiBJUCBBZGRyZXNzIGJsYWNrLWxpc3RlZCBieSBhbnRpLXNwYW0gKGJsb2NrZWQpLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMzAtcG9zdGZpeF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzMzMCxcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczoge1xuICAgICAgaWdub3JlOiAnMjQwJyxcbiAgICAgIGlmX3NpZDogJzMzMjAnLFxuICAgICAgbWF0Y2g6IFtcbiAgICAgICAgJ2RlZmVyIHNlcnZpY2UgZmFpbHVyZXxSZXNvdXJjZSB0ZW1wb3JhcmlseSB1bmF2YWlsYWJsZXwnLFxuICAgICAgICAnXmZhdGFsOiB0aGUgUG9zdGZpeCBtYWlsIHN5c3RlbSBpcyBub3QgcnVubmluZycsXG4gICAgICBdLFxuICAgIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnSW1wYWN0J10sIGlkOiBbJ1QxNDk5J10sIHRlY2huaXF1ZTogWydFbmRwb2ludCBEZW5pYWwgb2YgU2VydmljZSddIH0sXG4gICAgZ3JvdXBzOiBbJ3NlcnZpY2VfYXZhaWxhYmlsaXR5JywgJ3N5c2xvZycsICdwb3N0Zml4J10sXG4gICAgZGVzY3JpcHRpb246ICdQb3N0Zml4IHByb2Nlc3MgZXJyb3IuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAzMC1wb3N0Zml4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMzM1LFxuICAgIGxldmVsOiA2LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnMzMyMCcsIG1hdGNoOiAnXnRvbyBtYW55ICcgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMScsICcxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS42JywgJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnLCAnQ0M2LjEnLCAnQ0M2LjgnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnQ29sbGVjdGlvbiddLCBpZDogWydUMTExNCddLCB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbiddIH0sXG4gICAgZ3JvdXBzOiBbJ3NwYW0nLCAnc3lzbG9nJywgJ3Bvc3RmaXgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1Bvc3RmaXg6IHRvbyBtYW55IGVycm9ycyBhZnRlciBSQ1BUIGZyb20gdW5rbm93bicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMzAtcG9zdGZpeF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzM1MSxcbiAgICBsZXZlbDogNixcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7XG4gICAgICBmcmVxdWVuY3k6ICckUE9TVEZJWF9GUkVRJyxcbiAgICAgIHRpbWVmcmFtZTogJzkwJyxcbiAgICAgIGlmX21hdGNoZWRfc2lkOiAnMzMwMScsXG4gICAgICBzYW1lX3NvdXJjZV9pcDogJycsXG4gICAgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMScsICcxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS42JywgJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnLCAnQ0M2LjEnLCAnQ0M2LjgnXSxcbiAgICBtaXRyZToge1xuICAgICAgdGFjdGljOiBbJ0NvbGxlY3Rpb24nLCAnSW1wYWN0J10sXG4gICAgICBpZDogWydUMTExNCcsICdUMTQ5OSddLFxuICAgICAgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nLCAnRW5kcG9pbnQgRGVuaWFsIG9mIFNlcnZpY2UnXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydtdWx0aXBsZV9zcGFtJywgJ3N5c2xvZycsICdwb3N0Zml4J10sXG4gICAgZGVzY3JpcHRpb246ICdQb3N0Zml4OiBNdWx0aXBsZSByZWxheWluZyBhdHRlbXB0cyBvZiBzcGFtLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMzAtcG9zdGZpeF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzM1MixcbiAgICBsZXZlbDogNixcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7XG4gICAgICBmcmVxdWVuY3k6ICckUE9TVEZJWF9GUkVRJyxcbiAgICAgIHRpbWVmcmFtZTogJzEyMCcsXG4gICAgICBpZl9tYXRjaGVkX3NpZDogJzMzMDInLFxuICAgICAgc2FtZV9zb3VyY2VfaXA6ICcnLFxuICAgIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnLCAnU0kuNCddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMycsICdDQzYuMScsICdDQzYuOCddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnQ29sbGVjdGlvbicsICdJbXBhY3QnXSxcbiAgICAgIGlkOiBbJ1QxMTE0JywgJ1QxNDk5J10sXG4gICAgICB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbicsICdFbmRwb2ludCBEZW5pYWwgb2YgU2VydmljZSddLFxuICAgIH0sXG4gICAgZ3JvdXBzOiBbJ211bHRpcGxlX3NwYW0nLCAnc3lzbG9nJywgJ3Bvc3RmaXgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1Bvc3RmaXg6IE11bHRpcGxlIGF0dGVtcHRzIHRvIHNlbmQgZS1tYWlsIGZyb20gYSByZWplY3RlZCBzZW5kZXIgSVAgKGFjY2VzcykuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAzMC1wb3N0Zml4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMzUzLFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7XG4gICAgICBmcmVxdWVuY3k6ICckUE9TVEZJWF9GUkVRJyxcbiAgICAgIHRpbWVmcmFtZTogJzEyMCcsXG4gICAgICBpZl9tYXRjaGVkX3NpZDogJzMzMDMnLFxuICAgICAgc2FtZV9zb3VyY2VfaXA6ICcnLFxuICAgIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNicsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi4xJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogWydDb2xsZWN0aW9uJywgJ0ltcGFjdCddLFxuICAgICAgaWQ6IFsnVDExMTQnLCAnVDE0OTknXSxcbiAgICAgIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJywgJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10sXG4gICAgfSxcbiAgICBncm91cHM6IFsnbXVsdGlwbGVfc3BhbScsICdzeXNsb2cnLCAncG9zdGZpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUG9zdGZpeDogTXVsdGlwbGUgYXR0ZW1wdHMgdG8gc2VuZCBlLW1haWwgZnJvbSBpbnZhbGlkL3Vua25vd24gc2VuZGVyIGRvbWFpbi4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDMwLXBvc3RmaXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMzNTQsXG4gICAgbGV2ZWw6IDEyLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHtcbiAgICAgIGZyZXF1ZW5jeTogJyRQT1NURklYX0ZSRVEnLFxuICAgICAgdGltZWZyYW1lOiAnMTIwJyxcbiAgICAgIGlmX21hdGNoZWRfc2lkOiAnMzMwNCcsXG4gICAgICBzYW1lX3NvdXJjZV9pcDogJycsXG4gICAgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMScsICcxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS42JywgJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnLCAnQ0M2LjEnLCAnQ0M2LjgnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnQ29sbGVjdGlvbiddLCBpZDogWydUMTExNCddLCB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbiddIH0sXG4gICAgZ3JvdXBzOiBbJ211bHRpcGxlX3NwYW0nLCAnc3lzbG9nJywgJ3Bvc3RmaXgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1Bvc3RmaXg6IE11bHRpcGxlIG1pc3VzZSBvZiBTTVRQIHNlcnZpY2UgKGJhZCBzZXF1ZW5jZSBvZiBjb21tYW5kcykuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAzMC1wb3N0Zml4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMzU1LFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7XG4gICAgICBmcmVxdWVuY3k6ICckUE9TVEZJWF9GUkVRJyxcbiAgICAgIHRpbWVmcmFtZTogJzEyMCcsXG4gICAgICBpZl9tYXRjaGVkX3NpZDogJzMzMDUnLFxuICAgICAgc2FtZV9zb3VyY2VfaXA6ICcnLFxuICAgIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNicsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi4xJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogWydDb2xsZWN0aW9uJywgJ0ltcGFjdCddLFxuICAgICAgaWQ6IFsnVDExMTQnLCAnVDE0OTknXSxcbiAgICAgIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJywgJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10sXG4gICAgfSxcbiAgICBncm91cHM6IFsnbXVsdGlwbGVfc3BhbScsICdzeXNsb2cnLCAncG9zdGZpeCddLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ1Bvc3RmaXg6IE11bHRpcGxlIGF0dGVtcHRzIHRvIHNlbmQgZS1tYWlsIHRvIGludmFsaWQgcmVjaXBpZW50IG9yIGZyb20gdW5rbm93biBzZW5kZXIgZG9tYWluLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMzAtcG9zdGZpeF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzM1NixcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczoge1xuICAgICAgZnJlcXVlbmN5OiAnJFBPU1RGSVhfRlJFUScsXG4gICAgICB0aW1lZnJhbWU6ICcxMjAnLFxuICAgICAgaWdub3JlOiAnMzAnLFxuICAgICAgaWZfbWF0Y2hlZF9zaWQ6ICczMzA2JyxcbiAgICAgIHNhbWVfc291cmNlX2lwOiAnJyxcbiAgICB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJywgJzExLjQnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnLCAnU0kuNCddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMycsICdDQzYuMScsICdDQzYuOCddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbXBhY3QnXSwgaWQ6IFsnVDE0OTknXSwgdGVjaG5pcXVlOiBbJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10gfSxcbiAgICBncm91cHM6IFsnbXVsdGlwbGVfc3BhbScsICdzeXNsb2cnLCAncG9zdGZpeCddLFxuICAgIGRlc2NyaXB0aW9uOlxuICAgICAgJ1Bvc3RmaXg6IE11bHRpcGxlIGF0dGVtcHRzIHRvIHNlbmQgZS1tYWlsIGZyb20gYmxhY2stbGlzdGVkIElQIGFkZHJlc3MgKGJsb2NrZWQpLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMzAtcG9zdGZpeF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzM1NyxcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczoge1xuICAgICAgZnJlcXVlbmN5OiAnOCcsXG4gICAgICB0aW1lZnJhbWU6ICcxMjAnLFxuICAgICAgaWdub3JlOiAnNjAnLFxuICAgICAgaWZfbWF0Y2hlZF9zaWQ6ICczMzMyJyxcbiAgICAgIHNhbWVfc291cmNlX2lwOiAnJyxcbiAgICB9LFxuICAgIHBjaV9kc3M6IFsnMTAuMi40JywgJzEwLjIuNScsICcxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnLCAnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjE0JywgJ0FDLjcnLCAnU0kuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydDcmVkZW50aWFsIEFjY2VzcyddLCBpZDogWydUMTExMCddLCB0ZWNobmlxdWU6IFsnQnJ1dGUgRm9yY2UnXSB9LFxuICAgIGdyb3VwczogWydhdXRoZW50aWNhdGlvbl9mYWlsdXJlcycsICdzeXNsb2cnLCAncG9zdGZpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUG9zdGZpeDogTXVsdGlwbGUgU0FTTCBhdXRoZW50aWNhdGlvbiBmYWlsdXJlcy4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDMwLXBvc3RmaXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMzOTYsXG4gICAgbGV2ZWw6IDYsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICczMzk1JywgbWF0Y2g6ICd2ZXJpZmljYXRpb24nIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNicsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi4xJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbGxlY3Rpb24nXSwgaWQ6IFsnVDExMTQnXSwgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nXSB9LFxuICAgIGdyb3VwczogWydzcGFtJywgJ3N5c2xvZycsICdwb3N0Zml4J10sXG4gICAgZGVzY3JpcHRpb246ICdQb3N0Zml4OiBob3N0bmFtZSB2ZXJpZmljYXRpb24gZmFpbGVkJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAzMC1wb3N0Zml4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzMzk3LFxuICAgIGxldmVsOiA2LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnMzM5NScsIG1hdGNoOiAnUkJMJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJywgJzExLjQnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnLCAnU0kuNCddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMycsICdDQzYuMScsICdDQzYuOCddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydDb2xsZWN0aW9uJ10sIGlkOiBbJ1QxMTE0J10sIHRlY2huaXF1ZTogWydFbWFpbCBDb2xsZWN0aW9uJ10gfSxcbiAgICBncm91cHM6IFsnc3BhbScsICdzeXNsb2cnLCAncG9zdGZpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUG9zdGZpeDogUkJMIGxvb2t1cCBlcnJvcjogSG9zdCBvciBkb21haW4gbmFtZSBub3QgZm91bmQnLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDMwLXBvc3RmaXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDMzOTgsXG4gICAgbGV2ZWw6IDYsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICczMzk1JywgbWF0Y2g6ICdNQUlMfGRvZXMgbm90IHJlc29sdmUgdG8gYWRkcmVzcycgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMScsICcxMS40J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS42JywgJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnLCAnQ0M2LjEnLCAnQ0M2LjgnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnQ29sbGVjdGlvbiddLCBpZDogWydUMTExNCddLCB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbiddIH0sXG4gICAgZ3JvdXBzOiBbJ3NwYW0nLCAnc3lzbG9nJywgJ3Bvc3RmaXgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1Bvc3RmaXg6IElsbGVnYWwgYWRkcmVzcyBmcm9tIHVua25vd24gc2VuZGVyJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA0MC1pbWFwZF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzYwMixcbiAgICBsZXZlbDogMyxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzM2MDAnLCBtYXRjaDogJ0F1dGhlbnRpY2F0ZWQgdXNlcj0nIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnXSxcbiAgICBncGcxMzogWyc3LjEnXSxcbiAgICBnZHByOiBbJ0lWXzMyLjInXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS4xNCcsICdBQy43J10sXG4gICAgdHNjOiBbJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0luaXRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMDc4J10sIHRlY2huaXF1ZTogWydWYWxpZCBBY2NvdW50cyddIH0sXG4gICAgZ3JvdXBzOiBbJ2F1dGhlbnRpY2F0aW9uX3N1Y2Nlc3MnLCAnc3lzbG9nJywgJ2ltYXBkJ10sXG4gICAgZGVzY3JpcHRpb246ICdJbWFwZCB1c2VyIGxvZ2luLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNDAtaW1hcGRfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDM2NTEsXG4gICAgbGV2ZWw6IDEwLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHtcbiAgICAgIGZyZXF1ZW5jeTogJyRJTUFQRF9GUkVRJyxcbiAgICAgIHRpbWVmcmFtZTogJzEyMCcsXG4gICAgICBpZl9tYXRjaGVkX3NpZDogJzM2MDEnLFxuICAgICAgc2FtZV9zb3VyY2VfaXA6ICcnLFxuICAgIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjQnLCAnMTAuMi41JywgJzExLjQnXSxcbiAgICBncGcxMzogWyc3LjEnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCcsICdJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNycsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NyZWRlbnRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMTEwJ10sIHRlY2huaXF1ZTogWydCcnV0ZSBGb3JjZSddIH0sXG4gICAgZ3JvdXBzOiBbJ2F1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzJywgJ3N5c2xvZycsICdpbWFwZCddLFxuICAgIGRlc2NyaXB0aW9uOiAnSW1hcGQgTXVsdGlwbGUgZmFpbGVkIGxvZ2lucyBmcm9tIHNhbWUgc291cmNlIGlwLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNDUtbWFpbHNjYW5uZXJfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDM3NTEsXG4gICAgbGV2ZWw6IDYsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICc4JywgdGltZWZyYW1lOiAnMTgwJywgaWZfbWF0Y2hlZF9zaWQ6ICczNzAyJywgc2FtZV9zb3VyY2VfaXA6ICcnIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnXSxcbiAgICBncGcxMzogWyc0LjEyJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS42J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogWydDcmVkZW50aWFsIEFjY2VzcycsICdDb2xsZWN0aW9uJ10sXG4gICAgICBpZDogWydUMTExMCcsICdUMTExNCddLFxuICAgICAgdGVjaG5pcXVlOiBbJ0JydXRlIEZvcmNlJywgJ0VtYWlsIENvbGxlY3Rpb24nXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydtdWx0aXBsZV9zcGFtJywgJ3N5c2xvZycsICdtYWlsc2Nhbm5lciddLFxuICAgIGRlc2NyaXB0aW9uOiAnbWFpbHNjYW5uZXI6IE11bHRpcGxlIGF0dGVtcHRzIG9mIHNwYW0uJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA1MC1tcy1leGNoYW5nZV9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzg1MSxcbiAgICBsZXZlbDogOSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7XG4gICAgICBmcmVxdWVuY3k6ICcxMicsXG4gICAgICB0aW1lZnJhbWU6ICcxMjAnLFxuICAgICAgaWdub3JlOiAnMTIwJyxcbiAgICAgIGlmX21hdGNoZWRfc2lkOiAnMzgwMScsXG4gICAgICBzYW1lX3NvdXJjZV9pcDogJycsXG4gICAgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMSddLFxuICAgIGdwZzEzOiBbJzQuMTInXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZToge1xuICAgICAgdGFjdGljOiBbJ0NvbGxlY3Rpb24nLCAnSW1wYWN0J10sXG4gICAgICBpZDogWydUMTExNCcsICdUMTQ5OSddLFxuICAgICAgdGVjaG5pcXVlOiBbJ0VtYWlsIENvbGxlY3Rpb24nLCAnRW5kcG9pbnQgRGVuaWFsIG9mIFNlcnZpY2UnXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydtdWx0aXBsZV9zcGFtJywgJ21zJywgJ2V4Y2hhbmdlJ10sXG4gICAgZGVzY3JpcHRpb246ICdtcy1leGNoYW5nZTogTXVsdGlwbGUgZS1tYWlsIGF0dGVtcHRzIHRvIGFuIGludmFsaWQgYWNjb3VudC4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDUwLW1zLWV4Y2hhbmdlX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzODUyLFxuICAgIGxldmVsOiA5LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHtcbiAgICAgIGZyZXF1ZW5jeTogJzE0JyxcbiAgICAgIHRpbWVmcmFtZTogJzEyMCcsXG4gICAgICBpZ25vcmU6ICcyNDAnLFxuICAgICAgaWZfbWF0Y2hlZF9zaWQ6ICczODAyJyxcbiAgICAgIHNhbWVfc291cmNlX2lwOiAnJyxcbiAgICB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJ10sXG4gICAgZ3BnMTM6IFsnNC4xMiddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNiddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnQ29sbGVjdGlvbicsICdJbXBhY3QnXSxcbiAgICAgIGlkOiBbJ1QxMTE0JywgJ1QxNDk5J10sXG4gICAgICB0ZWNobmlxdWU6IFsnRW1haWwgQ29sbGVjdGlvbicsICdFbmRwb2ludCBEZW5pYWwgb2YgU2VydmljZSddLFxuICAgIH0sXG4gICAgZ3JvdXBzOiBbJ211bHRpcGxlX3NwYW0nLCAnbXMnLCAnZXhjaGFuZ2UnXSxcbiAgICBkZXNjcmlwdGlvbjogJ21zLWV4Y2hhbmdlOiBNdWx0aXBsZSBlLW1haWwgNTAwIGVycm9yIGNvZGUgKHNwYW0pLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNTUtY291cmllcl9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzkwNCxcbiAgICBsZXZlbDogMyxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzM5MDAnLCBtYXRjaDogJ15MT0dJTiwnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnXSxcbiAgICBncGcxMzogWyc3LjEnLCAnNy4yJ10sXG4gICAgZ2RwcjogWydJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNyddLFxuICAgIHRzYzogWydDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbml0aWFsIEFjY2VzcyddLCBpZDogWydUMTA3OCddLCB0ZWNobmlxdWU6IFsnVmFsaWQgQWNjb3VudHMnXSB9LFxuICAgIGdyb3VwczogWydhdXRoZW50aWNhdGlvbl9zdWNjZXNzJywgJ3N5c2xvZycsICdjb3VyaWVyJ10sXG4gICAgZGVzY3JpcHRpb246ICdDb3VyaWVyIChpbWFwL3BvcDMpIGF1dGhlbnRpY2F0aW9uIHN1Y2Nlc3MuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA1NS1jb3VyaWVyX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiAzOTEwLFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGZyZXF1ZW5jeTogJzEyJywgdGltZWZyYW1lOiAnMzAnLCBpZl9tYXRjaGVkX3NpZDogJzM5MDInLCBzYW1lX3NvdXJjZV9pcDogJycgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjIuNCcsICcxMC4yLjUnLCAnMTEuNCddLFxuICAgIGdwZzEzOiBbJzcuMSddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJywgJ0lWXzMyLjInXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS4xNCcsICdBQy43JywgJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M2LjEnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnQ3JlZGVudGlhbCBBY2Nlc3MnXSwgaWQ6IFsnVDExMTAnXSwgdGVjaG5pcXVlOiBbJ0JydXRlIEZvcmNlJ10gfSxcbiAgICBncm91cHM6IFsnYXV0aGVudGljYXRpb25fZmFpbHVyZXMnLCAnc3lzbG9nJywgJ2NvdXJpZXInXSxcbiAgICBkZXNjcmlwdGlvbjogJ0NvdXJpZXIgYnJ1dGUgZm9yY2UgKG11bHRpcGxlIGZhaWxlZCBsb2dpbnMpLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNTUtY291cmllcl9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogMzkxMSxcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICcxNycsIHRpbWVmcmFtZTogJzMwJywgaWZfbWF0Y2hlZF9zaWQ6ICczOTAxJywgc2FtZV9zb3VyY2VfaXA6ICcnIH0sXG4gICAgcGNpX2RzczogWycxMC42LjEnLCAnMTEuNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNicsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNy4yJywgJ0NDNy4zJywgJ0NDNi4xJywgJ0NDNi44J10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NyZWRlbnRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMTEwJ10sIHRlY2huaXF1ZTogWydCcnV0ZSBGb3JjZSddIH0sXG4gICAgZ3JvdXBzOiBbJ3JlY29uJywgJ3N5c2xvZycsICdjb3VyaWVyJ10sXG4gICAgZGVzY3JpcHRpb246ICdDb3VyaWVyOiBNdWx0aXBsZSBjb25uZWN0aW9uIGF0dGVtcHRzIGZyb20gc2FtZSBzb3VyY2UuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA2NS1waXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDQzMjMsXG4gICAgbGV2ZWw6IDMsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc0MzE0JywgaWQ6ICdeNi02MDUwMDUnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnXSxcbiAgICBncGcxMzogWyc3LjgnXSxcbiAgICBnZHByOiBbJ0lWXzMyLjInXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS4xNCcsICdBQy43J10sXG4gICAgdHNjOiBbJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0luaXRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMDc4J10sIHRlY2huaXF1ZTogWydWYWxpZCBBY2NvdW50cyddIH0sXG4gICAgZ3JvdXBzOiBbJ2F1dGhlbnRpY2F0aW9uX3N1Y2Nlc3MnLCAnc3lzbG9nJywgJ3BpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUElYOiBTdWNjZXNzZnVsIGxvZ2luLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNjUtcGl4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA0MzI1LFxuICAgIGxldmVsOiA4LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNDMxMycsIGlkOiAnXjQtNDA1MDAxJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJ10sXG4gICAgZ3BnMTM6IFsnNC4xMiddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNiddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnQ29tbWFuZCBhbmQgQ29udHJvbCddLFxuICAgICAgaWQ6IFsnVDEwOTUnXSxcbiAgICAgIHRlY2huaXF1ZTogWydTdGFuZGFyZCBOb24tQXBwbGljYXRpb24gTGF5ZXIgUHJvdG9jb2wnXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAncGl4J10sXG4gICAgZGVzY3JpcHRpb246ICdQSVg6IEFSUCBjb2xsaXNpb24gZGV0ZWN0ZWQuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA2NS1waXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDQzMzUsXG4gICAgbGV2ZWw6IDMsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc0MzE0JywgaWQ6ICdeNi0xMTMwMDQnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnXSxcbiAgICBncGcxMzogWyc3LjEnLCAnNy4yJ10sXG4gICAgZ2RwcjogWydJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNyddLFxuICAgIHRzYzogWydDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbml0aWFsIEFjY2VzcyddLCBpZDogWydUMTA3OCddLCB0ZWNobmlxdWU6IFsnVmFsaWQgQWNjb3VudHMnXSB9LFxuICAgIGdyb3VwczogWydhdXRoZW50aWNhdGlvbl9zdWNjZXNzJywgJ3N5c2xvZycsICdwaXgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1BJWDogQUFBIChWUE4pIGF1dGhlbnRpY2F0aW9uIHN1Y2Nlc3NmdWwuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA2NS1waXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDQzMzYsXG4gICAgbGV2ZWw6IDgsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc0MzE0JywgaWQ6ICdeNi0xMTMwMDYnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjQnLCAnMTAuMi41J10sXG4gICAgZ3BnMTM6IFsnNy4xJywgJzcuNSddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJywgJ0lWXzMyLjInXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS4xNCcsICdBQy43J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0luaXRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMTMzJ10sIHRlY2huaXF1ZTogWydFeHRlcm5hbCBSZW1vdGUgU2VydmljZXMnXSB9LFxuICAgIGdyb3VwczogWydhdXRoZW50aWNhdGlvbl9mYWlsZWQnLCAnc3lzbG9nJywgJ3BpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUElYOiBBQUEgKFZQTikgdXNlciBsb2NrZWQgb3V0LicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNjUtcGl4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA0MzM3LFxuICAgIGxldmVsOiA4LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNDMxMicsIGlkOiAnXjMtMjAxMDA4JyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJ10sXG4gICAgZ3BnMTM6IFsnNC4xMiddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNiddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbml0aWFsIEFjY2VzcyddLCBpZDogWydUMTEzMyddLCB0ZWNobmlxdWU6IFsnRXh0ZXJuYWwgUmVtb3RlIFNlcnZpY2VzJ10gfSxcbiAgICBncm91cHM6IFsnc2VydmljZV9hdmFpbGFiaWxpdHknLCAnc3lzbG9nJywgJ3BpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUElYOiBUaGUgUElYIGlzIGRpc2FsbG93aW5nIG5ldyBjb25uZWN0aW9ucy4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDY1LXBpeF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNDMzOSxcbiAgICBsZXZlbDogOCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzQzMTQnLCBpZDogJ141LTExMTAwMycgfSxcbiAgICBwY2lfZHNzOiBbJzEuMS4xJywgJzEwLjQnXSxcbiAgICBncGcxMzogWyc0LjEzJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmEuMScsICcxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydDTS4zJywgJ0NNLjUnLCAnQVUuOCddLFxuICAgIHRzYzogWydDQzguMScsICdDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydEZWZlbnNlIEV2YXNpb24nXSwgaWQ6IFsnVDEwODknXSwgdGVjaG5pcXVlOiBbJ0Rpc2FibGluZyBTZWN1cml0eSBUb29scyddIH0sXG4gICAgZ3JvdXBzOiBbJ2NvbmZpZ19jaGFuZ2VkJywgJ3N5c2xvZycsICdwaXgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1BJWDogRmlyZXdhbGwgY29uZmlndXJhdGlvbiBkZWxldGVkLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNjUtcGl4X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA0MzQwLFxuICAgIGxldmVsOiA4LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNDMxNCcsIGlkOiAnXjUtMTExMDA1fF41LTExMTAwNHxeNS0xMTEwMDJ8XjUtMTExMDA3JyB9LFxuICAgIHBjaV9kc3M6IFsnMS4xLjEnLCAnMTAuNCddLFxuICAgIGdwZzEzOiBbJzQuMTMnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYS4xJywgJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0NNLjMnLCAnQ00uNScsICdBVS44J10sXG4gICAgdHNjOiBbJ0NDOC4xJywgJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0RlZmVuc2UgRXZhc2lvbiddLCBpZDogWydUMTA4OSddLCB0ZWNobmlxdWU6IFsnRGlzYWJsaW5nIFNlY3VyaXR5IFRvb2xzJ10gfSxcbiAgICBncm91cHM6IFsnY29uZmlnX2NoYW5nZWQnLCAnc3lzbG9nJywgJ3BpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUElYOiBGaXJld2FsbCBjb25maWd1cmF0aW9uIGNoYW5nZWQuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA2NS1waXhfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDQzNDIsXG4gICAgbGV2ZWw6IDgsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc0MzE0JywgaWQ6ICdeNS01MDIxMDF8XjUtNTAyMTAyJyB9LFxuICAgIHBjaV9kc3M6IFsnOC4xLjInLCAnMTAuMi41J10sXG4gICAgZ3BnMTM6IFsnNC4xMyddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJywgJ0lWXzMyLjInXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmEuMi5JJywgJzE2NC4zMTIuYS4yLklJJywgJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FDLjInLCAnSUEuNCcsICdBVS4xNCcsICdBQy43J10sXG4gICAgdHNjOiBbJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogWydEZWZlbnNlIEV2YXNpb24nLCAnSW5pdGlhbCBBY2Nlc3MnXSxcbiAgICAgIGlkOiBbJ1QxMDg5JywgJ1QxMTMzJ10sXG4gICAgICB0ZWNobmlxdWU6IFsnRGlzYWJsaW5nIFNlY3VyaXR5IFRvb2xzJywgJ0V4dGVybmFsIFJlbW90ZSBTZXJ2aWNlcyddLFxuICAgIH0sXG4gICAgZ3JvdXBzOiBbJ2FkZHVzZXInLCAnYWNjb3VudF9jaGFuZ2VkJywgJ3N5c2xvZycsICdwaXgnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1BJWDogVXNlciBjcmVhdGVkIG9yIG1vZGlmaWVkIG9uIHRoZSBGaXJld2FsbC4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDY1LXBpeF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNDM4NixcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICcxMCcsIHRpbWVmcmFtZTogJzI0MCcsIGlmX21hdGNoZWRfc2lkOiAnNDMzNCcsIHNhbWVfc291cmNlX2lwOiAnJyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNCcsICcxMC4yLjQnLCAnMTAuMi41J10sXG4gICAgZ3BnMTM6IFsnNy4xJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnLCAnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ1NJLjQnLCAnQVUuMTQnLCAnQUMuNyddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnQ3JlZGVudGlhbCBBY2Nlc3MnLCAnSW5pdGlhbCBBY2Nlc3MnXSxcbiAgICAgIGlkOiBbJ1QxMTEwJywgJ1QxMTMzJ10sXG4gICAgICB0ZWNobmlxdWU6IFsnQnJ1dGUgRm9yY2UnLCAnRXh0ZXJuYWwgUmVtb3RlIFNlcnZpY2VzJ10sXG4gICAgfSxcbiAgICBncm91cHM6IFsnYXV0aGVudGljYXRpb25fZmFpbHVyZXMnLCAnc3lzbG9nJywgJ3BpeCddLFxuICAgIGRlc2NyaXB0aW9uOiAnUElYOiBNdWx0aXBsZSBBQUEgKFZQTikgYXV0aGVudGljYXRpb24gZmFpbHVyZXMuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA3MC1uZXRzY3JlZW5md19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNDUwNSxcbiAgICBsZXZlbDogMTEsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc0NTAzJywgaWQ6ICdeMDAwMjcnIH0sXG4gICAgcGNpX2RzczogWycxLjQnLCAnMTAuNi4xJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmEuMScsICcxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydTQy43JywgJ0FVLjYnXSxcbiAgICB0c2M6IFsnQ0M2LjcnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnSW1wYWN0J10sIGlkOiBbJ1QxNDg1J10sIHRlY2huaXF1ZTogWydEYXRhIERlc3RydWN0aW9uJ10gfSxcbiAgICBncm91cHM6IFsnc2VydmljZV9hdmFpbGFiaWxpdHknLCAnbmV0c2NyZWVuZncnXSxcbiAgICBkZXNjcmlwdGlvbjogJ05ldHNjcmVlbiBFcmFzZSBzZXF1ZW5jZSBzdGFydGVkLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNzAtbmV0c2NyZWVuZndfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDQ1MDYsXG4gICAgbGV2ZWw6IDgsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc0NTAxJywgaWQ6ICdeMDAwMDInIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnLCAnMTAuMi4yJ10sXG4gICAgZ3BnMTM6IFsnNy44J10sXG4gICAgZ2RwcjogWydJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNycsICdBQy42J10sXG4gICAgdHNjOiBbJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0luaXRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMDc4J10sIHRlY2huaXF1ZTogWydWYWxpZCBBY2NvdW50cyddIH0sXG4gICAgZ3JvdXBzOiBbJ2F1dGhlbnRpY2F0aW9uX3N1Y2Nlc3MnLCAnbmV0c2NyZWVuZncnXSxcbiAgICBkZXNjcmlwdGlvbjogJ05ldHNjcmVlbiBmaXJld2FsbDogU3VjY2Vzc2Z1bGwgYWRtaW4gbG9naW4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDcwLW5ldHNjcmVlbmZ3X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA0NTA3LFxuICAgIGxldmVsOiA4LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNDUwMicsIGlkOiAnXjAwNTE1JyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuMi41JywgJzEwLjIuMiddLFxuICAgIGdwZzEzOiBbJzcuOCddLFxuICAgIGdkcHI6IFsnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjE0JywgJ0FDLjcnLCAnQUMuNiddLFxuICAgIHRzYzogWydDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbml0aWFsIEFjY2VzcyddLCBpZDogWydUMTA3OCddLCB0ZWNobmlxdWU6IFsnVmFsaWQgQWNjb3VudHMnXSB9LFxuICAgIGdyb3VwczogWydhdXRoZW50aWNhdGlvbl9zdWNjZXNzJywgJ25ldHNjcmVlbmZ3J10sXG4gICAgZGVzY3JpcHRpb246ICdOZXRzY3JlZW4gZmlyZXdhbGw6IFN1Y2Nlc3NmdWxsIGFkbWluIGxvZ2luJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA3MC1uZXRzY3JlZW5md19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNDUwOSxcbiAgICBsZXZlbDogOCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzQ1MDQnLCBpZDogJ14wMDc2NycgfSxcbiAgICBwY2lfZHNzOiBbJzEuMS4xJ10sXG4gICAgZ3BnMTM6IFsnNC4xMiddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5hLjEnXSxcbiAgICBuaXN0XzgwMF81MzogWydDTS4zJywgJ0NNLjUnXSxcbiAgICB0c2M6IFsnQ0M4LjEnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnRGVmZW5zZSBFdmFzaW9uJ10sIGlkOiBbJ1QxMDg5J10sIHRlY2huaXF1ZTogWydEaXNhYmxpbmcgU2VjdXJpdHkgVG9vbHMnXSB9LFxuICAgIGdyb3VwczogWydjb25maWdfY2hhbmdlZCcsICduZXRzY3JlZW5mdyddLFxuICAgIGRlc2NyaXB0aW9uOiAnTmV0c2NyZWVuIGZpcmV3YWxsOiBjb25maWd1cmF0aW9uIGNoYW5nZWQuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA3MC1uZXRzY3JlZW5md19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNDU1MCxcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczoge1xuICAgICAgZnJlcXVlbmN5OiAnNicsXG4gICAgICB0aW1lZnJhbWU6ICcxODAnLFxuICAgICAgaWdub3JlOiAnNjAnLFxuICAgICAgaWZfbWF0Y2hlZF9zaWQ6ICc0NTAzJyxcbiAgICAgIHNhbWVfc291cmNlX2lwOiAnJyxcbiAgICB9LFxuICAgIHBjaV9kc3M6IFsnMS40JywgJzEwLjYuMScsICcxMS40J10sXG4gICAgZ3BnMTM6IFsnNC4xJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmEuMScsICcxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydTQy43JywgJ0FVLjYnLCAnU0kuNCddLFxuICAgIHRzYzogWydDQzYuNycsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMycsICdDQzYuMSddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbXBhY3QnXSwgaWQ6IFsnVDE0OTknXSwgdGVjaG5pcXVlOiBbJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10gfSxcbiAgICBncm91cHM6IFsnbmV0c2NyZWVuZncnXSxcbiAgICBkZXNjcmlwdGlvbjogJ05ldHNjcmVlbiBmaXJld2FsbDogTXVsdGlwbGUgY3JpdGljYWwgbWVzc2FnZXMgZnJvbSBzYW1lIHNvdXJjZSBJUC4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDcwLW5ldHNjcmVlbmZ3X3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA0NTUxLFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGZyZXF1ZW5jeTogJzgnLCB0aW1lZnJhbWU6ICcxODAnLCBpZ25vcmU6ICc2MCcsIGlmX21hdGNoZWRfc2lkOiAnNDUwMycgfSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnSW1wYWN0J10sIGlkOiBbJ1QxNDk5J10sIHRlY2huaXF1ZTogWydFbmRwb2ludCBEZW5pYWwgb2YgU2VydmljZSddIH0sXG4gICAgZ3JvdXBzOiBbJ25ldHNjcmVlbmZ3J10sXG4gICAgZGVzY3JpcHRpb246ICdOZXRzY3JlZW4gZmlyZXdhbGw6IE11bHRpcGxlIGNyaXRpY2FsIG1lc3NhZ2VzLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwNzUtY2lzY28taW9zX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA0NzIyLFxuICAgIGxldmVsOiAzLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNDcxNScsIGlkOiAnXiVTRUNfTE9HSU4tNS1MT0dJTl9TVUNDRVNTJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuMi41J10sXG4gICAgZ3BnMTM6IFsnMy42J10sXG4gICAgZ2RwcjogWydJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNyddLFxuICAgIHRzYzogWydDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbml0aWFsIEFjY2VzcyddLCBpZDogWydUMTA3OCddLCB0ZWNobmlxdWU6IFsnVmFsaWQgQWNjb3VudHMnXSB9LFxuICAgIGdyb3VwczogWydhdXRoZW50aWNhdGlvbl9zdWNjZXNzJywgJ3N5c2xvZycsICdjaXNjb19pb3MnXSxcbiAgICBkZXNjcmlwdGlvbjogJ0Npc2NvIElPUzogU3VjY2Vzc2Z1bCBsb2dpbiB0byB0aGUgcm91dGVyLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwODAtc29uaWN3YWxsX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA0ODEwLFxuICAgIGxldmVsOiAzLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNDgwNicsIGlkOiAnXjIzNiQnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnXSxcbiAgICBncGcxMzogWyczLjYnXSxcbiAgICBnZHByOiBbJ0lWXzMyLjInXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS4xNCcsICdBQy43J10sXG4gICAgdHNjOiBbJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0luaXRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMDc4J10sIHRlY2huaXF1ZTogWydWYWxpZCBBY2NvdW50cyddIH0sXG4gICAgZ3JvdXBzOiBbJ2F1dGhlbnRpY2F0aW9uX3N1Y2Nlc3MnLCAnc3lzbG9nJywgJ3Nvbmljd2FsbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnU29uaWNXYWxsOiBGaXJld2FsbCBhZG1pbmlzdHJhdG9yIGxvZ2luLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwODAtc29uaWN3YWxsX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA0ODUxLFxuICAgIGxldmVsOiAxMCxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGZyZXF1ZW5jeTogJzgnLCB0aW1lZnJhbWU6ICcxMjAnLCBpZ25vcmU6ICc2MCcsIGlmX21hdGNoZWRfc2lkOiAnNDgwMycgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMSddLFxuICAgIGdwZzEzOiBbJzMuNSddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNiddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbXBhY3QnXSwgaWQ6IFsnVDE0OTknXSwgdGVjaG5pcXVlOiBbJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10gfSxcbiAgICBncm91cHM6IFsnc2VydmljZV9hdmFpbGFiaWxpdHknLCAnc3lzbG9nJywgJ3Nvbmljd2FsbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnU29uaWNXYWxsOiBNdWx0aXBsZSBmaXJld2FsbCBlcnJvciBtZXNzYWdlcy4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDIwLXN5c2xvZ19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTEwMyxcbiAgICBsZXZlbDogOSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzUxMDAnLCBtYXRjaDogJ092ZXJzaXplZCBwYWNrZXQgcmVjZWl2ZWQgZnJvbScgfSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbXBhY3QnXSwgaWQ6IFsnVDE0OTknXSwgdGVjaG5pcXVlOiBbJ0VuZHBvaW50IERlbmlhbCBvZiBTZXJ2aWNlJ10gfSxcbiAgICBncm91cHM6IFsnc3lzbG9nJywgJ2xpbnV4a2VybmVsJ10sXG4gICAgZGVzY3JpcHRpb246ICdFcnJvciBtZXNzYWdlIGZyb20gdGhlIGtlcm5lbC4gUGluZyBvZiBkZWF0aCBhdHRhY2suJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDUxMDQsXG4gICAgbGV2ZWw6IDgsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczoge1xuICAgICAgaWZfc2lkOiAnNTEwMCcsXG4gICAgICByZWdleDogWydQcm9taXNjdW91cyBtb2RlIGVuYWJsZWR8JywgJ2RldmljZSBTKyBlbnRlcmVkIHByb21pc2N1b3VzIG1vZGUnXSxcbiAgICB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJywgJzExLjQnXSxcbiAgICBncGcxMzogWyc0LjEzJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS42JywgJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnLCAnQ0M2LjEnLCAnQ0M2LjgnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnRGlzY292ZXJ5J10sIGlkOiBbJ1QxMDQwJ10sIHRlY2huaXF1ZTogWydOZXR3b3JrIFNuaWZmaW5nJ10gfSxcbiAgICBncm91cHM6IFsncHJvbWlzYycsICdzeXNsb2cnLCAnbGludXhrZXJuZWwnXSxcbiAgICBkZXNjcmlwdGlvbjogJ0ludGVyZmFjZSBlbnRlcmVkIGluIHByb21pc2N1b3VzKHNuaWZmaW5nKSBtb2RlLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA1MTA4LFxuICAgIGxldmVsOiAxMixcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzUxMDAnLCBtYXRjaDogJ091dCBvZiBNZW1vcnk6ICcgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjYuMSddLFxuICAgIGdwZzEzOiBbJzQuMTInXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjYnXSxcbiAgICB0c2M6IFsnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnSW1wYWN0J10sIGlkOiBbJ1QxNDk5J10sIHRlY2huaXF1ZTogWydFbmRwb2ludCBEZW5pYWwgb2YgU2VydmljZSddIH0sXG4gICAgZ3JvdXBzOiBbJ3NlcnZpY2VfYXZhaWxhYmlsaXR5JywgJ3N5c2xvZycsICdsaW51eGtlcm5lbCddLFxuICAgIGRlc2NyaXB0aW9uOiAnU3lzdGVtIHJ1bm5pbmcgb3V0IG9mIG1lbW9yeS4gQXZhaWxhYmlsaXR5IG9mIHRoZSBzeXN0ZW0gaXMgaW4gcmlzay4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDIwLXN5c2xvZ19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTExMyxcbiAgICBsZXZlbDogNyxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzUxMDAnLCBtYXRjaDogJ0tlcm5lbCBsb2cgZGFlbW9uIHRlcm1pbmF0aW5nJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuNi4xJ10sXG4gICAgZ3BnMTM6IFsnNC4xNCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuNiddLFxuICAgIHRzYzogWydDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydJbXBhY3QnXSwgaWQ6IFsnVDE1MjknXSwgdGVjaG5pcXVlOiBbJ1N5c3RlbSBTaHV0ZG93bi9SZWJvb3QnXSB9LFxuICAgIGdyb3VwczogWydzeXN0ZW1fc2h1dGRvd24nLCAnc3lzbG9nJywgJ2xpbnV4a2VybmVsJ10sXG4gICAgZGVzY3JpcHRpb246ICdTeXN0ZW0gaXMgc2h1dHRpbmcgZG93bi4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDIwLXN5c2xvZ19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTEzMixcbiAgICBsZXZlbDogMTEsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc1MTAwJywgbWF0Y2g6ICdtb2R1bGUgdmVyaWZpY2F0aW9uIGZhaWxlZCcgfSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnUGVyc2lzdGVuY2UnXSwgaWQ6IFsnVDEyMTUnXSwgdGVjaG5pcXVlOiBbJ0tlcm5lbCBNb2R1bGVzIGFuZCBFeHRlbnNpb25zJ10gfSxcbiAgICBncm91cHM6IFsnc3lzbG9nJywgJ2xpbnV4a2VybmVsJ10sXG4gICAgZGVzY3JpcHRpb246ICdVbnNpZ25lZCBrZXJuZWwgbW9kdWxlIHdhcyBsb2FkZWQnLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDIwLXN5c2xvZ19ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTEzMyxcbiAgICBsZXZlbDogMTEsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc1MTAwJywgbWF0Y2g6ICdQS0NTIzcgc2lnbmF0dXJlIG5vdCBzaWduZWQgd2l0aCBhIHRydXN0ZWQga2V5JyB9LFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydQZXJzaXN0ZW5jZSddLCBpZDogWydUMTIxNSddLCB0ZWNobmlxdWU6IFsnS2VybmVsIE1vZHVsZXMgYW5kIEV4dGVuc2lvbnMnXSB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAnbGludXhrZXJuZWwnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1NpZ25lZCBidXQgdW50cnVzdGVkIGtlcm5lbCBtb2R1bGUgd2FzIGxvYWRlZCcsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA1MzAyLFxuICAgIGxldmVsOiA5LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNTMwMScsIHVzZXI6ICdecm9vdCcgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjIuNCcsICcxMC4yLjUnXSxcbiAgICBncGcxMzogWyc3LjgnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCcsICdJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNyddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMycsICdDQzcuNCddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydQcml2aWxlZ2UgRXNjYWxhdGlvbiddLCBpZDogWydUMTE2OSddLCB0ZWNobmlxdWU6IFsnU3VkbyddIH0sXG4gICAgZ3JvdXBzOiBbJ2F1dGhlbnRpY2F0aW9uX2ZhaWxlZCcsICdzeXNsb2cnLCAnc3UnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1VzZXIgbWlzc2VkIHRoZSBwYXNzd29yZCB0byBjaGFuZ2UgVUlEIHRvIHJvb3QuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDUzMDMsXG4gICAgbGV2ZWw6IDMsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczoge1xuICAgICAgaWZfc2lkOiAnNTMwMCcsXG4gICAgICByZWdleDogW1xuICAgICAgICBcInNlc3Npb24gb3BlbmVkIGZvciB1c2VyIHJvb3R8XidzdSByb290J3xcIixcbiAgICAgICAgJ14rIFMrIFMrcHJvb3QkfF5TKyB0byByb290IG9ufF5TVSBTKyBTKyArIFMrIFMrLXJvb3QkJyxcbiAgICAgIF0sXG4gICAgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjIuNSddLFxuICAgIGdwZzEzOiBbJzcuNicsICc3LjgnLCAnNy45J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnLCAnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjE0JywgJ0FDLjcnXSxcbiAgICB0c2M6IFsnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnSW5pdGlhbCBBY2Nlc3MnXSwgaWQ6IFsnVDEwNzgnXSwgdGVjaG5pcXVlOiBbJ1ZhbGlkIEFjY291bnRzJ10gfSxcbiAgICBncm91cHM6IFsnYXV0aGVudGljYXRpb25fc3VjY2VzcycsICdzeXNsb2cnLCAnc3UnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1VzZXIgc3VjY2Vzc2Z1bGx5IGNoYW5nZWQgVUlEIHRvIHJvb3QuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDUzMDQsXG4gICAgbGV2ZWw6IDMsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczoge1xuICAgICAgaWZfc2lkOiAnNTMwMCcsXG4gICAgICByZWdleDogWydzZXNzaW9uIG9wZW5lZCBmb3IgdXNlcnxzdWNjZWVkZWQgZm9yfCcsICdeK3xeUysgdG8gfF5TVSBTKyBTKyArICddLFxuICAgIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnXSxcbiAgICBncGcxMzogWyc3LjYnLCAnNy44J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnLCAnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjE0JywgJ0FDLjcnXSxcbiAgICB0c2M6IFsnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnSW5pdGlhbCBBY2Nlc3MnXSwgaWQ6IFsnVDEwNzgnXSwgdGVjaG5pcXVlOiBbJ1ZhbGlkIEFjY291bnRzJ10gfSxcbiAgICBncm91cHM6IFsnYXV0aGVudGljYXRpb25fc3VjY2VzcycsICdzeXNsb2cnLCAnc3UnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1VzZXIgc3VjY2Vzc2Z1bGx5IGNoYW5nZWQgVUlELicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA1NDAxLFxuICAgIGxldmVsOiA1LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNTQwMCcsIG1hdGNoOiAnaW5jb3JyZWN0IHBhc3N3b3JkIGF0dGVtcHQnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjQnLCAnMTAuMi41J10sXG4gICAgZ3BnMTM6IFsnNy44J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnLCAnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjE0JywgJ0FDLjcnXSxcbiAgICB0c2M6IFsnQ0M2LjEnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnUHJpdmlsZWdlIEVzY2FsYXRpb24nXSwgaWQ6IFsnVDExNjknXSwgdGVjaG5pcXVlOiBbJ1N1ZG8nXSB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAnc3VkbyddLFxuICAgIGRlc2NyaXB0aW9uOiAnRmFpbGVkIGF0dGVtcHQgdG8gcnVuIHN1ZG8uJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDU0MDIsXG4gICAgbGV2ZWw6IDMsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc1NDAwJywgcmVnZXg6ICcgOyBVU0VSPXJvb3QgOyBDT01NQU5EPXwgOyBVU0VSPXJvb3QgOyBUU0lEPVMrIDsgQ09NTUFORD0nIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnLCAnMTAuMi4yJ10sXG4gICAgZ3BnMTM6IFsnNy42JywgJzcuOCcsICc3LjEzJ10sXG4gICAgZ2RwcjogWydJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNycsICdBQy42J10sXG4gICAgdHNjOiBbJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ1ByaXZpbGVnZSBFc2NhbGF0aW9uJ10sIGlkOiBbJ1QxMTY5J10sIHRlY2huaXF1ZTogWydTdWRvJ10gfSxcbiAgICBncm91cHM6IFsnc3lzbG9nJywgJ3N1ZG8nXSxcbiAgICBkZXNjcmlwdGlvbjogJ1N1Y2Nlc3NmdWwgc3VkbyB0byBST09UIGV4ZWN1dGVkLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA1NDAzLFxuICAgIGxldmVsOiA0LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNTQwMCcsIGlmX2Z0czogJycgfSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnUHJpdmlsZWdlIEVzY2FsYXRpb24nXSwgaWQ6IFsnVDExNjknXSwgdGVjaG5pcXVlOiBbJ1N1ZG8nXSB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAnc3VkbyddLFxuICAgIGRlc2NyaXB0aW9uOiAnRmlyc3QgdGltZSB1c2VyIGV4ZWN1dGVkIHN1ZG8uJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDU0MDQsXG4gICAgbGV2ZWw6IDEwLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNTQwMScsIG1hdGNoOiAnMyBpbmNvcnJlY3QgcGFzc3dvcmQgYXR0ZW1wdHMnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjQnLCAnMTAuMi41J10sXG4gICAgZ3BnMTM6IFsnNy44J10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnLCAnSVZfMzIuMiddLFxuICAgIGhpcGFhOiBbJzE2NC4zMTIuYiddLFxuICAgIG5pc3RfODAwXzUzOiBbJ0FVLjE0JywgJ0FDLjcnXSxcbiAgICB0c2M6IFsnQ0M2LjEnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnUHJpdmlsZWdlIEVzY2FsYXRpb24nXSwgaWQ6IFsnVDExNjknXSwgdGVjaG5pcXVlOiBbJ1N1ZG8nXSB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAnc3VkbyddLFxuICAgIGRlc2NyaXB0aW9uOiAnVGhyZWUgZmFpbGVkIGF0dGVtcHRzIHRvIHJ1biBzdWRvJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDAyMC1zeXNsb2dfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDU0MDUsXG4gICAgbGV2ZWw6IDUsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBpZl9zaWQ6ICc1NDAwJywgbWF0Y2g6ICd1c2VyIE5PVCBpbiBzdWRvZXJzJyB9LFxuICAgIHBjaV9kc3M6IFsnMTAuMi4yJywgJzEwLjIuNSddLFxuICAgIGdwZzEzOiBbJzcuOCddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJywgJ0lWXzMyLjInXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS4xNCcsICdBQy42JywgJ0FDLjcnXSxcbiAgICB0c2M6IFsnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnUHJpdmlsZWdlIEVzY2FsYXRpb24nXSwgaWQ6IFsnVDExNjknXSwgdGVjaG5pcXVlOiBbJ1N1ZG8nXSB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAnc3VkbyddLFxuICAgIGRlc2NyaXB0aW9uOiAnVW5hdXRob3JpemVkIHVzZXIgYXR0ZW1wdGVkIHRvIHVzZSBzdWRvLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwMjAtc3lzbG9nX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA1NDA3LFxuICAgIGxldmVsOiAzLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNTQwMCcsIHJlZ2V4OiAnIDsgVVNFUj1TKyA7IENPTU1BTkQ9fCA7IFVTRVI9UysgOyBUU0lEPVMrIDsgQ09NTUFORD0nIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjUnLCAnMTAuMi4yJ10sXG4gICAgZ3BnMTM6IFsnNy42JywgJzcuOCcsICc3LjEzJ10sXG4gICAgZ2RwcjogWydJVl8zMi4yJ10sXG4gICAgdHNjOiBbJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ1ByaXZpbGVnZSBFc2NhbGF0aW9uJ10sIGlkOiBbJ1QxMTY5J10sIHRlY2huaXF1ZTogWydTdWRvJ10gfSxcbiAgICBncm91cHM6IFsnc3lzbG9nJywgJ3N1ZG8nXSxcbiAgICBkZXNjcmlwdGlvbjogJ1N1Y2Nlc3NmdWwgc3VkbyBleGVjdXRlZC4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDg1LXBhbV9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTUwMSxcbiAgICBsZXZlbDogMyxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzU1MDAnLCBtYXRjaDogJ3Nlc3Npb24gb3BlbmVkIGZvciB1c2VyICcgfSxcbiAgICBwY2lfZHNzOiBbJzEwLjIuNSddLFxuICAgIGdwZzEzOiBbJzcuOCcsICc3LjknXSxcbiAgICBnZHByOiBbJ0lWXzMyLjInXSxcbiAgICBoaXBhYTogWycxNjQuMzEyLmInXSxcbiAgICBuaXN0XzgwMF81MzogWydBVS4xNCcsICdBQy43J10sXG4gICAgdHNjOiBbJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0luaXRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMDc4J10sIHRlY2huaXF1ZTogWydWYWxpZCBBY2NvdW50cyddIH0sXG4gICAgZ3JvdXBzOiBbJ2F1dGhlbnRpY2F0aW9uX3N1Y2Nlc3MnLCAncGFtJywgJ3N5c2xvZyddLFxuICAgIGRlc2NyaXB0aW9uOiAnUEFNOiBMb2dpbiBzZXNzaW9uIG9wZW5lZC4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDg1LXBhbV9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTU1MSxcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICc4JywgdGltZWZyYW1lOiAnMTgwJywgaWZfbWF0Y2hlZF9zaWQ6ICc1NTAzJywgc2FtZV9zb3VyY2VfaXA6ICcnIH0sXG4gICAgcGNpX2RzczogWycxMC4yLjQnLCAnMTAuMi41JywgJzExLjQnXSxcbiAgICBncGcxMzogWyc3LjgnXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCcsICdJVl8zMi4yJ10sXG4gICAgaGlwYWE6IFsnMTY0LjMxMi5iJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnQVUuMTQnLCAnQUMuNycsICdTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NyZWRlbnRpYWwgQWNjZXNzJ10sIGlkOiBbJ1QxMTEwJ10sIHRlY2huaXF1ZTogWydCcnV0ZSBGb3JjZSddIH0sXG4gICAgZ3JvdXBzOiBbJ2F1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzJywgJ3BhbScsICdzeXNsb2cnXSxcbiAgICBkZXNjcmlwdGlvbjogJ1BBTTogTXVsdGlwbGUgZmFpbGVkIGxvZ2lucyBpbiBhIHNtYWxsIHBlcmlvZCBvZiB0aW1lLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwOTAtdGVsbmV0ZF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTYwMSxcbiAgICBsZXZlbDogNSxcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzU2MDAnLCBtYXRjaDogJ3JlZnVzZWQgY29ubmVjdCBmcm9tICcgfSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnQ29tbWFuZCBhbmQgQ29udHJvbCddLFxuICAgICAgaWQ6IFsnVDEwOTUnXSxcbiAgICAgIHRlY2huaXF1ZTogWydTdGFuZGFyZCBOb24tQXBwbGljYXRpb24gTGF5ZXIgUHJvdG9jb2wnXSxcbiAgICB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAndGVsbmV0ZCddLFxuICAgIGRlc2NyaXB0aW9uOiAndGVsbmV0ZDogQ29ubmVjdGlvbiByZWZ1c2VkIGJ5IFRDUCBXcmFwcGVycy4nLFxuICB9LFxuICB7XG4gICAgZmlsZW5hbWU6ICcwMDkwLXRlbG5ldGRfcnVsZXMueG1sJyxcbiAgICByZWxhdGl2ZV9kaXJuYW1lOiAncnVsZXNldC9ydWxlcycsXG4gICAgaWQ6IDU2MzEsXG4gICAgbGV2ZWw6IDEwLFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgZnJlcXVlbmN5OiAnNicsIHRpbWVmcmFtZTogJzEyMCcsIGlmX21hdGNoZWRfc2lkOiAnNTYwMicsIHNhbWVfc291cmNlX2lwOiAnJyB9LFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJywgJ0lWXzMyLjInXSxcbiAgICBtaXRyZTogeyB0YWN0aWM6IFsnQ3JlZGVudGlhbCBBY2Nlc3MnXSwgaWQ6IFsnVDExMTAnXSwgdGVjaG5pcXVlOiBbJ0JydXRlIEZvcmNlJ10gfSxcbiAgICBncm91cHM6IFsnc3lzbG9nJywgJ3RlbG5ldGQnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3RlbG5ldGQ6IE11bHRpcGxlIGNvbm5lY3Rpb24gYXR0ZW1wdHMgZnJvbSBzYW1lIHNvdXJjZSAocG9zc2libGUgc2NhbikuJyxcbiAgfSxcbiAge1xuICAgIGZpbGVuYW1lOiAnMDA5NS1zc2hkX3J1bGVzLnhtbCcsXG4gICAgcmVsYXRpdmVfZGlybmFtZTogJ3J1bGVzZXQvcnVsZXMnLFxuICAgIGlkOiA1NzAxLFxuICAgIGxldmVsOiA4LFxuICAgIHN0YXR1czogJ2VuYWJsZWQnLFxuICAgIGRldGFpbHM6IHsgaWZfc2lkOiAnNTcwMCcsIG1hdGNoOiAnQmFkIHByb3RvY29sIHZlcnNpb24gaWRlbnRpZmljYXRpb24nIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ3BnMTM6IFsnNC4xMiddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFsnSW5pdGlhbCBBY2Nlc3MnXSxcbiAgICAgIGlkOiBbJ1QxMTkwJ10sXG4gICAgICB0ZWNobmlxdWU6IFsnRXhwbG9pdCBQdWJsaWMtRmFjaW5nIEFwcGxpY2F0aW9uJ10sXG4gICAgfSxcbiAgICBncm91cHM6IFsncmVjb24nLCAnc3lzbG9nJywgJ3NzaGQnXSxcbiAgICBkZXNjcmlwdGlvbjogJ3NzaGQ6IFBvc3NpYmxlIGF0dGFjayBvbiB0aGUgc3NoIHNlcnZlciAob3IgdmVyc2lvbiBnYXRoZXJpbmcpLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwOTUtc3NoZF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTcwMyxcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICc2JywgdGltZWZyYW1lOiAnMzYwJywgaWZfbWF0Y2hlZF9zaWQ6ICc1NzAyJywgc2FtZV9zb3VyY2VfaXA6ICcnIH0sXG4gICAgcGNpX2RzczogWycxMS40J10sXG4gICAgZ3BnMTM6IFsnNC4xMiddLFxuICAgIGdkcHI6IFsnSVZfMzUuNy5kJ10sXG4gICAgbmlzdF84MDBfNTM6IFsnU0kuNCddLFxuICAgIHRzYzogWydDQzYuMScsICdDQzYuOCcsICdDQzcuMicsICdDQzcuMyddLFxuICAgIG1pdHJlOiB7IHRhY3RpYzogWydDcmVkZW50aWFsIEFjY2VzcyddLCBpZDogWydUMTExMCddLCB0ZWNobmlxdWU6IFsnQnJ1dGUgRm9yY2UnXSB9LFxuICAgIGdyb3VwczogWydzeXNsb2cnLCAnc3NoZCddLFxuICAgIGRlc2NyaXB0aW9uOiAnc3NoZDogUG9zc2libGUgYnJlYWtpbiBhdHRlbXB0IChoaWdoIG51bWJlciBvZiByZXZlcnNlIGxvb2t1cCBlcnJvcnMpLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwOTUtc3NoZF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTcwNSxcbiAgICBsZXZlbDogMTAsXG4gICAgc3RhdHVzOiAnZW5hYmxlZCcsXG4gICAgZGV0YWlsczogeyBmcmVxdWVuY3k6ICc2JywgdGltZWZyYW1lOiAnMzYwJywgaWZfbWF0Y2hlZF9zaWQ6ICc1NzA0JyB9LFxuICAgIHBjaV9kc3M6IFsnMTEuNCddLFxuICAgIGdwZzEzOiBbJzQuMTInXSxcbiAgICBnZHByOiBbJ0lWXzM1LjcuZCddLFxuICAgIG5pc3RfODAwXzUzOiBbJ1NJLjQnXSxcbiAgICB0c2M6IFsnQ0M2LjEnLCAnQ0M2LjgnLCAnQ0M3LjInLCAnQ0M3LjMnXSxcbiAgICBtaXRyZToge1xuICAgICAgdGFjdGljOiBbJ0luaXRpYWwgQWNjZXNzJywgJ0NyZWRlbnRpYWwgQWNjZXNzJ10sXG4gICAgICBpZDogWydUMTE5MCcsICdUMTExMCddLFxuICAgICAgdGVjaG5pcXVlOiBbJ0V4cGxvaXQgUHVibGljLUZhY2luZyBBcHBsaWNhdGlvbicsICdCcnV0ZSBGb3JjZSddLFxuICAgIH0sXG4gICAgZ3JvdXBzOiBbJ3N5c2xvZycsICdzc2hkJ10sXG4gICAgZGVzY3JpcHRpb246ICdzc2hkOiBQb3NzaWJsZSBzY2FuIG9yIGJyZWFraW4gYXR0ZW1wdCAoaGlnaCBudW1iZXIgb2YgbG9naW4gdGltZW91dHMpLicsXG4gIH0sXG4gIHtcbiAgICBmaWxlbmFtZTogJzAwOTUtc3NoZF9ydWxlcy54bWwnLFxuICAgIHJlbGF0aXZlX2Rpcm5hbWU6ICdydWxlc2V0L3J1bGVzJyxcbiAgICBpZDogNTcwNixcbiAgICBsZXZlbDogNixcbiAgICBzdGF0dXM6ICdlbmFibGVkJyxcbiAgICBkZXRhaWxzOiB7IGlmX3NpZDogJzU3MDAnLCBtYXRjaDogJ0RpZCBub3QgcmVjZWl2ZSBpZGVudGlmaWNhdGlvbiBzdHJpbmcgZnJvbScgfSxcbiAgICBwY2lfZHNzOiBbJzExLjQnXSxcbiAgICBncGcxMzogWyc0LjEyJ10sXG4gICAgZ2RwcjogWydJVl8zNS43LmQnXSxcbiAgICBuaXN0XzgwMF81MzogWydTSS40J10sXG4gICAgdHNjOiBbJ0NDNi4xJywgJ0NDNi44JywgJ0NDNy4yJywgJ0NDNy4zJ10sXG4gICAgbWl0cmU6IHsgdGFjdGljOiBbJ0NvbW1hbmQgYW5kIENvbnRyb2wnXSwgaWQ6IFsnVDEwNDMnXSwgdGVjaG5pcXVlOiBbJ0NvbW1vbmx5IFVzZWQgUG9ydCddIH0sXG4gICAgZ3JvdXBzOiBbJ3JlY29uJywgJ3N5c2xvZycsICdzc2hkJ10sXG4gICAgZGVzY3JpcHRpb246ICdzc2hkOiBpbnNlY3VyZSBjb25uZWN0aW9uIGF0dGVtcHQgKHNjYW4pLicsXG4gIH0sXG5dO1xuXG5leHBvcnQgY29uc3QgYXJyYXlMb2NhdGlvbiA9IFsnRXZlbnRDaGFubmVsJywgJy92YXIvbG9nL2F1dGgubG9nJywgJy92YXIvbG9nL3NlY3VyZSddO1xuIl19