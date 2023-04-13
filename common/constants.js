"use strict";

var _interopRequireDefault = require("@babel/runtime/helpers/interopRequireDefault");

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.WAZUH_STATISTICS_DEFAULT_CRON_FREQ = exports.WAZUH_STATISTICS_DEFAULT_CREATION = exports.WAZUH_SECURITY_PLUGIN_XPACK_SECURITY = exports.WAZUH_SECURITY_PLUGIN_OPEN_DISTRO_FOR_ELASTICSEARCH = exports.WAZUH_SECURITY_PLUGINS = exports.WAZUH_SAMPLE_ALERT_PREFIX = exports.WAZUH_SAMPLE_ALERTS_INDEX_SHARDS = exports.WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS = exports.WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING = exports.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS = exports.WAZUH_ROLE_ADMINISTRATOR_NAME = exports.WAZUH_ROLE_ADMINISTRATOR_ID = exports.WAZUH_QUEUE_CRON_FREQ = exports.WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME = exports.WAZUH_PLUGIN_PLATFORM_SETTING_TIME_FILTER = exports.WAZUH_PLUGIN_PLATFORM_SETTING_METAFIELDS = exports.WAZUH_PLUGIN_PLATFORM_SETTING_MAX_BUCKETS = exports.WAZUH_MONITORING_TEMPLATE_NAME = exports.WAZUH_MONITORING_PREFIX = exports.WAZUH_MONITORING_PATTERN = exports.WAZUH_MONITORING_DEFAULT_INDICES_SHARDS = exports.WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS = exports.WAZUH_MONITORING_DEFAULT_FREQUENCY = exports.WAZUH_MONITORING_DEFAULT_ENABLED = exports.WAZUH_MONITORING_DEFAULT_CRON_FREQ = exports.WAZUH_MONITORING_DEFAULT_CREATION = exports.WAZUH_MODULES_ID = exports.WAZUH_MENU_TOOLS_SECTIONS_ID = exports.WAZUH_MENU_SETTINGS_SECTIONS_ID = exports.WAZUH_MENU_SECURITY_SECTIONS_ID = exports.WAZUH_MENU_MANAGEMENT_SECTIONS_ID = exports.WAZUH_LINK_SLACK = exports.WAZUH_LINK_GOOGLE_GROUPS = exports.WAZUH_LINK_GITHUB = exports.WAZUH_INDEX_TYPE_STATISTICS = exports.WAZUH_INDEX_TYPE_MONITORING = exports.WAZUH_INDEX_TYPE_ALERTS = exports.WAZUH_ERROR_DAEMONS_NOT_READY = exports.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH = exports.WAZUH_DATA_LOGS_RAW_PATH = exports.WAZUH_DATA_LOGS_RAW_FILENAME = exports.WAZUH_DATA_LOGS_PLAIN_PATH = exports.WAZUH_DATA_LOGS_PLAIN_FILENAME = exports.WAZUH_DATA_LOGS_DIRECTORY_PATH = exports.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH = exports.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH = exports.WAZUH_DATA_CONFIG_REGISTRY_PATH = exports.WAZUH_DATA_CONFIG_DIRECTORY_PATH = exports.WAZUH_DATA_CONFIG_APP_PATH = exports.WAZUH_DATA_ABSOLUTE_PATH = exports.WAZUH_CONFIGURATION_CACHE_TIME = exports.WAZUH_API_RESERVED_ID_LOWER_THAN = exports.WAZUH_ALERTS_PREFIX = exports.WAZUH_ALERTS_PATTERN = exports.WAZUH_AGENTS_OS_TYPE = exports.UI_TOAST_COLOR = exports.UI_ORDER_AGENT_STATUS = exports.UI_LOGGER_LEVELS = exports.UI_LABEL_NAME_AGENT_STATUS = exports.UI_COLOR_AGENT_STATUS = exports.SettingCategory = exports.REPORTS_PRIMARY_COLOR = exports.REPORTS_PAGE_HEADER_TEXT = exports.REPORTS_PAGE_FOOTER_TEXT = exports.REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH = exports.PLUGIN_VERSION_SHORT = exports.PLUGIN_VERSION = exports.PLUGIN_SETTINGS_CATEGORIES = exports.PLUGIN_SETTINGS = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_UPGRADE_PLATFORM = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_TROUBLESHOOTING = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_APP_CONFIGURATION = exports.PLUGIN_PLATFORM_URL_GUIDE_TITLE = exports.PLUGIN_PLATFORM_URL_GUIDE = exports.PLUGIN_PLATFORM_SETTING_NAME_TIME_FILTER = exports.PLUGIN_PLATFORM_SETTING_NAME_METAFIELDS = exports.PLUGIN_PLATFORM_SETTING_NAME_MAX_BUCKETS = exports.PLUGIN_PLATFORM_REQUEST_HEADERS = exports.PLUGIN_PLATFORM_NAME = exports.PLUGIN_PLATFORM_INSTALLATION_USER_GROUP = exports.PLUGIN_PLATFORM_INSTALLATION_USER = exports.PLUGIN_PLATFORM_BASE_INSTALLATION_PATH = exports.PLUGIN_APP_NAME = exports.MODULE_SCA_CHECK_RESULT_LABEL = exports.MAX_MB_LOG_FILES = exports.HTTP_STATUS_CODES = exports.HEALTH_CHECK_REDIRECTION_TIME = exports.HEALTH_CHECK = exports.EpluginSettingType = exports.ELASTIC_NAME = exports.DOCUMENTATION_WEB_BASE_URL = exports.CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES = exports.AUTHORIZED_AGENTS = exports.ASSETS_PUBLIC_URL = exports.ASSETS_BASE_URL_PREFIX = exports.API_NAME_AGENT_STATUS = exports.AGENT_SYNCED_STATUS = void 0;
exports.WAZUH_UI_LOGS_RAW_PATH = exports.WAZUH_UI_LOGS_RAW_FILENAME = exports.WAZUH_UI_LOGS_PLAIN_PATH = exports.WAZUH_UI_LOGS_PLAIN_FILENAME = exports.WAZUH_STATISTICS_TEMPLATE_NAME = exports.WAZUH_STATISTICS_PATTERN = exports.WAZUH_STATISTICS_DEFAULT_STATUS = exports.WAZUH_STATISTICS_DEFAULT_PREFIX = exports.WAZUH_STATISTICS_DEFAULT_NAME = exports.WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS = exports.WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS = exports.WAZUH_STATISTICS_DEFAULT_FREQUENCY = exports.WAZUH_STATISTICS_DEFAULT_CRON_FREQ = exports.WAZUH_STATISTICS_DEFAULT_CREATION = exports.WAZUH_SECURITY_PLUGIN_XPACK_SECURITY = exports.WAZUH_SECURITY_PLUGIN_OPEN_DISTRO_FOR_ELASTICSEARCH = exports.WAZUH_SECURITY_PLUGINS = exports.WAZUH_SAMPLE_ALERT_PREFIX = exports.WAZUH_SAMPLE_ALERTS_INDEX_SHARDS = exports.WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS = exports.WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY = exports.WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING = exports.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS = exports.WAZUH_ROLE_ADMINISTRATOR_NAME = exports.WAZUH_ROLE_ADMINISTRATOR_ID = exports.WAZUH_QUEUE_CRON_FREQ = exports.WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME = exports.WAZUH_PLUGIN_PLATFORM_SETTING_TIME_FILTER = exports.WAZUH_PLUGIN_PLATFORM_SETTING_METAFIELDS = exports.WAZUH_PLUGIN_PLATFORM_SETTING_MAX_BUCKETS = exports.WAZUH_MONITORING_TEMPLATE_NAME = exports.WAZUH_MONITORING_PREFIX = exports.WAZUH_MONITORING_PATTERN = exports.WAZUH_MONITORING_DEFAULT_INDICES_SHARDS = exports.WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS = exports.WAZUH_MONITORING_DEFAULT_FREQUENCY = exports.WAZUH_MONITORING_DEFAULT_ENABLED = exports.WAZUH_MONITORING_DEFAULT_CRON_FREQ = exports.WAZUH_MONITORING_DEFAULT_CREATION = exports.WAZUH_MODULES_ID = exports.WAZUH_MENU_TOOLS_SECTIONS_ID = exports.WAZUH_MENU_SETTINGS_SECTIONS_ID = exports.WAZUH_MENU_SECURITY_SECTIONS_ID = exports.WAZUH_MENU_MANAGEMENT_SECTIONS_ID = exports.WAZUH_LINK_SLACK = exports.WAZUH_LINK_GOOGLE_GROUPS = exports.WAZUH_LINK_GITHUB = exports.WAZUH_INDEX_TYPE_STATISTICS = exports.WAZUH_INDEX_TYPE_MONITORING = exports.WAZUH_INDEX_TYPE_ALERTS = exports.WAZUH_ERROR_DAEMONS_NOT_READY = exports.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH = exports.WAZUH_DATA_LOGS_RAW_PATH = exports.WAZUH_DATA_LOGS_RAW_FILENAME = exports.WAZUH_DATA_LOGS_PLAIN_PATH = exports.WAZUH_DATA_LOGS_PLAIN_FILENAME = exports.WAZUH_DATA_LOGS_DIRECTORY_PATH = exports.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH = exports.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH = exports.WAZUH_DATA_CONFIG_REGISTRY_PATH = exports.WAZUH_DATA_CONFIG_DIRECTORY_PATH = exports.WAZUH_DATA_CONFIG_APP_PATH = exports.WAZUH_DATA_ABSOLUTE_PATH = exports.WAZUH_CONFIGURATION_CACHE_TIME = exports.WAZUH_API_RESERVED_ID_LOWER_THAN = exports.WAZUH_ALERTS_PREFIX = exports.WAZUH_ALERTS_PATTERN = exports.WAZUH_AGENTS_OS_TYPE = exports.UI_TOAST_COLOR = exports.UI_ORDER_AGENT_STATUS = exports.UI_LOGGER_LEVELS = exports.UI_LABEL_NAME_AGENT_STATUS = exports.UI_COLOR_AGENT_STATUS = exports.SettingCategory = exports.REPORTS_PRIMARY_COLOR = exports.REPORTS_PAGE_HEADER_TEXT = exports.REPORTS_PAGE_FOOTER_TEXT = exports.REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH = exports.PLUGIN_VERSION_SHORT = exports.PLUGIN_VERSION = exports.PLUGIN_SETTINGS_CATEGORIES = exports.PLUGIN_SETTINGS = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_UPGRADE_PLATFORM = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_TROUBLESHOOTING = exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_APP_CONFIGURATION = exports.PLUGIN_PLATFORM_URL_GUIDE_TITLE = exports.PLUGIN_PLATFORM_URL_GUIDE = exports.PLUGIN_PLATFORM_SETTING_NAME_TIME_FILTER = exports.PLUGIN_PLATFORM_SETTING_NAME_METAFIELDS = exports.PLUGIN_PLATFORM_SETTING_NAME_MAX_BUCKETS = exports.PLUGIN_PLATFORM_REQUEST_HEADERS = exports.PLUGIN_PLATFORM_NAME = exports.PLUGIN_PLATFORM_INSTALLATION_USER_GROUP = exports.PLUGIN_PLATFORM_INSTALLATION_USER = exports.PLUGIN_PLATFORM_BASE_INSTALLATION_PATH = exports.PLUGIN_APP_NAME = exports.MODULE_SCA_CHECK_RESULT_LABEL = exports.MAX_MB_LOG_FILES = exports.HTTP_STATUS_CODES = exports.HEALTH_CHECK_REDIRECTION_TIME = exports.HEALTH_CHECK = exports.EpluginSettingType = exports.ELASTIC_NAME = exports.DOCUMENTATION_WEB_BASE_URL = exports.CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES = exports.AUTHORIZED_AGENTS = exports.ASSETS_PUBLIC_URL = exports.ASSETS_BASE_URL_PREFIX = exports.API_NAME_AGENT_STATUS = exports.AGENT_SYNCED_STATUS = void 0;

var _path = _interopRequireDefault(require("path"));

var _package = require("../package.json");

var _nodeCron = require("node-cron");

var _settingsValidator = require("../common/services/settings-validator");

/*
 * Wazuh app - Wazuh Constants file
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// Plugin
const PLUGIN_VERSION = _package.version;
exports.PLUGIN_VERSION = PLUGIN_VERSION;

const PLUGIN_VERSION_SHORT = _package.version.split('.').splice(0, 2).join('.'); // Index patterns - Wazuh alerts


exports.PLUGIN_VERSION_SHORT = PLUGIN_VERSION_SHORT;
const WAZUH_INDEX_TYPE_ALERTS = 'alerts';
exports.WAZUH_INDEX_TYPE_ALERTS = WAZUH_INDEX_TYPE_ALERTS;
const WAZUH_ALERTS_PREFIX = 'wazuh-alerts-';
exports.WAZUH_ALERTS_PREFIX = WAZUH_ALERTS_PREFIX;
const WAZUH_ALERTS_PATTERN = 'wazuh-alerts-*'; // Job - Wazuh monitoring

exports.WAZUH_ALERTS_PATTERN = WAZUH_ALERTS_PATTERN;
const WAZUH_INDEX_TYPE_MONITORING = "monitoring";
exports.WAZUH_INDEX_TYPE_MONITORING = WAZUH_INDEX_TYPE_MONITORING;
const WAZUH_MONITORING_PREFIX = "wazuh-monitoring-";
exports.WAZUH_MONITORING_PREFIX = WAZUH_MONITORING_PREFIX;
const WAZUH_MONITORING_PATTERN = "wazuh-monitoring-*";
exports.WAZUH_MONITORING_PATTERN = WAZUH_MONITORING_PATTERN;
const WAZUH_MONITORING_TEMPLATE_NAME = "wazuh-agent";
exports.WAZUH_MONITORING_TEMPLATE_NAME = WAZUH_MONITORING_TEMPLATE_NAME;
const WAZUH_MONITORING_DEFAULT_INDICES_SHARDS = 1;
exports.WAZUH_MONITORING_DEFAULT_INDICES_SHARDS = WAZUH_MONITORING_DEFAULT_INDICES_SHARDS;
const WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS = 0;
exports.WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS = WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS;
const WAZUH_MONITORING_DEFAULT_CREATION = 'w';
exports.WAZUH_MONITORING_DEFAULT_CREATION = WAZUH_MONITORING_DEFAULT_CREATION;
const WAZUH_MONITORING_DEFAULT_ENABLED = true;
exports.WAZUH_MONITORING_DEFAULT_ENABLED = WAZUH_MONITORING_DEFAULT_ENABLED;
const WAZUH_MONITORING_DEFAULT_FREQUENCY = 900;
exports.WAZUH_MONITORING_DEFAULT_FREQUENCY = WAZUH_MONITORING_DEFAULT_FREQUENCY;
const WAZUH_MONITORING_DEFAULT_CRON_FREQ = '0 * * * * *'; // Job - Wazuh statistics

exports.WAZUH_MONITORING_DEFAULT_CRON_FREQ = WAZUH_MONITORING_DEFAULT_CRON_FREQ;
const WAZUH_INDEX_TYPE_STATISTICS = "statistics";
exports.WAZUH_INDEX_TYPE_STATISTICS = WAZUH_INDEX_TYPE_STATISTICS;
const WAZUH_STATISTICS_DEFAULT_PREFIX = "wazuh";
exports.WAZUH_STATISTICS_DEFAULT_PREFIX = WAZUH_STATISTICS_DEFAULT_PREFIX;
const WAZUH_STATISTICS_DEFAULT_NAME = "statistics";
exports.WAZUH_STATISTICS_DEFAULT_NAME = WAZUH_STATISTICS_DEFAULT_NAME;
const WAZUH_STATISTICS_PATTERN = `${WAZUH_STATISTICS_DEFAULT_PREFIX}-${WAZUH_STATISTICS_DEFAULT_NAME}-*`;
exports.WAZUH_STATISTICS_PATTERN = WAZUH_STATISTICS_PATTERN;
const WAZUH_STATISTICS_TEMPLATE_NAME = `${WAZUH_STATISTICS_DEFAULT_PREFIX}-${WAZUH_STATISTICS_DEFAULT_NAME}`;
exports.WAZUH_STATISTICS_TEMPLATE_NAME = WAZUH_STATISTICS_TEMPLATE_NAME;
const WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS = 1;
exports.WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS = WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS;
const WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS = 0;
exports.WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS = WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS;
const WAZUH_STATISTICS_DEFAULT_CREATION = 'w';
exports.WAZUH_STATISTICS_DEFAULT_CREATION = WAZUH_STATISTICS_DEFAULT_CREATION;
const WAZUH_STATISTICS_DEFAULT_STATUS = true;
exports.WAZUH_STATISTICS_DEFAULT_STATUS = WAZUH_STATISTICS_DEFAULT_STATUS;
const WAZUH_STATISTICS_DEFAULT_FREQUENCY = 900;
exports.WAZUH_STATISTICS_DEFAULT_FREQUENCY = WAZUH_STATISTICS_DEFAULT_FREQUENCY;
const WAZUH_STATISTICS_DEFAULT_CRON_FREQ = '0 */5 * * * *'; // Job - Wazuh initialize

exports.WAZUH_STATISTICS_DEFAULT_CRON_FREQ = WAZUH_STATISTICS_DEFAULT_CRON_FREQ;
const WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME = 'wazuh-kibana'; // Permissions

exports.WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME = WAZUH_PLUGIN_PLATFORM_TEMPLATE_NAME;
const WAZUH_ROLE_ADMINISTRATOR_ID = 1;
exports.WAZUH_ROLE_ADMINISTRATOR_ID = WAZUH_ROLE_ADMINISTRATOR_ID;
const WAZUH_ROLE_ADMINISTRATOR_NAME = 'administrator'; // Sample data

exports.WAZUH_ROLE_ADMINISTRATOR_NAME = WAZUH_ROLE_ADMINISTRATOR_NAME;
const WAZUH_SAMPLE_ALERT_PREFIX = 'wazuh-alerts-4.x-';
exports.WAZUH_SAMPLE_ALERT_PREFIX = WAZUH_SAMPLE_ALERT_PREFIX;
const WAZUH_SAMPLE_ALERTS_INDEX_SHARDS = 1;
exports.WAZUH_SAMPLE_ALERTS_INDEX_SHARDS = WAZUH_SAMPLE_ALERTS_INDEX_SHARDS;
const WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS = 0;
exports.WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS = WAZUH_SAMPLE_ALERTS_INDEX_REPLICAS;
const WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY = 'security';
exports.WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY = WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY;
const WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING = 'auditing-policy-monitoring';
exports.WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING = WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING;
const WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION = 'threat-detection';
exports.WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION = WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION;
const WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS = 3000;
exports.WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS = WAZUH_SAMPLE_ALERTS_DEFAULT_NUMBER_ALERTS;
const WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS = {
  [WAZUH_SAMPLE_ALERTS_CATEGORY_SECURITY]: [{
    syscheck: true
  }, {
    aws: true
  }, {
    office: true
  }, {
    gcp: true
  }, {
    authentication: true
  }, {
    ssh: true
  }, {
    apache: true,
    alerts: 2000
  }, {
    web: true
  }, {
    windows: {
      service_control_manager: true
    },
    alerts: 1000
  }, {
    github: true
  }],
  [WAZUH_SAMPLE_ALERTS_CATEGORY_AUDITING_POLICY_MONITORING]: [{
    rootcheck: true
  }, {
    audit: true
  }, {
    openscap: true
  }, {
    ciscat: true
  }],
  [WAZUH_SAMPLE_ALERTS_CATEGORY_THREAT_DETECTION]: [{
    vulnerabilities: true
  }, {
    virustotal: true
  }, {
    osquery: true
  }, {
    docker: true
  }, {
    mitre: true
  }]
}; // Security

exports.WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS = WAZUH_SAMPLE_ALERTS_CATEGORIES_TYPE_ALERTS;
const WAZUH_SECURITY_PLUGIN_XPACK_SECURITY = 'X-Pack Security';
exports.WAZUH_SECURITY_PLUGIN_XPACK_SECURITY = WAZUH_SECURITY_PLUGIN_XPACK_SECURITY;
const WAZUH_SECURITY_PLUGIN_OPEN_DISTRO_FOR_ELASTICSEARCH = 'Open Distro for Elasticsearch';
exports.WAZUH_SECURITY_PLUGIN_OPEN_DISTRO_FOR_ELASTICSEARCH = WAZUH_SECURITY_PLUGIN_OPEN_DISTRO_FOR_ELASTICSEARCH;
const WAZUH_SECURITY_PLUGINS = [WAZUH_SECURITY_PLUGIN_XPACK_SECURITY, WAZUH_SECURITY_PLUGIN_OPEN_DISTRO_FOR_ELASTICSEARCH]; // App configuration

exports.WAZUH_SECURITY_PLUGINS = WAZUH_SECURITY_PLUGINS;
const WAZUH_CONFIGURATION_CACHE_TIME = 10000; // time in ms;
// Reserved ids for Users/Role mapping

exports.WAZUH_CONFIGURATION_CACHE_TIME = WAZUH_CONFIGURATION_CACHE_TIME;
const WAZUH_API_RESERVED_ID_LOWER_THAN = 100; // Wazuh data path

exports.WAZUH_API_RESERVED_ID_LOWER_THAN = WAZUH_API_RESERVED_ID_LOWER_THAN;
const WAZUH_DATA_PLUGIN_PLATFORM_BASE_PATH = 'data';

const WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH = _path.default.join(__dirname, '../../../', WAZUH_DATA_PLUGIN_PLATFORM_BASE_PATH);

exports.WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH = WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH;

const WAZUH_DATA_ABSOLUTE_PATH = _path.default.join(WAZUH_DATA_PLUGIN_PLATFORM_BASE_ABSOLUTE_PATH, 'wazuh'); // Wazuh data path - config


exports.WAZUH_DATA_ABSOLUTE_PATH = WAZUH_DATA_ABSOLUTE_PATH;

const WAZUH_DATA_CONFIG_DIRECTORY_PATH = _path.default.join(WAZUH_DATA_ABSOLUTE_PATH, 'config');

exports.WAZUH_DATA_CONFIG_DIRECTORY_PATH = WAZUH_DATA_CONFIG_DIRECTORY_PATH;

const WAZUH_DATA_CONFIG_APP_PATH = _path.default.join(WAZUH_DATA_CONFIG_DIRECTORY_PATH, 'wazuh.yml');

exports.WAZUH_DATA_CONFIG_APP_PATH = WAZUH_DATA_CONFIG_APP_PATH;

const WAZUH_DATA_CONFIG_REGISTRY_PATH = _path.default.join(WAZUH_DATA_CONFIG_DIRECTORY_PATH, 'wazuh-registry.json'); // Wazuh data path - logs


exports.WAZUH_DATA_CONFIG_REGISTRY_PATH = WAZUH_DATA_CONFIG_REGISTRY_PATH;
const MAX_MB_LOG_FILES = 100;
exports.MAX_MB_LOG_FILES = MAX_MB_LOG_FILES;

const WAZUH_DATA_LOGS_DIRECTORY_PATH = _path.default.join(WAZUH_DATA_ABSOLUTE_PATH, 'logs');

exports.WAZUH_DATA_LOGS_DIRECTORY_PATH = WAZUH_DATA_LOGS_DIRECTORY_PATH;
const WAZUH_DATA_LOGS_PLAIN_FILENAME = 'wazuhapp-plain.log';
exports.WAZUH_DATA_LOGS_PLAIN_FILENAME = WAZUH_DATA_LOGS_PLAIN_FILENAME;

const WAZUH_DATA_LOGS_PLAIN_PATH = _path.default.join(WAZUH_DATA_LOGS_DIRECTORY_PATH, WAZUH_DATA_LOGS_PLAIN_FILENAME);

exports.WAZUH_DATA_LOGS_PLAIN_PATH = WAZUH_DATA_LOGS_PLAIN_PATH;
const WAZUH_DATA_LOGS_RAW_FILENAME = 'wazuhapp.log';
exports.WAZUH_DATA_LOGS_RAW_FILENAME = WAZUH_DATA_LOGS_RAW_FILENAME;

const WAZUH_DATA_LOGS_RAW_PATH = _path.default.join(WAZUH_DATA_LOGS_DIRECTORY_PATH, WAZUH_DATA_LOGS_RAW_FILENAME); // Wazuh data path - UI logs


exports.WAZUH_DATA_LOGS_RAW_PATH = WAZUH_DATA_LOGS_RAW_PATH;
const WAZUH_UI_LOGS_PLAIN_FILENAME = 'wazuh-ui-plain.log';
exports.WAZUH_UI_LOGS_PLAIN_FILENAME = WAZUH_UI_LOGS_PLAIN_FILENAME;
const WAZUH_UI_LOGS_RAW_FILENAME = 'wazuh-ui.log';
exports.WAZUH_UI_LOGS_RAW_FILENAME = WAZUH_UI_LOGS_RAW_FILENAME;

const WAZUH_UI_LOGS_PLAIN_PATH = _path.default.join(WAZUH_DATA_LOGS_DIRECTORY_PATH, WAZUH_UI_LOGS_PLAIN_FILENAME);

exports.WAZUH_UI_LOGS_PLAIN_PATH = WAZUH_UI_LOGS_PLAIN_PATH;

const WAZUH_UI_LOGS_RAW_PATH = _path.default.join(WAZUH_DATA_LOGS_DIRECTORY_PATH, WAZUH_UI_LOGS_RAW_FILENAME); // Wazuh data path - downloads


exports.WAZUH_UI_LOGS_RAW_PATH = WAZUH_UI_LOGS_RAW_PATH;

const WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH = _path.default.join(WAZUH_DATA_ABSOLUTE_PATH, 'downloads');

exports.WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH = WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH;

const WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH = _path.default.join(WAZUH_DATA_DOWNLOADS_DIRECTORY_PATH, 'reports'); // Queue


exports.WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH = WAZUH_DATA_DOWNLOADS_REPORTS_DIRECTORY_PATH;
const WAZUH_QUEUE_CRON_FREQ = '*/15 * * * * *'; // Every 15 seconds
// Wazuh errors

exports.WAZUH_QUEUE_CRON_FREQ = WAZUH_QUEUE_CRON_FREQ;
const WAZUH_ERROR_DAEMONS_NOT_READY = 'ERROR3099'; // Agents

exports.WAZUH_ERROR_DAEMONS_NOT_READY = WAZUH_ERROR_DAEMONS_NOT_READY;
let WAZUH_AGENTS_OS_TYPE;
exports.WAZUH_AGENTS_OS_TYPE = WAZUH_AGENTS_OS_TYPE;

(function (WAZUH_AGENTS_OS_TYPE) {
  WAZUH_AGENTS_OS_TYPE["WINDOWS"] = "windows";
  WAZUH_AGENTS_OS_TYPE["LINUX"] = "linux";
  WAZUH_AGENTS_OS_TYPE["SUNOS"] = "sunos";
  WAZUH_AGENTS_OS_TYPE["DARWIN"] = "darwin";
  WAZUH_AGENTS_OS_TYPE["OTHERS"] = "";
})(WAZUH_AGENTS_OS_TYPE || (exports.WAZUH_AGENTS_OS_TYPE = WAZUH_AGENTS_OS_TYPE = {}));

let WAZUH_MODULES_ID;
exports.WAZUH_MODULES_ID = WAZUH_MODULES_ID;

(function (WAZUH_MODULES_ID) {
  WAZUH_MODULES_ID["SECURITY_EVENTS"] = "general";
  WAZUH_MODULES_ID["INTEGRITY_MONITORING"] = "fim";
  WAZUH_MODULES_ID["AMAZON_WEB_SERVICES"] = "aws";
  WAZUH_MODULES_ID["OFFICE_365"] = "office";
  WAZUH_MODULES_ID["GOOGLE_CLOUD_PLATFORM"] = "gcp";
  WAZUH_MODULES_ID["POLICY_MONITORING"] = "pm";
  WAZUH_MODULES_ID["SECURITY_CONFIGURATION_ASSESSMENT"] = "sca";
  WAZUH_MODULES_ID["AUDITING"] = "audit";
  WAZUH_MODULES_ID["OPEN_SCAP"] = "oscap";
  WAZUH_MODULES_ID["VULNERABILITIES"] = "vuls";
  WAZUH_MODULES_ID["OSQUERY"] = "osquery";
  WAZUH_MODULES_ID["DOCKER"] = "docker";
  WAZUH_MODULES_ID["MITRE_ATTACK"] = "mitre";
  WAZUH_MODULES_ID["PCI_DSS"] = "pci";
  WAZUH_MODULES_ID["HIPAA"] = "hipaa";
  WAZUH_MODULES_ID["NIST_800_53"] = "nist";
  WAZUH_MODULES_ID["TSC"] = "tsc";
  WAZUH_MODULES_ID["CIS_CAT"] = "ciscat";
  WAZUH_MODULES_ID["VIRUSTOTAL"] = "virustotal";
  WAZUH_MODULES_ID["GDPR"] = "gdpr";
  WAZUH_MODULES_ID["GITHUB"] = "github";
})(WAZUH_MODULES_ID || (exports.WAZUH_MODULES_ID = WAZUH_MODULES_ID = {}));

;
let WAZUH_MENU_MANAGEMENT_SECTIONS_ID;
exports.WAZUH_MENU_MANAGEMENT_SECTIONS_ID = WAZUH_MENU_MANAGEMENT_SECTIONS_ID;

(function (WAZUH_MENU_MANAGEMENT_SECTIONS_ID) {
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["MANAGEMENT"] = "management";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["ADMINISTRATION"] = "administration";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["RULESET"] = "ruleset";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["RULES"] = "rules";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["DECODERS"] = "decoders";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["CDB_LISTS"] = "lists";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["GROUPS"] = "groups";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["CONFIGURATION"] = "configuration";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["STATUS_AND_REPORTS"] = "statusReports";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["STATUS"] = "status";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["CLUSTER"] = "monitoring";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["LOGS"] = "logs";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["REPORTING"] = "reporting";
  WAZUH_MENU_MANAGEMENT_SECTIONS_ID["STATISTICS"] = "statistics";
})(WAZUH_MENU_MANAGEMENT_SECTIONS_ID || (exports.WAZUH_MENU_MANAGEMENT_SECTIONS_ID = WAZUH_MENU_MANAGEMENT_SECTIONS_ID = {}));

;
let WAZUH_MENU_TOOLS_SECTIONS_ID;
exports.WAZUH_MENU_TOOLS_SECTIONS_ID = WAZUH_MENU_TOOLS_SECTIONS_ID;

(function (WAZUH_MENU_TOOLS_SECTIONS_ID) {
  WAZUH_MENU_TOOLS_SECTIONS_ID["API_CONSOLE"] = "devTools";
  WAZUH_MENU_TOOLS_SECTIONS_ID["RULESET_TEST"] = "logtest";
})(WAZUH_MENU_TOOLS_SECTIONS_ID || (exports.WAZUH_MENU_TOOLS_SECTIONS_ID = WAZUH_MENU_TOOLS_SECTIONS_ID = {}));

;
let WAZUH_MENU_SECURITY_SECTIONS_ID;
exports.WAZUH_MENU_SECURITY_SECTIONS_ID = WAZUH_MENU_SECURITY_SECTIONS_ID;

(function (WAZUH_MENU_SECURITY_SECTIONS_ID) {
  WAZUH_MENU_SECURITY_SECTIONS_ID["USERS"] = "users";
  WAZUH_MENU_SECURITY_SECTIONS_ID["ROLES"] = "roles";
  WAZUH_MENU_SECURITY_SECTIONS_ID["POLICIES"] = "policies";
  WAZUH_MENU_SECURITY_SECTIONS_ID["ROLES_MAPPING"] = "roleMapping";
})(WAZUH_MENU_SECURITY_SECTIONS_ID || (exports.WAZUH_MENU_SECURITY_SECTIONS_ID = WAZUH_MENU_SECURITY_SECTIONS_ID = {}));

;
let WAZUH_MENU_SETTINGS_SECTIONS_ID;
exports.WAZUH_MENU_SETTINGS_SECTIONS_ID = WAZUH_MENU_SETTINGS_SECTIONS_ID;

(function (WAZUH_MENU_SETTINGS_SECTIONS_ID) {
  WAZUH_MENU_SETTINGS_SECTIONS_ID["SETTINGS"] = "settings";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["API_CONFIGURATION"] = "api";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["MODULES"] = "modules";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["SAMPLE_DATA"] = "sample_data";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["CONFIGURATION"] = "configuration";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["LOGS"] = "logs";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["MISCELLANEOUS"] = "miscellaneous";
  WAZUH_MENU_SETTINGS_SECTIONS_ID["ABOUT"] = "about";
})(WAZUH_MENU_SETTINGS_SECTIONS_ID || (exports.WAZUH_MENU_SETTINGS_SECTIONS_ID = WAZUH_MENU_SETTINGS_SECTIONS_ID = {}));

;
const AUTHORIZED_AGENTS = 'authorized-agents'; // Wazuh links

exports.AUTHORIZED_AGENTS = AUTHORIZED_AGENTS;
const WAZUH_LINK_GITHUB = 'https://github.com/wazuh';
exports.WAZUH_LINK_GITHUB = WAZUH_LINK_GITHUB;
const WAZUH_LINK_GOOGLE_GROUPS = 'https://groups.google.com/forum/#!forum/wazuh';
exports.WAZUH_LINK_GOOGLE_GROUPS = WAZUH_LINK_GOOGLE_GROUPS;
const WAZUH_LINK_SLACK = 'https://wazuh.com/community/join-us-on-slack';
exports.WAZUH_LINK_SLACK = WAZUH_LINK_SLACK;
const HEALTH_CHECK = 'health-check'; // Health check

exports.HEALTH_CHECK = HEALTH_CHECK;
const HEALTH_CHECK_REDIRECTION_TIME = 300; //ms
// Plugin platform settings
// Default timeFilter set by the app

exports.HEALTH_CHECK_REDIRECTION_TIME = HEALTH_CHECK_REDIRECTION_TIME;
const WAZUH_PLUGIN_PLATFORM_SETTING_TIME_FILTER = {
  from: 'now-24h',
  to: 'now'
};
exports.WAZUH_PLUGIN_PLATFORM_SETTING_TIME_FILTER = WAZUH_PLUGIN_PLATFORM_SETTING_TIME_FILTER;
const PLUGIN_PLATFORM_SETTING_NAME_TIME_FILTER = 'timepicker:timeDefaults'; // Default maxBuckets set by the app

exports.PLUGIN_PLATFORM_SETTING_NAME_TIME_FILTER = PLUGIN_PLATFORM_SETTING_NAME_TIME_FILTER;
const WAZUH_PLUGIN_PLATFORM_SETTING_MAX_BUCKETS = 200000;
exports.WAZUH_PLUGIN_PLATFORM_SETTING_MAX_BUCKETS = WAZUH_PLUGIN_PLATFORM_SETTING_MAX_BUCKETS;
const PLUGIN_PLATFORM_SETTING_NAME_MAX_BUCKETS = 'timelion:max_buckets'; // Default metaFields set by the app

exports.PLUGIN_PLATFORM_SETTING_NAME_MAX_BUCKETS = PLUGIN_PLATFORM_SETTING_NAME_MAX_BUCKETS;
const WAZUH_PLUGIN_PLATFORM_SETTING_METAFIELDS = ['_source', '_index'];
exports.WAZUH_PLUGIN_PLATFORM_SETTING_METAFIELDS = WAZUH_PLUGIN_PLATFORM_SETTING_METAFIELDS;
const PLUGIN_PLATFORM_SETTING_NAME_METAFIELDS = 'metaFields'; // Logger

exports.PLUGIN_PLATFORM_SETTING_NAME_METAFIELDS = PLUGIN_PLATFORM_SETTING_NAME_METAFIELDS;
const UI_LOGGER_LEVELS = {
  WARNING: 'WARNING',
  INFO: 'INFO',
  ERROR: 'ERROR'
};
exports.UI_LOGGER_LEVELS = UI_LOGGER_LEVELS;
const UI_TOAST_COLOR = {
  SUCCESS: 'success',
  WARNING: 'warning',
  DANGER: 'danger'
}; // Assets

exports.UI_TOAST_COLOR = UI_TOAST_COLOR;
const ASSETS_BASE_URL_PREFIX = '/plugins/wazuh/assets/';
exports.ASSETS_BASE_URL_PREFIX = ASSETS_BASE_URL_PREFIX;
const ASSETS_PUBLIC_URL = '/plugins/wazuh/public/assets/'; // Reports

exports.ASSETS_PUBLIC_URL = ASSETS_PUBLIC_URL;
const REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH = 'images/logo_reports.png';
exports.REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH = REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH;
const REPORTS_PRIMARY_COLOR = '#256BD1';
exports.REPORTS_PRIMARY_COLOR = REPORTS_PRIMARY_COLOR;
const REPORTS_PAGE_FOOTER_TEXT = 'Copyright © 2022 Wazuh, Inc.';
exports.REPORTS_PAGE_FOOTER_TEXT = REPORTS_PAGE_FOOTER_TEXT;
const REPORTS_PAGE_HEADER_TEXT = 'info@wazuh.com\nhttps://wazuh.com'; // Plugin platform

exports.REPORTS_PAGE_HEADER_TEXT = REPORTS_PAGE_HEADER_TEXT;
const PLUGIN_PLATFORM_NAME = 'Kibana';
exports.PLUGIN_PLATFORM_NAME = PLUGIN_PLATFORM_NAME;
const PLUGIN_PLATFORM_BASE_INSTALLATION_PATH = '/usr/share/kibana/data/wazuh/';
exports.PLUGIN_PLATFORM_BASE_INSTALLATION_PATH = PLUGIN_PLATFORM_BASE_INSTALLATION_PATH;
const PLUGIN_PLATFORM_INSTALLATION_USER = 'kibana';
exports.PLUGIN_PLATFORM_INSTALLATION_USER = PLUGIN_PLATFORM_INSTALLATION_USER;
const PLUGIN_PLATFORM_INSTALLATION_USER_GROUP = 'kibana';
exports.PLUGIN_PLATFORM_INSTALLATION_USER_GROUP = PLUGIN_PLATFORM_INSTALLATION_USER_GROUP;
const PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_UPGRADE_PLATFORM = 'upgrade-guide';
exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_UPGRADE_PLATFORM = PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_UPGRADE_PLATFORM;
const PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_TROUBLESHOOTING = 'user-manual/elasticsearch/troubleshooting.html';
exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_TROUBLESHOOTING = PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_TROUBLESHOOTING;
const PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_APP_CONFIGURATION = 'user-manual/wazuh-dashboard/config-file.html';
exports.PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_APP_CONFIGURATION = PLUGIN_PLATFORM_WAZUH_DOCUMENTATION_URL_PATH_APP_CONFIGURATION;
const PLUGIN_PLATFORM_URL_GUIDE = 'https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html';
exports.PLUGIN_PLATFORM_URL_GUIDE = PLUGIN_PLATFORM_URL_GUIDE;
const PLUGIN_PLATFORM_URL_GUIDE_TITLE = 'Elastic guide';
exports.PLUGIN_PLATFORM_URL_GUIDE_TITLE = PLUGIN_PLATFORM_URL_GUIDE_TITLE;
const PLUGIN_PLATFORM_REQUEST_HEADERS = {
  'kbn-xsrf': 'kibana'
}; // Plugin app

exports.PLUGIN_PLATFORM_REQUEST_HEADERS = PLUGIN_PLATFORM_REQUEST_HEADERS;
const PLUGIN_APP_NAME = 'Wazuh App'; // UI

exports.PLUGIN_APP_NAME = PLUGIN_APP_NAME;
const API_NAME_AGENT_STATUS = {
  ACTIVE: 'active',
  DISCONNECTED: 'disconnected',
  PENDING: 'pending',
  NEVER_CONNECTED: 'never_connected'
};
exports.API_NAME_AGENT_STATUS = API_NAME_AGENT_STATUS;
const UI_COLOR_AGENT_STATUS = {
  [API_NAME_AGENT_STATUS.ACTIVE]: '#007871',
  [API_NAME_AGENT_STATUS.DISCONNECTED]: '#BD271E',
  [API_NAME_AGENT_STATUS.PENDING]: '#FEC514',
  [API_NAME_AGENT_STATUS.NEVER_CONNECTED]: '#646A77',
  default: '#000000'
};
exports.UI_COLOR_AGENT_STATUS = UI_COLOR_AGENT_STATUS;
const UI_LABEL_NAME_AGENT_STATUS = {
  [API_NAME_AGENT_STATUS.ACTIVE]: 'Active',
  [API_NAME_AGENT_STATUS.DISCONNECTED]: 'Disconnected',
  [API_NAME_AGENT_STATUS.PENDING]: 'Pending',
  [API_NAME_AGENT_STATUS.NEVER_CONNECTED]: 'Never connected',
  default: 'Unknown'
};
exports.UI_LABEL_NAME_AGENT_STATUS = UI_LABEL_NAME_AGENT_STATUS;
const UI_ORDER_AGENT_STATUS = [API_NAME_AGENT_STATUS.ACTIVE, API_NAME_AGENT_STATUS.DISCONNECTED, API_NAME_AGENT_STATUS.PENDING, API_NAME_AGENT_STATUS.NEVER_CONNECTED];
exports.UI_ORDER_AGENT_STATUS = UI_ORDER_AGENT_STATUS;
const AGENT_SYNCED_STATUS = {
  SYNCED: 'synced',
  NOT_SYNCED: 'not synced'
}; // Documentation

exports.AGENT_SYNCED_STATUS = AGENT_SYNCED_STATUS;
const DOCUMENTATION_WEB_BASE_URL = "https://documentation.wazuh.com"; // Default Elasticsearch user name context

exports.DOCUMENTATION_WEB_BASE_URL = DOCUMENTATION_WEB_BASE_URL;
const ELASTIC_NAME = 'elastic'; // Customization

exports.ELASTIC_NAME = ELASTIC_NAME;
const CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES = 1048576; // Plugin settings

exports.CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES = CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES;
let SettingCategory;
exports.SettingCategory = SettingCategory;

(function (SettingCategory) {
  SettingCategory[SettingCategory["GENERAL"] = 0] = "GENERAL";
  SettingCategory[SettingCategory["HEALTH_CHECK"] = 1] = "HEALTH_CHECK";
  SettingCategory[SettingCategory["EXTENSIONS"] = 2] = "EXTENSIONS";
  SettingCategory[SettingCategory["MONITORING"] = 3] = "MONITORING";
  SettingCategory[SettingCategory["STATISTICS"] = 4] = "STATISTICS";
  SettingCategory[SettingCategory["SECURITY"] = 5] = "SECURITY";
  SettingCategory[SettingCategory["CUSTOMIZATION"] = 6] = "CUSTOMIZATION";
})(SettingCategory || (exports.SettingCategory = SettingCategory = {}));

;
let EpluginSettingType;
exports.EpluginSettingType = EpluginSettingType;

(function (EpluginSettingType) {
  EpluginSettingType["text"] = "text";
  EpluginSettingType["textarea"] = "textarea";
  EpluginSettingType["switch"] = "switch";
  EpluginSettingType["number"] = "number";
  EpluginSettingType["editor"] = "editor";
  EpluginSettingType["select"] = "select";
  EpluginSettingType["filepicker"] = "filepicker";
})(EpluginSettingType || (exports.EpluginSettingType = EpluginSettingType = {}));

;
const PLUGIN_SETTINGS_CATEGORIES = {
  [SettingCategory.HEALTH_CHECK]: {
    title: 'Health check',
    description: "Checks will be executed by the app's Healthcheck.",
    renderOrder: SettingCategory.HEALTH_CHECK
  },
  [SettingCategory.GENERAL]: {
    title: 'General',
    description: "Basic app settings related to alerts index pattern, hide the manager alerts in the dashboards, logs level and more.",
    renderOrder: SettingCategory.GENERAL
  },
  [SettingCategory.EXTENSIONS]: {
    title: 'Initial display state of the modules of the new API host entries.',
    description: "Extensions."
  },
  [SettingCategory.SECURITY]: {
    title: 'Security',
    description: "Application security options such as unauthorized roles.",
    renderOrder: SettingCategory.SECURITY
  },
  [SettingCategory.MONITORING]: {
    title: 'Task:Monitoring',
    description: "Options related to the agent status monitoring job and its storage in indexes.",
    renderOrder: SettingCategory.MONITORING
  },
  [SettingCategory.STATISTICS]: {
    title: 'Task:Statistics',
    description: "Options related to the daemons manager monitoring job and their storage in indexes..",
    renderOrder: SettingCategory.STATISTICS
  },
  [SettingCategory.CUSTOMIZATION]: {
    title: 'Custom branding',
    description: "If you want to use custom branding elements such as logos, you can do so by editing the settings below.",
    documentationLink: 'user-manual/wazuh-dashboard/white-labeling.html',
    renderOrder: SettingCategory.CUSTOMIZATION
  }
};
exports.PLUGIN_SETTINGS_CATEGORIES = PLUGIN_SETTINGS_CATEGORIES;
const PLUGIN_SETTINGS = {
  "alerts.sample.prefix": {
    title: "Sample alerts prefix",
    description: "Define the index name prefix of sample alerts. It must match the template used by the index pattern to avoid unknown fields in dashboards.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_SAMPLE_ALERT_PREFIX,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#', '*')),
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate
      });
    }
  },
  "checks.api": {
    title: "API connection",
    description: "Enable or disable the API health check when opening the app.",
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "checks.fields": {
    title: "Known fields",
    description: "Enable or disable the known fields health check when opening the app.",
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "checks.maxBuckets": {
    title: "Set max buckets to 200000",
    description: "Change the default value of the plugin platform max buckets configuration.",
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "checks.metaFields": {
    title: "Remove meta fields",
    description: "Change the default value of the plugin platform metaField configuration.",
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "checks.pattern": {
    title: "Index pattern",
    description: "Enable or disable the index pattern health check when opening the app.",
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "checks.setup": {
    title: "API version",
    description: "Enable or disable the setup health check when opening the app.",
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "checks.template": {
    title: "Index template",
    description: "Enable or disable the template health check when opening the app.",
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "checks.timeFilter": {
    title: "Set time filter to 24h",
    description: "Change the default value of the plugin platform timeFilter configuration.",
    category: SettingCategory.HEALTH_CHECK,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "cron.prefix": {
    title: "Cron prefix",
    description: "Define the index prefix of predefined jobs.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_STATISTICS_DEFAULT_PREFIX,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#', '*')),
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate
      });
    }
  },
  "cron.statistics.apis": {
    title: "Includes APIs",
    description: "Enter the ID of the hosts you want to save data from, leave this empty to run the task on every host.",
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.editor,
    defaultValue: [],
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      editor: {
        language: 'json'
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return JSON.stringify(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      try {
        return JSON.parse(value);
      } catch (error) {
        return value;
      }

      ;
    },
    validate: _settingsValidator.SettingsValidator.json(_settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.array(_settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces)))),
    validateBackend: function (schema) {
      return schema.arrayOf(schema.string({
        validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces)
      }));
    }
  },
  "cron.statistics.index.creation": {
    title: "Index creation",
    description: "Define the interval in which a new index will be created.",
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.select,
    options: {
      select: [{
        text: "Hourly",
        value: "h"
      }, {
        text: "Daily",
        value: "d"
      }, {
        text: "Weekly",
        value: "w"
      }, {
        text: "Monthly",
        value: "m"
      }]
    },
    defaultValue: WAZUH_STATISTICS_DEFAULT_CREATION,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    validate: function (value) {
      return _settingsValidator.SettingsValidator.literal(this.options.select.map(({
        value
      }) => value))(value);
    },
    validateBackend: function (schema) {
      return schema.oneOf(this.options.select.map(({
        value
      }) => schema.literal(value)));
    }
  },
  "cron.statistics.index.name": {
    title: "Index name",
    description: "Define the name of the index in which the documents will be saved.",
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_STATISTICS_DEFAULT_NAME,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#', '*')),
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate
      });
    }
  },
  "cron.statistics.index.replicas": {
    title: "Index replicas",
    description: "Define the number of replicas to use for the statistics indices.",
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_STATISTICS_DEFAULT_INDICES_REPLICAS,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    options: {
      number: {
        min: 0,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    },
    validateBackend: function (schema) {
      return schema.number({
        validate: this.validate.bind(this)
      });
    }
  },
  "cron.statistics.index.shards": {
    title: "Index shards",
    description: "Define the number of shards to use for the statistics indices.",
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_STATISTICS_DEFAULT_INDICES_SHARDS,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    options: {
      number: {
        min: 1,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    },
    validateBackend: function (schema) {
      return schema.number({
        validate: this.validate.bind(this)
      });
    }
  },
  "cron.statistics.interval": {
    title: "Interval",
    description: "Define the frequency of task execution using cron schedule expressions.",
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_STATISTICS_DEFAULT_CRON_FREQ,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRestartingPluginPlatform: true,
    validate: function (value) {
      return (0, _nodeCron.validate)(value) ? undefined : "Interval is not valid.";
    },
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate
      });
    }
  },
  "cron.statistics.status": {
    title: "Status",
    description: "Enable or disable the statistics tasks.",
    category: SettingCategory.STATISTICS,
    type: EpluginSettingType.switch,
    defaultValue: WAZUH_STATISTICS_DEFAULT_STATUS,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "customization.enabled": {
    title: "Status",
    description: "Enable or disable the customization.",
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresReloadingBrowserTab: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "customization.logo.app": {
    title: "App main logo",
    description: `This logo is used in the app main menu, at the top left corner.`,
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.filepicker,
    defaultValue: "",
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      file: {
        type: 'image',
        extensions: ['.jpeg', '.jpg', '.png', '.svg'],
        size: {
          maxBytes: CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES
        },
        recommended: {
          dimensions: {
            width: 300,
            height: 70,
            unit: 'px'
          }
        },
        store: {
          relativePathFileSystem: 'public/assets/custom/images',
          filename: 'customization.logo.app',
          resolveStaticURL: filename => `custom/images/${filename}?v=${Date.now()}` // ?v=${Date.now()} is used to force the browser to reload the image when a new file is uploaded

        }
      }
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.filePickerFileSize({ ...this.options.file.size,
        meaningfulUnit: true
      }), _settingsValidator.SettingsValidator.filePickerSupportedExtensions(this.options.file.extensions))(value);
    }
  },
  "customization.logo.healthcheck": {
    title: "Healthcheck logo",
    description: `This logo is displayed during the Healthcheck routine of the app.`,
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.filepicker,
    defaultValue: "",
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      file: {
        type: 'image',
        extensions: ['.jpeg', '.jpg', '.png', '.svg'],
        size: {
          maxBytes: CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES
        },
        recommended: {
          dimensions: {
            width: 300,
            height: 70,
            unit: 'px'
          }
        },
        store: {
          relativePathFileSystem: 'public/assets/custom/images',
          filename: 'customization.logo.healthcheck',
          resolveStaticURL: filename => `custom/images/${filename}?v=${Date.now()}` // ?v=${Date.now()} is used to force the browser to reload the image when a new file is uploaded

        }
      }
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.filePickerFileSize({ ...this.options.file.size,
        meaningfulUnit: true
      }), _settingsValidator.SettingsValidator.filePickerSupportedExtensions(this.options.file.extensions))(value);
    }
  },
  "customization.logo.reports": {
    title: "PDF reports logo",
    description: `This logo is used in the PDF reports generated by the app. It's placed at the top left corner of every page of the PDF.`,
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.filepicker,
    defaultValue: "",
    defaultValueIfNotSet: REPORTS_LOGO_IMAGE_ASSETS_RELATIVE_PATH,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      file: {
        type: 'image',
        extensions: ['.jpeg', '.jpg', '.png'],
        size: {
          maxBytes: CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES
        },
        recommended: {
          dimensions: {
            width: 190,
            height: 40,
            unit: 'px'
          }
        },
        store: {
          relativePathFileSystem: 'public/assets/custom/images',
          filename: 'customization.logo.reports',
          resolveStaticURL: filename => `custom/images/${filename}`
        }
      }
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.filePickerFileSize({ ...this.options.file.size,
        meaningfulUnit: true
      }), _settingsValidator.SettingsValidator.filePickerSupportedExtensions(this.options.file.extensions))(value);
    }
  },
  "customization.logo.sidebar": {
    title: "Navigation drawer logo",
    description: `This is the logo for the app to display in the platform's navigation drawer, this is, the main sidebar collapsible menu.`,
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.filepicker,
    defaultValue: "",
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresReloadingBrowserTab: true,
    options: {
      file: {
        type: 'image',
        extensions: ['.jpeg', '.jpg', '.png', '.svg'],
        size: {
          maxBytes: CUSTOMIZATION_ENDPOINT_PAYLOAD_UPLOAD_CUSTOM_FILE_MAXIMUM_BYTES
        },
        recommended: {
          dimensions: {
            width: 80,
            height: 80,
            unit: 'px'
          }
        },
        store: {
          relativePathFileSystem: 'public/assets/custom/images',
          filename: 'customization.logo.sidebar',
          resolveStaticURL: filename => `custom/images/${filename}?v=${Date.now()}` // ?v=${Date.now()} is used to force the browser to reload the image when a new file is uploaded

        }
      }
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.filePickerFileSize({ ...this.options.file.size,
        meaningfulUnit: true
      }), _settingsValidator.SettingsValidator.filePickerSupportedExtensions(this.options.file.extensions))(value);
    }
  },
  "customization.reports.footer": {
    title: "Reports footer",
    description: "Set the footer of the reports.",
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.textarea,
    defaultValue: "",
    defaultValueIfNotSet: REPORTS_PAGE_FOOTER_TEXT,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      maxRows: 2,
      maxLength: 50
    },
    validate: function (value) {
      var _this$options, _this$options2;

      return _settingsValidator.SettingsValidator.multipleLinesString({
        maxRows: (_this$options = this.options) === null || _this$options === void 0 ? void 0 : _this$options.maxRows,
        maxLength: (_this$options2 = this.options) === null || _this$options2 === void 0 ? void 0 : _this$options2.maxLength
      })(value);
    },
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate.bind(this)
      });
    }
  },
  "customization.reports.header": {
    title: "Reports header",
    description: "Set the header of the reports.",
    category: SettingCategory.CUSTOMIZATION,
    type: EpluginSettingType.textarea,
    defaultValue: "",
    defaultValueIfNotSet: REPORTS_PAGE_HEADER_TEXT,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      maxRows: 3,
      maxLength: 40
    },
    validate: function (value) {
      var _this$options3, _this$options4;

      return _settingsValidator.SettingsValidator.multipleLinesString({
        maxRows: (_this$options3 = this.options) === null || _this$options3 === void 0 ? void 0 : _this$options3.maxRows,
        maxLength: (_this$options4 = this.options) === null || _this$options4 === void 0 ? void 0 : _this$options4.maxLength
      })(value);
    },
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate.bind(this)
      });
    }
  },
  "disabled_roles": {
    title: "Disable roles",
    description: "Disabled the plugin visibility for users with the roles.",
    category: SettingCategory.SECURITY,
    type: EpluginSettingType.editor,
    defaultValue: [],
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      editor: {
        language: 'json'
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return JSON.stringify(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      try {
        return JSON.parse(value);
      } catch (error) {
        return value;
      }

      ;
    },
    validate: _settingsValidator.SettingsValidator.json(_settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.array(_settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces)))),
    validateBackend: function (schema) {
      return schema.arrayOf(schema.string({
        validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces)
      }));
    }
  },
  "enrollment.dns": {
    title: "Enrollment DNS",
    description: "Specifies the Wazuh registration server, used for the agent enrollment.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: "",
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    validate: _settingsValidator.SettingsValidator.hasNoSpaces,
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate
      });
    }
  },
  "enrollment.password": {
    title: "Enrollment password",
    description: "Specifies the password used to authenticate during the agent enrollment.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: "",
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    validate: _settingsValidator.SettingsValidator.isNotEmptyString,
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate
      });
    }
  },
  "extensions.audit": {
    title: "System auditing",
    description: "Enable or disable the Audit tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.aws": {
    title: "Amazon AWS",
    description: "Enable or disable the Amazon (AWS) tab on Overview.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.ciscat": {
    title: "CIS-CAT",
    description: "Enable or disable the CIS-CAT tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.docker": {
    title: "Docker listener",
    description: "Enable or disable the Docker listener tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.gcp": {
    title: "Google Cloud platform",
    description: "Enable or disable the Google Cloud Platform tab on Overview.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.gdpr": {
    title: "GDPR",
    description: "Enable or disable the GDPR tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.hipaa": {
    title: "Hipaa",
    description: "Enable or disable the HIPAA tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.nist": {
    title: "NIST",
    description: "Enable or disable the NIST 800-53 tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.oscap": {
    title: "OSCAP",
    description: "Enable or disable the Open SCAP tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.osquery": {
    title: "Osquery",
    description: "Enable or disable the Osquery tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.pci": {
    title: "PCI DSS",
    description: "Enable or disable the PCI DSS tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.tsc": {
    title: "TSC",
    description: "Enable or disable the TSC tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "extensions.virustotal": {
    title: "Virustotal",
    description: "Enable or disable the VirusTotal tab on Overview and Agents.",
    category: SettingCategory.EXTENSIONS,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "hideManagerAlerts": {
    title: "Hide manager alerts",
    description: "Hide the alerts of the manager in every dashboard.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.switch,
    defaultValue: false,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresReloadingBrowserTab: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "ip.ignore": {
    title: "Index pattern ignore",
    description: "Disable certain index pattern names from being available in index pattern selector.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.editor,
    defaultValue: [],
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      editor: {
        language: 'json'
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return JSON.stringify(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      try {
        return JSON.parse(value);
      } catch (error) {
        return value;
      }

      ;
    },
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validate: _settingsValidator.SettingsValidator.json(_settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.array(_settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isString, _settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noLiteralString('.', '..'), _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#'))))),
    validateBackend: function (schema) {
      return schema.arrayOf(schema.string({
        validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noLiteralString('.', '..'), _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#'))
      }));
    }
  },
  "ip.selector": {
    title: "IP selector",
    description: "Define if the user is allowed to change the selected index pattern directly from the top menu bar.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.switch,
    defaultValue: true,
    isConfigurableFromFile: true,
    isConfigurableFromUI: false,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "logs.level": {
    title: "Log level",
    description: "Logging level of the App.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.select,
    options: {
      select: [{
        text: "Info",
        value: "info"
      }, {
        text: "Debug",
        value: "debug"
      }]
    },
    defaultValue: "info",
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRestartingPluginPlatform: true,
    validate: function (value) {
      return _settingsValidator.SettingsValidator.literal(this.options.select.map(({
        value
      }) => value))(value);
    },
    validateBackend: function (schema) {
      return schema.oneOf(this.options.select.map(({
        value
      }) => schema.literal(value)));
    }
  },
  "pattern": {
    title: "Index pattern",
    description: "Default index pattern to use on the app. If there's no valid index pattern, the app will automatically create one with the name indicated in this option.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_ALERTS_PATTERN,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    // Validation: https://github.com/elastic/elasticsearch/blob/v7.10.2/docs/reference/indices/create-index.asciidoc
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noLiteralString('.', '..'), _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#')),
    validateBackend: function (schema) {
      return schema.string({
        validate: this.validate
      });
    }
  },
  "timeout": {
    title: "Request timeout",
    description: "Maximum time, in milliseconds, the app will wait for an API response when making requests to it. It will be ignored if the value is set under 1500 milliseconds.",
    category: SettingCategory.GENERAL,
    type: EpluginSettingType.number,
    defaultValue: 20000,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    options: {
      number: {
        min: 1500,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    },
    validateBackend: function (schema) {
      return schema.number({
        validate: this.validate.bind(this)
      });
    }
  },
  "wazuh.monitoring.creation": {
    title: "Index creation",
    description: "Define the interval in which a new wazuh-monitoring index will be created.",
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.select,
    options: {
      select: [{
        text: "Hourly",
        value: "h"
      }, {
        text: "Daily",
        value: "d"
      }, {
        text: "Weekly",
        value: "w"
      }, {
        text: "Monthly",
        value: "m"
      }]
    },
    defaultValue: WAZUH_MONITORING_DEFAULT_CREATION,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    validate: function (value) {
      return _settingsValidator.SettingsValidator.literal(this.options.select.map(({
        value
      }) => value))(value);
    },
    validateBackend: function (schema) {
      return schema.oneOf(this.options.select.map(({
        value
      }) => schema.literal(value)));
    }
  },
  "wazuh.monitoring.enabled": {
    title: "Status",
    description: "Enable or disable the wazuh-monitoring index creation and/or visualization.",
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.switch,
    defaultValue: WAZUH_MONITORING_DEFAULT_ENABLED,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRestartingPluginPlatform: true,
    options: {
      switch: {
        values: {
          disabled: {
            label: 'false',
            value: false
          },
          enabled: {
            label: 'true',
            value: true
          }
        }
      }
    },
    uiFormTransformChangedInputValue: function (value) {
      return Boolean(value);
    },
    validate: _settingsValidator.SettingsValidator.isBoolean,
    validateBackend: function (schema) {
      return schema.boolean();
    }
  },
  "wazuh.monitoring.frequency": {
    title: "Frequency",
    description: "Frequency, in seconds, of API requests to get the state of the agents and create a new document in the wazuh-monitoring index with this data.",
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_MONITORING_DEFAULT_FREQUENCY,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRestartingPluginPlatform: true,
    options: {
      number: {
        min: 60,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    },
    validateBackend: function (schema) {
      return schema.number({
        validate: this.validate.bind(this)
      });
    }
  },
  "wazuh.monitoring.pattern": {
    title: "Index pattern",
    description: "Default index pattern to use for Wazuh monitoring.",
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.text,
    defaultValue: WAZUH_MONITORING_PATTERN,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    validate: _settingsValidator.SettingsValidator.compose(_settingsValidator.SettingsValidator.isNotEmptyString, _settingsValidator.SettingsValidator.hasNoSpaces, _settingsValidator.SettingsValidator.noLiteralString('.', '..'), _settingsValidator.SettingsValidator.noStartsWithString('-', '_', '+', '.'), _settingsValidator.SettingsValidator.hasNotInvalidCharacters('\\', '/', '?', '"', '<', '>', '|', ',', '#')),
    validateBackend: function (schema) {
      return schema.string({
        minLength: 1,
        validate: this.validate
      });
    }
  },
  "wazuh.monitoring.replicas": {
    title: "Index replicas",
    description: "Define the number of replicas to use for the wazuh-monitoring-* indices.",
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_MONITORING_DEFAULT_INDICES_REPLICAS,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    options: {
      number: {
        min: 0,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    },
    validateBackend: function (schema) {
      return schema.number({
        validate: this.validate.bind(this)
      });
    }
  },
  "wazuh.monitoring.shards": {
    title: "Index shards",
    description: "Define the number of shards to use for the wazuh-monitoring-* indices.",
    category: SettingCategory.MONITORING,
    type: EpluginSettingType.number,
    defaultValue: WAZUH_MONITORING_DEFAULT_INDICES_SHARDS,
    isConfigurableFromFile: true,
    isConfigurableFromUI: true,
    requiresRunningHealthCheck: true,
    options: {
      number: {
        min: 1,
        integer: true
      }
    },
    uiFormTransformConfigurationValueToInputValue: function (value) {
      return String(value);
    },
    uiFormTransformInputValueToConfigurationValue: function (value) {
      return Number(value);
    },
    validate: function (value) {
      return _settingsValidator.SettingsValidator.number(this.options.number)(value);
    },
    validateBackend: function (schema) {
      return schema.number({
        validate: this.validate.bind(this)
      });
    }
  }
};
exports.PLUGIN_SETTINGS = PLUGIN_SETTINGS;
let HTTP_STATUS_CODES; // Module Security configuration assessment

exports.HTTP_STATUS_CODES = HTTP_STATUS_CODES;

(function (HTTP_STATUS_CODES) {
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["CONTINUE"] = 100] = "CONTINUE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["SWITCHING_PROTOCOLS"] = 101] = "SWITCHING_PROTOCOLS";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PROCESSING"] = 102] = "PROCESSING";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["OK"] = 200] = "OK";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["CREATED"] = 201] = "CREATED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["ACCEPTED"] = 202] = "ACCEPTED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NON_AUTHORITATIVE_INFORMATION"] = 203] = "NON_AUTHORITATIVE_INFORMATION";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NO_CONTENT"] = 204] = "NO_CONTENT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["RESET_CONTENT"] = 205] = "RESET_CONTENT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PARTIAL_CONTENT"] = 206] = "PARTIAL_CONTENT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MULTI_STATUS"] = 207] = "MULTI_STATUS";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MULTIPLE_CHOICES"] = 300] = "MULTIPLE_CHOICES";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MOVED_PERMANENTLY"] = 301] = "MOVED_PERMANENTLY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MOVED_TEMPORARILY"] = 302] = "MOVED_TEMPORARILY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["SEE_OTHER"] = 303] = "SEE_OTHER";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NOT_MODIFIED"] = 304] = "NOT_MODIFIED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["USE_PROXY"] = 305] = "USE_PROXY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["TEMPORARY_REDIRECT"] = 307] = "TEMPORARY_REDIRECT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PERMANENT_REDIRECT"] = 308] = "PERMANENT_REDIRECT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["BAD_REQUEST"] = 400] = "BAD_REQUEST";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["UNAUTHORIZED"] = 401] = "UNAUTHORIZED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PAYMENT_REQUIRED"] = 402] = "PAYMENT_REQUIRED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["FORBIDDEN"] = 403] = "FORBIDDEN";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NOT_FOUND"] = 404] = "NOT_FOUND";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["METHOD_NOT_ALLOWED"] = 405] = "METHOD_NOT_ALLOWED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NOT_ACCEPTABLE"] = 406] = "NOT_ACCEPTABLE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PROXY_AUTHENTICATION_REQUIRED"] = 407] = "PROXY_AUTHENTICATION_REQUIRED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUEST_TIMEOUT"] = 408] = "REQUEST_TIMEOUT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["CONFLICT"] = 409] = "CONFLICT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["GONE"] = 410] = "GONE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["LENGTH_REQUIRED"] = 411] = "LENGTH_REQUIRED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PRECONDITION_FAILED"] = 412] = "PRECONDITION_FAILED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUEST_TOO_LONG"] = 413] = "REQUEST_TOO_LONG";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUEST_URI_TOO_LONG"] = 414] = "REQUEST_URI_TOO_LONG";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["UNSUPPORTED_MEDIA_TYPE"] = 415] = "UNSUPPORTED_MEDIA_TYPE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUESTED_RANGE_NOT_SATISFIABLE"] = 416] = "REQUESTED_RANGE_NOT_SATISFIABLE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["EXPECTATION_FAILED"] = 417] = "EXPECTATION_FAILED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["IM_A_TEAPOT"] = 418] = "IM_A_TEAPOT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["INSUFFICIENT_SPACE_ON_RESOURCE"] = 419] = "INSUFFICIENT_SPACE_ON_RESOURCE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["METHOD_FAILURE"] = 420] = "METHOD_FAILURE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["MISDIRECTED_REQUEST"] = 421] = "MISDIRECTED_REQUEST";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["UNPROCESSABLE_ENTITY"] = 422] = "UNPROCESSABLE_ENTITY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["LOCKED"] = 423] = "LOCKED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["FAILED_DEPENDENCY"] = 424] = "FAILED_DEPENDENCY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["PRECONDITION_REQUIRED"] = 428] = "PRECONDITION_REQUIRED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["TOO_MANY_REQUESTS"] = 429] = "TOO_MANY_REQUESTS";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["REQUEST_HEADER_FIELDS_TOO_LARGE"] = 431] = "REQUEST_HEADER_FIELDS_TOO_LARGE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["UNAVAILABLE_FOR_LEGAL_REASONS"] = 451] = "UNAVAILABLE_FOR_LEGAL_REASONS";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["INTERNAL_SERVER_ERROR"] = 500] = "INTERNAL_SERVER_ERROR";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NOT_IMPLEMENTED"] = 501] = "NOT_IMPLEMENTED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["BAD_GATEWAY"] = 502] = "BAD_GATEWAY";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["SERVICE_UNAVAILABLE"] = 503] = "SERVICE_UNAVAILABLE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["GATEWAY_TIMEOUT"] = 504] = "GATEWAY_TIMEOUT";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["HTTP_VERSION_NOT_SUPPORTED"] = 505] = "HTTP_VERSION_NOT_SUPPORTED";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["INSUFFICIENT_STORAGE"] = 507] = "INSUFFICIENT_STORAGE";
  HTTP_STATUS_CODES[HTTP_STATUS_CODES["NETWORK_AUTHENTICATION_REQUIRED"] = 511] = "NETWORK_AUTHENTICATION_REQUIRED";
})(HTTP_STATUS_CODES || (exports.HTTP_STATUS_CODES = HTTP_STATUS_CODES = {}));

const MODULE_SCA_CHECK_RESULT_LABEL = {
  passed: 'Passed',
  failed: 'Failed',
  'not applicable': 'Not applicable'
};
exports.MODULE_SCA_CHECK_RESULT_LABEL = MODULE_SCA_CHECK_RESULT_LABEL;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImNvbnN0YW50cy50cyJdLCJuYW1lcyI6WyJQTFVHSU5fVkVSU0lPTiIsInZlcnNpb24iLCJQTFVHSU5fVkVSU0lPTl9TSE9SVCIsInNwbGl0Iiwic3BsaWNlIiwiam9pbiIsIldBWlVIX0lOREVYX1RZUEVfQUxFUlRTIiwiV0FaVUhfQUxFUlRTX1BSRUZJWCIsIldBWlVIX0FMRVJUU19QQVRURVJOIiwiV0FaVUhfSU5ERVhfVFlQRV9NT05JVE9SSU5HIiwiV0FaVUhfTU9OSVRPUklOR19QUkVGSVgiLCJXQVpVSF9NT05JVE9SSU5HX1BBVFRFUk4iLCJXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUUiLCJXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfSU5ESUNFU19TSEFSRFMiLCJXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfSU5ESUNFU19SRVBMSUNBUyIsIldBWlVIX01PTklUT1JJTkdfREVGQVVMVF9DUkVBVElPTiIsIldBWlVIX01PTklUT1JJTkdfREVGQVVMVF9FTkFCTEVEIiwiV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0ZSRVFVRU5DWSIsIldBWlVIX01PTklUT1JJTkdfREVGQVVMVF9DUk9OX0ZSRVEiLCJXQVpVSF9JTkRFWF9UWVBFX1NUQVRJU1RJQ1MiLCJXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfUFJFRklYIiwiV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX05BTUUiLCJXQVpVSF9TVEFUSVNUSUNTX1BBVFRFUk4iLCJXQVpVSF9TVEFUSVNUSUNTX1RFTVBMQVRFX05BTUUiLCJXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfSU5ESUNFU19TSEFSRFMiLCJXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfSU5ESUNFU19SRVBMSUNBUyIsIldBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9DUkVBVElPTiIsIldBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9TVEFUVVMiLCJXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfRlJFUVVFTkNZIiwiV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX0NST05fRlJFUSIsIldBWlVIX1BMVUdJTl9QTEFURk9STV9URU1QTEFURV9OQU1FIiwiV0FaVUhfUk9MRV9BRE1JTklTVFJBVE9SX0lEIiwiV0FaVUhfUk9MRV9BRE1JTklTVFJBVE9SX05BTUUiLCJXQVpVSF9TQU1QTEVfQUxFUlRfUFJFRklYIiwiV0FaVUhfU0FNUExFX0FMRVJUU19JTkRFWF9TSEFSRFMiLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1JFUExJQ0FTIiwiV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SWV9TRUNVUklUWSIsIldBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUllfQVVESVRJTkdfUE9MSUNZX01PTklUT1JJTkciLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JZX1RIUkVBVF9ERVRFQ1RJT04iLCJXQVpVSF9TQU1QTEVfQUxFUlRTX0RFRkFVTFRfTlVNQkVSX0FMRVJUUyIsIldBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUklFU19UWVBFX0FMRVJUUyIsInN5c2NoZWNrIiwiYXdzIiwib2ZmaWNlIiwiZ2NwIiwiYXV0aGVudGljYXRpb24iLCJzc2giLCJhcGFjaGUiLCJhbGVydHMiLCJ3ZWIiLCJ3aW5kb3dzIiwic2VydmljZV9jb250cm9sX21hbmFnZXIiLCJnaXRodWIiLCJyb290Y2hlY2siLCJhdWRpdCIsIm9wZW5zY2FwIiwiY2lzY2F0IiwidnVsbmVyYWJpbGl0aWVzIiwidmlydXN0b3RhbCIsIm9zcXVlcnkiLCJkb2NrZXIiLCJtaXRyZSIsIldBWlVIX1NFQ1VSSVRZX1BMVUdJTl9YUEFDS19TRUNVUklUWSIsIldBWlVIX1NFQ1VSSVRZX1BMVUdJTl9PUEVOX0RJU1RST19GT1JfRUxBU1RJQ1NFQVJDSCIsIldBWlVIX1NFQ1VSSVRZX1BMVUdJTlMiLCJXQVpVSF9DT05GSUdVUkFUSU9OX0NBQ0hFX1RJTUUiLCJXQVpVSF9BUElfUkVTRVJWRURfSURfTE9XRVJfVEhBTiIsIldBWlVIX0RBVEFfUExVR0lOX1BMQVRGT1JNX0JBU0VfUEFUSCIsIldBWlVIX0RBVEFfUExVR0lOX1BMQVRGT1JNX0JBU0VfQUJTT0xVVEVfUEFUSCIsInBhdGgiLCJfX2Rpcm5hbWUiLCJXQVpVSF9EQVRBX0FCU09MVVRFX1BBVEgiLCJXQVpVSF9EQVRBX0NPTkZJR19ESVJFQ1RPUllfUEFUSCIsIldBWlVIX0RBVEFfQ09ORklHX0FQUF9QQVRIIiwiV0FaVUhfREFUQV9DT05GSUdfUkVHSVNUUllfUEFUSCIsIk1BWF9NQl9MT0dfRklMRVMiLCJXQVpVSF9EQVRBX0xPR1NfRElSRUNUT1JZX1BBVEgiLCJXQVpVSF9EQVRBX0xPR1NfUExBSU5fRklMRU5BTUUiLCJXQVpVSF9EQVRBX0xPR1NfUExBSU5fUEFUSCIsIldBWlVIX0RBVEFfTE9HU19SQVdfRklMRU5BTUUiLCJXQVpVSF9EQVRBX0xPR1NfUkFXX1BBVEgiLCJXQVpVSF9VSV9MT0dTX1BMQUlOX0ZJTEVOQU1FIiwiV0FaVUhfVUlfTE9HU19SQVdfRklMRU5BTUUiLCJXQVpVSF9VSV9MT0dTX1BMQUlOX1BBVEgiLCJXQVpVSF9VSV9MT0dTX1JBV19QQVRIIiwiV0FaVUhfREFUQV9ET1dOTE9BRFNfRElSRUNUT1JZX1BBVEgiLCJXQVpVSF9EQVRBX0RPV05MT0FEU19SRVBPUlRTX0RJUkVDVE9SWV9QQVRIIiwiV0FaVUhfUVVFVUVfQ1JPTl9GUkVRIiwiV0FaVUhfRVJST1JfREFFTU9OU19OT1RfUkVBRFkiLCJXQVpVSF9BR0VOVFNfT1NfVFlQRSIsIldBWlVIX01PRFVMRVNfSUQiLCJXQVpVSF9NRU5VX01BTkFHRU1FTlRfU0VDVElPTlNfSUQiLCJXQVpVSF9NRU5VX1RPT0xTX1NFQ1RJT05TX0lEIiwiV0FaVUhfTUVOVV9TRUNVUklUWV9TRUNUSU9OU19JRCIsIldBWlVIX01FTlVfU0VUVElOR1NfU0VDVElPTlNfSUQiLCJBVVRIT1JJWkVEX0FHRU5UUyIsIldBWlVIX0xJTktfR0lUSFVCIiwiV0FaVUhfTElOS19HT09HTEVfR1JPVVBTIiwiV0FaVUhfTElOS19TTEFDSyIsIkhFQUxUSF9DSEVDSyIsIkhFQUxUSF9DSEVDS19SRURJUkVDVElPTl9USU1FIiwiV0FaVUhfUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfVElNRV9GSUxURVIiLCJmcm9tIiwidG8iLCJQTFVHSU5fUExBVEZPUk1fU0VUVElOR19OQU1FX1RJTUVfRklMVEVSIiwiV0FaVUhfUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfTUFYX0JVQ0tFVFMiLCJQTFVHSU5fUExBVEZPUk1fU0VUVElOR19OQU1FX01BWF9CVUNLRVRTIiwiV0FaVUhfUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfTUVUQUZJRUxEUyIsIlBMVUdJTl9QTEFURk9STV9TRVRUSU5HX05BTUVfTUVUQUZJRUxEUyIsIlVJX0xPR0dFUl9MRVZFTFMiLCJXQVJOSU5HIiwiSU5GTyIsIkVSUk9SIiwiVUlfVE9BU1RfQ09MT1IiLCJTVUNDRVNTIiwiREFOR0VSIiwiQVNTRVRTX0JBU0VfVVJMX1BSRUZJWCIsIkFTU0VUU19QVUJMSUNfVVJMIiwiUkVQT1JUU19MT0dPX0lNQUdFX0FTU0VUU19SRUxBVElWRV9QQVRIIiwiUkVQT1JUU19QUklNQVJZX0NPTE9SIiwiUkVQT1JUU19QQUdFX0ZPT1RFUl9URVhUIiwiUkVQT1JUU19QQUdFX0hFQURFUl9URVhUIiwiUExVR0lOX1BMQVRGT1JNX05BTUUiLCJQTFVHSU5fUExBVEZPUk1fQkFTRV9JTlNUQUxMQVRJT05fUEFUSCIsIlBMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUiIsIlBMVUdJTl9QTEFURk9STV9JTlNUQUxMQVRJT05fVVNFUl9HUk9VUCIsIlBMVUdJTl9QTEFURk9STV9XQVpVSF9ET0NVTUVOVEFUSU9OX1VSTF9QQVRIX1VQR1JBREVfUExBVEZPUk0iLCJQTFVHSU5fUExBVEZPUk1fV0FaVUhfRE9DVU1FTlRBVElPTl9VUkxfUEFUSF9UUk9VQkxFU0hPT1RJTkciLCJQTFVHSU5fUExBVEZPUk1fV0FaVUhfRE9DVU1FTlRBVElPTl9VUkxfUEFUSF9BUFBfQ09ORklHVVJBVElPTiIsIlBMVUdJTl9QTEFURk9STV9VUkxfR1VJREUiLCJQTFVHSU5fUExBVEZPUk1fVVJMX0dVSURFX1RJVExFIiwiUExVR0lOX1BMQVRGT1JNX1JFUVVFU1RfSEVBREVSUyIsIlBMVUdJTl9BUFBfTkFNRSIsIkFQSV9OQU1FX0FHRU5UX1NUQVRVUyIsIkFDVElWRSIsIkRJU0NPTk5FQ1RFRCIsIlBFTkRJTkciLCJORVZFUl9DT05ORUNURUQiLCJVSV9DT0xPUl9BR0VOVF9TVEFUVVMiLCJkZWZhdWx0IiwiVUlfTEFCRUxfTkFNRV9BR0VOVF9TVEFUVVMiLCJVSV9PUkRFUl9BR0VOVF9TVEFUVVMiLCJBR0VOVF9TWU5DRURfU1RBVFVTIiwiU1lOQ0VEIiwiTk9UX1NZTkNFRCIsIkRPQ1VNRU5UQVRJT05fV0VCX0JBU0VfVVJMIiwiRUxBU1RJQ19OQU1FIiwiQ1VTVE9NSVpBVElPTl9FTkRQT0lOVF9QQVlMT0FEX1VQTE9BRF9DVVNUT01fRklMRV9NQVhJTVVNX0JZVEVTIiwiU2V0dGluZ0NhdGVnb3J5IiwiRXBsdWdpblNldHRpbmdUeXBlIiwiUExVR0lOX1NFVFRJTkdTX0NBVEVHT1JJRVMiLCJ0aXRsZSIsImRlc2NyaXB0aW9uIiwicmVuZGVyT3JkZXIiLCJHRU5FUkFMIiwiRVhURU5TSU9OUyIsIlNFQ1VSSVRZIiwiTU9OSVRPUklORyIsIlNUQVRJU1RJQ1MiLCJDVVNUT01JWkFUSU9OIiwiZG9jdW1lbnRhdGlvbkxpbmsiLCJQTFVHSU5fU0VUVElOR1MiLCJjYXRlZ29yeSIsInR5cGUiLCJ0ZXh0IiwiZGVmYXVsdFZhbHVlIiwiaXNDb25maWd1cmFibGVGcm9tRmlsZSIsImlzQ29uZmlndXJhYmxlRnJvbVVJIiwicmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2siLCJ2YWxpZGF0ZSIsIlNldHRpbmdzVmFsaWRhdG9yIiwiY29tcG9zZSIsImlzTm90RW1wdHlTdHJpbmciLCJoYXNOb1NwYWNlcyIsIm5vU3RhcnRzV2l0aFN0cmluZyIsImhhc05vdEludmFsaWRDaGFyYWN0ZXJzIiwidmFsaWRhdGVCYWNrZW5kIiwic2NoZW1hIiwic3RyaW5nIiwic3dpdGNoIiwib3B0aW9ucyIsInZhbHVlcyIsImRpc2FibGVkIiwibGFiZWwiLCJ2YWx1ZSIsImVuYWJsZWQiLCJ1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZSIsIkJvb2xlYW4iLCJpc0Jvb2xlYW4iLCJib29sZWFuIiwiZWRpdG9yIiwibGFuZ3VhZ2UiLCJ1aUZvcm1UcmFuc2Zvcm1Db25maWd1cmF0aW9uVmFsdWVUb0lucHV0VmFsdWUiLCJKU09OIiwic3RyaW5naWZ5IiwidWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlIiwicGFyc2UiLCJlcnJvciIsImpzb24iLCJhcnJheSIsImlzU3RyaW5nIiwiYXJyYXlPZiIsInNlbGVjdCIsImxpdGVyYWwiLCJtYXAiLCJvbmVPZiIsIm51bWJlciIsIm1pbiIsImludGVnZXIiLCJTdHJpbmciLCJOdW1iZXIiLCJiaW5kIiwicmVxdWlyZXNSZXN0YXJ0aW5nUGx1Z2luUGxhdGZvcm0iLCJ1bmRlZmluZWQiLCJyZXF1aXJlc1JlbG9hZGluZ0Jyb3dzZXJUYWIiLCJmaWxlcGlja2VyIiwiZmlsZSIsImV4dGVuc2lvbnMiLCJzaXplIiwibWF4Qnl0ZXMiLCJyZWNvbW1lbmRlZCIsImRpbWVuc2lvbnMiLCJ3aWR0aCIsImhlaWdodCIsInVuaXQiLCJzdG9yZSIsInJlbGF0aXZlUGF0aEZpbGVTeXN0ZW0iLCJmaWxlbmFtZSIsInJlc29sdmVTdGF0aWNVUkwiLCJEYXRlIiwibm93IiwiZmlsZVBpY2tlckZpbGVTaXplIiwibWVhbmluZ2Z1bFVuaXQiLCJmaWxlUGlja2VyU3VwcG9ydGVkRXh0ZW5zaW9ucyIsImRlZmF1bHRWYWx1ZUlmTm90U2V0IiwidGV4dGFyZWEiLCJtYXhSb3dzIiwibWF4TGVuZ3RoIiwibXVsdGlwbGVMaW5lc1N0cmluZyIsIm5vTGl0ZXJhbFN0cmluZyIsIm1pbkxlbmd0aCIsIkhUVFBfU1RBVFVTX0NPREVTIiwiTU9EVUxFX1NDQV9DSEVDS19SRVNVTFRfTEFCRUwiLCJwYXNz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QTNEWUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7QUFBQUEsRUFBQUEsaUIsQ0FBQUEsaUI7R0FBQUEsaUIsaUNBQUFBLGlCOztBQTRETCxNQUFNQyw2QkFBNkIsR0FBRztBQUMzQ0MsRUFBQUEsTUFBTSxFQUFFLFFBRG1DO0FBRTNDQyxFQUFBQSxNQUFNLEVBQUUsUUFGbUM7QUFHM0Msb0JBQWtCO0FBSHlCLENBQXRDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIFdhenVoIENvbnN0YW50cyBmaWxlXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHBhdGggZnJvbSAncGF0aCc7XG5pbXBvcnQgeyB2ZXJzaW9uIH0gZnJvbSAnLi4vcGFja2FnZS5qc29uJztcbmltcG9ydCB7IHZhbGlkYXRlIGFzIHZhbGlkYXRlTm9kZUNyb25JbnRlcnZhbCB9IGZyb20gJ25vZGUtY3Jvbic7XG5pbXBvcnQgeyBTZXR0aW5nc1ZhbGlkYXRvciB9IGZyb20gJy4uL2NvbW1vbi9zZXJ2aWNlcy9zZXR0aW5ncy12YWxpZGF0b3InO1xuXG4vLyBQbHVnaW5cbmV4cG9ydCBjb25zdCBQTFVHSU5fVkVSU0lPTiA9IHZlcnNpb247XG5leHBvcnQgY29uc3QgUExVR0lOX1ZFUlNJT05fU0hPUlQgPSB2ZXJzaW9uLnNwbGl0KCcuJykuc3BsaWNlKDAsIDIpLmpvaW4oJy4nKTtcblxuLy8gSW5kZXggcGF0dGVybnMgLSBXYXp1aCBhbGVydHNcbmV4cG9ydCBjb25zdCBXQVpVSF9JTkRFWF9UWVBFX0FMRVJUUyA9ICdhbGVydHMnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0FMRVJUU19QUkVGSVggPSAnd2F6dWgtYWxlcnRzLSc7XG5leHBvcnQgY29uc3QgV0FaVUhfQUxFUlRTX1BBVFRFUk4gPSAnd2F6dWgtYWxlcnRzLSonO1xuXG4vLyBKb2IgLSBXYXp1aCBtb25pdG9yaW5nXG5leHBvcnQgY29uc3QgV0FaVUhfSU5ERVhfVFlQRV9NT05JVE9SSU5HID0gXCJtb25pdG9yaW5nXCI7XG5leHBvcnQgY29uc3QgV0FaVUhfTU9OSVRPUklOR19QUkVGSVggPSBcIndhenVoLW1vbml0b3JpbmctXCI7XG5leHBvcnQgY29uc3QgV0FaVUhfTU9OSVRPUklOR19QQVRURVJOID0gXCJ3YXp1aC1tb25pdG9yaW5nLSpcIjtcbmV4cG9ydCBjb25zdCBXQVpVSF9NT05JVE9SSU5HX1RFTVBMQVRFX05BTUUgPSBcIndhenVoLWFnZW50XCI7XG5leHBvcnQgY29uc3QgV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0lORElDRVNfU0hBUkRTID0gMTtcbmV4cG9ydCBjb25zdCBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfSU5ESUNFU19SRVBMSUNBUyA9IDA7XG5leHBvcnQgY29uc3QgV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0NSRUFUSU9OID0gJ3cnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9FTkFCTEVEID0gdHJ1ZTtcbmV4cG9ydCBjb25zdCBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfRlJFUVVFTkNZID0gOTAwO1xuZXhwb3J0IGNvbnN0IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9DUk9OX0ZSRVEgPSAnMCAqICogKiAqIConO1xuXG4vLyBKb2IgLSBXYXp1aCBzdGF0aXN0aWNzXG5leHBvcnQgY29uc3QgV0FaVUhfSU5ERVhfVFlQRV9TVEFUSVNUSUNTID0gXCJzdGF0aXN0aWNzXCI7XG5leHBvcnQgY29uc3QgV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX1BSRUZJWCA9IFwid2F6dWhcIjtcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfTkFNRSA9IFwic3RhdGlzdGljc1wiO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NUQVRJU1RJQ1NfUEFUVEVSTiA9IGAke1dBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9QUkVGSVh9LSR7V0FaVUhfU1RBVElTVElDU19ERUZBVUxUX05BTUV9LSpgO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NUQVRJU1RJQ1NfVEVNUExBVEVfTkFNRSA9IGAke1dBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9QUkVGSVh9LSR7V0FaVUhfU1RBVElTVElDU19ERUZBVUxUX05BTUV9YDtcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfSU5ESUNFU19TSEFSRFMgPSAxO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9JTkRJQ0VTX1JFUExJQ0FTID0gMDtcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfQ1JFQVRJT04gPSAndyc7XG5leHBvcnQgY29uc3QgV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX1NUQVRVUyA9IHRydWU7XG5leHBvcnQgY29uc3QgV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX0ZSRVFVRU5DWSA9IDkwMDtcbmV4cG9ydCBjb25zdCBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfQ1JPTl9GUkVRID0gJzAgKi81ICogKiAqIConO1xuXG4vLyBKb2IgLSBXYXp1aCBpbml0aWFsaXplXG5leHBvcnQgY29uc3QgV0FaVUhfUExVR0lOX1BMQVRGT1JNX1RFTVBMQVRFX05BTUUgPSAnd2F6dWgta2liYW5hJztcblxuLy8gUGVybWlzc2lvbnNcbmV4cG9ydCBjb25zdCBXQVpVSF9ST0xFX0FETUlOSVNUUkFUT1JfSUQgPSAxO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1JPTEVfQURNSU5JU1RSQVRPUl9OQU1FID0gJ2FkbWluaXN0cmF0b3InO1xuXG4vLyBTYW1wbGUgZGF0YVxuZXhwb3J0IGNvbnN0IFdBWlVIX1NBTVBMRV9BTEVSVF9QUkVGSVggPSAnd2F6dWgtYWxlcnRzLTQueC0nO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NBTVBMRV9BTEVSVFNfSU5ERVhfU0hBUkRTID0gMTtcbmV4cG9ydCBjb25zdCBXQVpVSF9TQU1QTEVfQUxFUlRTX0lOREVYX1JFUExJQ0FTID0gMDtcbmV4cG9ydCBjb25zdCBXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JZX1NFQ1VSSVRZID0gJ3NlY3VyaXR5JztcbmV4cG9ydCBjb25zdCBXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JZX0FVRElUSU5HX1BPTElDWV9NT05JVE9SSU5HID0gJ2F1ZGl0aW5nLXBvbGljeS1tb25pdG9yaW5nJztcbmV4cG9ydCBjb25zdCBXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JZX1RIUkVBVF9ERVRFQ1RJT04gPSAndGhyZWF0LWRldGVjdGlvbic7XG5leHBvcnQgY29uc3QgV0FaVUhfU0FNUExFX0FMRVJUU19ERUZBVUxUX05VTUJFUl9BTEVSVFMgPSAzMDAwO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUklFU19UWVBFX0FMRVJUUyA9IHtcbiAgW1dBWlVIX1NBTVBMRV9BTEVSVFNfQ0FURUdPUllfU0VDVVJJVFldOiBbXG4gICAgeyBzeXNjaGVjazogdHJ1ZSB9LFxuICAgIHsgYXdzOiB0cnVlIH0sXG4gICAgeyBvZmZpY2U6IHRydWUgfSxcbiAgICB7IGdjcDogdHJ1ZSB9LFxuICAgIHsgYXV0aGVudGljYXRpb246IHRydWUgfSxcbiAgICB7IHNzaDogdHJ1ZSB9LFxuICAgIHsgYXBhY2hlOiB0cnVlLCBhbGVydHM6IDIwMDAgfSxcbiAgICB7IHdlYjogdHJ1ZSB9LFxuICAgIHsgd2luZG93czogeyBzZXJ2aWNlX2NvbnRyb2xfbWFuYWdlcjogdHJ1ZSB9LCBhbGVydHM6IDEwMDAgfSxcbiAgICB7IGdpdGh1YjogdHJ1ZSB9XG4gIF0sXG4gIFtXQVpVSF9TQU1QTEVfQUxFUlRTX0NBVEVHT1JZX0FVRElUSU5HX1BPTElDWV9NT05JVE9SSU5HXTogW1xuICAgIHsgcm9vdGNoZWNrOiB0cnVlIH0sXG4gICAgeyBhdWRpdDogdHJ1ZSB9LFxuICAgIHsgb3BlbnNjYXA6IHRydWUgfSxcbiAgICB7IGNpc2NhdDogdHJ1ZSB9LFxuICBdLFxuICBbV0FaVUhfU0FNUExFX0FMRVJUU19DQVRFR09SWV9USFJFQVRfREVURUNUSU9OXTogW1xuICAgIHsgdnVsbmVyYWJpbGl0aWVzOiB0cnVlIH0sXG4gICAgeyB2aXJ1c3RvdGFsOiB0cnVlIH0sXG4gICAgeyBvc3F1ZXJ5OiB0cnVlIH0sXG4gICAgeyBkb2NrZXI6IHRydWUgfSxcbiAgICB7IG1pdHJlOiB0cnVlIH0sXG4gIF0sXG59O1xuXG4vLyBTZWN1cml0eVxuZXhwb3J0IGNvbnN0IFdBWlVIX1NFQ1VSSVRZX1BMVUdJTl9YUEFDS19TRUNVUklUWSA9ICdYLVBhY2sgU2VjdXJpdHknO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1NFQ1VSSVRZX1BMVUdJTl9PUEVOX0RJU1RST19GT1JfRUxBU1RJQ1NFQVJDSCA9ICdPcGVuIERpc3RybyBmb3IgRWxhc3RpY3NlYXJjaCc7XG5cbmV4cG9ydCBjb25zdCBXQVpVSF9TRUNVUklUWV9QTFVHSU5TID0gW1xuICBXQVpVSF9TRUNVUklUWV9QTFVHSU5fWFBBQ0tfU0VDVVJJVFksXG4gIFdBWlVIX1NFQ1VSSVRZX1BMVUdJTl9PUEVOX0RJU1RST19GT1JfRUxBU1RJQ1NFQVJDSCxcbl07XG5cbi8vIEFwcCBjb25maWd1cmF0aW9uXG5leHBvcnQgY29uc3QgV0FaVUhfQ09ORklHVVJBVElPTl9DQUNIRV9USU1FID0gMTAwMDA7IC8vIHRpbWUgaW4gbXM7XG5cbi8vIFJlc2VydmVkIGlkcyBmb3IgVXNlcnMvUm9sZSBtYXBwaW5nXG5leHBvcnQgY29uc3QgV0FaVUhfQVBJX1JFU0VSVkVEX0lEX0xPV0VSX1RIQU4gPSAxMDA7XG5cbi8vIFdhenVoIGRhdGEgcGF0aFxuY29uc3QgV0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9QQVRIID0gJ2RhdGEnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfUExVR0lOX1BMQVRGT1JNX0JBU0VfQUJTT0xVVEVfUEFUSCA9IHBhdGguam9pbihcbiAgX19kaXJuYW1lLFxuICAnLi4vLi4vLi4vJyxcbiAgV0FaVUhfREFUQV9QTFVHSU5fUExBVEZPUk1fQkFTRV9QQVRIXG4pO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfQUJTT0xVVEVfUEFUSCA9IHBhdGguam9pbihXQVpVSF9EQVRBX1BMVUdJTl9QTEFURk9STV9CQVNFX0FCU09MVVRFX1BBVEgsICd3YXp1aCcpO1xuXG4vLyBXYXp1aCBkYXRhIHBhdGggLSBjb25maWdcbmV4cG9ydCBjb25zdCBXQVpVSF9EQVRBX0NPTkZJR19ESVJFQ1RPUllfUEFUSCA9IHBhdGguam9pbihXQVpVSF9EQVRBX0FCU09MVVRFX1BBVEgsICdjb25maWcnKTtcbmV4cG9ydCBjb25zdCBXQVpVSF9EQVRBX0NPTkZJR19BUFBfUEFUSCA9IHBhdGguam9pbihXQVpVSF9EQVRBX0NPTkZJR19ESVJFQ1RPUllfUEFUSCwgJ3dhenVoLnltbCcpO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfQ09ORklHX1JFR0lTVFJZX1BBVEggPSBwYXRoLmpvaW4oXG4gIFdBWlVIX0RBVEFfQ09ORklHX0RJUkVDVE9SWV9QQVRILFxuICAnd2F6dWgtcmVnaXN0cnkuanNvbidcbik7XG5cbi8vIFdhenVoIGRhdGEgcGF0aCAtIGxvZ3NcbmV4cG9ydCBjb25zdCBNQVhfTUJfTE9HX0ZJTEVTID0gMTAwO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCA9IHBhdGguam9pbihXQVpVSF9EQVRBX0FCU09MVVRFX1BBVEgsICdsb2dzJyk7XG5leHBvcnQgY29uc3QgV0FaVUhfREFUQV9MT0dTX1BMQUlOX0ZJTEVOQU1FID0gJ3dhenVoYXBwLXBsYWluLmxvZyc7XG5leHBvcnQgY29uc3QgV0FaVUhfREFUQV9MT0dTX1BMQUlOX1BBVEggPSBwYXRoLmpvaW4oXG4gIFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCxcbiAgV0FaVUhfREFUQV9MT0dTX1BMQUlOX0ZJTEVOQU1FXG4pO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfTE9HU19SQVdfRklMRU5BTUUgPSAnd2F6dWhhcHAubG9nJztcbmV4cG9ydCBjb25zdCBXQVpVSF9EQVRBX0xPR1NfUkFXX1BBVEggPSBwYXRoLmpvaW4oXG4gIFdBWlVIX0RBVEFfTE9HU19ESVJFQ1RPUllfUEFUSCxcbiAgV0FaVUhfREFUQV9MT0dTX1JBV19GSUxFTkFNRVxuKTtcblxuLy8gV2F6dWggZGF0YSBwYXRoIC0gVUkgbG9nc1xuZXhwb3J0IGNvbnN0IFdBWlVIX1VJX0xPR1NfUExBSU5fRklMRU5BTUUgPSAnd2F6dWgtdWktcGxhaW4ubG9nJztcbmV4cG9ydCBjb25zdCBXQVpVSF9VSV9MT0dTX1JBV19GSUxFTkFNRSA9ICd3YXp1aC11aS5sb2cnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1VJX0xPR1NfUExBSU5fUEFUSCA9IHBhdGguam9pbihcbiAgV0FaVUhfREFUQV9MT0dTX0RJUkVDVE9SWV9QQVRILFxuICBXQVpVSF9VSV9MT0dTX1BMQUlOX0ZJTEVOQU1FXG4pO1xuZXhwb3J0IGNvbnN0IFdBWlVIX1VJX0xPR1NfUkFXX1BBVEggPSBwYXRoLmpvaW4oV0FaVUhfREFUQV9MT0dTX0RJUkVDVE9SWV9QQVRILCBXQVpVSF9VSV9MT0dTX1JBV19GSUxFTkFNRSk7XG5cbi8vIFdhenVoIGRhdGEgcGF0aCAtIGRvd25sb2Fkc1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRIID0gcGF0aC5qb2luKFdBWlVIX0RBVEFfQUJTT0xVVEVfUEFUSCwgJ2Rvd25sb2FkcycpO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0RBVEFfRE9XTkxPQURTX1JFUE9SVFNfRElSRUNUT1JZX1BBVEggPSBwYXRoLmpvaW4oXG4gIFdBWlVIX0RBVEFfRE9XTkxPQURTX0RJUkVDVE9SWV9QQVRILFxuICAncmVwb3J0cydcbik7XG5cbi8vIFF1ZXVlXG5leHBvcnQgY29uc3QgV0FaVUhfUVVFVUVfQ1JPTl9GUkVRID0gJyovMTUgKiAqICogKiAqJzsgLy8gRXZlcnkgMTUgc2Vjb25kc1xuXG4vLyBXYXp1aCBlcnJvcnNcbmV4cG9ydCBjb25zdCBXQVpVSF9FUlJPUl9EQUVNT05TX05PVF9SRUFEWSA9ICdFUlJPUjMwOTknO1xuXG4vLyBBZ2VudHNcbmV4cG9ydCBlbnVtIFdBWlVIX0FHRU5UU19PU19UWVBFIHtcbiAgV0lORE9XUyA9ICd3aW5kb3dzJyxcbiAgTElOVVggPSAnbGludXgnLFxuICBTVU5PUyA9ICdzdW5vcycsXG4gIERBUldJTiA9ICdkYXJ3aW4nLFxuICBPVEhFUlMgPSAnJyxcbn1cblxuZXhwb3J0IGVudW0gV0FaVUhfTU9EVUxFU19JRCB7XG4gIFNFQ1VSSVRZX0VWRU5UUyA9ICdnZW5lcmFsJyxcbiAgSU5URUdSSVRZX01PTklUT1JJTkcgPSAnZmltJyxcbiAgQU1BWk9OX1dFQl9TRVJWSUNFUyA9ICdhd3MnLFxuICBPRkZJQ0VfMzY1ID0gJ29mZmljZScsXG4gIEdPT0dMRV9DTE9VRF9QTEFURk9STSA9ICdnY3AnLFxuICBQT0xJQ1lfTU9OSVRPUklORyA9ICdwbScsXG4gIFNFQ1VSSVRZX0NPTkZJR1VSQVRJT05fQVNTRVNTTUVOVCA9ICdzY2EnLFxuICBBVURJVElORyA9ICdhdWRpdCcsXG4gIE9QRU5fU0NBUCA9ICdvc2NhcCcsXG4gIFZVTE5FUkFCSUxJVElFUyA9ICd2dWxzJyxcbiAgT1NRVUVSWSA9ICdvc3F1ZXJ5JyxcbiAgRE9DS0VSID0gJ2RvY2tlcicsXG4gIE1JVFJFX0FUVEFDSyA9ICdtaXRyZScsXG4gIFBDSV9EU1MgPSAncGNpJyxcbiAgSElQQUEgPSAnaGlwYWEnLFxuICBOSVNUXzgwMF81MyA9ICduaXN0JyxcbiAgVFNDID0gJ3RzYycsXG4gIENJU19DQVQgPSAnY2lzY2F0JyxcbiAgVklSVVNUT1RBTCA9ICd2aXJ1c3RvdGFsJyxcbiAgR0RQUiA9ICdnZHByJyxcbiAgR0lUSFVCID0gJ2dpdGh1Yidcbn07XG5cbmV4cG9ydCBlbnVtIFdBWlVIX01FTlVfTUFOQUdFTUVOVF9TRUNUSU9OU19JRCB7XG4gIE1BTkFHRU1FTlQgPSAnbWFuYWdlbWVudCcsXG4gIEFETUlOSVNUUkFUSU9OID0gJ2FkbWluaXN0cmF0aW9uJyxcbiAgUlVMRVNFVCA9ICdydWxlc2V0JyxcbiAgUlVMRVMgPSAncnVsZXMnLFxuICBERUNPREVSUyA9ICdkZWNvZGVycycsXG4gIENEQl9MSVNUUyA9ICdsaXN0cycsXG4gIEdST1VQUyA9ICdncm91cHMnLFxuICBDT05GSUdVUkFUSU9OID0gJ2NvbmZpZ3VyYXRpb24nLFxuICBTVEFUVVNfQU5EX1JFUE9SVFMgPSAnc3RhdHVzUmVwb3J0cycsXG4gIFNUQVRVUyA9ICdzdGF0dXMnLFxuICBDTFVTVEVSID0gJ21vbml0b3JpbmcnLFxuICBMT0dTID0gJ2xvZ3MnLFxuICBSRVBPUlRJTkcgPSAncmVwb3J0aW5nJyxcbiAgU1RBVElTVElDUyA9ICdzdGF0aXN0aWNzJyxcbn07XG5cbmV4cG9ydCBlbnVtIFdBWlVIX01FTlVfVE9PTFNfU0VDVElPTlNfSUQge1xuICBBUElfQ09OU09MRSA9ICdkZXZUb29scycsXG4gIFJVTEVTRVRfVEVTVCA9ICdsb2d0ZXN0Jyxcbn07XG5cbmV4cG9ydCBlbnVtIFdBWlVIX01FTlVfU0VDVVJJVFlfU0VDVElPTlNfSUQge1xuICBVU0VSUyA9ICd1c2VycycsXG4gIFJPTEVTID0gJ3JvbGVzJyxcbiAgUE9MSUNJRVMgPSAncG9saWNpZXMnLFxuICBST0xFU19NQVBQSU5HID0gJ3JvbGVNYXBwaW5nJyxcbn07XG5cbmV4cG9ydCBlbnVtIFdBWlVIX01FTlVfU0VUVElOR1NfU0VDVElPTlNfSUQge1xuICBTRVRUSU5HUyA9ICdzZXR0aW5ncycsXG4gIEFQSV9DT05GSUdVUkFUSU9OID0gJ2FwaScsXG4gIE1PRFVMRVMgPSAnbW9kdWxlcycsXG4gIFNBTVBMRV9EQVRBID0gJ3NhbXBsZV9kYXRhJyxcbiAgQ09ORklHVVJBVElPTiA9ICdjb25maWd1cmF0aW9uJyxcbiAgTE9HUyA9ICdsb2dzJyxcbiAgTUlTQ0VMTEFORU9VUyA9ICdtaXNjZWxsYW5lb3VzJyxcbiAgQUJPVVQgPSAnYWJvdXQnLFxufTtcblxuZXhwb3J0IGNvbnN0IEFVVEhPUklaRURfQUdFTlRTID0gJ2F1dGhvcml6ZWQtYWdlbnRzJztcblxuLy8gV2F6dWggbGlua3NcbmV4cG9ydCBjb25zdCBXQVpVSF9MSU5LX0dJVEhVQiA9ICdodHRwczovL2dpdGh1Yi5jb20vd2F6dWgnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0xJTktfR09PR0xFX0dST1VQUyA9ICdodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2ZvcnVtLyMhZm9ydW0vd2F6dWgnO1xuZXhwb3J0IGNvbnN0IFdBWlVIX0xJTktfU0xBQ0sgPSAnaHR0cHM6Ly93YXp1aC5jb20vY29tbXVuaXR5L2pvaW4tdXMtb24tc2xhY2snO1xuXG5leHBvcnQgY29uc3QgSEVBTFRIX0NIRUNLID0gJ2hlYWx0aC1jaGVjayc7XG5cbi8vIEhlYWx0aCBjaGVja1xuZXhwb3J0IGNvbnN0IEhFQUxUSF9DSEVDS19SRURJUkVDVElPTl9USU1FID0gMzAwOyAvL21zXG5cbi8vIFBsdWdpbiBwbGF0Zm9ybSBzZXR0aW5nc1xuLy8gRGVmYXVsdCB0aW1lRmlsdGVyIHNldCBieSB0aGUgYXBwXG5leHBvcnQgY29uc3QgV0FaVUhfUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfVElNRV9GSUxURVIgPSB7XG4gIGZyb206ICdub3ctMjRoJyxcbiAgdG86ICdub3cnLFxufTtcbmV4cG9ydCBjb25zdCBQTFVHSU5fUExBVEZPUk1fU0VUVElOR19OQU1FX1RJTUVfRklMVEVSID0gJ3RpbWVwaWNrZXI6dGltZURlZmF1bHRzJztcblxuLy8gRGVmYXVsdCBtYXhCdWNrZXRzIHNldCBieSB0aGUgYXBwXG5leHBvcnQgY29uc3QgV0FaVUhfUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfTUFYX0JVQ0tFVFMgPSAyMDAwMDA7XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfTkFNRV9NQVhfQlVDS0VUUyA9ICd0aW1lbGlvbjptYXhfYnVja2V0cyc7XG5cbi8vIERlZmF1bHQgbWV0YUZpZWxkcyBzZXQgYnkgdGhlIGFwcFxuZXhwb3J0IGNvbnN0IFdBWlVIX1BMVUdJTl9QTEFURk9STV9TRVRUSU5HX01FVEFGSUVMRFMgPSBbJ19zb3VyY2UnLCAnX2luZGV4J107XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX1NFVFRJTkdfTkFNRV9NRVRBRklFTERTID0gJ21ldGFGaWVsZHMnO1xuXG4vLyBMb2dnZXJcbmV4cG9ydCBjb25zdCBVSV9MT0dHRVJfTEVWRUxTID0ge1xuICBXQVJOSU5HOiAnV0FSTklORycsXG4gIElORk86ICdJTkZPJyxcbiAgRVJST1I6ICdFUlJPUicsXG59O1xuXG5leHBvcnQgY29uc3QgVUlfVE9BU1RfQ09MT1IgPSB7XG4gIFNVQ0NFU1M6ICdzdWNjZXNzJyxcbiAgV0FSTklORzogJ3dhcm5pbmcnLFxuICBEQU5HRVI6ICdkYW5nZXInLFxufTtcblxuLy8gQXNzZXRzXG5leHBvcnQgY29uc3QgQVNTRVRTX0JBU0VfVVJMX1BSRUZJWCA9ICcvcGx1Z2lucy93YXp1aC9hc3NldHMvJztcbmV4cG9ydCBjb25zdCBBU1NFVFNfUFVCTElDX1VSTCA9ICcvcGx1Z2lucy93YXp1aC9wdWJsaWMvYXNzZXRzLyc7XG5cbi8vIFJlcG9ydHNcbmV4cG9ydCBjb25zdCBSRVBPUlRTX0xPR09fSU1BR0VfQVNTRVRTX1JFTEFUSVZFX1BBVEggPSAnaW1hZ2VzL2xvZ29fcmVwb3J0cy5wbmcnO1xuZXhwb3J0IGNvbnN0IFJFUE9SVFNfUFJJTUFSWV9DT0xPUiA9ICcjMjU2QkQxJztcbmV4cG9ydCBjb25zdCBSRVBPUlRTX1BBR0VfRk9PVEVSX1RFWFQgPSAnQ29weXJpZ2h0IMKpIDIwMjIgV2F6dWgsIEluYy4nO1xuZXhwb3J0IGNvbnN0IFJFUE9SVFNfUEFHRV9IRUFERVJfVEVYVCA9ICdpbmZvQHdhenVoLmNvbVxcbmh0dHBzOi8vd2F6dWguY29tJztcblxuLy8gUGx1Z2luIHBsYXRmb3JtXG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX05BTUUgPSAnS2liYW5hJztcbmV4cG9ydCBjb25zdCBQTFVHSU5fUExBVEZPUk1fQkFTRV9JTlNUQUxMQVRJT05fUEFUSCA9ICcvdXNyL3NoYXJlL2tpYmFuYS9kYXRhL3dhenVoLyc7XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX0lOU1RBTExBVElPTl9VU0VSID0gJ2tpYmFuYSc7XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX0lOU1RBTExBVElPTl9VU0VSX0dST1VQID0gJ2tpYmFuYSc7XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX1dBWlVIX0RPQ1VNRU5UQVRJT05fVVJMX1BBVEhfVVBHUkFERV9QTEFURk9STSA9ICd1cGdyYWRlLWd1aWRlJztcbmV4cG9ydCBjb25zdCBQTFVHSU5fUExBVEZPUk1fV0FaVUhfRE9DVU1FTlRBVElPTl9VUkxfUEFUSF9UUk9VQkxFU0hPT1RJTkcgPSAndXNlci1tYW51YWwvZWxhc3RpY3NlYXJjaC90cm91Ymxlc2hvb3RpbmcuaHRtbCc7XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX1dBWlVIX0RPQ1VNRU5UQVRJT05fVVJMX1BBVEhfQVBQX0NPTkZJR1VSQVRJT04gPSAndXNlci1tYW51YWwvd2F6dWgtZGFzaGJvYXJkL2NvbmZpZy1maWxlLmh0bWwnO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9VUkxfR1VJREUgPSAnaHR0cHM6Ly93d3cuZWxhc3RpYy5jby9ndWlkZS9lbi9lbGFzdGljc2VhcmNoL3JlZmVyZW5jZS9jdXJyZW50L2luZGV4Lmh0bWwnO1xuZXhwb3J0IGNvbnN0IFBMVUdJTl9QTEFURk9STV9VUkxfR1VJREVfVElUTEUgPSAnRWxhc3RpYyBndWlkZSc7XG5leHBvcnQgY29uc3QgUExVR0lOX1BMQVRGT1JNX1JFUVVFU1RfSEVBREVSUyA9IHtcbiAgJ2tibi14c3JmJzogJ2tpYmFuYSdcbn07XG5cbi8vIFBsdWdpbiBhcHBcbmV4cG9ydCBjb25zdCBQTFVHSU5fQVBQX05BTUUgPSAnV2F6dWggQXBwJztcblxuLy8gVUlcbmV4cG9ydCBjb25zdCBBUElfTkFNRV9BR0VOVF9TVEFUVVMgPSB7XG4gIEFDVElWRTogJ2FjdGl2ZScsXG4gIERJU0NPTk5FQ1RFRDogJ2Rpc2Nvbm5lY3RlZCcsXG4gIFBFTkRJTkc6ICdwZW5kaW5nJyxcbiAgTkVWRVJfQ09OTkVDVEVEOiAnbmV2ZXJfY29ubmVjdGVkJyxcbn0gYXMgY29uc3Q7XG5cbmV4cG9ydCBjb25zdCBVSV9DT0xPUl9BR0VOVF9TVEFUVVMgPSB7XG4gIFtBUElfTkFNRV9BR0VOVF9TVEFUVVMuQUNUSVZFXTogJyMwMDc4NzEnLFxuICBbQVBJX05BTUVfQUdFTlRfU1RBVFVTLkRJU0NPTk5FQ1RFRF06ICcjQkQyNzFFJyxcbiAgW0FQSV9OQU1FX0FHRU5UX1NUQVRVUy5QRU5ESU5HXTogJyNGRUM1MTQnLFxuICBbQVBJX05BTUVfQUdFTlRfU1RBVFVTLk5FVkVSX0NPTk5FQ1RFRF06ICcjNjQ2QTc3JyxcbiAgZGVmYXVsdDogJyMwMDAwMDAnXG59IGFzIGNvbnN0O1xuXG5leHBvcnQgY29uc3QgVUlfTEFCRUxfTkFNRV9BR0VOVF9TVEFUVVMgPSB7XG4gIFtBUElfTkFNRV9BR0VOVF9TVEFUVVMuQUNUSVZFXTogJ0FjdGl2ZScsXG4gIFtBUElfTkFNRV9BR0VOVF9TVEFUVVMuRElTQ09OTkVDVEVEXTogJ0Rpc2Nvbm5lY3RlZCcsXG4gIFtBUElfTkFNRV9BR0VOVF9TVEFUVVMuUEVORElOR106ICdQZW5kaW5nJyxcbiAgW0FQSV9OQU1FX0FHRU5UX1NUQVRVUy5ORVZFUl9DT05ORUNURURdOiAnTmV2ZXIgY29ubmVjdGVkJyxcbiAgZGVmYXVsdDogJ1Vua25vd24nXG59IGFzIGNvbnN0O1xuXG5leHBvcnQgY29uc3QgVUlfT1JERVJfQUdFTlRfU1RBVFVTID0gW1xuICBBUElfTkFNRV9BR0VOVF9TVEFUVVMuQUNUSVZFLFxuICBBUElfTkFNRV9BR0VOVF9TVEFUVVMuRElTQ09OTkVDVEVELFxuICBBUElfTkFNRV9BR0VOVF9TVEFUVVMuUEVORElORyxcbiAgQVBJX05BTUVfQUdFTlRfU1RBVFVTLk5FVkVSX0NPTk5FQ1RFRFxuXVxuXG5leHBvcnQgY29uc3QgQUdFTlRfU1lOQ0VEX1NUQVRVUyA9IHtcbiAgU1lOQ0VEOiAnc3luY2VkJyxcbiAgTk9UX1NZTkNFRDogJ25vdCBzeW5jZWQnLFxufVxuXG4vLyBEb2N1bWVudGF0aW9uXG5leHBvcnQgY29uc3QgRE9DVU1FTlRBVElPTl9XRUJfQkFTRV9VUkwgPSBcImh0dHBzOi8vZG9jdW1lbnRhdGlvbi53YXp1aC5jb21cIjtcblxuLy8gRGVmYXVsdCBFbGFzdGljc2VhcmNoIHVzZXIgbmFtZSBjb250ZXh0XG5leHBvcnQgY29uc3QgRUxBU1RJQ19OQU1FID0gJ2VsYXN0aWMnO1xuXG5cbi8vIEN1c3RvbWl6YXRpb25cbmV4cG9ydCBjb25zdCBDVVNUT01JWkFUSU9OX0VORFBPSU5UX1BBWUxPQURfVVBMT0FEX0NVU1RPTV9GSUxFX01BWElNVU1fQllURVMgPSAxMDQ4NTc2O1xuXG5cbi8vIFBsdWdpbiBzZXR0aW5nc1xuZXhwb3J0IGVudW0gU2V0dGluZ0NhdGVnb3J5IHtcbiAgR0VORVJBTCxcbiAgSEVBTFRIX0NIRUNLLFxuICBFWFRFTlNJT05TLFxuICBNT05JVE9SSU5HLFxuICBTVEFUSVNUSUNTLFxuICBTRUNVUklUWSxcbiAgQ1VTVE9NSVpBVElPTixcbn07XG5cbnR5cGUgVFBsdWdpblNldHRpbmdPcHRpb25zVGV4dEFyZWEgPSB7XG4gIG1heFJvd3M/OiBudW1iZXJcbiAgbWluUm93cz86IG51bWJlclxuICBtYXhMZW5ndGg/OiBudW1iZXJcbn07XG5cbnR5cGUgVFBsdWdpblNldHRpbmdPcHRpb25zU2VsZWN0ID0ge1xuICBzZWxlY3Q6IHsgdGV4dDogc3RyaW5nLCB2YWx1ZTogYW55IH1bXVxufTtcblxudHlwZSBUUGx1Z2luU2V0dGluZ09wdGlvbnNFZGl0b3IgPSB7XG5cdGVkaXRvcjoge1xuXHRcdGxhbmd1YWdlOiBzdHJpbmdcblx0fVxufTtcblxudHlwZSBUUGx1Z2luU2V0dGluZ09wdGlvbnNGaWxlID0ge1xuXHRmaWxlOiB7XG5cdFx0dHlwZTogJ2ltYWdlJ1xuXHRcdGV4dGVuc2lvbnM/OiBzdHJpbmdbXVxuXHRcdHNpemU/OiB7XG5cdFx0XHRtYXhCeXRlcz86IG51bWJlclxuXHRcdFx0bWluQnl0ZXM/OiBudW1iZXJcblx0XHR9XG5cdFx0cmVjb21tZW5kZWQ/OiB7XG5cdFx0XHRkaW1lbnNpb25zPzoge1xuXHRcdFx0XHR3aWR0aDogbnVtYmVyLFxuXHRcdFx0XHRoZWlnaHQ6IG51bWJlcixcblx0XHRcdFx0dW5pdDogc3RyaW5nXG5cdFx0XHR9XG5cdFx0fVxuXHRcdHN0b3JlPzoge1xuXHRcdFx0cmVsYXRpdmVQYXRoRmlsZVN5c3RlbTogc3RyaW5nXG5cdFx0XHRmaWxlbmFtZTogc3RyaW5nXG5cdFx0XHRyZXNvbHZlU3RhdGljVVJMOiAoZmlsZW5hbWU6IHN0cmluZykgPT4gc3RyaW5nXG5cdFx0fVxuXHR9XG59O1xuXG50eXBlIFRQbHVnaW5TZXR0aW5nT3B0aW9uc051bWJlciA9IHtcbiAgbnVtYmVyOiB7XG4gICAgbWluPzogbnVtYmVyXG4gICAgbWF4PzogbnVtYmVyXG4gICAgaW50ZWdlcj86IGJvb2xlYW5cbiAgfVxufTtcblxudHlwZSBUUGx1Z2luU2V0dGluZ09wdGlvbnNTd2l0Y2ggPSB7XG4gIHN3aXRjaDoge1xuICAgIHZhbHVlczoge1xuICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw/OiBzdHJpbmcsIHZhbHVlOiBhbnkgfSxcbiAgICAgIGVuYWJsZWQ6IHsgbGFiZWw/OiBzdHJpbmcsIHZhbHVlOiBhbnkgfSxcbiAgICB9XG4gIH1cbn07XG5cbmV4cG9ydCBlbnVtIEVwbHVnaW5TZXR0aW5nVHlwZSB7XG4gIHRleHQgPSAndGV4dCcsXG4gIHRleHRhcmVhID0gJ3RleHRhcmVhJyxcbiAgc3dpdGNoID0gJ3N3aXRjaCcsXG4gIG51bWJlciA9ICdudW1iZXInLFxuICBlZGl0b3IgPSAnZWRpdG9yJyxcbiAgc2VsZWN0ID0gJ3NlbGVjdCcsXG4gIGZpbGVwaWNrZXIgPSAnZmlsZXBpY2tlcidcbn07XG5cbmV4cG9ydCB0eXBlIFRQbHVnaW5TZXR0aW5nID0ge1xuICAvLyBEZWZpbmUgdGhlIHRleHQgZGlzcGxheWVkIGluIHRoZSBVSS5cbiAgdGl0bGU6IHN0cmluZ1xuICAvLyBEZXNjcmlwdGlvbi5cbiAgZGVzY3JpcHRpb246IHN0cmluZ1xuICAvLyBDYXRlZ29yeS5cbiAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeVxuICAvLyBUeXBlLlxuICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGVcbiAgLy8gRGVmYXVsdCB2YWx1ZS5cbiAgZGVmYXVsdFZhbHVlOiBhbnlcbiAgLy8gRGVmYXVsdCB2YWx1ZSBpZiBpdCBpcyBub3Qgc2V0LiBJdCBoYXMgcHJlZmVyZW5jZSBvdmVyIGBkZWZhdWx0YC5cbiAgZGVmYXVsdFZhbHVlSWZOb3RTZXQ/OiBhbnlcbiAgLy8gQ29uZmlndXJhYmxlIGZyb20gdGhlIGNvbmZpZ3VyYXRpb24gZmlsZS5cbiAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogYm9vbGVhblxuICAvLyBDb25maWd1cmFibGUgZnJvbSB0aGUgVUkgKFNldHRpbmdzL0NvbmZpZ3VyYXRpb24pLlxuICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogYm9vbGVhblxuICAvLyBNb2RpZnkgdGhlIHNldHRpbmcgcmVxdWlyZXMgcnVubmluZyB0aGUgcGx1Z2luIGhlYWx0aCBjaGVjayAoZnJvbnRlbmQpLlxuICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjaz86IGJvb2xlYW5cbiAgLy8gTW9kaWZ5IHRoZSBzZXR0aW5nIHJlcXVpcmVzIHJlbG9hZGluZyB0aGUgYnJvd3NlciB0YWIgKGZyb250ZW5kKS5cbiAgcmVxdWlyZXNSZWxvYWRpbmdCcm93c2VyVGFiPzogYm9vbGVhblxuICAvLyBNb2RpZnkgdGhlIHNldHRpbmcgcmVxdWlyZXMgcmVzdGFydGluZyB0aGUgcGx1Z2luIHBsYXRmb3JtIHRvIHRha2UgZWZmZWN0LlxuICByZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybT86IGJvb2xlYW5cbiAgLy8gRGVmaW5lIG9wdGlvbnMgcmVsYXRlZCB0byB0aGUgYHR5cGVgLlxuICBvcHRpb25zPzpcbiAgVFBsdWdpblNldHRpbmdPcHRpb25zRWRpdG9yIHxcbiAgVFBsdWdpblNldHRpbmdPcHRpb25zRmlsZSB8XG4gIFRQbHVnaW5TZXR0aW5nT3B0aW9uc051bWJlciB8XG4gIFRQbHVnaW5TZXR0aW5nT3B0aW9uc1NlbGVjdCB8XG4gIFRQbHVnaW5TZXR0aW5nT3B0aW9uc1N3aXRjaCB8XG4gIFRQbHVnaW5TZXR0aW5nT3B0aW9uc1RleHRBcmVhXG4gIC8vIFRyYW5zZm9ybSB0aGUgaW5wdXQgdmFsdWUuIFRoZSByZXN1bHQgaXMgc2F2ZWQgaW4gdGhlIGZvcm0gZ2xvYmFsIHN0YXRlIG9mIFNldHRpbmdzL0NvbmZpZ3VyYXRpb25cbiAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU/OiAodmFsdWU6IGFueSkgPT4gYW55XG4gIC8vIFRyYW5zZm9ybSB0aGUgY29uZmlndXJhdGlvbiB2YWx1ZSBvciBkZWZhdWx0IGFzIGluaXRpYWwgdmFsdWUgZm9yIHRoZSBpbnB1dCBpbiBTZXR0aW5ncy9Db25maWd1cmF0aW9uXG4gIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZT86ICh2YWx1ZTogYW55KSA9PiBhbnlcbiAgLy8gVHJhbnNmb3JtIHRoZSBpbnB1dCB2YWx1ZSBjaGFuZ2VkIGluIHRoZSBmb3JtIG9mIFNldHRpbmdzL0NvbmZpZ3VyYXRpb24gYW5kIHJldHVybmVkIGluIHRoZSBgY2hhbmdlZGAgcHJvcGVydHkgb2YgdGhlIGhvb2sgdXNlRm9ybVxuICB1aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWU/OiAodmFsdWU6IGFueSkgPT4gYW55XG4gIC8vIFZhbGlkYXRlIHRoZSB2YWx1ZSBpbiB0aGUgZm9ybSBvZiBTZXR0aW5ncy9Db25maWd1cmF0aW9uLiBJdCByZXR1cm5zIGEgc3RyaW5nIGlmIHRoZXJlIGlzIHNvbWUgdmFsaWRhdGlvbiBlcnJvci5cblx0dmFsaWRhdGU/OiAodmFsdWU6IGFueSkgPT4gc3RyaW5nIHwgdW5kZWZpbmVkXG5cdC8vIFZhbGlkYXRlIGZ1bmN0aW9uIGNyZWF0b3IgdG8gdmFsaWRhdGUgdGhlIHNldHRpbmcgaW4gdGhlIGJhY2tlbmQuIEl0IHVzZXMgYHNjaGVtYWAgb2YgdGhlIGBAa2JuL2NvbmZpZy1zY2hlbWFgIHBhY2thZ2UuXG5cdHZhbGlkYXRlQmFja2VuZD86IChzY2hlbWE6IGFueSkgPT4gKHZhbHVlOiB1bmtub3duKSA9PiBzdHJpbmcgfCB1bmRlZmluZWRcbn07XG5cbmV4cG9ydCB0eXBlIFRQbHVnaW5TZXR0aW5nV2l0aEtleSA9IFRQbHVnaW5TZXR0aW5nICYgeyBrZXk6IFRQbHVnaW5TZXR0aW5nS2V5IH07XG5leHBvcnQgdHlwZSBUUGx1Z2luU2V0dGluZ0NhdGVnb3J5ID0ge1xuICB0aXRsZTogc3RyaW5nXG4gIGRlc2NyaXB0aW9uPzogc3RyaW5nXG4gIGRvY3VtZW50YXRpb25MaW5rPzogc3RyaW5nXG4gIHJlbmRlck9yZGVyPzogbnVtYmVyXG59O1xuXG5leHBvcnQgY29uc3QgUExVR0lOX1NFVFRJTkdTX0NBVEVHT1JJRVM6IHsgW2NhdGVnb3J5OiBudW1iZXJdOiBUUGx1Z2luU2V0dGluZ0NhdGVnb3J5IH0gPSB7XG4gIFtTZXR0aW5nQ2F0ZWdvcnkuSEVBTFRIX0NIRUNLXToge1xuICAgIHRpdGxlOiAnSGVhbHRoIGNoZWNrJyxcbiAgICBkZXNjcmlwdGlvbjogXCJDaGVja3Mgd2lsbCBiZSBleGVjdXRlZCBieSB0aGUgYXBwJ3MgSGVhbHRoY2hlY2suXCIsXG4gICAgcmVuZGVyT3JkZXI6IFNldHRpbmdDYXRlZ29yeS5IRUFMVEhfQ0hFQ0ssXG4gIH0sXG4gIFtTZXR0aW5nQ2F0ZWdvcnkuR0VORVJBTF06IHtcbiAgICB0aXRsZTogJ0dlbmVyYWwnLFxuICAgIGRlc2NyaXB0aW9uOiBcIkJhc2ljIGFwcCBzZXR0aW5ncyByZWxhdGVkIHRvIGFsZXJ0cyBpbmRleCBwYXR0ZXJuLCBoaWRlIHRoZSBtYW5hZ2VyIGFsZXJ0cyBpbiB0aGUgZGFzaGJvYXJkcywgbG9ncyBsZXZlbCBhbmQgbW9yZS5cIixcbiAgICByZW5kZXJPcmRlcjogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gIH0sXG4gIFtTZXR0aW5nQ2F0ZWdvcnkuRVhURU5TSU9OU106IHtcbiAgICB0aXRsZTogJ0luaXRpYWwgZGlzcGxheSBzdGF0ZSBvZiB0aGUgbW9kdWxlcyBvZiB0aGUgbmV3IEFQSSBob3N0IGVudHJpZXMuJyxcbiAgICBkZXNjcmlwdGlvbjogXCJFeHRlbnNpb25zLlwiLFxuICB9LFxuICBbU2V0dGluZ0NhdGVnb3J5LlNFQ1VSSVRZXToge1xuICAgIHRpdGxlOiAnU2VjdXJpdHknLFxuICAgIGRlc2NyaXB0aW9uOiBcIkFwcGxpY2F0aW9uIHNlY3VyaXR5IG9wdGlvbnMgc3VjaCBhcyB1bmF1dGhvcml6ZWQgcm9sZXMuXCIsXG4gICAgcmVuZGVyT3JkZXI6IFNldHRpbmdDYXRlZ29yeS5TRUNVUklUWSxcbiAgfSxcbiAgW1NldHRpbmdDYXRlZ29yeS5NT05JVE9SSU5HXToge1xuICAgIHRpdGxlOiAnVGFzazpNb25pdG9yaW5nJyxcbiAgICBkZXNjcmlwdGlvbjogXCJPcHRpb25zIHJlbGF0ZWQgdG8gdGhlIGFnZW50IHN0YXR1cyBtb25pdG9yaW5nIGpvYiBhbmQgaXRzIHN0b3JhZ2UgaW4gaW5kZXhlcy5cIixcbiAgICByZW5kZXJPcmRlcjogU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkcsXG4gIH0sXG4gIFtTZXR0aW5nQ2F0ZWdvcnkuU1RBVElTVElDU106IHtcbiAgICB0aXRsZTogJ1Rhc2s6U3RhdGlzdGljcycsXG4gICAgZGVzY3JpcHRpb246IFwiT3B0aW9ucyByZWxhdGVkIHRvIHRoZSBkYWVtb25zIG1hbmFnZXIgbW9uaXRvcmluZyBqb2IgYW5kIHRoZWlyIHN0b3JhZ2UgaW4gaW5kZXhlcy4uXCIsXG4gICAgcmVuZGVyT3JkZXI6IFNldHRpbmdDYXRlZ29yeS5TVEFUSVNUSUNTLFxuICB9LFxuICBbU2V0dGluZ0NhdGVnb3J5LkNVU1RPTUlaQVRJT05dOiB7XG4gICAgdGl0bGU6ICdDdXN0b20gYnJhbmRpbmcnLFxuICAgIGRlc2NyaXB0aW9uOiBcIklmIHlvdSB3YW50IHRvIHVzZSBjdXN0b20gYnJhbmRpbmcgZWxlbWVudHMgc3VjaCBhcyBsb2dvcywgeW91IGNhbiBkbyBzbyBieSBlZGl0aW5nIHRoZSBzZXR0aW5ncyBiZWxvdy5cIixcbiAgICBkb2N1bWVudGF0aW9uTGluazogJ3VzZXItbWFudWFsL3dhenVoLWRhc2hib2FyZC93aGl0ZS1sYWJlbGluZy5odG1sJyxcbiAgICByZW5kZXJPcmRlcjogU2V0dGluZ0NhdGVnb3J5LkNVU1RPTUlaQVRJT04sXG4gIH1cbn07XG5cbmV4cG9ydCBjb25zdCBQTFVHSU5fU0VUVElOR1M6IHsgW2tleTogc3RyaW5nXTogVFBsdWdpblNldHRpbmcgfSA9IHtcbiAgXCJhbGVydHMuc2FtcGxlLnByZWZpeFwiOiB7XG4gICAgdGl0bGU6IFwiU2FtcGxlIGFsZXJ0cyBwcmVmaXhcIixcbiAgICBkZXNjcmlwdGlvbjogXCJEZWZpbmUgdGhlIGluZGV4IG5hbWUgcHJlZml4IG9mIHNhbXBsZSBhbGVydHMuIEl0IG11c3QgbWF0Y2ggdGhlIHRlbXBsYXRlIHVzZWQgYnkgdGhlIGluZGV4IHBhdHRlcm4gdG8gYXZvaWQgdW5rbm93biBmaWVsZHMgaW4gZGFzaGJvYXJkcy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnRleHQsXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9TQU1QTEVfQUxFUlRfUFJFRklYLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgLy8gVmFsaWRhdGlvbjogaHR0cHM6Ly9naXRodWIuY29tL2VsYXN0aWMvZWxhc3RpY3NlYXJjaC9ibG9iL3Y3LjEwLjIvZG9jcy9yZWZlcmVuY2UvaW5kaWNlcy9jcmVhdGUtaW5kZXguYXNjaWlkb2NcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb1NwYWNlcyxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm5vU3RhcnRzV2l0aFN0cmluZygnLScsICdfJywgJysnLCAnLicpLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm90SW52YWxpZENoYXJhY3RlcnMoJ1xcXFwnLCAnLycsICc/JywgJ1wiJywgJzwnLCAnPicsICd8JywgJywnLCAnIycsICcqJylcbiAgICApLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuc3RyaW5nKHt2YWxpZGF0ZTogdGhpcy52YWxpZGF0ZX0pO1xuXHRcdH0sXG4gIH0sXG4gIFwiY2hlY2tzLmFwaVwiOiB7XG4gICAgdGl0bGU6IFwiQVBJIGNvbm5lY3Rpb25cIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgQVBJIGhlYWx0aCBjaGVjayB3aGVuIG9wZW5pbmcgdGhlIGFwcC5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkhFQUxUSF9DSEVDSyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBib29sZWFuIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYm9vbGVhbigpO1xuXHRcdH0sXG4gIH0sXG4gIFwiY2hlY2tzLmZpZWxkc1wiOiB7XG4gICAgdGl0bGU6IFwiS25vd24gZmllbGRzXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRW5hYmxlIG9yIGRpc2FibGUgdGhlIGtub3duIGZpZWxkcyBoZWFsdGggY2hlY2sgd2hlbiBvcGVuaW5nIHRoZSBhcHAuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5IRUFMVEhfQ0hFQ0ssXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzd2l0Y2g6IHtcbiAgICAgICAgdmFsdWVzOiB7XG4gICAgICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw6ICdmYWxzZScsIHZhbHVlOiBmYWxzZSB9LFxuICAgICAgICAgIGVuYWJsZWQ6IHsgbGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWUgfSxcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLmJvb2xlYW4oKTtcblx0XHR9LFxuICB9LFxuICBcImNoZWNrcy5tYXhCdWNrZXRzXCI6IHtcbiAgICB0aXRsZTogXCJTZXQgbWF4IGJ1Y2tldHMgdG8gMjAwMDAwXCIsXG4gICAgZGVzY3JpcHRpb246IFwiQ2hhbmdlIHRoZSBkZWZhdWx0IHZhbHVlIG9mIHRoZSBwbHVnaW4gcGxhdGZvcm0gbWF4IGJ1Y2tldHMgY29uZmlndXJhdGlvbi5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkhFQUxUSF9DSEVDSyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9XG4gICAgICB9LFxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLmJvb2xlYW4oKTtcblx0XHR9LFxuICB9LFxuICBcImNoZWNrcy5tZXRhRmllbGRzXCI6IHtcbiAgICB0aXRsZTogXCJSZW1vdmUgbWV0YSBmaWVsZHNcIixcbiAgICBkZXNjcmlwdGlvbjogXCJDaGFuZ2UgdGhlIGRlZmF1bHQgdmFsdWUgb2YgdGhlIHBsdWdpbiBwbGF0Zm9ybSBtZXRhRmllbGQgY29uZmlndXJhdGlvbi5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkhFQUxUSF9DSEVDSyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBib29sZWFuIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYm9vbGVhbigpO1xuXHRcdH0sXG4gIH0sXG4gIFwiY2hlY2tzLnBhdHRlcm5cIjoge1xuICAgIHRpdGxlOiBcIkluZGV4IHBhdHRlcm5cIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgaW5kZXggcGF0dGVybiBoZWFsdGggY2hlY2sgd2hlbiBvcGVuaW5nIHRoZSBhcHAuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5IRUFMVEhfQ0hFQ0ssXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzd2l0Y2g6IHtcbiAgICAgICAgdmFsdWVzOiB7XG4gICAgICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw6ICdmYWxzZScsIHZhbHVlOiBmYWxzZSB9LFxuICAgICAgICAgIGVuYWJsZWQ6IHsgbGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWUgfSxcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLmJvb2xlYW4oKTtcblx0XHR9LFxuICB9LFxuICBcImNoZWNrcy5zZXR1cFwiOiB7XG4gICAgdGl0bGU6IFwiQVBJIHZlcnNpb25cIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgc2V0dXAgaGVhbHRoIGNoZWNrIHdoZW4gb3BlbmluZyB0aGUgYXBwLlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuSEVBTFRIX0NIRUNLLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJjaGVja3MudGVtcGxhdGVcIjoge1xuICAgIHRpdGxlOiBcIkluZGV4IHRlbXBsYXRlXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRW5hYmxlIG9yIGRpc2FibGUgdGhlIHRlbXBsYXRlIGhlYWx0aCBjaGVjayB3aGVuIG9wZW5pbmcgdGhlIGFwcC5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkhFQUxUSF9DSEVDSyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBib29sZWFuIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYm9vbGVhbigpO1xuXHRcdH0sXG4gIH0sXG4gIFwiY2hlY2tzLnRpbWVGaWx0ZXJcIjoge1xuICAgIHRpdGxlOiBcIlNldCB0aW1lIGZpbHRlciB0byAyNGhcIixcbiAgICBkZXNjcmlwdGlvbjogXCJDaGFuZ2UgdGhlIGRlZmF1bHQgdmFsdWUgb2YgdGhlIHBsdWdpbiBwbGF0Zm9ybSB0aW1lRmlsdGVyIGNvbmZpZ3VyYXRpb24uXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5IRUFMVEhfQ0hFQ0ssXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzd2l0Y2g6IHtcbiAgICAgICAgdmFsdWVzOiB7XG4gICAgICAgICAgZGlzYWJsZWQ6IHsgbGFiZWw6ICdmYWxzZScsIHZhbHVlOiBmYWxzZSB9LFxuICAgICAgICAgIGVuYWJsZWQ6IHsgbGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWUgfSxcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ2hhbmdlZElucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogYm9vbGVhbiB8IHN0cmluZyk6IGJvb2xlYW4ge1xuICAgICAgcmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLmJvb2xlYW4oKTtcblx0XHR9LFxuICB9LFxuICBcImNyb24ucHJlZml4XCI6IHtcbiAgICB0aXRsZTogXCJDcm9uIHByZWZpeFwiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkRlZmluZSB0aGUgaW5kZXggcHJlZml4IG9mIHByZWRlZmluZWQgam9icy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnRleHQsXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfUFJFRklYLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgLy8gVmFsaWRhdGlvbjogaHR0cHM6Ly9naXRodWIuY29tL2VsYXN0aWMvZWxhc3RpY3NlYXJjaC9ibG9iL3Y3LjEwLjIvZG9jcy9yZWZlcmVuY2UvaW5kaWNlcy9jcmVhdGUtaW5kZXguYXNjaWlkb2NcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb1NwYWNlcyxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm5vU3RhcnRzV2l0aFN0cmluZygnLScsICdfJywgJysnLCAnLicpLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm90SW52YWxpZENoYXJhY3RlcnMoJ1xcXFwnLCAnLycsICc/JywgJ1wiJywgJzwnLCAnPicsICd8JywgJywnLCAnIycsICcqJylcbiAgICApLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuc3RyaW5nKHt2YWxpZGF0ZTogdGhpcy52YWxpZGF0ZX0pO1xuXHRcdH0sXG4gIH0sXG4gIFwiY3Jvbi5zdGF0aXN0aWNzLmFwaXNcIjoge1xuICAgIHRpdGxlOiBcIkluY2x1ZGVzIEFQSXNcIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbnRlciB0aGUgSUQgb2YgdGhlIGhvc3RzIHlvdSB3YW50IHRvIHNhdmUgZGF0YSBmcm9tLCBsZWF2ZSB0aGlzIGVtcHR5IHRvIHJ1biB0aGUgdGFzayBvbiBldmVyeSBob3N0LlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuU1RBVElTVElDUyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuZWRpdG9yLFxuICAgIGRlZmF1bHRWYWx1ZTogW10sXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG4gICAgICBlZGl0b3I6IHtcbiAgICAgICAgbGFuZ3VhZ2U6ICdqc29uJ1xuICAgICAgfVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ29uZmlndXJhdGlvblZhbHVlVG9JbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGFueSk6IGFueSB7XG4gICAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkodmFsdWUpO1xuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IHN0cmluZyk6IGFueSB7XG4gICAgICB0cnkge1xuICAgICAgICByZXR1cm4gSlNPTi5wYXJzZSh2YWx1ZSk7XG4gICAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICByZXR1cm4gdmFsdWU7XG4gICAgICB9O1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmpzb24oU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmFycmF5KFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzU3RyaW5nLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc05vdEVtcHR5U3RyaW5nLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb1NwYWNlcyxcbiAgICAgICkpLFxuICAgICkpLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYXJyYXlPZihzY2hlbWEuc3RyaW5nKHt2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNOb3RFbXB0eVN0cmluZyxcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm9TcGFjZXMsXG4gICAgICApfSkpO1xuXHRcdH0sXG4gIH0sXG4gIFwiY3Jvbi5zdGF0aXN0aWNzLmluZGV4LmNyZWF0aW9uXCI6IHtcbiAgICB0aXRsZTogXCJJbmRleCBjcmVhdGlvblwiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkRlZmluZSB0aGUgaW50ZXJ2YWwgaW4gd2hpY2ggYSBuZXcgaW5kZXggd2lsbCBiZSBjcmVhdGVkLlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuU1RBVElTVElDUyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc2VsZWN0LFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHNlbGVjdDogW1xuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogXCJIb3VybHlcIixcbiAgICAgICAgICB2YWx1ZTogXCJoXCJcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHRleHQ6IFwiRGFpbHlcIixcbiAgICAgICAgICB2YWx1ZTogXCJkXCJcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHRleHQ6IFwiV2Vla2x5XCIsXG4gICAgICAgICAgdmFsdWU6IFwid1wiXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiBcIk1vbnRobHlcIixcbiAgICAgICAgICB2YWx1ZTogXCJtXCJcbiAgICAgICAgfVxuICAgICAgXVxuICAgIH0sXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfQ1JFQVRJT04sXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjazogdHJ1ZSxcbiAgICB2YWxpZGF0ZTogZnVuY3Rpb24gKHZhbHVlKXtcblx0XHRcdHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5saXRlcmFsKHRoaXMub3B0aW9ucy5zZWxlY3QubWFwKCh7dmFsdWV9KSA9PiB2YWx1ZSkpKHZhbHVlKVxuXHRcdH0sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5vbmVPZih0aGlzLm9wdGlvbnMuc2VsZWN0Lm1hcCgoe3ZhbHVlfSkgPT4gc2NoZW1hLmxpdGVyYWwodmFsdWUpKSk7XG5cdFx0fSxcbiAgfSxcbiAgXCJjcm9uLnN0YXRpc3RpY3MuaW5kZXgubmFtZVwiOiB7XG4gICAgdGl0bGU6IFwiSW5kZXggbmFtZVwiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkRlZmluZSB0aGUgbmFtZSBvZiB0aGUgaW5kZXggaW4gd2hpY2ggdGhlIGRvY3VtZW50cyB3aWxsIGJlIHNhdmVkLlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuU1RBVElTVElDUyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUudGV4dCxcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9OQU1FLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgLy8gVmFsaWRhdGlvbjogaHR0cHM6Ly9naXRodWIuY29tL2VsYXN0aWMvZWxhc3RpY3NlYXJjaC9ibG9iL3Y3LjEwLjIvZG9jcy9yZWZlcmVuY2UvaW5kaWNlcy9jcmVhdGUtaW5kZXguYXNjaWlkb2NcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb1NwYWNlcyxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm5vU3RhcnRzV2l0aFN0cmluZygnLScsICdfJywgJysnLCAnLicpLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm90SW52YWxpZENoYXJhY3RlcnMoJ1xcXFwnLCAnLycsICc/JywgJ1wiJywgJzwnLCAnPicsICd8JywgJywnLCAnIycsICcqJylcbiAgICApLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuc3RyaW5nKHt2YWxpZGF0ZTogdGhpcy52YWxpZGF0ZX0pO1xuXHRcdH0sXG4gIH0sXG4gIFwiY3Jvbi5zdGF0aXN0aWNzLmluZGV4LnJlcGxpY2FzXCI6IHtcbiAgICB0aXRsZTogXCJJbmRleCByZXBsaWNhc1wiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkRlZmluZSB0aGUgbnVtYmVyIG9mIHJlcGxpY2FzIHRvIHVzZSBmb3IgdGhlIHN0YXRpc3RpY3MgaW5kaWNlcy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LlNUQVRJU1RJQ1MsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLm51bWJlcixcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9JTkRJQ0VTX1JFUExJQ0FTLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgbnVtYmVyOiB7XG4gICAgICAgIG1pbjogMCxcbiAgICAgICAgaW50ZWdlcjogdHJ1ZVxuICAgICAgfVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ29uZmlndXJhdGlvblZhbHVlVG9JbnB1dFZhbHVlOiBmdW5jdGlvbih2YWx1ZTogbnVtYmVyKTogc3RyaW5nIHtcbiAgICAgIHJldHVybiBTdHJpbmcodmFsdWUpO1xuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlOiBmdW5jdGlvbih2YWx1ZTogc3RyaW5nKTogbnVtYmVyIHtcbiAgICAgIHJldHVybiBOdW1iZXIodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uKHZhbHVlKXtcblx0XHRcdHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpXG5cdFx0fSxcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLm51bWJlcih7dmFsaWRhdGU6IHRoaXMudmFsaWRhdGUuYmluZCh0aGlzKX0pO1xuXHRcdH0sXG4gIH0sXG4gIFwiY3Jvbi5zdGF0aXN0aWNzLmluZGV4LnNoYXJkc1wiOiB7XG4gICAgdGl0bGU6IFwiSW5kZXggc2hhcmRzXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRGVmaW5lIHRoZSBudW1iZXIgb2Ygc2hhcmRzIHRvIHVzZSBmb3IgdGhlIHN0YXRpc3RpY3MgaW5kaWNlcy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LlNUQVRJU1RJQ1MsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLm51bWJlcixcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX1NUQVRJU1RJQ1NfREVGQVVMVF9JTkRJQ0VTX1NIQVJEUyxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIHJlcXVpcmVzUnVubmluZ0hlYWx0aENoZWNrOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIG51bWJlcjoge1xuICAgICAgICBtaW46IDEsXG4gICAgICAgIGludGVnZXI6IHRydWVcbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZTogZnVuY3Rpb24odmFsdWU6IG51bWJlcil7XG4gICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlOiBmdW5jdGlvbih2YWx1ZTogc3RyaW5nKTogbnVtYmVyIHtcbiAgICAgIHJldHVybiBOdW1iZXIodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uKHZhbHVlKXtcblx0XHRcdHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpXG5cdFx0fSxcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLm51bWJlcih7dmFsaWRhdGU6IHRoaXMudmFsaWRhdGUuYmluZCh0aGlzKX0pO1xuXHRcdH0sXG4gIH0sXG4gIFwiY3Jvbi5zdGF0aXN0aWNzLmludGVydmFsXCI6IHtcbiAgICB0aXRsZTogXCJJbnRlcnZhbFwiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkRlZmluZSB0aGUgZnJlcXVlbmN5IG9mIHRhc2sgZXhlY3V0aW9uIHVzaW5nIGNyb24gc2NoZWR1bGUgZXhwcmVzc2lvbnMuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5TVEFUSVNUSUNTLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0LFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfU1RBVElTVElDU19ERUZBVUxUX0NST05fRlJFUSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIHJlcXVpcmVzUmVzdGFydGluZ1BsdWdpblBsYXRmb3JtOiB0cnVlLFxuICAgIHZhbGlkYXRlOiBmdW5jdGlvbih2YWx1ZTogc3RyaW5nKXtcblx0XHRcdHJldHVybiB2YWxpZGF0ZU5vZGVDcm9uSW50ZXJ2YWwodmFsdWUpID8gdW5kZWZpbmVkIDogXCJJbnRlcnZhbCBpcyBub3QgdmFsaWQuXCJcblx0XHR9LFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuc3RyaW5nKHt2YWxpZGF0ZTogdGhpcy52YWxpZGF0ZX0pO1xuXHRcdH0sXG4gIH0sXG4gIFwiY3Jvbi5zdGF0aXN0aWNzLnN0YXR1c1wiOiB7XG4gICAgdGl0bGU6IFwiU3RhdHVzXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRW5hYmxlIG9yIGRpc2FibGUgdGhlIHN0YXRpc3RpY3MgdGFza3MuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5TVEFUSVNUSUNTLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9TVEFUSVNUSUNTX0RFRkFVTFRfU1RBVFVTLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJjdXN0b21pemF0aW9uLmVuYWJsZWRcIjoge1xuXHRcdHRpdGxlOiBcIlN0YXR1c1wiLFxuXHRcdGRlc2NyaXB0aW9uOiBcIkVuYWJsZSBvciBkaXNhYmxlIHRoZSBjdXN0b21pemF0aW9uLlwiLFxuXHRcdGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuQ1VTVE9NSVpBVElPTixcblx0XHR0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuXHRcdGRlZmF1bHRWYWx1ZTogdHJ1ZSxcblx0XHRpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuXHRcdGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIHJlcXVpcmVzUmVsb2FkaW5nQnJvd3NlclRhYjogdHJ1ZSxcblx0XHRvcHRpb25zOiB7XG5cdFx0XHRzd2l0Y2g6IHtcblx0XHRcdFx0dmFsdWVzOiB7XG5cdFx0XHRcdFx0ZGlzYWJsZWQ6IHtsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlfSxcblx0XHRcdFx0XHRlbmFibGVkOiB7bGFiZWw6ICd0cnVlJywgdmFsdWU6IHRydWV9LFxuXHRcdFx0XHR9XG5cdFx0XHR9XG5cdFx0fSxcblx0XHR1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24odmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFue1xuXHRcdFx0cmV0dXJuIEJvb2xlYW4odmFsdWUpO1xuXHRcdH0sXG5cdFx0dmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmlzQm9vbGVhbixcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLmJvb2xlYW4oKTtcblx0XHR9LFxuXHR9LFxuICBcImN1c3RvbWl6YXRpb24ubG9nby5hcHBcIjoge1xuICAgIHRpdGxlOiBcIkFwcCBtYWluIGxvZ29cIixcbiAgICBkZXNjcmlwdGlvbjogYFRoaXMgbG9nbyBpcyB1c2VkIGluIHRoZSBhcHAgbWFpbiBtZW51LCBhdCB0aGUgdG9wIGxlZnQgY29ybmVyLmAsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5DVVNUT01JWkFUSU9OLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5maWxlcGlja2VyLFxuICAgIGRlZmF1bHRWYWx1ZTogXCJcIixcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcblx0XHRcdGZpbGU6IHtcblx0XHRcdFx0dHlwZTogJ2ltYWdlJyxcblx0XHRcdFx0ZXh0ZW5zaW9uczogWycuanBlZycsICcuanBnJywgJy5wbmcnLCAnLnN2ZyddLFxuXHRcdFx0XHRzaXplOiB7XG5cdFx0XHRcdFx0bWF4Qnl0ZXM6IENVU1RPTUlaQVRJT05fRU5EUE9JTlRfUEFZTE9BRF9VUExPQURfQ1VTVE9NX0ZJTEVfTUFYSU1VTV9CWVRFUyxcblx0XHRcdFx0fSxcblx0XHRcdFx0cmVjb21tZW5kZWQ6IHtcblx0XHRcdFx0XHRkaW1lbnNpb25zOiB7XG5cdFx0XHRcdFx0XHR3aWR0aDogMzAwLFxuXHRcdFx0XHRcdFx0aGVpZ2h0OiA3MCxcblx0XHRcdFx0XHRcdHVuaXQ6ICdweCdcblx0XHRcdFx0XHR9XG5cdFx0XHRcdH0sXG5cdFx0XHRcdHN0b3JlOiB7XG5cdFx0XHRcdFx0cmVsYXRpdmVQYXRoRmlsZVN5c3RlbTogJ3B1YmxpYy9hc3NldHMvY3VzdG9tL2ltYWdlcycsXG5cdFx0XHRcdFx0ZmlsZW5hbWU6ICdjdXN0b21pemF0aW9uLmxvZ28uYXBwJyxcblx0XHRcdFx0XHRyZXNvbHZlU3RhdGljVVJMOiAoZmlsZW5hbWU6IHN0cmluZykgPT4gYGN1c3RvbS9pbWFnZXMvJHtmaWxlbmFtZX0/dj0ke0RhdGUubm93KCl9YFxuICAgICAgICAgIC8vID92PSR7RGF0ZS5ub3coKX0gaXMgdXNlZCB0byBmb3JjZSB0aGUgYnJvd3NlciB0byByZWxvYWQgdGhlIGltYWdlIHdoZW4gYSBuZXcgZmlsZSBpcyB1cGxvYWRlZFxuXHRcdFx0XHR9XG5cdFx0XHR9XG5cdFx0fSxcblx0XHR2YWxpZGF0ZTogZnVuY3Rpb24odmFsdWUpe1xuXHRcdFx0cmV0dXJuIFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG5cdFx0XHRcdFNldHRpbmdzVmFsaWRhdG9yLmZpbGVQaWNrZXJGaWxlU2l6ZSh7Li4udGhpcy5vcHRpb25zLmZpbGUuc2l6ZSwgbWVhbmluZ2Z1bFVuaXQ6IHRydWV9KSxcblx0XHRcdFx0U2V0dGluZ3NWYWxpZGF0b3IuZmlsZVBpY2tlclN1cHBvcnRlZEV4dGVuc2lvbnModGhpcy5vcHRpb25zLmZpbGUuZXh0ZW5zaW9ucylcblx0XHRcdCkodmFsdWUpXG5cdFx0fSxcbiAgfSxcbiAgXCJjdXN0b21pemF0aW9uLmxvZ28uaGVhbHRoY2hlY2tcIjoge1xuICAgIHRpdGxlOiBcIkhlYWx0aGNoZWNrIGxvZ29cIixcbiAgICBkZXNjcmlwdGlvbjogYFRoaXMgbG9nbyBpcyBkaXNwbGF5ZWQgZHVyaW5nIHRoZSBIZWFsdGhjaGVjayByb3V0aW5lIG9mIHRoZSBhcHAuYCxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkNVU1RPTUlaQVRJT04sXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLmZpbGVwaWNrZXIsXG4gICAgZGVmYXVsdFZhbHVlOiBcIlwiLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgb3B0aW9uczoge1xuXHRcdFx0ZmlsZToge1xuXHRcdFx0XHR0eXBlOiAnaW1hZ2UnLFxuXHRcdFx0XHRleHRlbnNpb25zOiBbJy5qcGVnJywgJy5qcGcnLCAnLnBuZycsICcuc3ZnJ10sXG5cdFx0XHRcdHNpemU6IHtcblx0XHRcdFx0XHRtYXhCeXRlczogQ1VTVE9NSVpBVElPTl9FTkRQT0lOVF9QQVlMT0FEX1VQTE9BRF9DVVNUT01fRklMRV9NQVhJTVVNX0JZVEVTLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRyZWNvbW1lbmRlZDoge1xuXHRcdFx0XHRcdGRpbWVuc2lvbnM6IHtcblx0XHRcdFx0XHRcdHdpZHRoOiAzMDAsXG5cdFx0XHRcdFx0XHRoZWlnaHQ6IDcwLFxuXHRcdFx0XHRcdFx0dW5pdDogJ3B4J1xuXHRcdFx0XHRcdH1cblx0XHRcdFx0fSxcblx0XHRcdFx0c3RvcmU6IHtcblx0XHRcdFx0XHRyZWxhdGl2ZVBhdGhGaWxlU3lzdGVtOiAncHVibGljL2Fzc2V0cy9jdXN0b20vaW1hZ2VzJyxcblx0XHRcdFx0XHRmaWxlbmFtZTogJ2N1c3RvbWl6YXRpb24ubG9nby5oZWFsdGhjaGVjaycsXG5cdFx0XHRcdFx0cmVzb2x2ZVN0YXRpY1VSTDogKGZpbGVuYW1lOiBzdHJpbmcpID0+IGBjdXN0b20vaW1hZ2VzLyR7ZmlsZW5hbWV9P3Y9JHtEYXRlLm5vdygpfWBcbiAgICAgICAgICAvLyA/dj0ke0RhdGUubm93KCl9IGlzIHVzZWQgdG8gZm9yY2UgdGhlIGJyb3dzZXIgdG8gcmVsb2FkIHRoZSBpbWFnZSB3aGVuIGEgbmV3IGZpbGUgaXMgdXBsb2FkZWRcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdH0sXG5cdFx0dmFsaWRhdGU6IGZ1bmN0aW9uKHZhbHVlKXtcblx0XHRcdHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuXHRcdFx0XHRTZXR0aW5nc1ZhbGlkYXRvci5maWxlUGlja2VyRmlsZVNpemUoey4uLnRoaXMub3B0aW9ucy5maWxlLnNpemUsIG1lYW5pbmdmdWxVbml0OiB0cnVlfSksXG5cdFx0XHRcdFNldHRpbmdzVmFsaWRhdG9yLmZpbGVQaWNrZXJTdXBwb3J0ZWRFeHRlbnNpb25zKHRoaXMub3B0aW9ucy5maWxlLmV4dGVuc2lvbnMpXG5cdFx0XHQpKHZhbHVlKVxuXHRcdH0sXG4gIH0sXG4gIFwiY3VzdG9taXphdGlvbi5sb2dvLnJlcG9ydHNcIjoge1xuICAgIHRpdGxlOiBcIlBERiByZXBvcnRzIGxvZ29cIixcbiAgICBkZXNjcmlwdGlvbjogYFRoaXMgbG9nbyBpcyB1c2VkIGluIHRoZSBQREYgcmVwb3J0cyBnZW5lcmF0ZWQgYnkgdGhlIGFwcC4gSXQncyBwbGFjZWQgYXQgdGhlIHRvcCBsZWZ0IGNvcm5lciBvZiBldmVyeSBwYWdlIG9mIHRoZSBQREYuYCxcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkNVU1RPTUlaQVRJT04sXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLmZpbGVwaWNrZXIsXG4gICAgZGVmYXVsdFZhbHVlOiBcIlwiLFxuICAgIGRlZmF1bHRWYWx1ZUlmTm90U2V0OiBSRVBPUlRTX0xPR09fSU1BR0VfQVNTRVRTX1JFTEFUSVZFX1BBVEgsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICBvcHRpb25zOiB7XG5cdFx0XHRmaWxlOiB7XG5cdFx0XHRcdHR5cGU6ICdpbWFnZScsXG5cdFx0XHRcdGV4dGVuc2lvbnM6IFsnLmpwZWcnLCAnLmpwZycsICcucG5nJ10sXG5cdFx0XHRcdHNpemU6IHtcblx0XHRcdFx0XHRtYXhCeXRlczogQ1VTVE9NSVpBVElPTl9FTkRQT0lOVF9QQVlMT0FEX1VQTE9BRF9DVVNUT01fRklMRV9NQVhJTVVNX0JZVEVTLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRyZWNvbW1lbmRlZDoge1xuXHRcdFx0XHRcdGRpbWVuc2lvbnM6IHtcblx0XHRcdFx0XHRcdHdpZHRoOiAxOTAsXG5cdFx0XHRcdFx0XHRoZWlnaHQ6IDQwLFxuXHRcdFx0XHRcdFx0dW5pdDogJ3B4J1xuXHRcdFx0XHRcdH1cblx0XHRcdFx0fSxcblx0XHRcdFx0c3RvcmU6IHtcblx0XHRcdFx0XHRyZWxhdGl2ZVBhdGhGaWxlU3lzdGVtOiAncHVibGljL2Fzc2V0cy9jdXN0b20vaW1hZ2VzJyxcblx0XHRcdFx0XHRmaWxlbmFtZTogJ2N1c3RvbWl6YXRpb24ubG9nby5yZXBvcnRzJyxcblx0XHRcdFx0XHRyZXNvbHZlU3RhdGljVVJMOiAoZmlsZW5hbWU6IHN0cmluZykgPT4gYGN1c3RvbS9pbWFnZXMvJHtmaWxlbmFtZX1gXG5cdFx0XHRcdH1cblx0XHRcdH1cblx0XHR9LFxuXHRcdHZhbGlkYXRlOiBmdW5jdGlvbih2YWx1ZSl7XG5cdFx0XHRyZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcblx0XHRcdFx0U2V0dGluZ3NWYWxpZGF0b3IuZmlsZVBpY2tlckZpbGVTaXplKHsuLi50aGlzLm9wdGlvbnMuZmlsZS5zaXplLCBtZWFuaW5nZnVsVW5pdDogdHJ1ZX0pLFxuXHRcdFx0XHRTZXR0aW5nc1ZhbGlkYXRvci5maWxlUGlja2VyU3VwcG9ydGVkRXh0ZW5zaW9ucyh0aGlzLm9wdGlvbnMuZmlsZS5leHRlbnNpb25zKVxuXHRcdFx0KSh2YWx1ZSlcblx0XHR9LFxuICB9LFxuICBcImN1c3RvbWl6YXRpb24ubG9nby5zaWRlYmFyXCI6IHtcbiAgICB0aXRsZTogXCJOYXZpZ2F0aW9uIGRyYXdlciBsb2dvXCIsXG4gICAgZGVzY3JpcHRpb246IGBUaGlzIGlzIHRoZSBsb2dvIGZvciB0aGUgYXBwIHRvIGRpc3BsYXkgaW4gdGhlIHBsYXRmb3JtJ3MgbmF2aWdhdGlvbiBkcmF3ZXIsIHRoaXMgaXMsIHRoZSBtYWluIHNpZGViYXIgY29sbGFwc2libGUgbWVudS5gLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuQ1VTVE9NSVpBVElPTixcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuZmlsZXBpY2tlcixcbiAgICBkZWZhdWx0VmFsdWU6IFwiXCIsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICByZXF1aXJlc1JlbG9hZGluZ0Jyb3dzZXJUYWI6IHRydWUsXG4gICAgb3B0aW9uczoge1xuXHRcdFx0ZmlsZToge1xuXHRcdFx0XHR0eXBlOiAnaW1hZ2UnLFxuXHRcdFx0XHRleHRlbnNpb25zOiBbJy5qcGVnJywgJy5qcGcnLCAnLnBuZycsICcuc3ZnJ10sXG5cdFx0XHRcdHNpemU6IHtcblx0XHRcdFx0XHRtYXhCeXRlczogQ1VTVE9NSVpBVElPTl9FTkRQT0lOVF9QQVlMT0FEX1VQTE9BRF9DVVNUT01fRklMRV9NQVhJTVVNX0JZVEVTLFxuXHRcdFx0XHR9LFxuXHRcdFx0XHRyZWNvbW1lbmRlZDoge1xuXHRcdFx0XHRcdGRpbWVuc2lvbnM6IHtcblx0XHRcdFx0XHRcdHdpZHRoOiA4MCxcblx0XHRcdFx0XHRcdGhlaWdodDogODAsXG5cdFx0XHRcdFx0XHR1bml0OiAncHgnXG5cdFx0XHRcdFx0fVxuXHRcdFx0XHR9LFxuXHRcdFx0XHRzdG9yZToge1xuXHRcdFx0XHRcdHJlbGF0aXZlUGF0aEZpbGVTeXN0ZW06ICdwdWJsaWMvYXNzZXRzL2N1c3RvbS9pbWFnZXMnLFxuXHRcdFx0XHRcdGZpbGVuYW1lOiAnY3VzdG9taXphdGlvbi5sb2dvLnNpZGViYXInLFxuXHRcdFx0XHRcdHJlc29sdmVTdGF0aWNVUkw6IChmaWxlbmFtZTogc3RyaW5nKSA9PiBgY3VzdG9tL2ltYWdlcy8ke2ZpbGVuYW1lfT92PSR7RGF0ZS5ub3coKX1gXG4gICAgICAgICAgLy8gP3Y9JHtEYXRlLm5vdygpfSBpcyB1c2VkIHRvIGZvcmNlIHRoZSBicm93c2VyIHRvIHJlbG9hZCB0aGUgaW1hZ2Ugd2hlbiBhIG5ldyBmaWxlIGlzIHVwbG9hZGVkXG5cdFx0XHRcdH1cblx0XHRcdH1cblx0XHR9LFxuXHRcdHZhbGlkYXRlOiBmdW5jdGlvbih2YWx1ZSl7XG5cdFx0XHRyZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcblx0XHRcdFx0U2V0dGluZ3NWYWxpZGF0b3IuZmlsZVBpY2tlckZpbGVTaXplKHsuLi50aGlzLm9wdGlvbnMuZmlsZS5zaXplLCBtZWFuaW5nZnVsVW5pdDogdHJ1ZX0pLFxuXHRcdFx0XHRTZXR0aW5nc1ZhbGlkYXRvci5maWxlUGlja2VyU3VwcG9ydGVkRXh0ZW5zaW9ucyh0aGlzLm9wdGlvbnMuZmlsZS5leHRlbnNpb25zKVxuXHRcdFx0KSh2YWx1ZSlcblx0XHR9LFxuICB9LFxuICBcImN1c3RvbWl6YXRpb24ucmVwb3J0cy5mb290ZXJcIjoge1xuXHRcdHRpdGxlOiBcIlJlcG9ydHMgZm9vdGVyXCIsXG5cdFx0ZGVzY3JpcHRpb246IFwiU2V0IHRoZSBmb290ZXIgb2YgdGhlIHJlcG9ydHMuXCIsXG5cdFx0Y2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5DVVNUT01JWkFUSU9OLFxuXHRcdHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0YXJlYSxcblx0XHRkZWZhdWx0VmFsdWU6IFwiXCIsXG4gICAgZGVmYXVsdFZhbHVlSWZOb3RTZXQ6IFJFUE9SVFNfUEFHRV9GT09URVJfVEVYVCxcblx0XHRpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuXHRcdGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIG9wdGlvbnM6IHsgbWF4Um93czogMiwgbWF4TGVuZ3RoOiA1MCB9LFxuICAgIHZhbGlkYXRlOiBmdW5jdGlvbiAodmFsdWUpIHtcbiAgICAgIHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5tdWx0aXBsZUxpbmVzU3RyaW5nKHtcbiAgICAgICAgbWF4Um93czogdGhpcy5vcHRpb25zPy5tYXhSb3dzLFxuICAgICAgICBtYXhMZW5ndGg6IHRoaXMub3B0aW9ucz8ubWF4TGVuZ3RoXG4gICAgICB9KSh2YWx1ZSlcbiAgICB9LFxuICAgIHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24gKHNjaGVtYSkge1xuICAgICAgcmV0dXJuIHNjaGVtYS5zdHJpbmcoeyB2YWxpZGF0ZTogdGhpcy52YWxpZGF0ZS5iaW5kKHRoaXMpIH0pO1xuICAgIH0sXG4gIH0sXG4gIFwiY3VzdG9taXphdGlvbi5yZXBvcnRzLmhlYWRlclwiOiB7XG4gICAgdGl0bGU6IFwiUmVwb3J0cyBoZWFkZXJcIixcbiAgICBkZXNjcmlwdGlvbjogXCJTZXQgdGhlIGhlYWRlciBvZiB0aGUgcmVwb3J0cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkNVU1RPTUlaQVRJT04sXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnRleHRhcmVhLFxuICAgIGRlZmF1bHRWYWx1ZTogXCJcIixcbiAgICBkZWZhdWx0VmFsdWVJZk5vdFNldDogUkVQT1JUU19QQUdFX0hFQURFUl9URVhULFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgb3B0aW9uczogeyBtYXhSb3dzOiAzLCBtYXhMZW5ndGg6IDQwIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uICh2YWx1ZSkge1xuICAgICAgcmV0dXJuIFNldHRpbmdzVmFsaWRhdG9yLm11bHRpcGxlTGluZXNTdHJpbmcoe1xuICAgICAgICBtYXhSb3dzOiB0aGlzLm9wdGlvbnM/Lm1heFJvd3MsXG4gICAgICAgIG1heExlbmd0aDogdGhpcy5vcHRpb25zPy5tYXhMZW5ndGhcbiAgICAgIH0pKHZhbHVlKVxuICAgIH0sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5zdHJpbmcoe3ZhbGlkYXRlOiB0aGlzLnZhbGlkYXRlLmJpbmQodGhpcyl9KTtcblx0XHR9LFxuXHR9LFxuICBcImRpc2FibGVkX3JvbGVzXCI6IHtcbiAgICB0aXRsZTogXCJEaXNhYmxlIHJvbGVzXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRGlzYWJsZWQgdGhlIHBsdWdpbiB2aXNpYmlsaXR5IGZvciB1c2VycyB3aXRoIHRoZSByb2xlcy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LlNFQ1VSSVRZLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5lZGl0b3IsXG4gICAgZGVmYXVsdFZhbHVlOiBbXSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIGVkaXRvcjoge1xuICAgICAgICBsYW5ndWFnZTogJ2pzb24nXG4gICAgICB9XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1Db25maWd1cmF0aW9uVmFsdWVUb0lucHV0VmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogYW55KTogYW55IHtcbiAgICAgIHJldHVybiBKU09OLnN0cmluZ2lmeSh2YWx1ZSk7XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWU6IGZ1bmN0aW9uICh2YWx1ZTogc3RyaW5nKTogYW55IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIHJldHVybiBKU09OLnBhcnNlKHZhbHVlKTtcbiAgICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIHJldHVybiB2YWx1ZTtcbiAgICAgIH07XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuanNvbihTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuYXJyYXkoU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNTdHJpbmcsXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzTm90RW1wdHlTdHJpbmcsXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmhhc05vU3BhY2VzLFxuICAgICAgKSksXG4gICAgKSksXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5hcnJheU9mKHNjaGVtYS5zdHJpbmcoe3ZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc05vdEVtcHR5U3RyaW5nLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb1NwYWNlcyxcbiAgICAgICl9KSk7XG5cdFx0fSxcbiAgfSxcbiAgXCJlbnJvbGxtZW50LmRuc1wiOiB7XG4gICAgdGl0bGU6IFwiRW5yb2xsbWVudCBETlNcIixcbiAgICBkZXNjcmlwdGlvbjogXCJTcGVjaWZpZXMgdGhlIFdhenVoIHJlZ2lzdHJhdGlvbiBzZXJ2ZXIsIHVzZWQgZm9yIHRoZSBhZ2VudCBlbnJvbGxtZW50LlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuR0VORVJBTCxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUudGV4dCxcbiAgICBkZWZhdWx0VmFsdWU6IFwiXCIsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm9TcGFjZXMsXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5zdHJpbmcoe3ZhbGlkYXRlOiB0aGlzLnZhbGlkYXRlfSk7XG5cdFx0fSxcbiAgfSxcbiAgXCJlbnJvbGxtZW50LnBhc3N3b3JkXCI6IHtcbiAgICB0aXRsZTogXCJFbnJvbGxtZW50IHBhc3N3b3JkXCIsXG4gICAgZGVzY3JpcHRpb246IFwiU3BlY2lmaWVzIHRoZSBwYXNzd29yZCB1c2VkIHRvIGF1dGhlbnRpY2F0ZSBkdXJpbmcgdGhlIGFnZW50IGVucm9sbG1lbnQuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5HRU5FUkFMLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0LFxuICAgIGRlZmF1bHRWYWx1ZTogXCJcIixcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiBmYWxzZSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNOb3RFbXB0eVN0cmluZyxcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLnN0cmluZyh7dmFsaWRhdGU6IHRoaXMudmFsaWRhdGV9KTtcblx0XHR9LFxuICB9LFxuICBcImV4dGVuc2lvbnMuYXVkaXRcIjoge1xuICAgIHRpdGxlOiBcIlN5c3RlbSBhdWRpdGluZ1wiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkVuYWJsZSBvciBkaXNhYmxlIHRoZSBBdWRpdCB0YWIgb24gT3ZlcnZpZXcgYW5kIEFnZW50cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkVYVEVOU0lPTlMsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLmF3c1wiOiB7XG4gICAgdGl0bGU6IFwiQW1hem9uIEFXU1wiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkVuYWJsZSBvciBkaXNhYmxlIHRoZSBBbWF6b24gKEFXUykgdGFiIG9uIE92ZXJ2aWV3LlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuRVhURU5TSU9OUyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogZmFsc2UsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLmNpc2NhdFwiOiB7XG4gICAgdGl0bGU6IFwiQ0lTLUNBVFwiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkVuYWJsZSBvciBkaXNhYmxlIHRoZSBDSVMtQ0FUIHRhYiBvbiBPdmVydmlldyBhbmQgQWdlbnRzLlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuRVhURU5TSU9OUyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogZmFsc2UsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLmRvY2tlclwiOiB7XG4gICAgdGl0bGU6IFwiRG9ja2VyIGxpc3RlbmVyXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRW5hYmxlIG9yIGRpc2FibGUgdGhlIERvY2tlciBsaXN0ZW5lciB0YWIgb24gT3ZlcnZpZXcgYW5kIEFnZW50cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkVYVEVOU0lPTlMsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IGZhbHNlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IGZhbHNlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBib29sZWFuIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYm9vbGVhbigpO1xuXHRcdH0sXG4gIH0sXG4gIFwiZXh0ZW5zaW9ucy5nY3BcIjoge1xuICAgIHRpdGxlOiBcIkdvb2dsZSBDbG91ZCBwbGF0Zm9ybVwiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkVuYWJsZSBvciBkaXNhYmxlIHRoZSBHb29nbGUgQ2xvdWQgUGxhdGZvcm0gdGFiIG9uIE92ZXJ2aWV3LlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuRVhURU5TSU9OUyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogZmFsc2UsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLmdkcHJcIjoge1xuICAgIHRpdGxlOiBcIkdEUFJcIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgR0RQUiB0YWIgb24gT3ZlcnZpZXcgYW5kIEFnZW50cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkVYVEVOU0lPTlMsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLmhpcGFhXCI6IHtcbiAgICB0aXRsZTogXCJIaXBhYVwiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkVuYWJsZSBvciBkaXNhYmxlIHRoZSBISVBBQSB0YWIgb24gT3ZlcnZpZXcgYW5kIEFnZW50cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkVYVEVOU0lPTlMsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLm5pc3RcIjoge1xuICAgIHRpdGxlOiBcIk5JU1RcIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgTklTVCA4MDAtNTMgdGFiIG9uIE92ZXJ2aWV3IGFuZCBBZ2VudHMuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5FWFRFTlNJT05TLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zd2l0Y2gsXG4gICAgZGVmYXVsdFZhbHVlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IGZhbHNlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBib29sZWFuIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYm9vbGVhbigpO1xuXHRcdH0sXG4gIH0sXG4gIFwiZXh0ZW5zaW9ucy5vc2NhcFwiOiB7XG4gICAgdGl0bGU6IFwiT1NDQVBcIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgT3BlbiBTQ0FQIHRhYiBvbiBPdmVydmlldyBhbmQgQWdlbnRzLlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuRVhURU5TSU9OUyxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogZmFsc2UsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLm9zcXVlcnlcIjoge1xuICAgIHRpdGxlOiBcIk9zcXVlcnlcIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgT3NxdWVyeSB0YWIgb24gT3ZlcnZpZXcgYW5kIEFnZW50cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkVYVEVOU0lPTlMsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IGZhbHNlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IGZhbHNlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBib29sZWFuIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYm9vbGVhbigpO1xuXHRcdH0sXG4gIH0sXG4gIFwiZXh0ZW5zaW9ucy5wY2lcIjoge1xuICAgIHRpdGxlOiBcIlBDSSBEU1NcIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgUENJIERTUyB0YWIgb24gT3ZlcnZpZXcgYW5kIEFnZW50cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkVYVEVOU0lPTlMsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLnRzY1wiOiB7XG4gICAgdGl0bGU6IFwiVFNDXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRW5hYmxlIG9yIGRpc2FibGUgdGhlIFRTQyB0YWIgb24gT3ZlcnZpZXcgYW5kIEFnZW50cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkVYVEVOU0lPTlMsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJleHRlbnNpb25zLnZpcnVzdG90YWxcIjoge1xuICAgIHRpdGxlOiBcIlZpcnVzdG90YWxcIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgVmlydXNUb3RhbCB0YWIgb24gT3ZlcnZpZXcgYW5kIEFnZW50cy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkVYVEVOU0lPTlMsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IGZhbHNlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IGZhbHNlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIHN3aXRjaDoge1xuICAgICAgICB2YWx1ZXM6IHtcbiAgICAgICAgICBkaXNhYmxlZDogeyBsYWJlbDogJ2ZhbHNlJywgdmFsdWU6IGZhbHNlIH0sXG4gICAgICAgICAgZW5hYmxlZDogeyBsYWJlbDogJ3RydWUnLCB2YWx1ZTogdHJ1ZSB9LFxuICAgICAgICB9XG4gICAgICB9XG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1DaGFuZ2VkSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBib29sZWFuIHwgc3RyaW5nKTogYm9vbGVhbiB7XG4gICAgICByZXR1cm4gQm9vbGVhbih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuaXNCb29sZWFuLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYm9vbGVhbigpO1xuXHRcdH0sXG4gIH0sXG4gIFwiaGlkZU1hbmFnZXJBbGVydHNcIjoge1xuICAgIHRpdGxlOiBcIkhpZGUgbWFuYWdlciBhbGVydHNcIixcbiAgICBkZXNjcmlwdGlvbjogXCJIaWRlIHRoZSBhbGVydHMgb2YgdGhlIG1hbmFnZXIgaW4gZXZlcnkgZGFzaGJvYXJkLlwiLFxuICAgIGNhdGVnb3J5OiBTZXR0aW5nQ2F0ZWdvcnkuR0VORVJBTCxcbiAgICB0eXBlOiBFcGx1Z2luU2V0dGluZ1R5cGUuc3dpdGNoLFxuICAgIGRlZmF1bHRWYWx1ZTogZmFsc2UsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICByZXF1aXJlc1JlbG9hZGluZ0Jyb3dzZXJUYWI6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJpcC5pZ25vcmVcIjoge1xuICAgIHRpdGxlOiBcIkluZGV4IHBhdHRlcm4gaWdub3JlXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRGlzYWJsZSBjZXJ0YWluIGluZGV4IHBhdHRlcm4gbmFtZXMgZnJvbSBiZWluZyBhdmFpbGFibGUgaW4gaW5kZXggcGF0dGVybiBzZWxlY3Rvci5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLmVkaXRvcixcbiAgICBkZWZhdWx0VmFsdWU6IFtdLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgZWRpdG9yOiB7XG4gICAgICAgIGxhbmd1YWdlOiAnanNvbidcbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBhbnkpOiBhbnkge1xuICAgICAgcmV0dXJuIEpTT04uc3RyaW5naWZ5KHZhbHVlKTtcbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUlucHV0VmFsdWVUb0NvbmZpZ3VyYXRpb25WYWx1ZTogZnVuY3Rpb24gKHZhbHVlOiBzdHJpbmcpOiBhbnkge1xuICAgICAgdHJ5IHtcbiAgICAgICAgcmV0dXJuIEpTT04ucGFyc2UodmFsdWUpO1xuICAgICAgfSBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgcmV0dXJuIHZhbHVlO1xuICAgICAgfTtcbiAgICB9LFxuICAgIC8vIFZhbGlkYXRpb246IGh0dHBzOi8vZ2l0aHViLmNvbS9lbGFzdGljL2VsYXN0aWNzZWFyY2gvYmxvYi92Ny4xMC4yL2RvY3MvcmVmZXJlbmNlL2luZGljZXMvY3JlYXRlLWluZGV4LmFzY2lpZG9jXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmpzb24oU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmFycmF5KFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmlzU3RyaW5nLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc05vdEVtcHR5U3RyaW5nLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb1NwYWNlcyxcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3Iubm9MaXRlcmFsU3RyaW5nKCcuJywgJy4uJyksXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm5vU3RhcnRzV2l0aFN0cmluZygnLScsICdfJywgJysnLCAnLicpLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5oYXNOb3RJbnZhbGlkQ2hhcmFjdGVycygnXFxcXCcsICcvJywgJz8nLCAnXCInLCAnPCcsICc+JywgJ3wnLCAnLCcsICcjJylcbiAgICAgICkpLFxuICAgICkpLFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEuYXJyYXlPZihzY2hlbWEuc3RyaW5nKHt2YWxpZGF0ZTogU2V0dGluZ3NWYWxpZGF0b3IuY29tcG9zZShcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNOb3RFbXB0eVN0cmluZyxcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm9TcGFjZXMsXG4gICAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm5vTGl0ZXJhbFN0cmluZygnLicsICcuLicpLFxuICAgICAgICBTZXR0aW5nc1ZhbGlkYXRvci5ub1N0YXJ0c1dpdGhTdHJpbmcoJy0nLCAnXycsICcrJywgJy4nKSxcbiAgICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm90SW52YWxpZENoYXJhY3RlcnMoJ1xcXFwnLCAnLycsICc/JywgJ1wiJywgJzwnLCAnPicsICd8JywgJywnLCAnIycpXG4gICAgICApfSkpO1xuXHRcdH0sXG4gIH0sXG4gIFwiaXAuc2VsZWN0b3JcIjoge1xuICAgIHRpdGxlOiBcIklQIHNlbGVjdG9yXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRGVmaW5lIGlmIHRoZSB1c2VyIGlzIGFsbG93ZWQgdG8gY2hhbmdlIHRoZSBzZWxlY3RlZCBpbmRleCBwYXR0ZXJuIGRpcmVjdGx5IGZyb20gdGhlIHRvcCBtZW51IGJhci5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5LkdFTkVSQUwsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogZmFsc2UsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJsb2dzLmxldmVsXCI6IHtcbiAgICB0aXRsZTogXCJMb2cgbGV2ZWxcIixcbiAgICBkZXNjcmlwdGlvbjogXCJMb2dnaW5nIGxldmVsIG9mIHRoZSBBcHAuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5HRU5FUkFMLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5zZWxlY3QsXG4gICAgb3B0aW9uczoge1xuICAgICAgc2VsZWN0OiBbXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiBcIkluZm9cIixcbiAgICAgICAgICB2YWx1ZTogXCJpbmZvXCJcbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHRleHQ6IFwiRGVidWdcIixcbiAgICAgICAgICB2YWx1ZTogXCJkZWJ1Z1wiXG4gICAgICAgIH1cbiAgICAgIF1cbiAgICB9LFxuICAgIGRlZmF1bHRWYWx1ZTogXCJpbmZvXCIsXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICByZXF1aXJlc1Jlc3RhcnRpbmdQbHVnaW5QbGF0Zm9ybTogdHJ1ZSxcbiAgICB2YWxpZGF0ZTogZnVuY3Rpb24gKHZhbHVlKXtcblx0XHRcdHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5saXRlcmFsKHRoaXMub3B0aW9ucy5zZWxlY3QubWFwKCh7dmFsdWV9KSA9PiB2YWx1ZSkpKHZhbHVlKVxuXHRcdH0sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5vbmVPZih0aGlzLm9wdGlvbnMuc2VsZWN0Lm1hcCgoe3ZhbHVlfSkgPT4gc2NoZW1hLmxpdGVyYWwodmFsdWUpKSk7XG5cdFx0fSxcbiAgfSxcbiAgXCJwYXR0ZXJuXCI6IHtcbiAgICB0aXRsZTogXCJJbmRleCBwYXR0ZXJuXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRGVmYXVsdCBpbmRleCBwYXR0ZXJuIHRvIHVzZSBvbiB0aGUgYXBwLiBJZiB0aGVyZSdzIG5vIHZhbGlkIGluZGV4IHBhdHRlcm4sIHRoZSBhcHAgd2lsbCBhdXRvbWF0aWNhbGx5IGNyZWF0ZSBvbmUgd2l0aCB0aGUgbmFtZSBpbmRpY2F0ZWQgaW4gdGhpcyBvcHRpb24uXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5HRU5FUkFMLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0LFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfQUxFUlRTX1BBVFRFUk4sXG4gICAgaXNDb25maWd1cmFibGVGcm9tRmlsZTogdHJ1ZSxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21VSTogdHJ1ZSxcbiAgICByZXF1aXJlc1J1bm5pbmdIZWFsdGhDaGVjazogdHJ1ZSxcbiAgICAvLyBWYWxpZGF0aW9uOiBodHRwczovL2dpdGh1Yi5jb20vZWxhc3RpYy9lbGFzdGljc2VhcmNoL2Jsb2IvdjcuMTAuMi9kb2NzL3JlZmVyZW5jZS9pbmRpY2VzL2NyZWF0ZS1pbmRleC5hc2NpaWRvY1xuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5jb21wb3NlKFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaXNOb3RFbXB0eVN0cmluZyxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmhhc05vU3BhY2VzLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3Iubm9MaXRlcmFsU3RyaW5nKCcuJywgJy4uJyksXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5ub1N0YXJ0c1dpdGhTdHJpbmcoJy0nLCAnXycsICcrJywgJy4nKSxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLmhhc05vdEludmFsaWRDaGFyYWN0ZXJzKCdcXFxcJywgJy8nLCAnPycsICdcIicsICc8JywgJz4nLCAnfCcsICcsJywgJyMnKVxuICAgICksXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5zdHJpbmcoe3ZhbGlkYXRlOiB0aGlzLnZhbGlkYXRlfSk7XG5cdFx0fSxcbiAgfSxcbiAgXCJ0aW1lb3V0XCI6IHtcbiAgICB0aXRsZTogXCJSZXF1ZXN0IHRpbWVvdXRcIixcbiAgICBkZXNjcmlwdGlvbjogXCJNYXhpbXVtIHRpbWUsIGluIG1pbGxpc2Vjb25kcywgdGhlIGFwcCB3aWxsIHdhaXQgZm9yIGFuIEFQSSByZXNwb25zZSB3aGVuIG1ha2luZyByZXF1ZXN0cyB0byBpdC4gSXQgd2lsbCBiZSBpZ25vcmVkIGlmIHRoZSB2YWx1ZSBpcyBzZXQgdW5kZXIgMTUwMCBtaWxsaXNlY29uZHMuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5HRU5FUkFMLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5udW1iZXIsXG4gICAgZGVmYXVsdFZhbHVlOiAyMDAwMCxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIG51bWJlcjoge1xuICAgICAgICBtaW46IDE1MDAsXG4gICAgICAgIGludGVnZXI6IHRydWVcbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZTogZnVuY3Rpb24odmFsdWU6IG51bWJlcil7XG4gICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlOiBmdW5jdGlvbih2YWx1ZTogc3RyaW5nKTogbnVtYmVyIHtcbiAgICAgIHJldHVybiBOdW1iZXIodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uKHZhbHVlKXtcblx0XHRcdHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpO1xuXHRcdH0sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5udW1iZXIoe3ZhbGlkYXRlOiB0aGlzLnZhbGlkYXRlLmJpbmQodGhpcyl9KTtcblx0XHR9LFxuICB9LFxuICBcIndhenVoLm1vbml0b3JpbmcuY3JlYXRpb25cIjoge1xuICAgIHRpdGxlOiBcIkluZGV4IGNyZWF0aW9uXCIsXG4gICAgZGVzY3JpcHRpb246IFwiRGVmaW5lIHRoZSBpbnRlcnZhbCBpbiB3aGljaCBhIG5ldyB3YXp1aC1tb25pdG9yaW5nIGluZGV4IHdpbGwgYmUgY3JlYXRlZC5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkcsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnNlbGVjdCxcbiAgICBvcHRpb25zOiB7XG4gICAgICBzZWxlY3Q6IFtcbiAgICAgICAge1xuICAgICAgICAgIHRleHQ6IFwiSG91cmx5XCIsXG4gICAgICAgICAgdmFsdWU6IFwiaFwiXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiBcIkRhaWx5XCIsXG4gICAgICAgICAgdmFsdWU6IFwiZFwiXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICB0ZXh0OiBcIldlZWtseVwiLFxuICAgICAgICAgIHZhbHVlOiBcIndcIlxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgdGV4dDogXCJNb250aGx5XCIsXG4gICAgICAgICAgdmFsdWU6IFwibVwiXG4gICAgICAgIH1cbiAgICAgIF1cbiAgICB9LFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfTU9OSVRPUklOR19ERUZBVUxUX0NSRUFUSU9OLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uICh2YWx1ZSl7XG5cdFx0XHRyZXR1cm4gU2V0dGluZ3NWYWxpZGF0b3IubGl0ZXJhbCh0aGlzLm9wdGlvbnMuc2VsZWN0Lm1hcCgoe3ZhbHVlfSkgPT4gdmFsdWUpKSh2YWx1ZSlcblx0XHR9LFxuXHRcdHZhbGlkYXRlQmFja2VuZDogZnVuY3Rpb24oc2NoZW1hKXtcblx0XHRcdHJldHVybiBzY2hlbWEub25lT2YodGhpcy5vcHRpb25zLnNlbGVjdC5tYXAoKHt2YWx1ZX0pID0+IHNjaGVtYS5saXRlcmFsKHZhbHVlKSkpO1xuXHRcdH0sXG4gIH0sXG4gIFwid2F6dWgubW9uaXRvcmluZy5lbmFibGVkXCI6IHtcbiAgICB0aXRsZTogXCJTdGF0dXNcIixcbiAgICBkZXNjcmlwdGlvbjogXCJFbmFibGUgb3IgZGlzYWJsZSB0aGUgd2F6dWgtbW9uaXRvcmluZyBpbmRleCBjcmVhdGlvbiBhbmQvb3IgdmlzdWFsaXphdGlvbi5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkcsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLnN3aXRjaCxcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9FTkFCTEVELFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgcmVxdWlyZXNSZXN0YXJ0aW5nUGx1Z2luUGxhdGZvcm06IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgc3dpdGNoOiB7XG4gICAgICAgIHZhbHVlczoge1xuICAgICAgICAgIGRpc2FibGVkOiB7IGxhYmVsOiAnZmFsc2UnLCB2YWx1ZTogZmFsc2UgfSxcbiAgICAgICAgICBlbmFibGVkOiB7IGxhYmVsOiAndHJ1ZScsIHZhbHVlOiB0cnVlIH0sXG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNoYW5nZWRJbnB1dFZhbHVlOiBmdW5jdGlvbiAodmFsdWU6IGJvb2xlYW4gfCBzdHJpbmcpOiBib29sZWFuIHtcbiAgICAgIHJldHVybiBCb29sZWFuKHZhbHVlKTtcbiAgICB9LFxuICAgIHZhbGlkYXRlOiBTZXR0aW5nc1ZhbGlkYXRvci5pc0Jvb2xlYW4sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5ib29sZWFuKCk7XG5cdFx0fSxcbiAgfSxcbiAgXCJ3YXp1aC5tb25pdG9yaW5nLmZyZXF1ZW5jeVwiOiB7XG4gICAgdGl0bGU6IFwiRnJlcXVlbmN5XCIsXG4gICAgZGVzY3JpcHRpb246IFwiRnJlcXVlbmN5LCBpbiBzZWNvbmRzLCBvZiBBUEkgcmVxdWVzdHMgdG8gZ2V0IHRoZSBzdGF0ZSBvZiB0aGUgYWdlbnRzIGFuZCBjcmVhdGUgYSBuZXcgZG9jdW1lbnQgaW4gdGhlIHdhenVoLW1vbml0b3JpbmcgaW5kZXggd2l0aCB0aGlzIGRhdGEuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5NT05JVE9SSU5HLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS5udW1iZXIsXG4gICAgZGVmYXVsdFZhbHVlOiBXQVpVSF9NT05JVE9SSU5HX0RFRkFVTFRfRlJFUVVFTkNZLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgcmVxdWlyZXNSZXN0YXJ0aW5nUGx1Z2luUGxhdGZvcm06IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgbnVtYmVyOiB7XG4gICAgICAgIG1pbjogNjAsXG4gICAgICAgIGludGVnZXI6IHRydWVcbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZTogZnVuY3Rpb24odmFsdWU6IG51bWJlcil7XG4gICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlOiBmdW5jdGlvbih2YWx1ZTogc3RyaW5nKTogbnVtYmVyIHtcbiAgICAgIHJldHVybiBOdW1iZXIodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uKHZhbHVlKXtcblx0XHRcdHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpO1xuXHRcdH0sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5udW1iZXIoe3ZhbGlkYXRlOiB0aGlzLnZhbGlkYXRlLmJpbmQodGhpcyl9KTtcblx0XHR9LFxuICB9LFxuICBcIndhenVoLm1vbml0b3JpbmcucGF0dGVyblwiOiB7XG4gICAgdGl0bGU6IFwiSW5kZXggcGF0dGVyblwiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkRlZmF1bHQgaW5kZXggcGF0dGVybiB0byB1c2UgZm9yIFdhenVoIG1vbml0b3JpbmcuXCIsXG4gICAgY2F0ZWdvcnk6IFNldHRpbmdDYXRlZ29yeS5NT05JVE9SSU5HLFxuICAgIHR5cGU6IEVwbHVnaW5TZXR0aW5nVHlwZS50ZXh0LFxuICAgIGRlZmF1bHRWYWx1ZTogV0FaVUhfTU9OSVRPUklOR19QQVRURVJOLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgdmFsaWRhdGU6IFNldHRpbmdzVmFsaWRhdG9yLmNvbXBvc2UoXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5pc05vdEVtcHR5U3RyaW5nLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm9TcGFjZXMsXG4gICAgICBTZXR0aW5nc1ZhbGlkYXRvci5ub0xpdGVyYWxTdHJpbmcoJy4nLCAnLi4nKSxcbiAgICAgIFNldHRpbmdzVmFsaWRhdG9yLm5vU3RhcnRzV2l0aFN0cmluZygnLScsICdfJywgJysnLCAnLicpLFxuICAgICAgU2V0dGluZ3NWYWxpZGF0b3IuaGFzTm90SW52YWxpZENoYXJhY3RlcnMoJ1xcXFwnLCAnLycsICc/JywgJ1wiJywgJzwnLCAnPicsICd8JywgJywnLCAnIycpXG4gICAgKSxcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLnN0cmluZyh7bWluTGVuZ3RoOiAxLCB2YWxpZGF0ZTogdGhpcy52YWxpZGF0ZX0pO1xuXHRcdH0sXG4gIH0sXG4gIFwid2F6dWgubW9uaXRvcmluZy5yZXBsaWNhc1wiOiB7XG4gICAgdGl0bGU6IFwiSW5kZXggcmVwbGljYXNcIixcbiAgICBkZXNjcmlwdGlvbjogXCJEZWZpbmUgdGhlIG51bWJlciBvZiByZXBsaWNhcyB0byB1c2UgZm9yIHRoZSB3YXp1aC1tb25pdG9yaW5nLSogaW5kaWNlcy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkcsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLm51bWJlcixcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9JTkRJQ0VTX1JFUExJQ0FTLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbUZpbGU6IHRydWUsXG4gICAgaXNDb25maWd1cmFibGVGcm9tVUk6IHRydWUsXG4gICAgcmVxdWlyZXNSdW5uaW5nSGVhbHRoQ2hlY2s6IHRydWUsXG4gICAgb3B0aW9uczoge1xuICAgICAgbnVtYmVyOiB7XG4gICAgICAgIG1pbjogMCxcbiAgICAgICAgaW50ZWdlcjogdHJ1ZVxuICAgICAgfVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtQ29uZmlndXJhdGlvblZhbHVlVG9JbnB1dFZhbHVlOiBmdW5jdGlvbih2YWx1ZTogbnVtYmVyKXtcbiAgICAgIHJldHVybiBTdHJpbmcodmFsdWUpXG4gICAgfSxcbiAgICB1aUZvcm1UcmFuc2Zvcm1JbnB1dFZhbHVlVG9Db25maWd1cmF0aW9uVmFsdWU6IGZ1bmN0aW9uKHZhbHVlOiBzdHJpbmcpOiBudW1iZXIge1xuICAgICAgcmV0dXJuIE51bWJlcih2YWx1ZSk7XG4gICAgfSxcbiAgICB2YWxpZGF0ZTogZnVuY3Rpb24odmFsdWUpe1xuXHRcdFx0cmV0dXJuIFNldHRpbmdzVmFsaWRhdG9yLm51bWJlcih0aGlzLm9wdGlvbnMubnVtYmVyKSh2YWx1ZSk7XG5cdFx0fSxcblx0XHR2YWxpZGF0ZUJhY2tlbmQ6IGZ1bmN0aW9uKHNjaGVtYSl7XG5cdFx0XHRyZXR1cm4gc2NoZW1hLm51bWJlcih7dmFsaWRhdGU6IHRoaXMudmFsaWRhdGUuYmluZCh0aGlzKX0pO1xuXHRcdH0sXG4gIH0sXG4gIFwid2F6dWgubW9uaXRvcmluZy5zaGFyZHNcIjoge1xuICAgIHRpdGxlOiBcIkluZGV4IHNoYXJkc1wiLFxuICAgIGRlc2NyaXB0aW9uOiBcIkRlZmluZSB0aGUgbnVtYmVyIG9mIHNoYXJkcyB0byB1c2UgZm9yIHRoZSB3YXp1aC1tb25pdG9yaW5nLSogaW5kaWNlcy5cIixcbiAgICBjYXRlZ29yeTogU2V0dGluZ0NhdGVnb3J5Lk1PTklUT1JJTkcsXG4gICAgdHlwZTogRXBsdWdpblNldHRpbmdUeXBlLm51bWJlcixcbiAgICBkZWZhdWx0VmFsdWU6IFdBWlVIX01PTklUT1JJTkdfREVGQVVMVF9JTkRJQ0VTX1NIQVJEUyxcbiAgICBpc0NvbmZpZ3VyYWJsZUZyb21GaWxlOiB0cnVlLFxuICAgIGlzQ29uZmlndXJhYmxlRnJvbVVJOiB0cnVlLFxuICAgIHJlcXVpcmVzUnVubmluZ0hlYWx0aENoZWNrOiB0cnVlLFxuICAgIG9wdGlvbnM6IHtcbiAgICAgIG51bWJlcjoge1xuICAgICAgICBtaW46IDEsXG4gICAgICAgIGludGVnZXI6IHRydWVcbiAgICAgIH1cbiAgICB9LFxuICAgIHVpRm9ybVRyYW5zZm9ybUNvbmZpZ3VyYXRpb25WYWx1ZVRvSW5wdXRWYWx1ZTogZnVuY3Rpb24odmFsdWU6IG51bWJlcil7XG4gICAgICByZXR1cm4gU3RyaW5nKHZhbHVlKVxuICAgIH0sXG4gICAgdWlGb3JtVHJhbnNmb3JtSW5wdXRWYWx1ZVRvQ29uZmlndXJhdGlvblZhbHVlOiBmdW5jdGlvbih2YWx1ZTogc3RyaW5nKTogbnVtYmVyIHtcbiAgICAgIHJldHVybiBOdW1iZXIodmFsdWUpO1xuICAgIH0sXG4gICAgdmFsaWRhdGU6IGZ1bmN0aW9uKHZhbHVlKXtcblx0XHRcdHJldHVybiBTZXR0aW5nc1ZhbGlkYXRvci5udW1iZXIodGhpcy5vcHRpb25zLm51bWJlcikodmFsdWUpO1xuXHRcdH0sXG5cdFx0dmFsaWRhdGVCYWNrZW5kOiBmdW5jdGlvbihzY2hlbWEpe1xuXHRcdFx0cmV0dXJuIHNjaGVtYS5udW1iZXIoe3ZhbGlkYXRlOiB0aGlzLnZhbGlkYXRlLmJpbmQodGhpcyl9KTtcblx0XHR9LFxuICB9XG59O1xuXG5leHBvcnQgdHlwZSBUUGx1Z2luU2V0dGluZ0tleSA9IGtleW9mIHR5cGVvZiBQTFVHSU5fU0VUVElOR1M7XG5cbmV4cG9ydCBlbnVtIEhUVFBfU1RBVFVTX0NPREVTIHtcbiAgQ09OVElOVUUgPSAxMDAsXG4gIFNXSVRDSElOR19QUk9UT0NPTFMgPSAxMDEsXG4gIFBST0NFU1NJTkcgPSAxMDIsXG4gIE9LID0gMjAwLFxuICBDUkVBVEVEID0gMjAxLFxuICBBQ0NFUFRFRCA9IDIwMixcbiAgTk9OX0FVVEhPUklUQVRJVkVfSU5GT1JNQVRJT04gPSAyMDMsXG4gIE5PX0NPTlRFTlQgPSAyMDQsXG4gIFJFU0VUX0NPTlRFTlQgPSAyMDUsXG4gIFBBUlRJQUxfQ09OVEVOVCA9IDIwNixcbiAgTVVMVElfU1RBVFVTID0gMjA3LFxuICBNVUxUSVBMRV9DSE9JQ0VTID0gMzAwLFxuICBNT1ZFRF9QRVJNQU5FTlRMWSA9IDMwMSxcbiAgTU9WRURfVEVNUE9SQVJJTFkgPSAzMDIsXG4gIFNFRV9PVEhFUiA9IDMwMyxcbiAgTk9UX01PRElGSUVEID0gMzA0LFxuICBVU0VfUFJPWFkgPSAzMDUsXG4gIFRFTVBPUkFSWV9SRURJUkVDVCA9IDMwNyxcbiAgUEVSTUFORU5UX1JFRElSRUNUID0gMzA4LFxuICBCQURfUkVRVUVTVCA9IDQwMCxcbiAgVU5BVVRIT1JJWkVEID0gNDAxLFxuICBQQVlNRU5UX1JFUVVJUkVEID0gNDAyLFxuICBGT1JCSURERU4gPSA0MDMsXG4gIE5PVF9GT1VORCA9IDQwNCxcbiAgTUVUSE9EX05PVF9BTExPV0VEID0gNDA1LFxuICBOT1RfQUNDRVBUQUJMRSA9IDQwNixcbiAgUFJPWFlfQVVUSEVOVElDQVRJT05fUkVRVUlSRUQgPSA0MDcsXG4gIFJFUVVFU1RfVElNRU9VVCA9IDQwOCxcbiAgQ09ORkxJQ1QgPSA0MDksXG4gIEdPTkUgPSA0MTAsXG4gIExFTkdUSF9SRVFVSVJFRCA9IDQxMSxcbiAgUFJFQ09ORElUSU9OX0ZBSUxFRCA9IDQxMixcbiAgUkVRVUVTVF9UT09fTE9ORyA9IDQxMyxcbiAgUkVRVUVTVF9VUklfVE9PX0xPTkcgPSA0MTQsXG4gIFVOU1VQUE9SVEVEX01FRElBX1RZUEUgPSA0MTUsXG4gIFJFUVVFU1RFRF9SQU5HRV9OT1RfU0FUSVNGSUFCTEUgPSA0MTYsXG4gIEVYUEVDVEFUSU9OX0ZBSUxFRCA9IDQxNyxcbiAgSU1fQV9URUFQT1QgPSA0MTgsXG4gIElOU1VGRklDSUVOVF9TUEFDRV9PTl9SRVNPVVJDRSA9IDQxOSxcbiAgTUVUSE9EX0ZBSUxVUkUgPSA0MjAsXG4gIE1JU0RJUkVDVEVEX1JFUVVFU1QgPSA0MjEsXG4gIFVOUFJPQ0VTU0FCTEVfRU5USVRZID0gNDIyLFxuICBMT0NLRUQgPSA0MjMsXG4gIEZBSUxFRF9ERVBFTkRFTkNZID0gNDI0LFxuICBQUkVDT05ESVRJT05fUkVRVUlSRUQgPSA0MjgsXG4gIFRPT19NQU5ZX1JFUVVFU1RTID0gNDI5LFxuICBSRVFVRVNUX0hFQURFUl9GSUVMRFNfVE9PX0xBUkdFID0gNDMxLFxuICBVTkFWQUlMQUJMRV9GT1JfTEVHQUxfUkVBU09OUyA9IDQ1MSxcbiAgSU5URVJOQUxfU0VSVkVSX0VSUk9SID0gNTAwLFxuICBOT1RfSU1QTEVNRU5URUQgPSA1MDEsXG4gIEJBRF9HQVRFV0FZID0gNTAyLFxuICBTRVJWSUNFX1VOQVZBSUxBQkxFID0gNTAzLFxuICBHQVRFV0FZX1RJTUVPVVQgPSA1MDQsXG4gIEhUVFBfVkVSU0lPTl9OT1RfU1VQUE9SVEVEID0gNTA1LFxuICBJTlNVRkZJQ0lFTlRfU1RPUkFHRSA9IDUwNyxcbiAgTkVUV09SS19BVVRIRU5USUNBVElPTl9SRVFVSVJFRCA9IDUxMVxufVxuXG4vLyBNb2R1bGUgU2VjdXJpdHkgY29uZmlndXJhdGlvbiBhc3Nlc3NtZW50XG5leHBvcnQgY29uc3QgTU9EVUxFX1NDQV9DSEVDS19SRVNVTFRfTEFCRUwgPSB7XG4gIHBhc3NlZDogJ1Bhc3NlZCcsXG4gIGZhaWxlZDogJ0ZhaWxlZCcsXG4gICdub3QgYXBwbGljYWJsZSc6ICdOb3QgYXBwbGljYWJsZSdcbn1cbiJdfQ==