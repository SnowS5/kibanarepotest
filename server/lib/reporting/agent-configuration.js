"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.AgentConfiguration = void 0;

var _web_documentation = require("../../../common/services/web_documentation");

/*
 * Wazuh app - Agent configuration request objet for exporting it
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const AgentConfiguration = {
  configurations: [{
    title: 'Main configurations',
    sections: [{
      subtitle: 'Global configuration',
      desc: 'Logging settings that apply to the agent',
      config: [{
        component: 'com',
        configuration: 'logging'
      }],
      labels: [{
        plain: 'Write internal logs in plain text',
        json: 'Write internal logs in JSON format',
        server: 'List of managers to connect'
      }]
    }, {
      subtitle: 'Communication',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/client.html'),
      desc: 'Settings related to the connection with the manager',
      config: [{
        component: 'agent',
        configuration: 'client'
      }],
      labels: [{
        crypto_method: 'Method used to encrypt communications',
        auto_restart: 'Auto-restart the agent when receiving valid configuration from manager',
        notify_time: 'Time (in seconds) between agent checkings to the manager',
        'time-reconnect': 'Time (in seconds) before attempting to reconnect',
        server: 'List of managers to connect',
        'config-profile': 'Configuration profiles',
        remote_conf: 'Remote configuration is enabled'
      }]
    }, {
      subtitle: 'Anti-flooding settings',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/capabilities/antiflooding.html'),
      desc: 'Agent bucket parameters to avoid event flooding',
      config: [{
        component: 'agent',
        configuration: 'buffer'
      }],
      labels: [{
        disabled: 'Buffer disabled',
        queue_size: 'Queue size',
        events_per_second: 'Events per second'
      }]
    }, {
      subtitle: 'Agent labels',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/labels.html'),
      desc: 'User-defined information about the agent included in alerts',
      config: [{
        component: 'agent',
        configuration: 'labels'
      }]
    }]
  }, {
    title: 'Auditing and policy monitoring',
    sections: [{
      subtitle: 'Policy monitoring',
      docuLink: (0, _web_documentation.webDocumentationLink)('pci-dss/policy-monitoring.html'),
      desc: 'Configuration to ensure compliance with security policies, standards and hardening guides',
      config: [{
        component: 'syscheck',
        configuration: 'rootcheck'
      }],
      wodle: [{
        name: 'sca'
      }],
      labels: [{
        disabled: 'Policy monitoring service disabled',
        base_directory: 'Base directory',
        rootkit_files: 'Rootkit files database path',
        rootkit_trojans: 'Rootkit trojans database path',
        scanall: 'Scan the entire system',
        skip_nfs: 'Skip scan on CIFS/NFS mounts',
        frequency: 'Frequency (in seconds) to run the scan',
        check_dev: 'Check /dev path',
        check_files: 'Check files',
        check_if: 'Check network interfaces',
        check_pids: 'Check processes IDs',
        check_ports: 'Check network ports',
        check_sys: 'Check anomalous system objects',
        check_trojans: 'Check trojans',
        check_unixaudit: 'Check UNIX audit',
        system_audit: 'UNIX audit files paths',
        enabled: 'Security configuration assessment enabled',
        scan_on_start: 'Scan on start',
        interval: 'Interval',
        policies: 'Policies'
      }],
      tabs: ['General', 'Security configuration assessment']
    }, {
      subtitle: 'OpenSCAP',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/wodle-openscap.html'),
      desc: 'Configuration assessment and automation of compliance monitoring using SCAP checks',
      wodle: [{
        name: 'open-scap'
      }],
      labels: [{
        content: 'Evaluations',
        disabled: 'OpenSCAP integration disabled',
        'scan-on-start': 'Scan on start',
        interval: 'Interval between scan executions',
        timeout: 'Timeout (in seconds) for scan executions'
      }]
    }, {
      subtitle: 'CIS-CAT',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/wodle-ciscat.html'),
      desc: 'Configuration assessment using CIS scanner and SCAP checks',
      wodle: [{
        name: 'cis-cat'
      }],
      labels: [{
        disabled: 'CIS-CAT integration disabled',
        'scan-on-start': 'Scan on start',
        interval: 'Interval between scan executions',
        java_path: 'Path to Java executable directory',
        ciscat_path: 'Path to CIS-CAT executable directory',
        timeout: 'Timeout (in seconds) for scan executions',
        content: 'Benchmarks'
      }]
    }]
  }, {
    title: 'System threats and incident response',
    sections: [{
      subtitle: 'Osquery',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/wodle-osquery.html'),
      desc: 'Expose an operating system as a high-performance relational database',
      wodle: [{
        name: 'osquery'
      }],
      labels: [{
        disabled: 'Osquery integration disabled',
        run_daemon: 'Auto-run the Osquery daemon',
        add_labels: 'Use defined labels as decorators',
        log_path: 'Path to the Osquery results log file',
        config_path: 'Path to the Osquery configuration file'
      }]
    }, {
      subtitle: 'Inventory data',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/wodle-syscollector.html'),
      desc: 'Gather relevant information about the operating system, hardware, networking and packages',
      wodle: [{
        name: 'syscollector'
      }],
      labels: [{
        disabled: 'Syscollector integration disabled',
        'scan-on-start': 'Scan on start',
        interval: 'Interval between system scans',
        network: 'Scan network interfaces',
        os: 'Scan operating system info',
        hardware: 'Scan hardware info',
        packages: 'Scan installed packages',
        ports: 'Scan listening network ports',
        ports_all: 'Scan all network ports',
        processes: 'Scan current processes'
      }]
    }, {
      subtitle: 'Active response',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/active-response.html'),
      desc: 'Active threat addressing by immediate response',
      config: [{
        component: 'com',
        configuration: 'active-response'
      }],
      labels: [{
        disabled: 'Active response disabled',
        ca_store: 'Use the following list of root CA certificates',
        ca_verification: 'Validate WPKs using root CA certificate'
      }]
    }, {
      subtitle: 'Commands',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/wodle-command.html'),
      desc: 'Configuration options of the Command wodle',
      wodle: [{
        name: 'command'
      }],
      labels: [{
        disabled: 'Command disabled',
        run_on_start: 'Run on start',
        ignore_output: 'Ignore command output',
        skip_verification: 'Ignore checksum verification',
        interval: 'Interval between executions',
        tag: 'Command name',
        command: 'Command to execute',
        verify_md5: 'Verify MD5 sum',
        verify_sha1: 'Verify SHA1 sum',
        verify_sha256: 'Verify SHA256 sum'
      }]
    }, {
      subtitle: 'Docker listener',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/wodle-docker.html'),
      desc: 'Monitor and collect the activity from Docker containers such as creation, running, starting, stopping or pausing events',
      wodle: [{
        name: 'docker-listener'
      }],
      labels: [{
        disabled: 'Docker listener disabled',
        run_on_start: 'Run the listener immediately when service is started',
        interval: 'Waiting time to rerun the listener in case it fails',
        attempts: 'Number of attempts to execute the listener'
      }]
    }]
  }, {
    title: 'Log data analysis',
    sections: [{
      subtitle: 'Log collection',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/capabilities/log-data-collection/index.html'),
      desc: 'Log analysis from text files, Windows events or syslog outputs',
      config: [{
        component: 'logcollector',
        configuration: 'localfile',
        filterBy: 'logformat'
      }, {
        component: 'logcollector',
        configuration: 'socket'
      }],
      labels: [{
        logformat: 'Log format',
        log_format: 'Log format',
        alias: 'Command alias',
        ignore_binaries: 'Ignore binaries',
        target: 'Redirect output to this socket',
        frequency: 'Interval between command executions',
        file: 'Log location',
        location: 'Log location',
        socket: 'Output sockets',
        syslog: 'Syslog',
        command: 'Command',
        full_command: 'Full command',
        audit: 'Audit'
      }],
      options: {
        hideHeader: true
      }
    }, {
      subtitle: 'Integrity monitoring',
      docuLink: (0, _web_documentation.webDocumentationLink)('user-manual/reference/ossec-conf/syscheck.html'),
      desc: 'Identify changes in content, permissions, ownership, and attributes of files',
      config: [{
        component: 'syscheck',
        configuration: 'syscheck',
        matrix: true
      }],
      tabs: ['General', 'Who data'],
      labels: [{
        disabled: 'Integrity monitoring disabled',
        frequency: 'Interval (in seconds) to run the integrity scan',
        skip_nfs: 'Skip scan on CIFS/NFS mounts',
        scan_on_start: 'Scan on start',
        directories: 'Monitored directories',
        nodiff: 'No diff directories',
        ignore: 'Ignored files and directories',
        restart_audit: 'Restart audit',
        startup_healthcheck: 'Startup healthcheck'
      }],
      opts: {
        realtime: 'RT',
        check_whodata: 'WD',
        report_changes: 'Changes',
        check_md5sum: 'MD5',
        check_sha1sum: 'SHA1',
        check_perm: 'Per.',
        check_size: 'Size',
        check_owner: 'Owner',
        check_group: 'Group',
        check_mtime: 'MT',
        check_inode: 'Inode',
        check_sha256sum: 'SHA256',
        follow_symbolic_link: 'SL'
      }
    }]
  }]
};
exports.AgentConfiguration = AgentConfiguration;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50LWNvbmZpZ3VyYXRpb24udHMiXSwibmFtZXMiOlsiQWdlbnRDb25maWd1cmF0aW9uIiwiY29uZmlndXJhdGlvbnMiLCJ0aXRsZSIsInNlY3Rpb25zIiwic3VidGl0bGUiLCJkZXNjIiwiY29uZmlnIiwiY29tcG9uZW50IiwiY29uZmlndXJhdGlvbiIsImxhYmVscyIsInBsYWluIiwianNvbiIsInNlcnZlciIsImRvY3VMaW5rIiwiY3J5cHRvX21ldGhvZCIsImF1dG9fcmVzdGFydCIsIm5vdGlmeV90aW1lIiwicmVtb3RlX2NvbmYiLCJkaXNhYmxlZCIsInF1ZXVlX3NpemUiLCJldmVudHNfcGVyX3NlY29uZCIsIndvZGxlIiwibmFtZSIsImJhc2VfZGlyZWN0b3J5Iiwicm9vdGtpdF9maWxlcyIsInJvb3RraXRfdHJvamFucyIsInNjYW5hbGwiLCJza2lwX25mcyIsImZyZXF1ZW5jeSIsImNoZWNrX2RldiIsImNoZWNrX2ZpbGVzIiwiY2hlY2tfaWYiLCJjaGVja19waWRzIiwiY2hlY2tfcG9ydHMiLCJjaGVja19zeXMiLCJjaGVja190cm9qYW5zIiwiY2hlY2tfdW5peGF1ZGl0Iiwic3lzdGVtX2F1ZGl0IiwiZW5hYmxlZCIsInNjYW5fb25fc3RhcnQiLCJpbnRlcnZhbCIsInBvbGljaWVzIiwidGFicyIsImNvbnRlbnQiLCJ0aW1lb3V0IiwiamF2YV9wYXRoIiwiY2lzY2F0X3BhdGgiLCJydW5fZGFlbW9uIiwiYWRkX2xhYmVscyIsImxvZ19wYXRoIiwiY29uZmlnX3BhdGgiLCJuZXR3b3JrIiwib3MiLCJoYXJkd2FyZSIsInBhY2thZ2VzIiwicG9ydHMiLCJwb3J0c19hbGwiLCJwcm9jZXNzZXMiLCJjYV9zdG9yZSIsImNhX3ZlcmlmaWNhdGlvbiIsInJ1bl9vbl9zdGFydCIsImlnbm9yZV9vdXRwdXQiLCJza2lwX3ZlcmlmaWNhdGlvbiIsInRhZyIsImNvbW1hbmQiLCJ2ZXJpZnlfbWQ1IiwidmVyaWZ5X3NoYTEiLCJ2ZXJpZnlfc2hhMjU2IiwiYXR0ZW1wdHMiLCJmaWx0ZXJCeSIsImxvZ2Zvcm1hdCIsImxvZ19mb3JtYXQiLCJhbGlhcyIsImlnbm9yZV9iaW5hcmllcyIsInRhcmdldCIsImZpbGUiLCJsb2NhdGlvbiIsInNvY2tldCIsInN5c2xvZyIsImZ1bGxfY29tbWFuZCIsImF1ZGl0Iiwib3B0aW9ucyIsImhpZGVIZWFkZXIiLCJtYXRyaXgiLCJkaXJlY3RvcmllcyIsIm5vZGlmZiIsImlnbm9yZSIsInJlc3RhcnRfYXVkaXQiLCJzdGFydHVwX2hlYWx0aGNoZWNrIiwib3B0cyIsInJlYWx0aW1lIiwiY2hlY2tfd2hvZGF0YSIsInJlcG9ydF9jaGFuZ2VzIiwiY2hlY2tfbWQ1c3VtIiwiY2hlY2tfc2hhMXN1bSIsImNoZWNrX3Blcm0iLCJjaGVja19zaXplIiwiY2hlY2tfb3duZXIiLCJjaGVja19ncm91cCIsImNoZWNrX210aW1lIiwiY2hlY2tfaW5vZGUiLCJjaGVja19zaGEyNTZzdW0iLCJmb2xsb3dfc3ltYm9saWNfbGluayJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTyxNQUFNQSxrQkFBa0IsR0FBRztBQUNoQ0MsRUFBQUEsY0FBYyxFQUFFLENBQ2Q7QUFDRUMsSUFBQUEsS0FBSyxFQUFFLHFCQURUO0FBRUVDLElBQUFBLFFBQVEsRUFBRSxDQUNSO0FBQ0VDLE1BQUFBLFFBQVEsRUFBRSxzQkFEWjtBQUVFQyxNQUFBQSxJQUFJLEVBQUUsMENBRlI7QUFHRUMsTUFBQUEsTUFBTSxFQUFFLENBQUM7QUFBRUMsUUFBQUEsU0FBUyxFQUFFLEtBQWI7QUFBb0JDLFFBQUFBLGFBQWEsRUFBRTtBQUFuQyxPQUFELENBSFY7QUFJRUMsTUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRUMsUUFBQUEsS0FBSyxFQUFFLG1DQURUO0FBRUVDLFFBQUFBLElBQUksRUFBRSxvQ0FGUjtBQUdFQyxRQUFBQSxNQUFNLEVBQUU7QUFIVixPQURN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QUEsVUFBVSxFQUFFLE1BUFI7QUFRSkMsUUFBQUEsV0FBVyxFQUFFLE9BUlQ7QUFTSkMsUUFBQUEsV0FBVyxFQUFFLE9BVFQ7QUFVSkMsUUFBQUEsV0FBVyxFQUFFLElBVlQ7QUFXSkMsUUFBQUEsV0FBVyxFQUFFLE9BWFQ7QUFZSkMsUUFBQUEsZUFBZSxFQUFFLFFBWmI7QUFhSkMsUUFBQUEsb0JBQW9CLEVBQUU7QUFibEI7QUF0QlIsS0FqQ1E7QUFGWixHQTNOYztBQURnQixDQUEzQiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCB7IHdlYkRvY3VtZW50YXRpb25MaW5rIH0gZnJvbSBcIi4uLy4uLy4uL2NvbW1vbi9zZXJ2aWNlcy93ZWJfZG9jdW1lbnRhdGlvblwiO1xuXG4vKlxuICogV2F6dWggYXBwIC0gQWdlbnQgY29uZmlndXJhdGlvbiByZXF1ZXN0IG9iamV0IGZvciBleHBvcnRpbmcgaXRcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgY29uc3QgQWdlbnRDb25maWd1cmF0aW9uID0ge1xuICBjb25maWd1cmF0aW9uczogW1xuICAgIHtcbiAgICAgIHRpdGxlOiAnTWFpbiBjb25maWd1cmF0aW9ucycsXG4gICAgICBzZWN0aW9uczogW1xuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdHbG9iYWwgY29uZmlndXJhdGlvbicsXG4gICAgICAgICAgZGVzYzogJ0xvZ2dpbmcgc2V0dGluZ3MgdGhhdCBhcHBseSB0byB0aGUgYWdlbnQnLFxuICAgICAgICAgIGNvbmZpZzogW3sgY29tcG9uZW50OiAnY29tJywgY29uZmlndXJhdGlvbjogJ2xvZ2dpbmcnIH1dLFxuICAgICAgICAgIGxhYmVsczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBwbGFpbjogJ1dyaXRlIGludGVybmFsIGxvZ3MgaW4gcGxhaW4gdGV4dCcsXG4gICAgICAgICAgICAgIGpzb246ICdXcml0ZSBpbnRlcm5hbCBsb2dzIGluIEpTT04gZm9ybWF0JyxcbiAgICAgICAgICAgICAgc2VydmVyOiAnTGlzdCBvZiBtYW5hZ2VycyB0byBjb25uZWN0J1xuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnQ29tbXVuaWNhdGlvbicsXG4gICAgICAgICAgZG9jdUxpbms6IHdlYkRvY3VtZW50YXRpb25MaW5rKCd1c2VyLW1hbnVhbC9yZWZlcmVuY2Uvb3NzZWMtY29uZi9jbGllbnQuaHRtbCcpLFxuICAgICAgICAgIGRlc2M6ICdTZXR0aW5ncyByZWxhdGVkIHRvIHRoZSBjb25uZWN0aW9uIHdpdGggdGhlIG1hbmFnZXInLFxuICAgICAgICAgIGNvbmZpZzogW3sgY29tcG9uZW50OiAnYWdlbnQnLCBjb25maWd1cmF0aW9uOiAnY2xpZW50JyB9XSxcbiAgICAgICAgICBsYWJlbHM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgY3J5cHRvX21ldGhvZDogJ01ldGhvZCB1c2VkIHRvIGVuY3J5cHQgY29tbXVuaWNhdGlvbnMnLFxuICAgICAgICAgICAgICBhdXRvX3Jlc3RhcnQ6XG4gICAgICAgICAgICAgICAgJ0F1dG8tcmVzdGFydCB0aGUgYWdlbnQgd2hlbiByZWNlaXZpbmcgdmFsaWQgY29uZmlndXJhdGlvbiBmcm9tIG1hbmFnZXInLFxuICAgICAgICAgICAgICBub3RpZnlfdGltZTpcbiAgICAgICAgICAgICAgICAnVGltZSAoaW4gc2Vjb25kcykgYmV0d2VlbiBhZ2VudCBjaGVja2luZ3MgdG8gdGhlIG1hbmFnZXInLFxuICAgICAgICAgICAgICAndGltZS1yZWNvbm5lY3QnOlxuICAgICAgICAgICAgICAgICdUaW1lIChpbiBzZWNvbmRzKSBiZWZvcmUgYXR0ZW1wdGluZyB0byByZWNvbm5lY3QnLFxuICAgICAgICAgICAgICBzZXJ2ZXI6ICdMaXN0IG9mIG1hbmFnZXJzIHRvIGNvbm5lY3QnLFxuICAgICAgICAgICAgICAnY29uZmlnLXByb2ZpbGUnOiAnQ29uZmlndXJhdGlvbiBwcm9maWxlcycsXG4gICAgICAgICAgICAgIHJlbW90ZV9jb25mOiAnUmVtb3RlIGNvbmZpZ3VyYXRpb24gaXMgZW5hYmxlZCdcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBzdWJ0aXRsZTogJ0FudGktZmxvb2Rpbmcgc2V0dGluZ3MnLFxuICAgICAgICAgIGRvY3VMaW5rOiB3ZWJEb2N1bWVudGF0aW9uTGluaygndXNlci1tYW51YWwvY2FwYWJpbGl0aWVzL2FudGlmbG9vZGluZy5odG1sJyksXG4gICAgICAgICAgZGVzYzogJ0FnZW50IGJ1Y2tldCBwYXJhbWV0ZXJzIHRvIGF2b2lkIGV2ZW50IGZsb29kaW5nJyxcbiAgICAgICAgICBjb25maWc6IFt7IGNvbXBvbmVudDogJ2FnZW50JywgY29uZmlndXJhdGlvbjogJ2J1ZmZlcicgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnQnVmZmVyIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgcXVldWVfc2l6ZTogJ1F1ZXVlIHNpemUnLFxuICAgICAgICAgICAgICBldmVudHNfcGVyX3NlY29uZDogJ0V2ZW50cyBwZXIgc2Vjb25kJ1xuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnQWdlbnQgbGFiZWxzJyxcbiAgICAgICAgICBkb2N1TGluazogd2ViRG9jdW1lbnRhdGlvbkxpbmsoJ3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL2xhYmVscy5odG1sJyksXG4gICAgICAgICAgZGVzYzogJ1VzZXItZGVmaW5lZCBpbmZvcm1hdGlvbiBhYm91dCB0aGUgYWdlbnQgaW5jbHVkZWQgaW4gYWxlcnRzJyxcbiAgICAgICAgICBjb25maWc6IFt7IGNvbXBvbmVudDogJ2FnZW50JywgY29uZmlndXJhdGlvbjogJ2xhYmVscycgfV1cbiAgICAgICAgfVxuICAgICAgXVxuICAgIH0sXG4gICAge1xuICAgICAgdGl0bGU6ICdBdWRpdGluZyBhbmQgcG9saWN5IG1vbml0b3JpbmcnLFxuICAgICAgc2VjdGlvbnM6IFtcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnUG9saWN5IG1vbml0b3JpbmcnLFxuICAgICAgICAgIGRvY3VMaW5rOiB3ZWJEb2N1bWVudGF0aW9uTGluaygncGNpLWRzcy9wb2xpY3ktbW9uaXRvcmluZy5odG1sJyksXG4gICAgICAgICAgZGVzYzpcbiAgICAgICAgICAgICdDb25maWd1cmF0aW9uIHRvIGVuc3VyZSBjb21wbGlhbmNlIHdpdGggc2VjdXJpdHkgcG9saWNpZXMsIHN0YW5kYXJkcyBhbmQgaGFyZGVuaW5nIGd1aWRlcycsXG4gICAgICAgICAgY29uZmlnOiBbeyBjb21wb25lbnQ6ICdzeXNjaGVjaycsIGNvbmZpZ3VyYXRpb246ICdyb290Y2hlY2snIH1dLFxuICAgICAgICAgIHdvZGxlOiBbeyBuYW1lOiAnc2NhJyB9XSxcbiAgICAgICAgICBsYWJlbHM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgZGlzYWJsZWQ6ICdQb2xpY3kgbW9uaXRvcmluZyBzZXJ2aWNlIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgYmFzZV9kaXJlY3Rvcnk6ICdCYXNlIGRpcmVjdG9yeScsXG4gICAgICAgICAgICAgIHJvb3RraXRfZmlsZXM6ICdSb290a2l0IGZpbGVzIGRhdGFiYXNlIHBhdGgnLFxuICAgICAgICAgICAgICByb290a2l0X3Ryb2phbnM6ICdSb290a2l0IHRyb2phbnMgZGF0YWJhc2UgcGF0aCcsXG4gICAgICAgICAgICAgIHNjYW5hbGw6ICdTY2FuIHRoZSBlbnRpcmUgc3lzdGVtJyxcbiAgICAgICAgICAgICAgc2tpcF9uZnM6ICdTa2lwIHNjYW4gb24gQ0lGUy9ORlMgbW91bnRzJyxcbiAgICAgICAgICAgICAgZnJlcXVlbmN5OiAnRnJlcXVlbmN5IChpbiBzZWNvbmRzKSB0byBydW4gdGhlIHNjYW4nLFxuICAgICAgICAgICAgICBjaGVja19kZXY6ICdDaGVjayAvZGV2IHBhdGgnLFxuICAgICAgICAgICAgICBjaGVja19maWxlczogJ0NoZWNrIGZpbGVzJyxcbiAgICAgICAgICAgICAgY2hlY2tfaWY6ICdDaGVjayBuZXR3b3JrIGludGVyZmFjZXMnLFxuICAgICAgICAgICAgICBjaGVja19waWRzOiAnQ2hlY2sgcHJvY2Vzc2VzIElEcycsXG4gICAgICAgICAgICAgIGNoZWNrX3BvcnRzOiAnQ2hlY2sgbmV0d29yayBwb3J0cycsXG4gICAgICAgICAgICAgIGNoZWNrX3N5czogJ0NoZWNrIGFub21hbG91cyBzeXN0ZW0gb2JqZWN0cycsXG4gICAgICAgICAgICAgIGNoZWNrX3Ryb2phbnM6ICdDaGVjayB0cm9qYW5zJyxcbiAgICAgICAgICAgICAgY2hlY2tfdW5peGF1ZGl0OiAnQ2hlY2sgVU5JWCBhdWRpdCcsXG4gICAgICAgICAgICAgIHN5c3RlbV9hdWRpdDogJ1VOSVggYXVkaXQgZmlsZXMgcGF0aHMnLFxuICAgICAgICAgICAgICBlbmFibGVkOiAnU2VjdXJpdHkgY29uZmlndXJhdGlvbiBhc3Nlc3NtZW50IGVuYWJsZWQnLFxuICAgICAgICAgICAgICBzY2FuX29uX3N0YXJ0OiAnU2NhbiBvbiBzdGFydCcsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnSW50ZXJ2YWwnLFxuICAgICAgICAgICAgICBwb2xpY2llczogJ1BvbGljaWVzJ1xuICAgICAgICAgICAgfVxuICAgICAgICAgIF0sXG4gICAgICAgICAgdGFiczogWydHZW5lcmFsJywgJ1NlY3VyaXR5IGNvbmZpZ3VyYXRpb24gYXNzZXNzbWVudCddXG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBzdWJ0aXRsZTogJ09wZW5TQ0FQJyxcbiAgICAgICAgICBkb2N1TGluazogd2ViRG9jdW1lbnRhdGlvbkxpbmsoJ3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL3dvZGxlLW9wZW5zY2FwLmh0bWwnKSxcbiAgICAgICAgICBkZXNjOlxuICAgICAgICAgICAgJ0NvbmZpZ3VyYXRpb24gYXNzZXNzbWVudCBhbmQgYXV0b21hdGlvbiBvZiBjb21wbGlhbmNlIG1vbml0b3JpbmcgdXNpbmcgU0NBUCBjaGVja3MnLFxuICAgICAgICAgIHdvZGxlOiBbeyBuYW1lOiAnb3Blbi1zY2FwJyB9XSxcbiAgICAgICAgICBsYWJlbHM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgY29udGVudDogJ0V2YWx1YXRpb25zJyxcbiAgICAgICAgICAgICAgZGlzYWJsZWQ6ICdPcGVuU0NBUCBpbnRlZ3JhdGlvbiBkaXNhYmxlZCcsXG4gICAgICAgICAgICAgICdzY2FuLW9uLXN0YXJ0JzogJ1NjYW4gb24gc3RhcnQnLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ0ludGVydmFsIGJldHdlZW4gc2NhbiBleGVjdXRpb25zJyxcbiAgICAgICAgICAgICAgdGltZW91dDogJ1RpbWVvdXQgKGluIHNlY29uZHMpIGZvciBzY2FuIGV4ZWN1dGlvbnMnXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdDSVMtQ0FUJyxcbiAgICAgICAgICBkb2N1TGluazogd2ViRG9jdW1lbnRhdGlvbkxpbmsoJ3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL3dvZGxlLWNpc2NhdC5odG1sJyksXG4gICAgICAgICAgZGVzYzogJ0NvbmZpZ3VyYXRpb24gYXNzZXNzbWVudCB1c2luZyBDSVMgc2Nhbm5lciBhbmQgU0NBUCBjaGVja3MnLFxuICAgICAgICAgIHdvZGxlOiBbeyBuYW1lOiAnY2lzLWNhdCcgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnQ0lTLUNBVCBpbnRlZ3JhdGlvbiBkaXNhYmxlZCcsXG4gICAgICAgICAgICAgICdzY2FuLW9uLXN0YXJ0JzogJ1NjYW4gb24gc3RhcnQnLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ0ludGVydmFsIGJldHdlZW4gc2NhbiBleGVjdXRpb25zJyxcbiAgICAgICAgICAgICAgamF2YV9wYXRoOiAnUGF0aCB0byBKYXZhIGV4ZWN1dGFibGUgZGlyZWN0b3J5JyxcbiAgICAgICAgICAgICAgY2lzY2F0X3BhdGg6ICdQYXRoIHRvIENJUy1DQVQgZXhlY3V0YWJsZSBkaXJlY3RvcnknLFxuICAgICAgICAgICAgICB0aW1lb3V0OiAnVGltZW91dCAoaW4gc2Vjb25kcykgZm9yIHNjYW4gZXhlY3V0aW9ucycsXG4gICAgICAgICAgICAgIGNvbnRlbnQ6ICdCZW5jaG1hcmtzJ1xuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfVxuICAgICAgXVxuICAgIH0sXG4gICAge1xuICAgICAgdGl0bGU6ICdTeXN0ZW0gdGhyZWF0cyBhbmQgaW5jaWRlbnQgcmVzcG9uc2UnLFxuICAgICAgc2VjdGlvbnM6IFtcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnT3NxdWVyeScsXG4gICAgICAgICAgZG9jdUxpbms6IHdlYkRvY3VtZW50YXRpb25MaW5rKCd1c2VyLW1hbnVhbC9yZWZlcmVuY2Uvb3NzZWMtY29uZi93b2RsZS1vc3F1ZXJ5Lmh0bWwnKSxcbiAgICAgICAgICBkZXNjOlxuICAgICAgICAgICAgJ0V4cG9zZSBhbiBvcGVyYXRpbmcgc3lzdGVtIGFzIGEgaGlnaC1wZXJmb3JtYW5jZSByZWxhdGlvbmFsIGRhdGFiYXNlJyxcbiAgICAgICAgICB3b2RsZTogW3sgbmFtZTogJ29zcXVlcnknIH1dLFxuICAgICAgICAgIGxhYmVsczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBkaXNhYmxlZDogJ09zcXVlcnkgaW50ZWdyYXRpb24gZGlzYWJsZWQnLFxuICAgICAgICAgICAgICBydW5fZGFlbW9uOiAnQXV0by1ydW4gdGhlIE9zcXVlcnkgZGFlbW9uJyxcbiAgICAgICAgICAgICAgYWRkX2xhYmVsczogJ1VzZSBkZWZpbmVkIGxhYmVscyBhcyBkZWNvcmF0b3JzJyxcbiAgICAgICAgICAgICAgbG9nX3BhdGg6ICdQYXRoIHRvIHRoZSBPc3F1ZXJ5IHJlc3VsdHMgbG9nIGZpbGUnLFxuICAgICAgICAgICAgICBjb25maWdfcGF0aDogJ1BhdGggdG8gdGhlIE9zcXVlcnkgY29uZmlndXJhdGlvbiBmaWxlJ1xuICAgICAgICAgICAgfVxuICAgICAgICAgIF1cbiAgICAgICAgfSxcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnSW52ZW50b3J5IGRhdGEnLFxuICAgICAgICAgIGRvY3VMaW5rOiB3ZWJEb2N1bWVudGF0aW9uTGluaygndXNlci1tYW51YWwvcmVmZXJlbmNlL29zc2VjLWNvbmYvd29kbGUtc3lzY29sbGVjdG9yLmh0bWwnKSxcbiAgICAgICAgICBkZXNjOlxuICAgICAgICAgICAgJ0dhdGhlciByZWxldmFudCBpbmZvcm1hdGlvbiBhYm91dCB0aGUgb3BlcmF0aW5nIHN5c3RlbSwgaGFyZHdhcmUsIG5ldHdvcmtpbmcgYW5kIHBhY2thZ2VzJyxcbiAgICAgICAgICB3b2RsZTogW3sgbmFtZTogJ3N5c2NvbGxlY3RvcicgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnU3lzY29sbGVjdG9yIGludGVncmF0aW9uIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgJ3NjYW4tb24tc3RhcnQnOiAnU2NhbiBvbiBzdGFydCcsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnSW50ZXJ2YWwgYmV0d2VlbiBzeXN0ZW0gc2NhbnMnLFxuICAgICAgICAgICAgICBuZXR3b3JrOiAnU2NhbiBuZXR3b3JrIGludGVyZmFjZXMnLFxuICAgICAgICAgICAgICBvczogJ1NjYW4gb3BlcmF0aW5nIHN5c3RlbSBpbmZvJyxcbiAgICAgICAgICAgICAgaGFyZHdhcmU6ICdTY2FuIGhhcmR3YXJlIGluZm8nLFxuICAgICAgICAgICAgICBwYWNrYWdlczogJ1NjYW4gaW5zdGFsbGVkIHBhY2thZ2VzJyxcbiAgICAgICAgICAgICAgcG9ydHM6ICdTY2FuIGxpc3RlbmluZyBuZXR3b3JrIHBvcnRzJyxcbiAgICAgICAgICAgICAgcG9ydHNfYWxsOiAnU2NhbiBhbGwgbmV0d29yayBwb3J0cycsXG4gICAgICAgICAgICAgIHByb2Nlc3NlczogJ1NjYW4gY3VycmVudCBwcm9jZXNzZXMnXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdBY3RpdmUgcmVzcG9uc2UnLFxuICAgICAgICAgIGRvY3VMaW5rOiB3ZWJEb2N1bWVudGF0aW9uTGluaygndXNlci1tYW51YWwvcmVmZXJlbmNlL29zc2VjLWNvbmYvYWN0aXZlLXJlc3BvbnNlLmh0bWwnKSxcbiAgICAgICAgICBkZXNjOiAnQWN0aXZlIHRocmVhdCBhZGRyZXNzaW5nIGJ5IGltbWVkaWF0ZSByZXNwb25zZScsXG4gICAgICAgICAgY29uZmlnOiBbeyBjb21wb25lbnQ6ICdjb20nLCBjb25maWd1cmF0aW9uOiAnYWN0aXZlLXJlc3BvbnNlJyB9XSxcbiAgICAgICAgICBsYWJlbHM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgZGlzYWJsZWQ6ICdBY3RpdmUgcmVzcG9uc2UgZGlzYWJsZWQnLFxuICAgICAgICAgICAgICBjYV9zdG9yZTogJ1VzZSB0aGUgZm9sbG93aW5nIGxpc3Qgb2Ygcm9vdCBDQSBjZXJ0aWZpY2F0ZXMnLFxuICAgICAgICAgICAgICBjYV92ZXJpZmljYXRpb246ICdWYWxpZGF0ZSBXUEtzIHVzaW5nIHJvb3QgQ0EgY2VydGlmaWNhdGUnXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdDb21tYW5kcycsXG4gICAgICAgICAgZG9jdUxpbms6IHdlYkRvY3VtZW50YXRpb25MaW5rKCd1c2VyLW1hbnVhbC9yZWZlcmVuY2Uvb3NzZWMtY29uZi93b2RsZS1jb21tYW5kLmh0bWwnKSxcbiAgICAgICAgICBkZXNjOiAnQ29uZmlndXJhdGlvbiBvcHRpb25zIG9mIHRoZSBDb21tYW5kIHdvZGxlJyxcbiAgICAgICAgICB3b2RsZTogW3sgbmFtZTogJ2NvbW1hbmQnIH1dLFxuICAgICAgICAgIGxhYmVsczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBkaXNhYmxlZDogJ0NvbW1hbmQgZGlzYWJsZWQnLFxuICAgICAgICAgICAgICBydW5fb25fc3RhcnQ6ICdSdW4gb24gc3RhcnQnLFxuICAgICAgICAgICAgICBpZ25vcmVfb3V0cHV0OiAnSWdub3JlIGNvbW1hbmQgb3V0cHV0JyxcbiAgICAgICAgICAgICAgc2tpcF92ZXJpZmljYXRpb246ICdJZ25vcmUgY2hlY2tzdW0gdmVyaWZpY2F0aW9uJyxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdJbnRlcnZhbCBiZXR3ZWVuIGV4ZWN1dGlvbnMnLFxuICAgICAgICAgICAgICB0YWc6ICdDb21tYW5kIG5hbWUnLFxuICAgICAgICAgICAgICBjb21tYW5kOiAnQ29tbWFuZCB0byBleGVjdXRlJyxcbiAgICAgICAgICAgICAgdmVyaWZ5X21kNTogJ1ZlcmlmeSBNRDUgc3VtJyxcbiAgICAgICAgICAgICAgdmVyaWZ5X3NoYTE6ICdWZXJpZnkgU0hBMSBzdW0nLFxuICAgICAgICAgICAgICB2ZXJpZnlfc2hhMjU2OiAnVmVyaWZ5IFNIQTI1NiBzdW0nXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXVxuICAgICAgICB9LFxuICAgICAgICB7XG4gICAgICAgICAgc3VidGl0bGU6ICdEb2NrZXIgbGlzdGVuZXInLFxuICAgICAgICAgIGRvY3VMaW5rOiB3ZWJEb2N1bWVudGF0aW9uTGluaygndXNlci1tYW51YWwvcmVmZXJlbmNlL29zc2VjLWNvbmYvd29kbGUtZG9ja2VyLmh0bWwnKSxcbiAgICAgICAgICBkZXNjOlxuICAgICAgICAgICAgJ01vbml0b3IgYW5kIGNvbGxlY3QgdGhlIGFjdGl2aXR5IGZyb20gRG9ja2VyIGNvbnRhaW5lcnMgc3VjaCBhcyBjcmVhdGlvbiwgcnVubmluZywgc3RhcnRpbmcsIHN0b3BwaW5nIG9yIHBhdXNpbmcgZXZlbnRzJyxcbiAgICAgICAgICB3b2RsZTogW3sgbmFtZTogJ2RvY2tlci1saXN0ZW5lcicgfV0sXG4gICAgICAgICAgbGFiZWxzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRpc2FibGVkOiAnRG9ja2VyIGxpc3RlbmVyIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgcnVuX29uX3N0YXJ0OlxuICAgICAgICAgICAgICAgICdSdW4gdGhlIGxpc3RlbmVyIGltbWVkaWF0ZWx5IHdoZW4gc2VydmljZSBpcyBzdGFydGVkJyxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdXYWl0aW5nIHRpbWUgdG8gcmVydW4gdGhlIGxpc3RlbmVyIGluIGNhc2UgaXQgZmFpbHMnLFxuICAgICAgICAgICAgICBhdHRlbXB0czogJ051bWJlciBvZiBhdHRlbXB0cyB0byBleGVjdXRlIHRoZSBsaXN0ZW5lcidcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdXG4gICAgICAgIH1cbiAgICAgIF1cbiAgICB9LFxuICAgIHtcbiAgICAgIHRpdGxlOiAnTG9nIGRhdGEgYW5hbHlzaXMnLFxuICAgICAgc2VjdGlvbnM6IFtcbiAgICAgICAge1xuICAgICAgICAgIHN1YnRpdGxlOiAnTG9nIGNvbGxlY3Rpb24nLFxuICAgICAgICAgIGRvY3VMaW5rOiB3ZWJEb2N1bWVudGF0aW9uTGluaygndXNlci1tYW51YWwvY2FwYWJpbGl0aWVzL2xvZy1kYXRhLWNvbGxlY3Rpb24vaW5kZXguaHRtbCcpLFxuICAgICAgICAgIGRlc2M6XG4gICAgICAgICAgICAnTG9nIGFuYWx5c2lzIGZyb20gdGV4dCBmaWxlcywgV2luZG93cyBldmVudHMgb3Igc3lzbG9nIG91dHB1dHMnLFxuICAgICAgICAgIGNvbmZpZzogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBjb21wb25lbnQ6ICdsb2djb2xsZWN0b3InLFxuICAgICAgICAgICAgICBjb25maWd1cmF0aW9uOiAnbG9jYWxmaWxlJyxcbiAgICAgICAgICAgICAgZmlsdGVyQnk6ICdsb2dmb3JtYXQnXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgeyBjb21wb25lbnQ6ICdsb2djb2xsZWN0b3InLCBjb25maWd1cmF0aW9uOiAnc29ja2V0JyB9XG4gICAgICAgICAgXSxcbiAgICAgICAgICBsYWJlbHM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbG9nZm9ybWF0OiAnTG9nIGZvcm1hdCcsXG4gICAgICAgICAgICAgIGxvZ19mb3JtYXQ6ICdMb2cgZm9ybWF0JyxcbiAgICAgICAgICAgICAgYWxpYXM6ICdDb21tYW5kIGFsaWFzJyxcbiAgICAgICAgICAgICAgaWdub3JlX2JpbmFyaWVzOiAnSWdub3JlIGJpbmFyaWVzJyxcbiAgICAgICAgICAgICAgdGFyZ2V0OiAnUmVkaXJlY3Qgb3V0cHV0IHRvIHRoaXMgc29ja2V0JyxcbiAgICAgICAgICAgICAgZnJlcXVlbmN5OiAnSW50ZXJ2YWwgYmV0d2VlbiBjb21tYW5kIGV4ZWN1dGlvbnMnLFxuICAgICAgICAgICAgICBmaWxlOiAnTG9nIGxvY2F0aW9uJyxcbiAgICAgICAgICAgICAgbG9jYXRpb246ICdMb2cgbG9jYXRpb24nLFxuICAgICAgICAgICAgICBzb2NrZXQ6ICdPdXRwdXQgc29ja2V0cycsXG4gICAgICAgICAgICAgIHN5c2xvZzogJ1N5c2xvZycsXG4gICAgICAgICAgICAgIGNvbW1hbmQ6ICdDb21tYW5kJyxcbiAgICAgICAgICAgICAgZnVsbF9jb21tYW5kOiAnRnVsbCBjb21tYW5kJyxcbiAgICAgICAgICAgICAgYXVkaXQ6ICdBdWRpdCdcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdLFxuICAgICAgICAgIG9wdGlvbnM6IHsgaGlkZUhlYWRlcjogdHJ1ZSB9XG4gICAgICAgIH0sXG4gICAgICAgIHtcbiAgICAgICAgICBzdWJ0aXRsZTogJ0ludGVncml0eSBtb25pdG9yaW5nJyxcbiAgICAgICAgICBkb2N1TGluazogd2ViRG9jdW1lbnRhdGlvbkxpbmsoJ3VzZXItbWFudWFsL3JlZmVyZW5jZS9vc3NlYy1jb25mL3N5c2NoZWNrLmh0bWwnKSxcbiAgICAgICAgICBkZXNjOlxuICAgICAgICAgICAgJ0lkZW50aWZ5IGNoYW5nZXMgaW4gY29udGVudCwgcGVybWlzc2lvbnMsIG93bmVyc2hpcCwgYW5kIGF0dHJpYnV0ZXMgb2YgZmlsZXMnLFxuICAgICAgICAgIGNvbmZpZzogW1xuICAgICAgICAgICAgeyBjb21wb25lbnQ6ICdzeXNjaGVjaycsIGNvbmZpZ3VyYXRpb246ICdzeXNjaGVjaycsIG1hdHJpeDogdHJ1ZSB9XG4gICAgICAgICAgXSxcbiAgICAgICAgICB0YWJzOiBbJ0dlbmVyYWwnLCdXaG8gZGF0YSddLFxuICAgICAgICAgIGxhYmVsczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBkaXNhYmxlZDogJ0ludGVncml0eSBtb25pdG9yaW5nIGRpc2FibGVkJyxcbiAgICAgICAgICAgICAgZnJlcXVlbmN5OiAnSW50ZXJ2YWwgKGluIHNlY29uZHMpIHRvIHJ1biB0aGUgaW50ZWdyaXR5IHNjYW4nLFxuICAgICAgICAgICAgICBza2lwX25mczogJ1NraXAgc2NhbiBvbiBDSUZTL05GUyBtb3VudHMnLFxuICAgICAgICAgICAgICBzY2FuX29uX3N0YXJ0OiAnU2NhbiBvbiBzdGFydCcsXG4gICAgICAgICAgICAgIGRpcmVjdG9yaWVzOiAnTW9uaXRvcmVkIGRpcmVjdG9yaWVzJyxcbiAgICAgICAgICAgICAgbm9kaWZmOiAnTm8gZGlmZiBkaXJlY3RvcmllcycsXG4gICAgICAgICAgICAgIGlnbm9yZTogJ0lnbm9yZWQgZmlsZXMgYW5kIGRpcmVjdG9yaWVzJyxcbiAgICAgICAgICAgICAgcmVzdGFydF9hdWRpdDogJ1Jlc3RhcnQgYXVkaXQnLFxuICAgICAgICAgICAgICBzdGFydHVwX2hlYWx0aGNoZWNrOiAnU3RhcnR1cCBoZWFsdGhjaGVjaydcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdLFxuICAgICAgICAgIG9wdHM6IHtcbiAgICAgICAgICAgIHJlYWx0aW1lOiAnUlQnLFxuICAgICAgICAgICAgY2hlY2tfd2hvZGF0YTogJ1dEJyxcbiAgICAgICAgICAgIHJlcG9ydF9jaGFuZ2VzOiAnQ2hhbmdlcycsXG4gICAgICAgICAgICBjaGVja19tZDVzdW06ICdNRDUnLFxuICAgICAgICAgICAgY2hlY2tfc2hhMXN1bTogJ1NIQTEnLFxuICAgICAgICAgICAgY2hlY2tfcGVybTogJ1Blci4nLFxuICAgICAgICAgICAgY2hlY2tfc2l6ZTogJ1NpemUnLFxuICAgICAgICAgICAgY2hlY2tfb3duZXI6ICdPd25lcicsXG4gICAgICAgICAgICBjaGVja19ncm91cDogJ0dyb3VwJyxcbiAgICAgICAgICAgIGNoZWNrX210aW1lOiAnTVQnLFxuICAgICAgICAgICAgY2hlY2tfaW5vZGU6ICdJbm9kZScsXG4gICAgICAgICAgICBjaGVja19zaGEyNTZzdW06ICdTSEEyNTYnLFxuICAgICAgICAgICAgZm9sbG93X3N5bWJvbGljX2xpbms6ICdTTCdcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIF1cbiAgICB9XG4gIF1cbn07XG4iXX0=