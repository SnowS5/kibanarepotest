"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.reverseLoockupError = exports.possibleBreakinAttempt = exports.possibleAttackServer = exports.insecureConnectionAttempt = exports.data = void 0;

/*
 * Wazuh app - SSH sample data
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const reverseLoockupError = {
  location: "/var/log/secure",
  rule: {
    "mail": false,
    "level": 5,
    "pci_dss": ["11.4"],
    "description": "sshd: Reverse lookup error (bad ISP or attack).",
    "groups": ["syslog", "sshd"],
    "mitre": {
      "tactic": ["Lateral Movement"],
      "id": ["T1021"]
    },
    "id": "5702",
    "nist_800_53": ["SI.4"],
    "gpg13": ["4.12"],
    "gdpr": ["IV_35.7.d"]
  },
  full_log: "{predecoder.timestamp} {predecoder.hostname} sshd[15409]: reverse mapping checking getaddrinfo for {data.srcip}.static.impsat.com.co [{data.srcip}] failed - POSSIBLE BREAK-IN ATTEMPT!"
};
exports.reverseLoockupError = reverseLoockupError;
const insecureConnectionAttempt = {
  rule: {
    mail: false,
    level: 6,
    pci_dss: ["11.4"],
    description: "sshd: insecure connection attempt (scan).",
    groups: ["syslog", "sshd", "recon"],
    id: "5706",
    nist_800_53: ["SI.4"],
    gpg13: ["4.12"],
    gdpr: ["IV_35.7.d"]
  },
  full_log: "{predecoder.timestamp} {predecoder.hostname} sshd[15225]: Did not receive identification string from {data.srcip} port {data.srcport}",
  location: "/var/log/secure"
};
exports.insecureConnectionAttempt = insecureConnectionAttempt;
const possibleAttackServer = {
  rule: {
    mail: false,
    level: 8,
    pci_dss: ["11.4"],
    description: "sshd: Possible attack on the ssh server (or version gathering).",
    groups: ["syslog", "sshd", "recon"],
    mitre: {
      tactic: ["Lateral Movement"],
      technique: ["Brute Force", "Remove Services"],
      id: ["T1021"]
    },
    id: "5701",
    nist_800_53: ["SI.4"],
    gpg13: ["4.12"],
    gdpr: ["IV_35.7.d"]
  },
  location: "/var/log/secure",
  full_log: "{predecoder.timestamp} {predecoder.hostname} sshd[15122]: Bad protocol version identification '\\003' from {data.srcip} port {data.srcport}"
};
exports.possibleAttackServer = possibleAttackServer;
const possibleBreakinAttempt = {
  rule: {
    mail: false,
    level: 10,
    pci_dss: ["11.4"],
    description: "sshd: Possible breakin attempt (high number of reverse lookup errors).",
    groups: ["syslog", "sshd"],
    mitre: {
      tactic: ["Lateral Movement"],
      technique: ["Brute Force", "Remove Services"],
      id: ["T1021"]
    },
    id: "5703",
    nist_800_53: ["SI.4"],
    frequency: 6,
    gpg13: ["4.12"],
    gdpr: ["IV_35.7.d"]
  },
  location: "/var/log/secure",
  full_log: "{predecoder.timestamp} {predecoder.hostname} sshd[10385]: reverse mapping checking getaddrinfo for . [{data.srcip}] failed - POSSIBLE BREAK-IN ATTEMPT!"
};
exports.possibleBreakinAttempt = possibleBreakinAttempt;
const data = [reverseLoockupError, insecureConnectionAttempt, possibleAttackServer, possibleBreakinAttempt];
exports.data = data;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNzaC5qcyJdLCJuYW1lcyI6WyJyZXZlcnNlTG9vY2t1cEVycm9yIiwibG9jYXRpb24iLCJydWxlIiwiZnVsbF9sb2ciLCJpbnNlY3VyZUNvbm5lY3Rpb25BdHRlbXB0IiwibWFpbCIsImxldmVsIiwicGNpX2RzcyIsImRlc2NyaXB0aW9uIiwiZ3JvdXBzIiwiaWQiLCJuaXN0XzgwMF81MyIsImdwZzEzIiwiZ2RwciIsInBvc3NpYmxlQXR0YWNrU2VydmVyIiwibWl0cmUiLCJ0YWN0aWMiLCJ0ZWNobmlxdWUiLCJwb3NzaWJsZUJyZWFraW5BdHRlbXB0IiwiZnJlcXVlbmN5IiwiZGF0YSJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFFTyxNQUFNQSxtQkFBbUIsR0FBRztBQUNqQ0MsRUFBQUEsUUFBUSxFQUFFLGlCQUR1QjtBQUVqQ0MsRUFBQUEsSUFBSSxFQUFFO0FBQ0osWUFBUSxLQURKO0FBRUosYUFBUyxDQUZMO0FBR0osZUFBVyxDQUFDLE1BQUQsQ0FIUDtBQUlKLG1CQUFlLGlEQUpYO0FBS0osY0FBVSxDQUFDLFFBQUQsRUFBVSxNQUFWLENBTE47QUFNSixhQUFTO0FBQ1AsZ0JBQVUsQ0FBQyxrQkFBRCxDQURIO0FBRVAsWUFBTSxDQUFDLE9BQUQ7QUFGQyxLQU5MO0FBVUosVUFBTSxNQVZGO0FBV0osbUJBQWUsQ0FBQyxNQUFELENBWFg7QUFZSixhQUFTLENBQUMsTUFBRCxDQVpMO0FBYUosWUFBUSxDQUFDLFdBQUQ7QUFiSixHQUYyQjtBQWlCakNDLEVBQUFBLFFBQVEsRUFBRTtBQWpCdUIsQ0FBNUI7O0FBb0JBLE1BQU1DLHlCQUF5QixHQUFHO0FBQ3ZDRixFQUFBQSxJQUFJLEVBQUU7QUFDSkcsSUFBQUEsSUFBSSxFQUFFLEtBREY7QUFFSkMsSUFBQUEsS0FBSyxFQUFFLENBRkg7QUFHSkMsSUFBQUEsT0FBTyxFQUFFLENBQUMsTUFBRCxDQUhMO0FBSUpDLElBQUFBLFdBQVcsRUFBRSwyQ0FKVDtBQUtKQyxJQUFBQSxNQUFNLEVBQUUsQ0FBQyxRQUFELEVBQVUsTUFBVixFQUFpQixPQUFqQixDQUxKO0FBTUpDLElBQUFBLEVBQUUsRUFBRSxNQU5BO0FBT0pDLElBQUFBLFdBQVcsRUFBRSxDQUFDLE1BQUQsQ0FQVDtBQVFKQyxJQUFBQSxLQUFLLEVBQUUsQ0FBQyxNQUFELENBUkg7QUFTSkMsSUFBQUEsSUFBSSxFQUFFLENBQUMsV0FBRDtBQVRGLEdBRGlDO0FBWXZDVixFQUFBQSxRQUFRLEVBQUUsdUlBWjZCO0FBYXZDRixFQUFBQSxRQUFRLEVBQUU7QUFiNkIsQ0FBbEM7O0FBZ0JBLE1BQU1hLG9CQUFvQixHQUFHO0FBQ2xDWixFQUFBQSxJQUFJLEVBQUU7QUFDSkcsSUFBQUEsSUFBSSxFQUFFLEtBREY7QUFFSkMsSUFBQUEsS0FBSyxFQUFFLENBRkg7QUFHSkMsSUFBQUEsT0FBTyxFQUFFLENBQUMsTUFBRCxDQUhMO0FBSUpDLElBQUFBLFdBQVcsRUFBRSxpRUFKVDtBQUtKQyxJQUFBQSxNQUFNLEVBQUUsQ0FBQyxRQUFELEVBQVUsTUFBVixFQUFpQixPQUFqQixDQUxKO0FBTUpNLElBQUFBLEtBQUssRUFBRTtBQUNMQyxNQUFBQSxNQUFNLEVBQUUsQ0FBQyxrQkFBRCxDQURIO0FBRUxDLE1BQUFBLFNBQVMsRUFBRSxDQUFDLGFBQUQsRUFBZSxpQkFBZixDQUZOO0FBR0xQLE1BQUFBLEVBQUUsRUFBRSxDQUFDLE9BQUQ7QUFIQyxLQU5IO0FBV0pBLElBQUFBLEVBQUUsRUFBRSxNQVhBO0FBWUpDLElBQUFBLFdBQVcsRUFBRSxDQUFDLE1BQUQsQ0FaVDtBQWFKQyxJQUFBQSxLQUFLLEVBQUUsQ0FBQyxNQUFELENBYkg7QUFjSkMsSUFBQUEsSUFBSSxFQUFFLENBQUMsV0FBRDtBQWRGLEdBRDRCO0FBaUJsQ1osRUFBQUEsUUFBUSxFQUFFLGlCQWpCd0I7QUFrQmxDRSxFQUFBQSxRQUFRLEVBQUU7QUFsQndCLENBQTdCOztBQXFCQSxNQUFNZSxzQkFBc0IsR0FBRztBQUNwQ2hCLEVBQUFBLElBQUksRUFBRTtBQUNKRyxJQUFBQSxJQUFJLEVBQUUsS0FERjtBQUVKQyxJQUFBQSxLQUFLLEVBQUUsRUFGSDtBQUdKQyxJQUFBQSxPQUFPLEVBQUUsQ0FBQyxNQUFELENBSEw7QUFJSkMsSUFBQUEsV0FBVyxFQUFFLHdFQUpUO0FBS0pDLElBQUFBLE1BQU0sRUFBRSxDQUFDLFFBQUQsRUFBVSxNQUFWLENBTEo7QUFNSk0sSUFBQUEsS0FBSyxFQUFFO0FBQ0xDLE1BQUFBLE1BQU0sRUFBRSxDQUFDLGtCQUFELENBREg7QUFFTEMsTUFBQUEsU0FBUyxFQUFFLENBQUMsYUFBRCxFQUFlLGlCQUFmLENBRk47QUFHTFAsTUFBQUEsRUFBRSxFQUFFLENBQUMsT0FBRDtBQUhDLEtBTkg7QUFXSkEsSUFBQUEsRUFBRSxFQUFFLE1BWEE7QUFZSkMsSUFBQUEsV0FBVyxFQUFFLENBQUMsTUFBRCxDQVpUO0FBYUpRLElBQUFBLFNBQVMsRUFBRSxDQWJQO0FBY0pQLElBQUFBLEtBQUssRUFBRSxDQUFDLE1BQUQsQ0FkSDtBQWVKQyxJQUFBQSxJQUFJLEVBQUUsQ0FBQyxXQUFEO0FBZkYsR0FEOEI7QUFrQnBDWixFQUFBQSxRQUFRLEVBQUUsaUJBbEIwQjtBQW1CcENFLEVBQUFBLFFBQVEsRUFBRTtBQW5CMEIsQ0FBL0I7O0FBc0JBLE1BQU1pQixJQUFJLEdBQUcsQ0FBQ3BCLG1CQUFELEVBQXNCSSx5QkFBdEIsRUFBaURVLG9CQUFqRCxFQUF1RUksc0JBQXZFLENBQWIiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gU1NIIHNhbXBsZSBkYXRhXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG5leHBvcnQgY29uc3QgcmV2ZXJzZUxvb2NrdXBFcnJvciA9IHtcbiAgbG9jYXRpb246IFwiL3Zhci9sb2cvc2VjdXJlXCIsXG4gIHJ1bGU6IHtcbiAgICBcIm1haWxcIjogZmFsc2UsXG4gICAgXCJsZXZlbFwiOiA1LFxuICAgIFwicGNpX2Rzc1wiOiBbXCIxMS40XCJdLFxuICAgIFwiZGVzY3JpcHRpb25cIjogXCJzc2hkOiBSZXZlcnNlIGxvb2t1cCBlcnJvciAoYmFkIElTUCBvciBhdHRhY2spLlwiLFxuICAgIFwiZ3JvdXBzXCI6IFtcInN5c2xvZ1wiLFwic3NoZFwiXSxcbiAgICBcIm1pdHJlXCI6IHtcbiAgICAgIFwidGFjdGljXCI6IFtcIkxhdGVyYWwgTW92ZW1lbnRcIl0sXG4gICAgICBcImlkXCI6IFtcIlQxMDIxXCJdXG4gICAgfSxcbiAgICBcImlkXCI6IFwiNTcwMlwiLFxuICAgIFwibmlzdF84MDBfNTNcIjogW1wiU0kuNFwiXSxcbiAgICBcImdwZzEzXCI6IFtcIjQuMTJcIl0sXG4gICAgXCJnZHByXCI6IFtcIklWXzM1LjcuZFwiXVxuICB9LFxuICBmdWxsX2xvZzogXCJ7cHJlZGVjb2Rlci50aW1lc3RhbXB9IHtwcmVkZWNvZGVyLmhvc3RuYW1lfSBzc2hkWzE1NDA5XTogcmV2ZXJzZSBtYXBwaW5nIGNoZWNraW5nIGdldGFkZHJpbmZvIGZvciB7ZGF0YS5zcmNpcH0uc3RhdGljLmltcHNhdC5jb20uY28gW3tkYXRhLnNyY2lwfV0gZmFpbGVkIC0gUE9TU0lCTEUgQlJFQUstSU4gQVRURU1QVCFcIlxufTtcblxuZXhwb3J0IGNvbnN0IGluc2VjdXJlQ29ubmVjdGlvbkF0dGVtcHQgPSB7XG4gIHJ1bGU6IHtcbiAgICBtYWlsOiBmYWxzZSxcbiAgICBsZXZlbDogNixcbiAgICBwY2lfZHNzOiBbXCIxMS40XCJdLFxuICAgIGRlc2NyaXB0aW9uOiBcInNzaGQ6IGluc2VjdXJlIGNvbm5lY3Rpb24gYXR0ZW1wdCAoc2NhbikuXCIsXG4gICAgZ3JvdXBzOiBbXCJzeXNsb2dcIixcInNzaGRcIixcInJlY29uXCJdLFxuICAgIGlkOiBcIjU3MDZcIixcbiAgICBuaXN0XzgwMF81MzogW1wiU0kuNFwiXSxcbiAgICBncGcxMzogW1wiNC4xMlwiXSxcbiAgICBnZHByOiBbXCJJVl8zNS43LmRcIl1cbiAgfSxcbiAgZnVsbF9sb2c6IFwie3ByZWRlY29kZXIudGltZXN0YW1wfSB7cHJlZGVjb2Rlci5ob3N0bmFtZX0gc3NoZFsxNTIyNV06IERpZCBub3QgcmVjZWl2ZSBpZGVudGlmaWNhdGlvbiBzdHJpbmcgZnJvbSB7ZGF0YS5zcmNpcH0gcG9ydCB7ZGF0YS5zcmNwb3J0fVwiLFxuICBsb2NhdGlvbjogXCIvdmFyL2xvZy9zZWN1cmVcIlxufTtcblxuZXhwb3J0IGNvbnN0IHBvc3NpYmxlQXR0YWNrU2VydmVyID0ge1xuICBydWxlOiB7XG4gICAgbWFpbDogZmFsc2UsXG4gICAgbGV2ZWw6IDgsXG4gICAgcGNpX2RzczogW1wiMTEuNFwiXSxcbiAgICBkZXNjcmlwdGlvbjogXCJzc2hkOiBQb3NzaWJsZSBhdHRhY2sgb24gdGhlIHNzaCBzZXJ2ZXIgKG9yIHZlcnNpb24gZ2F0aGVyaW5nKS5cIixcbiAgICBncm91cHM6IFtcInN5c2xvZ1wiLFwic3NoZFwiLFwicmVjb25cIl0sXG4gICAgbWl0cmU6IHtcbiAgICAgIHRhY3RpYzogW1wiTGF0ZXJhbCBNb3ZlbWVudFwiXSxcbiAgICAgIHRlY2huaXF1ZTogW1wiQnJ1dGUgRm9yY2VcIixcIlJlbW92ZSBTZXJ2aWNlc1wiXSxcbiAgICAgIGlkOiBbXCJUMTAyMVwiXVxuICAgIH0sXG4gICAgaWQ6IFwiNTcwMVwiLFxuICAgIG5pc3RfODAwXzUzOiBbXCJTSS40XCJdLFxuICAgIGdwZzEzOiBbXCI0LjEyXCJdLFxuICAgIGdkcHI6IFtcIklWXzM1LjcuZFwiXVxuICB9LFxuICBsb2NhdGlvbjogXCIvdmFyL2xvZy9zZWN1cmVcIixcbiAgZnVsbF9sb2c6IFwie3ByZWRlY29kZXIudGltZXN0YW1wfSB7cHJlZGVjb2Rlci5ob3N0bmFtZX0gc3NoZFsxNTEyMl06IEJhZCBwcm90b2NvbCB2ZXJzaW9uIGlkZW50aWZpY2F0aW9uICdcXFxcMDAzJyBmcm9tIHtkYXRhLnNyY2lwfSBwb3J0IHtkYXRhLnNyY3BvcnR9XCIsXG59XG5cbmV4cG9ydCBjb25zdCBwb3NzaWJsZUJyZWFraW5BdHRlbXB0ID0ge1xuICBydWxlOiB7XG4gICAgbWFpbDogZmFsc2UsXG4gICAgbGV2ZWw6IDEwLFxuICAgIHBjaV9kc3M6IFtcIjExLjRcIl0sXG4gICAgZGVzY3JpcHRpb246IFwic3NoZDogUG9zc2libGUgYnJlYWtpbiBhdHRlbXB0IChoaWdoIG51bWJlciBvZiByZXZlcnNlIGxvb2t1cCBlcnJvcnMpLlwiLFxuICAgIGdyb3VwczogW1wic3lzbG9nXCIsXCJzc2hkXCJdLFxuICAgIG1pdHJlOiB7XG4gICAgICB0YWN0aWM6IFtcIkxhdGVyYWwgTW92ZW1lbnRcIl0sXG4gICAgICB0ZWNobmlxdWU6IFtcIkJydXRlIEZvcmNlXCIsXCJSZW1vdmUgU2VydmljZXNcIl0sXG4gICAgICBpZDogW1wiVDEwMjFcIl1cbiAgICB9LFxuICAgIGlkOiBcIjU3MDNcIixcbiAgICBuaXN0XzgwMF81MzogW1wiU0kuNFwiXSxcbiAgICBmcmVxdWVuY3k6IDYsXG4gICAgZ3BnMTM6IFtcIjQuMTJcIl0sXG4gICAgZ2RwcjogW1wiSVZfMzUuNy5kXCJdXG4gIH0sXG4gIGxvY2F0aW9uOiBcIi92YXIvbG9nL3NlY3VyZVwiLFxuICBmdWxsX2xvZzogXCJ7cHJlZGVjb2Rlci50aW1lc3RhbXB9IHtwcmVkZWNvZGVyLmhvc3RuYW1lfSBzc2hkWzEwMzg1XTogcmV2ZXJzZSBtYXBwaW5nIGNoZWNraW5nIGdldGFkZHJpbmZvIGZvciAuIFt7ZGF0YS5zcmNpcH1dIGZhaWxlZCAtIFBPU1NJQkxFIEJSRUFLLUlOIEFUVEVNUFQhXCIsXG59O1xuXG5leHBvcnQgY29uc3QgZGF0YSA9IFtyZXZlcnNlTG9vY2t1cEVycm9yLCBpbnNlY3VyZUNvbm5lY3Rpb25BdHRlbXB0LCBwb3NzaWJsZUF0dGFja1NlcnZlciwgcG9zc2libGVCcmVha2luQXR0ZW1wdF07Il19