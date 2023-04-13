"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.tsc = exports.PCI_DSS = exports.NIST_800_53 = exports.HIPAA = exports.GPG13 = exports.GDPR = void 0;

/*
 * Wazuh app - Regulatory compliance
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// Regulatory compliance
const PCI_DSS = ["1.1.1", "1.3.4", "1.4", "10.1", "10.2.1", "10.2.2", "10.2.4", "10.2.5", "10.2.6", "10.2.7", "10.4", "10.5.2", "10.5.5", "10.6", "10.6.1", "11.2.1", "11.2.3", "11.4", "11.5", "2.2", "2.2.3", "4.1", "5.1", "5.2", "6.2", "6.5", "6.5.1", "6.5.10", "6.5.2", "6.5.5", "6.5.7", "6.5.8", "6.6", "8.1.2", "8.1.4", "8.1.5", "8.1.6", "8.1.8", "8.2.4", "8.7"];
exports.PCI_DSS = PCI_DSS;
const GDPR = ["IV_35.7.d", "II_5.1.f", "IV_32.2", "IV_30.1.g"];
exports.GDPR = GDPR;
const HIPAA = ["164.312.a.1", "164.312.a.2.I", "164.312.a.2.II", "164.312.a.2.III", "164.312.a.2.IV", "164.312.b", "164.312.c.1", "164.312.c.2", "164.312.d", "164.312.e.1", "164.312.e.2.I", "164.312.e.2.II"];
exports.HIPAA = HIPAA;
const NIST_800_53 = ["AC.12", "AC.2", "AC.6", "AC.7", "AU.12", "AU.14", "AU.5", "AU.6", "AU.8", "AU.9", "CA.3", "CM.1", "CM.3", "CM.5", "IA.4", "IA.5", "SA.11", "SC.2", "SC.5", "SC.7", "SC.8", "SI.2", "SI.3", "SI.4", "SI.7"];
exports.NIST_800_53 = NIST_800_53;
const GPG13 = ["7.8", "7.9"];
exports.GPG13 = GPG13;
const tsc = ["CC1.1", "CC1.2", "CC1.3", "CC1.4", "CC1.5", "CC2.1", "CC2.2", "CC2.3", "CC3.1", "CC3.2", "CC3.3", "CC3.4", "CC4.1", "CC4.2", "CC5.1", "CC5.2", "CC5.3", "CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "CC6.7", "CC6.8", "CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5", "CC8.1", "CC9.1", "CC9.2", "A1.1", "A1.2", "A1.3", "C1.1", "C1.2", "PI1.1", "PI1.2", "PI1.3", "PI1.4", "PI1.5", "P1.0", "P1.1", "P2.0", "P2.1", "P3.0", "P3.1", "P3.2", "P4.0", "P4.1", "P4.2", "P4.3", "P5.0", "P5.1", "P5.2", "P6.0", "P6.1", "P6.2", "P6.3", "P6.4", "P6.5", "P6.6", "P6.7", "P7.0", "P7.1", "P8.0", "P8.1"];
exports.tsc = tsc;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInJlZ3VsYXRvcnktY29tcGxpYW5jZS5qcyJdLCJuYW1lcyI6WyJQQ0lfRFNTIiwiR0RQUiIsIkhJUEFBIiwiTklTVF84MDBfNTMiLCJHUEcxMyIsInRzYyJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFFQTtBQUNPLE1BQU1BLE9BQU8sR0FBRyxDQUFDLE9BQUQsRUFBUyxPQUFULEVBQWlCLEtBQWpCLEVBQXVCLE1BQXZCLEVBQThCLFFBQTlCLEVBQXVDLFFBQXZDLEVBQWdELFFBQWhELEVBQXlELFFBQXpELEVBQWtFLFFBQWxFLEVBQTJFLFFBQTNFLEVBQW9GLE1BQXBGLEVBQTJGLFFBQTNGLEVBQW9HLFFBQXBHLEVBQTZHLE1BQTdHLEVBQW9ILFFBQXBILEVBQTZILFFBQTdILEVBQXNJLFFBQXRJLEVBQStJLE1BQS9JLEVBQXNKLE1BQXRKLEVBQTZKLEtBQTdKLEVBQW1LLE9BQW5LLEVBQTJLLEtBQTNLLEVBQWlMLEtBQWpMLEVBQXVMLEtBQXZMLEVBQTZMLEtBQTdMLEVBQW1NLEtBQW5NLEVBQXlNLE9BQXpNLEVBQWlOLFFBQWpOLEVBQTBOLE9BQTFOLEVBQWtPLE9BQWxPLEVBQTBPLE9BQTFPLEVBQWtQLE9BQWxQLEVBQTBQLEtBQTFQLEVBQWdRLE9BQWhRLEVBQXdRLE9BQXhRLEVBQWdSLE9BQWhSLEVBQXdSLE9BQXhSLEVBQWdTLE9BQWhTLEVBQXdTLE9BQXhTLEVBQWdULEtBQWhULENBQWhCOztBQUNBLE1BQU1DLElBQUksR0FBRyxDQUFDLFdBQUQsRUFBYyxVQUFkLEVBQTBCLFNBQTFCLEVBQXFDLFdBQXJDLENBQWI7O0FBQ0EsTUFBTUMsS0FBSyxHQUFHLENBQUMsYUFBRCxFQUFlLGVBQWYsRUFBK0IsZ0JBQS9CLEVBQWdELGlCQUFoRCxFQUFrRSxnQkFBbEUsRUFBbUYsV0FBbkYsRUFBK0YsYUFBL0YsRUFBNkcsYUFBN0csRUFBMkgsV0FBM0gsRUFBdUksYUFBdkksRUFBcUosZUFBckosRUFBcUssZ0JBQXJLLENBQWQ7O0FBQ0EsTUFBTUMsV0FBVyxHQUFHLENBQUMsT0FBRCxFQUFTLE1BQVQsRUFBZ0IsTUFBaEIsRUFBdUIsTUFBdkIsRUFBOEIsT0FBOUIsRUFBc0MsT0FBdEMsRUFBOEMsTUFBOUMsRUFBcUQsTUFBckQsRUFBNEQsTUFBNUQsRUFBbUUsTUFBbkUsRUFBMEUsTUFBMUUsRUFBaUYsTUFBakYsRUFBd0YsTUFBeEYsRUFBK0YsTUFBL0YsRUFBc0csTUFBdEcsRUFBNkcsTUFBN0csRUFBb0gsT0FBcEgsRUFBNEgsTUFBNUgsRUFBbUksTUFBbkksRUFBMEksTUFBMUksRUFBaUosTUFBakosRUFBd0osTUFBeEosRUFBK0osTUFBL0osRUFBc0ssTUFBdEssRUFBNkssTUFBN0ssQ0FBcEI7O0FBQ0EsTUFBTUMsS0FBSyxHQUFHLENBQUMsS0FBRCxFQUFRLEtBQVIsQ0FBZDs7QUFDQSxNQUFNQyxHQUFHLEdBQUcsQ0FBQyxPQUFELEVBQVMsT0FBVCxFQUFpQixPQUFqQixFQUF5QixPQUF6QixFQUFpQyxPQUFqQyxFQUF5QyxPQUF6QyxFQUFpRCxPQUFqRCxFQUF5RCxPQUF6RCxFQUFpRSxPQUFqRSxFQUF5RSxPQUF6RSxFQUFpRixPQUFqRixFQUF5RixPQUF6RixFQUFpRyxPQUFqRyxFQUF5RyxPQUF6RyxFQUFpSCxPQUFqSCxFQUF5SCxPQUF6SCxFQUFpSSxPQUFqSSxFQUF5SSxPQUF6SSxFQUFpSixPQUFqSixFQUF5SixPQUF6SixFQUFpSyxPQUFqSyxFQUF5SyxPQUF6SyxFQUFpTCxPQUFqTCxFQUF5TCxPQUF6TCxFQUFpTSxPQUFqTSxFQUF5TSxPQUF6TSxFQUFpTixPQUFqTixFQUF5TixPQUF6TixFQUFpTyxPQUFqTyxFQUF5TyxPQUF6TyxFQUFpUCxPQUFqUCxFQUF5UCxPQUF6UCxFQUFpUSxPQUFqUSxFQUF5USxNQUF6USxFQUFnUixNQUFoUixFQUF1UixNQUF2UixFQUE4UixNQUE5UixFQUFxUyxNQUFyUyxFQUE0UyxPQUE1UyxFQUFvVCxPQUFwVCxFQUE0VCxPQUE1VCxFQUFvVSxPQUFwVSxFQUE0VSxPQUE1VSxFQUFvVixNQUFwVixFQUEyVixNQUEzVixFQUFrVyxNQUFsVyxFQUF5VyxNQUF6VyxFQUFnWCxNQUFoWCxFQUF1WCxNQUF2WCxFQUE4WCxNQUE5WCxFQUFxWSxNQUFyWSxFQUE0WSxNQUE1WSxFQUFtWixNQUFuWixFQUEwWixNQUExWixFQUFpYSxNQUFqYSxFQUF3YSxNQUF4YSxFQUErYSxNQUEvYSxFQUFzYixNQUF0YixFQUE2YixNQUE3YixFQUFvYyxNQUFwYyxFQUEyYyxNQUEzYyxFQUFrZCxNQUFsZCxFQUF5ZCxNQUF6ZCxFQUFnZSxNQUFoZSxFQUF1ZSxNQUF2ZSxFQUE4ZSxNQUE5ZSxFQUFxZixNQUFyZixFQUE0ZixNQUE1ZixFQUFtZ0IsTUFBbmdCLENBQVoiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gUmVndWxhdG9yeSBjb21wbGlhbmNlXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG4vLyBSZWd1bGF0b3J5IGNvbXBsaWFuY2VcbmV4cG9ydCBjb25zdCBQQ0lfRFNTID0gW1wiMS4xLjFcIixcIjEuMy40XCIsXCIxLjRcIixcIjEwLjFcIixcIjEwLjIuMVwiLFwiMTAuMi4yXCIsXCIxMC4yLjRcIixcIjEwLjIuNVwiLFwiMTAuMi42XCIsXCIxMC4yLjdcIixcIjEwLjRcIixcIjEwLjUuMlwiLFwiMTAuNS41XCIsXCIxMC42XCIsXCIxMC42LjFcIixcIjExLjIuMVwiLFwiMTEuMi4zXCIsXCIxMS40XCIsXCIxMS41XCIsXCIyLjJcIixcIjIuMi4zXCIsXCI0LjFcIixcIjUuMVwiLFwiNS4yXCIsXCI2LjJcIixcIjYuNVwiLFwiNi41LjFcIixcIjYuNS4xMFwiLFwiNi41LjJcIixcIjYuNS41XCIsXCI2LjUuN1wiLFwiNi41LjhcIixcIjYuNlwiLFwiOC4xLjJcIixcIjguMS40XCIsXCI4LjEuNVwiLFwiOC4xLjZcIixcIjguMS44XCIsXCI4LjIuNFwiLFwiOC43XCJdO1xuZXhwb3J0IGNvbnN0IEdEUFIgPSBbXCJJVl8zNS43LmRcIiwgXCJJSV81LjEuZlwiLCBcIklWXzMyLjJcIiwgXCJJVl8zMC4xLmdcIl07XG5leHBvcnQgY29uc3QgSElQQUEgPSBbXCIxNjQuMzEyLmEuMVwiLFwiMTY0LjMxMi5hLjIuSVwiLFwiMTY0LjMxMi5hLjIuSUlcIixcIjE2NC4zMTIuYS4yLklJSVwiLFwiMTY0LjMxMi5hLjIuSVZcIixcIjE2NC4zMTIuYlwiLFwiMTY0LjMxMi5jLjFcIixcIjE2NC4zMTIuYy4yXCIsXCIxNjQuMzEyLmRcIixcIjE2NC4zMTIuZS4xXCIsXCIxNjQuMzEyLmUuMi5JXCIsXCIxNjQuMzEyLmUuMi5JSVwiXTtcbmV4cG9ydCBjb25zdCBOSVNUXzgwMF81MyA9IFtcIkFDLjEyXCIsXCJBQy4yXCIsXCJBQy42XCIsXCJBQy43XCIsXCJBVS4xMlwiLFwiQVUuMTRcIixcIkFVLjVcIixcIkFVLjZcIixcIkFVLjhcIixcIkFVLjlcIixcIkNBLjNcIixcIkNNLjFcIixcIkNNLjNcIixcIkNNLjVcIixcIklBLjRcIixcIklBLjVcIixcIlNBLjExXCIsXCJTQy4yXCIsXCJTQy41XCIsXCJTQy43XCIsXCJTQy44XCIsXCJTSS4yXCIsXCJTSS4zXCIsXCJTSS40XCIsXCJTSS43XCJdO1xuZXhwb3J0IGNvbnN0IEdQRzEzID0gW1wiNy44XCIsIFwiNy45XCJdO1xuZXhwb3J0IGNvbnN0IHRzYyA9IFtcIkNDMS4xXCIsXCJDQzEuMlwiLFwiQ0MxLjNcIixcIkNDMS40XCIsXCJDQzEuNVwiLFwiQ0MyLjFcIixcIkNDMi4yXCIsXCJDQzIuM1wiLFwiQ0MzLjFcIixcIkNDMy4yXCIsXCJDQzMuM1wiLFwiQ0MzLjRcIixcIkNDNC4xXCIsXCJDQzQuMlwiLFwiQ0M1LjFcIixcIkNDNS4yXCIsXCJDQzUuM1wiLFwiQ0M2LjFcIixcIkNDNi4yXCIsXCJDQzYuM1wiLFwiQ0M2LjRcIixcIkNDNi41XCIsXCJDQzYuNlwiLFwiQ0M2LjdcIixcIkNDNi44XCIsXCJDQzcuMVwiLFwiQ0M3LjJcIixcIkNDNy4zXCIsXCJDQzcuNFwiLFwiQ0M3LjVcIixcIkNDOC4xXCIsXCJDQzkuMVwiLFwiQ0M5LjJcIixcIkExLjFcIixcIkExLjJcIixcIkExLjNcIixcIkMxLjFcIixcIkMxLjJcIixcIlBJMS4xXCIsXCJQSTEuMlwiLFwiUEkxLjNcIixcIlBJMS40XCIsXCJQSTEuNVwiLFwiUDEuMFwiLFwiUDEuMVwiLFwiUDIuMFwiLFwiUDIuMVwiLFwiUDMuMFwiLFwiUDMuMVwiLFwiUDMuMlwiLFwiUDQuMFwiLFwiUDQuMVwiLFwiUDQuMlwiLFwiUDQuM1wiLFwiUDUuMFwiLFwiUDUuMVwiLFwiUDUuMlwiLFwiUDYuMFwiLFwiUDYuMVwiLFwiUDYuMlwiLFwiUDYuM1wiLFwiUDYuNFwiLFwiUDYuNVwiLFwiUDYuNlwiLFwiUDYuN1wiLFwiUDcuMFwiLFwiUDcuMVwiLFwiUDguMFwiLFwiUDguMVwiXTsiXX0=