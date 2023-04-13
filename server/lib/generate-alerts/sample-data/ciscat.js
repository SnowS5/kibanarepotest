"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.ruleTitle = exports.result = exports.group = exports.benchmark = void 0;

/*
 * Wazuh app - CIS-CAT sample data
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
// CIS-CAT
// More info https://documentation.wazuh.com/3.12/user-manual/capabilities/policy-monitoring/ciscat/ciscat.html
const ruleTitle = ["CIS-CAT 1", "CIS-CAT 2", "CIS-CAT 3", "CIS-CAT 4", "CIS-CAT 5", "CIS-CAT 6"];
exports.ruleTitle = ruleTitle;
const group = ["Access, Authentication and Authorization", "Logging and Auditing"];
exports.group = group;
const benchmark = ["CIS Ubuntu Linux 16.04 LTS Benchmark"]; // TODO: add more benchmarks

exports.benchmark = benchmark;
const result = ["fail", "errors", "pass", "unknown", "notchecked"];
exports.result = result;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImNpc2NhdC5qcyJdLCJuYW1lcyI6WyJydWxlVGl0bGUiLCJncm91cCIsImJlbmNobWFyayIsInJlc3VsdCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFFQztBQUNEO0FBQ08sTUFBTUEsU0FBUyxHQUFHLENBQUMsV0FBRCxFQUFjLFdBQWQsRUFBMkIsV0FBM0IsRUFBd0MsV0FBeEMsRUFBcUQsV0FBckQsRUFBa0UsV0FBbEUsQ0FBbEI7O0FBQ0EsTUFBTUMsS0FBSyxHQUFHLENBQUMsMENBQUQsRUFBNkMsc0JBQTdDLENBQWQ7O0FBQ0EsTUFBTUMsU0FBUyxHQUFHLENBQUMsc0NBQUQsQ0FBbEIsQyxDQUE0RDs7O0FBQzVELE1BQU1DLE1BQU0sR0FBRyxDQUFDLE1BQUQsRUFBUyxRQUFULEVBQW1CLE1BQW5CLEVBQTJCLFNBQTNCLEVBQXNDLFlBQXRDLENBQWYiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gQ0lTLUNBVCBzYW1wbGUgZGF0YVxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuIC8vIENJUy1DQVRcbi8vIE1vcmUgaW5mbyBodHRwczovL2RvY3VtZW50YXRpb24ud2F6dWguY29tLzMuMTIvdXNlci1tYW51YWwvY2FwYWJpbGl0aWVzL3BvbGljeS1tb25pdG9yaW5nL2Npc2NhdC9jaXNjYXQuaHRtbFxuZXhwb3J0IGNvbnN0IHJ1bGVUaXRsZSA9IFtcIkNJUy1DQVQgMVwiLCBcIkNJUy1DQVQgMlwiLCBcIkNJUy1DQVQgM1wiLCBcIkNJUy1DQVQgNFwiLCBcIkNJUy1DQVQgNVwiLCBcIkNJUy1DQVQgNlwiXTtcbmV4cG9ydCBjb25zdCBncm91cCA9IFtcIkFjY2VzcywgQXV0aGVudGljYXRpb24gYW5kIEF1dGhvcml6YXRpb25cIiwgXCJMb2dnaW5nIGFuZCBBdWRpdGluZ1wiXTtcbmV4cG9ydCBjb25zdCBiZW5jaG1hcmsgPSBbXCJDSVMgVWJ1bnR1IExpbnV4IDE2LjA0IExUUyBCZW5jaG1hcmtcIl07IC8vIFRPRE86IGFkZCBtb3JlIGJlbmNobWFya3NcbmV4cG9ydCBjb25zdCByZXN1bHQgPSBbXCJmYWlsXCIsIFwiZXJyb3JzXCIsIFwicGFzc1wiLCBcInVua25vd25cIiwgXCJub3RjaGVja2VkXCJdOyJdfQ==