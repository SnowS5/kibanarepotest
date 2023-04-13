"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.location = exports.decoder = exports.data = void 0;

/*
 * Wazuh app - Apache sample data
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const location = '/var/log/httpd/error_log';
exports.location = location;
const decoder = {
  parent: "apache-errorlog",
  name: "apache-errorlog"
};
exports.decoder = decoder;
const data = [{
  "rule": {
    "firedtimes": 5,
    "mail": false,
    "level": 5,
    "pci_dss": ["6.5.8", "10.2.4"],
    "hipaa": ["164.312.b"],
    "description": "Apache: Attempt to access forbidden directory index.",
    "groups": ["apache", "web", "access_denied"],
    "id": "30306",
    "nist_800_53": ["SA.11", "AU.14", "AC.7"],
    "gdpr": ["IV_35.7.d"]
  },
  "full_log": "[{_timestamp_apache}] [autoindex:error] [pid {_pi_id}] [client {data.srcip}:{data.srcport}] {data.id}: Cannot serve directory /var/www/html/: No matching DirectoryIndex (index.html) found, and server-generated directory index forbidden by Options directive"
}];
exports.data = data;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwYWNoZS5qcyJdLCJuYW1lcyI6WyJsb2NhdGlvbiIsImRlY29kZXIiLCJwYXJlbnQiLCJuYW1lIiwiZGF0YSJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFFTyxNQUFNQSxRQUFRLEdBQUcsMEJBQWpCOztBQUVBLE1BQU1DLE9BQU8sR0FBRztBQUNyQkMsRUFBQUEsTUFBTSxFQUFFLGlCQURhO0FBRXJCQyxFQUFBQSxJQUFJLEVBQUU7QUFGZSxDQUFoQjs7QUFLQSxNQUFNQyxJQUFJLEdBQUcsQ0FDbEI7QUFDRSxVQUFRO0FBQ04sa0JBQWMsQ0FEUjtBQUVOLFlBQVEsS0FGRjtBQUdOLGFBQVMsQ0FISDtBQUlOLGVBQVcsQ0FBQyxPQUFELEVBQVMsUUFBVCxDQUpMO0FBS04sYUFBUyxDQUNQLFdBRE8sQ0FMSDtBQVFOLG1CQUFlLHNEQVJUO0FBU04sY0FBVSxDQUFDLFFBQUQsRUFBVSxLQUFWLEVBQWdCLGVBQWhCLENBVEo7QUFVTixVQUFNLE9BVkE7QUFXTixtQkFBZSxDQUNiLE9BRGEsRUFFYixPQUZhLEVBR2IsTUFIYSxDQVhUO0FBZ0JOLFlBQVEsQ0FBQyxXQUFEO0FBaEJGLEdBRFY7QUFtQkUsY0FBWTtBQW5CZCxDQURrQixDQUFiIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIEFwYWNoZSBzYW1wbGUgZGF0YVxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuZXhwb3J0IGNvbnN0IGxvY2F0aW9uID0gJy92YXIvbG9nL2h0dHBkL2Vycm9yX2xvZyc7XG5cbmV4cG9ydCBjb25zdCBkZWNvZGVyID0ge1xuICBwYXJlbnQ6IFwiYXBhY2hlLWVycm9ybG9nXCIsXG4gIG5hbWU6IFwiYXBhY2hlLWVycm9ybG9nXCJcbn07XG5cbmV4cG9ydCBjb25zdCBkYXRhID0gW1xuICB7XG4gICAgXCJydWxlXCI6IHtcbiAgICAgIFwiZmlyZWR0aW1lc1wiOiA1LFxuICAgICAgXCJtYWlsXCI6IGZhbHNlLFxuICAgICAgXCJsZXZlbFwiOiA1LFxuICAgICAgXCJwY2lfZHNzXCI6IFtcIjYuNS44XCIsXCIxMC4yLjRcIl0sXG4gICAgICBcImhpcGFhXCI6IFtcbiAgICAgICAgXCIxNjQuMzEyLmJcIlxuICAgICAgXSxcbiAgICAgIFwiZGVzY3JpcHRpb25cIjogXCJBcGFjaGU6IEF0dGVtcHQgdG8gYWNjZXNzIGZvcmJpZGRlbiBkaXJlY3RvcnkgaW5kZXguXCIsXG4gICAgICBcImdyb3Vwc1wiOiBbXCJhcGFjaGVcIixcIndlYlwiLFwiYWNjZXNzX2RlbmllZFwiXSxcbiAgICAgIFwiaWRcIjogXCIzMDMwNlwiLFxuICAgICAgXCJuaXN0XzgwMF81M1wiOiBbXG4gICAgICAgIFwiU0EuMTFcIixcbiAgICAgICAgXCJBVS4xNFwiLFxuICAgICAgICBcIkFDLjdcIlxuICAgICAgXSxcbiAgICAgIFwiZ2RwclwiOiBbXCJJVl8zNS43LmRcIl1cbiAgICB9LFxuICAgIFwiZnVsbF9sb2dcIjogXCJbe190aW1lc3RhbXBfYXBhY2hlfV0gW2F1dG9pbmRleDplcnJvcl0gW3BpZCB7X3BpX2lkfV0gW2NsaWVudCB7ZGF0YS5zcmNpcH06e2RhdGEuc3JjcG9ydH1dIHtkYXRhLmlkfTogQ2Fubm90IHNlcnZlIGRpcmVjdG9yeSAvdmFyL3d3dy9odG1sLzogTm8gbWF0Y2hpbmcgRGlyZWN0b3J5SW5kZXggKGluZGV4Lmh0bWwpIGZvdW5kLCBhbmQgc2VydmVyLWdlbmVyYXRlZCBkaXJlY3RvcnkgaW5kZXggZm9yYmlkZGVuIGJ5IE9wdGlvbnMgZGlyZWN0aXZlXCIsXG4gIH1cbl07Il19