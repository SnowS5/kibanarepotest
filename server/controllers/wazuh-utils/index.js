"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _wazuhUtils = require("./wazuh-utils");

Object.keys(_wazuhUtils).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _wazuhUtils[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function () {
      return _wazuhUtils[key];
    }
  });
});

var _uiLogs = require("./ui-logs.controller");

Object.keys(_uiLogs).forEach(function (key) {
  if (key === "default" || key === "__esModule") return;
  if (key in exports && exports[key] === _uiLogs[key]) return;
  Object.defineProperty(exports, key, {
    enumerable: true,
    get: function () {
      return _uiLogs[key];
    }
  });
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImluZGV4LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7OztBQUFBOztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBOztBQUNBOztBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBO0FBQUE7QUFBQTtBQUFBIiwic291cmNlc0NvbnRlbnQiOlsiZXhwb3J0ICogZnJvbSAnLi93YXp1aC11dGlscyc7XG5leHBvcnQgKiBmcm9tICcuL3VpLWxvZ3MuY29udHJvbGxlcic7XG4iXX0=