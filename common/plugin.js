"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.getPluginDataPath = void 0;

var _constants = require("./constants");

/**
 * 
 * @param path Path to file or directory
 * @returns Absolute path to the file or directory with the prefix path of app data path
 */
const getPluginDataPath = (path = '') => `${_constants.PLUGIN_PLATFORM_BASE_INSTALLATION_PATH}${path}`;

exports.getPluginDataPath = getPluginDataPath;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInBsdWdpbi50cyJdLCJuYW1lcyI6WyJnZXRQbHVnaW5EYXRhUGF0aCIsInBhdGgiLCJQTFVHSU5fUExBVEZPUk1fQkFTRV9JTlNUQUxMQVRJT05fUEFUSCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTyxNQUFNQSxpQkFBaUIsR0FBRyxDQUFDQyxJQUFZLEdBQUcsRUFBaEIsS0FBZ0MsR0FBRUMsaURBQXVDLEdBQUVELElBQUssRUFBMUciLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBQTFVHSU5fUExBVEZPUk1fQkFTRV9JTlNUQUxMQVRJT05fUEFUSCB9IGZyb20gXCIuL2NvbnN0YW50c1wiO1xuXG4vKipcbiAqIFxuICogQHBhcmFtIHBhdGggUGF0aCB0byBmaWxlIG9yIGRpcmVjdG9yeVxuICogQHJldHVybnMgQWJzb2x1dGUgcGF0aCB0byB0aGUgZmlsZSBvciBkaXJlY3Rvcnkgd2l0aCB0aGUgcHJlZml4IHBhdGggb2YgYXBwIGRhdGEgcGF0aFxuICovXG5leHBvcnQgY29uc3QgZ2V0UGx1Z2luRGF0YVBhdGggPSAocGF0aDogc3RyaW5nID0gJycpOiBzdHJpbmcgPT4gYCR7UExVR0lOX1BMQVRGT1JNX0JBU0VfSU5TVEFMTEFUSU9OX1BBVEh9JHtwYXRofWA7Il19