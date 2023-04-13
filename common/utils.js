"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.delayAsPromise = void 0;

/**
 * 
 * @param timeMs Time in milliseconds
 * @returns Promise
 */
const delayAsPromise = timeMs => new Promise(resolve => setTimeout(resolve, timeMs));

exports.delayAsPromise = delayAsPromise;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInV0aWxzLnRzIl0sIm5hbWVzIjpbImRlbGF5QXNQcm9taXNlIiwidGltZU1zIiwiUHJvbWlzZSIsInJlc29sdmUiLCJzZXRUaW1lb3V0Il0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPLE1BQU1BLGNBQWMsR0FBSUMsTUFBRCxJQUFvQixJQUFJQyxPQUFKLENBQVlDLE9BQU8sSUFBSUMsVUFBVSxDQUFDRCxPQUFELEVBQVVGLE1BQVYsQ0FBakMsQ0FBM0MiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIFxuICogQHBhcmFtIHRpbWVNcyBUaW1lIGluIG1pbGxpc2Vjb25kc1xuICogQHJldHVybnMgUHJvbWlzZVxuICovXG5leHBvcnQgY29uc3QgZGVsYXlBc1Byb21pc2UgPSAodGltZU1zOiBudW1iZXIpID0+IG5ldyBQcm9taXNlKHJlc29sdmUgPT4gc2V0VGltZW91dChyZXNvbHZlLCB0aW1lTXMpKTsiXX0=