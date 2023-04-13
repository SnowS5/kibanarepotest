"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.monitoringTemplate = void 0;

/*
 * Wazuh app - Module for monitoring template
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const monitoringTemplate = {
  order: 0,
  settings: {
    'index.refresh_interval': '5s'
  },
  mappings: {
    properties: {
      timestamp: {
        type: 'date',
        format: 'dateOptionalTime'
      },
      status: {
        type: 'keyword'
      },
      ip: {
        type: 'keyword'
      },
      host: {
        type: 'keyword'
      },
      name: {
        type: 'keyword'
      },
      id: {
        type: 'keyword'
      },
      cluster: {
        properties: {
          name: {
            type: 'keyword'
          }
        }
      }
    }
  }
};
exports.monitoringTemplate = monitoringTemplate;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm1vbml0b3JpbmctdGVtcGxhdGUudHMiXSwibmFtZXMiOlsibW9uaXRvcmluZ1RlbXBsYXRlIiwib3JkZXIiLCJzZXR0aW5ncyIsIm1hcHBpbmdzIiwicHJvcGVydGllcyIsInRpbWVzdGFtcCIsInR5cGUiLCJmb3JtYXQiLCJzdGF0dXMiLCJpcCIsImhvc3QiLCJuYW1lIiwiaWQiLCJjbHVzdGVyIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPLE1BQU1BLGtCQUFrQixHQUFHO0FBQ2hDQyxFQUFBQSxLQUFLLEVBQUUsQ0FEeUI7QUFFaENDLEVBQUFBLFFBQVEsRUFBRTtBQUNSLDhCQUEwQjtBQURsQixHQUZzQjtBQUtoQ0MsRUFBQUEsUUFBUSxFQUFFO0FBQ1JDLElBQUFBLFVBQVUsRUFBRTtBQUNWQyxNQUFBQSxTQUFTLEVBQUU7QUFDVEMsUUFBQUEsSUFBSSxFQUFFLE1BREc7QUFFVEMsUUFBQUEsTUFBTSxFQUFFO0FBRkMsT0FERDtBQUtWQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkYsUUFBQUEsSUFBSSxFQUFFO0FBREEsT0FMRTtBQVFWRyxNQUFBQSxFQUFFLEVBQUU7QUFDRkgsUUFBQUEsSUFBSSxFQUFFO0FBREosT0FSTTtBQVdWSSxNQUFBQSxJQUFJLEVBQUU7QUFDSkosUUFBQUEsSUFBSSxFQUFFO0FBREYsT0FYSTtBQWNWSyxNQUFBQSxJQUFJLEVBQUU7QUFDSkwsUUFBQUEsSUFBSSxFQUFFO0FBREYsT0FkSTtBQWlCVk0sTUFBQUEsRUFBRSxFQUFFO0FBQ0ZOLFFBQUFBLElBQUksRUFBRTtBQURKLE9BakJNO0FBb0JWTyxNQUFBQSxPQUFPLEVBQUU7QUFDUFQsUUFBQUEsVUFBVSxFQUFFO0FBQ1ZPLFVBQUFBLElBQUksRUFBRTtBQUNKTCxZQUFBQSxJQUFJLEVBQUU7QUFERjtBQURJO0FBREw7QUFwQkM7QUFESjtBQUxzQixDQUEzQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgZm9yIG1vbml0b3JpbmcgdGVtcGxhdGVcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgY29uc3QgbW9uaXRvcmluZ1RlbXBsYXRlID0ge1xuICBvcmRlcjogMCxcbiAgc2V0dGluZ3M6IHtcbiAgICAnaW5kZXgucmVmcmVzaF9pbnRlcnZhbCc6ICc1cydcbiAgfSxcbiAgbWFwcGluZ3M6IHtcbiAgICBwcm9wZXJ0aWVzOiB7XG4gICAgICB0aW1lc3RhbXA6IHtcbiAgICAgICAgdHlwZTogJ2RhdGUnLFxuICAgICAgICBmb3JtYXQ6ICdkYXRlT3B0aW9uYWxUaW1lJ1xuICAgICAgfSxcbiAgICAgIHN0YXR1czoge1xuICAgICAgICB0eXBlOiAna2V5d29yZCdcbiAgICAgIH0sXG4gICAgICBpcDoge1xuICAgICAgICB0eXBlOiAna2V5d29yZCdcbiAgICAgIH0sXG4gICAgICBob3N0OiB7XG4gICAgICAgIHR5cGU6ICdrZXl3b3JkJ1xuICAgICAgfSxcbiAgICAgIG5hbWU6IHtcbiAgICAgICAgdHlwZTogJ2tleXdvcmQnXG4gICAgICB9LFxuICAgICAgaWQ6IHtcbiAgICAgICAgdHlwZTogJ2tleXdvcmQnXG4gICAgICB9LFxuICAgICAgY2x1c3Rlcjoge1xuICAgICAgICBwcm9wZXJ0aWVzOiB7XG4gICAgICAgICAgbmFtZToge1xuICAgICAgICAgICAgdHlwZTogJ2tleXdvcmQnXG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9XG59O1xuIl19