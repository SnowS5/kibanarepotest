"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.cleanKeys = cleanKeys;

/*
 * Wazuh app - Useful function for removing sensible keys
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
function cleanKeys(response) {
  // Remove agent key
  if (response.data.data.internal_key) {
    response.data.data.internal_key = '********';
  } // Remove cluster key (/com/cluster)


  if (response.data.data.node_type && response.data.data.key) {
    response.data.data.key = '********';
  } // Remove cluster key (/manager/configuration)


  if (response.data.data.cluster && response.data.data.cluster.node_type && response.data.data.cluster.key) {
    response.data.data.cluster.key = '********';
  } // Remove AWS keys


  if (response.data.data.wmodules) {
    response.data.data.wmodules.map(item => {
      if (item['aws-s3']) {
        if (item['aws-s3'].buckets) {
          item['aws-s3'].buckets.map(item => {
            item.access_key = '********';
            item.secret_key = '********';
          });
        }

        if (item['aws-s3'].services) {
          item['aws-s3'].services.map(item => {
            item.access_key = '********';
            item.secret_key = '********';
          });
        }
      }
    });
  } // Remove integrations keys


  if (response.data.data.integration) {
    response.data.data.integration.map(item => item.api_key = '********');
  }
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInJlbW92ZS1rZXkudHMiXSwibmFtZXMiOlsiY2xlYW5LZXlzIiwicmVzcG9uc2UiLCJkYXRhIiwiaW50ZXJuYWxfa2V5Iiwibm9kZV90eXBlIiwia2V5IiwiY2x1c3RlciIsIndtb2R1bGVzIiwibWFwIiwiaXRlbSIsImJ1Y2tldHMiLCJhY2Nlc3Nfa2V5Iiwic2VjcmV0X2tleSIsInNlcnZpY2VzIiwiaW50ZWdyYXRpb24iLCJhcGlfa2V5Il0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNPLFNBQVNBLFNBQVQsQ0FBbUJDLFFBQW5CLEVBQXVDO0FBQzVDO0FBQ0EsTUFBSUEsUUFBUSxDQUFDQyxJQUFULENBQWNBLElBQWQsQ0FBbUJDLFlBQXZCLEVBQXFDO0FBQ25DRixJQUFBQSxRQUFRLENBQUNDLElBQVQsQ0FBY0EsSUFBZCxDQUFtQkMsWUFBbkIsR0FBa0MsVUFBbEM7QUFDRCxHQUoyQyxDQU01Qzs7O0FBQ0EsTUFBSUYsUUFBUSxDQUFDQyxJQUFULENBQWNBLElBQWQsQ0FBbUJFLFNBQW5CLElBQWdDSCxRQUFRLENBQUNDLElBQVQsQ0FBY0EsSUFBZCxDQUFtQkcsR0FBdkQsRUFBNEQ7QUFDMURKLElBQUFBLFFBQVEsQ0FBQ0MsSUFBVCxDQUFjQSxJQUFkLENBQW1CRyxHQUFuQixHQUF5QixVQUF6QjtBQUNELEdBVDJDLENBVzVDOzs7QUFDQSxNQUNFSixRQUFRLENBQUNDLElBQVQsQ0FBY0EsSUFBZCxDQUFtQkksT0FBbkIsSUFDQUwsUUFBUSxDQUFDQyxJQUFULENBQWNBLElBQWQsQ0FBbUJJLE9BQW5CLENBQTJCRixTQUQzQixJQUVBSCxRQUFRLENBQUNDLElBQVQsQ0FBY0EsSUFBZCxDQUFtQkksT0FBbkIsQ0FBMkJELEdBSDdCLEVBSUU7QUFDQUosSUFBQUEsUUFBUSxDQUFDQyxJQUFULENBQWNBLElBQWQsQ0FBbUJJLE9BQW5CLENBQTJCRCxHQUEzQixHQUFpQyxVQUFqQztBQUNELEdBbEIyQyxDQW9CNUM7OztBQUNBLE1BQUlKLFFBQVEsQ0FBQ0MsSUFBVCxDQUFjQSxJQUFkLENBQW1CSyxRQUF2QixFQUFpQztBQUMvQk4sSUFBQUEsUUFBUSxDQUFDQyxJQUFULENBQWNBLElBQWQsQ0FBbUJLLFFBQW5CLENBQTRCQyxHQUE1QixDQUFnQ0MsSUFBSSxJQUFJO0FBQ3RDLFVBQUlBLElBQUksQ0FBQyxRQUFELENBQVIsRUFBb0I7QUFDbEIsWUFBSUEsSUFBSSxDQUFDLFFBQUQsQ0FBSixDQUFlQyxPQUFuQixFQUE0QjtBQUMxQkQsVUFBQUEsSUFBSSxDQUFDLFFBQUQsQ0FBSixDQUFlQyxPQUFmLENBQXVCRixHQUF2QixDQUEyQkMsSUFBSSxJQUFJO0FBQ2pDQSxZQUFBQSxJQUFJLENBQUNFLFVBQUwsR0FBa0IsVUFBbEI7QUFDQUYsWUFBQUEsSUFBSSxDQUFDRyxVQUFMLEdBQWtCLFVBQWxCO0FBQ0QsV0FIRDtBQUlEOztBQUNELFlBQUlILElBQUksQ0FBQyxRQUFELENBQUosQ0FBZUksUUFBbkIsRUFBNkI7QUFDM0JKLFVBQUFBLElBQUksQ0FBQyxRQUFELENBQUosQ0FBZUksUUFBZixDQUF3QkwsR0FBeEIsQ0FBNEJDLElBQUksSUFBSTtBQUNsQ0EsWUFBQUEsSUFBSSxDQUFDRSxVQUFMLEdBQWtCLFVBQWxCO0FBQ0FGLFlBQUFBLElBQUksQ0FBQ0csVUFBTCxHQUFrQixVQUFsQjtBQUNELFdBSEQ7QUFJRDtBQUNGO0FBQ0YsS0FmRDtBQWdCRCxHQXRDMkMsQ0F3QzVDOzs7QUFDQSxNQUFJWCxRQUFRLENBQUNDLElBQVQsQ0FBY0EsSUFBZCxDQUFtQlksV0FBdkIsRUFBb0M7QUFDbENiLElBQUFBLFFBQVEsQ0FBQ0MsSUFBVCxDQUFjQSxJQUFkLENBQW1CWSxXQUFuQixDQUErQk4sR0FBL0IsQ0FBbUNDLElBQUksSUFBS0EsSUFBSSxDQUFDTSxPQUFMLEdBQWUsVUFBM0Q7QUFDRDtBQUNGIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIFVzZWZ1bCBmdW5jdGlvbiBmb3IgcmVtb3Zpbmcgc2Vuc2libGUga2V5c1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBjbGVhbktleXMocmVzcG9uc2U6IGFueSk6IGFueSB7XG4gIC8vIFJlbW92ZSBhZ2VudCBrZXlcbiAgaWYgKHJlc3BvbnNlLmRhdGEuZGF0YS5pbnRlcm5hbF9rZXkpIHtcbiAgICByZXNwb25zZS5kYXRhLmRhdGEuaW50ZXJuYWxfa2V5ID0gJyoqKioqKioqJztcbiAgfVxuXG4gIC8vIFJlbW92ZSBjbHVzdGVyIGtleSAoL2NvbS9jbHVzdGVyKVxuICBpZiAocmVzcG9uc2UuZGF0YS5kYXRhLm5vZGVfdHlwZSAmJiByZXNwb25zZS5kYXRhLmRhdGEua2V5KSB7XG4gICAgcmVzcG9uc2UuZGF0YS5kYXRhLmtleSA9ICcqKioqKioqKic7XG4gIH1cblxuICAvLyBSZW1vdmUgY2x1c3RlciBrZXkgKC9tYW5hZ2VyL2NvbmZpZ3VyYXRpb24pXG4gIGlmIChcbiAgICByZXNwb25zZS5kYXRhLmRhdGEuY2x1c3RlciAmJlxuICAgIHJlc3BvbnNlLmRhdGEuZGF0YS5jbHVzdGVyLm5vZGVfdHlwZSAmJlxuICAgIHJlc3BvbnNlLmRhdGEuZGF0YS5jbHVzdGVyLmtleVxuICApIHtcbiAgICByZXNwb25zZS5kYXRhLmRhdGEuY2x1c3Rlci5rZXkgPSAnKioqKioqKionO1xuICB9XG5cbiAgLy8gUmVtb3ZlIEFXUyBrZXlzXG4gIGlmIChyZXNwb25zZS5kYXRhLmRhdGEud21vZHVsZXMpIHtcbiAgICByZXNwb25zZS5kYXRhLmRhdGEud21vZHVsZXMubWFwKGl0ZW0gPT4ge1xuICAgICAgaWYgKGl0ZW1bJ2F3cy1zMyddKSB7XG4gICAgICAgIGlmIChpdGVtWydhd3MtczMnXS5idWNrZXRzKSB7XG4gICAgICAgICAgaXRlbVsnYXdzLXMzJ10uYnVja2V0cy5tYXAoaXRlbSA9PiB7XG4gICAgICAgICAgICBpdGVtLmFjY2Vzc19rZXkgPSAnKioqKioqKionO1xuICAgICAgICAgICAgaXRlbS5zZWNyZXRfa2V5ID0gJyoqKioqKioqJztcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgICBpZiAoaXRlbVsnYXdzLXMzJ10uc2VydmljZXMpIHtcbiAgICAgICAgICBpdGVtWydhd3MtczMnXS5zZXJ2aWNlcy5tYXAoaXRlbSA9PiB7XG4gICAgICAgICAgICBpdGVtLmFjY2Vzc19rZXkgPSAnKioqKioqKionO1xuICAgICAgICAgICAgaXRlbS5zZWNyZXRfa2V5ID0gJyoqKioqKioqJztcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuICB9XG5cbiAgLy8gUmVtb3ZlIGludGVncmF0aW9ucyBrZXlzXG4gIGlmIChyZXNwb25zZS5kYXRhLmRhdGEuaW50ZWdyYXRpb24pIHtcbiAgICByZXNwb25zZS5kYXRhLmRhdGEuaW50ZWdyYXRpb24ubWFwKGl0ZW0gPT4gKGl0ZW0uYXBpX2tleSA9ICcqKioqKioqKicpKTtcbiAgfVxufVxuIl19