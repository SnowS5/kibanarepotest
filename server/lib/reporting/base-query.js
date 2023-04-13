"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.Base = Base;

/*
 * Wazuh app - Base query for reporting queries
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
function Base(pattern, filters, gte, lte, allowedAgentsFilter = null) {
  var _allowedAgentsFilter$;

  const base = {
    // index: pattern,
    from: 0,
    size: 500,
    aggs: {},
    sort: [],
    script_fields: {},
    query: {
      bool: {
        must: [{
          query_string: {
            query: filters,
            analyze_wildcard: true,
            default_field: '*'
          }
        }, {
          range: {
            timestamp: {
              gte: gte,
              lte: lte,
              format: 'epoch_millis'
            }
          }
        }],
        must_not: []
      }
    }
  }; //Add allowed agents filter

  if (allowedAgentsFilter !== null && allowedAgentsFilter !== void 0 && (_allowedAgentsFilter$ = allowedAgentsFilter.query) !== null && _allowedAgentsFilter$ !== void 0 && _allowedAgentsFilter$.bool) {
    base.query.bool.minimum_should_match = allowedAgentsFilter.query.bool.minimum_should_match;
    base.query.bool.should = allowedAgentsFilter.query.bool.should;
  }

  return base;
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImJhc2UtcXVlcnkudHMiXSwibmFtZXMiOlsiQmFzZSIsInBhdHRlcm4iLCJmaWx0ZXJzIiwiZ3RlIiwibHRlIiwiYWxsb3dlZEFnZW50c0ZpbHRlciIsImJhc2UiLCJmcm9tIiwic2l6ZSIsImFnZ3MiLCJzb3J0Iiwic2NyaXB0X2ZpZWxkcyIsInF1ZXJ5IiwiYm9vbCIsIm11c3QiLCJxdWVyeV9zdHJpbmciLCJhbmFseXplX3dpbGRjYXJkIiwiZGVmYXVsdF9maWVsZCIsInJhbmdlIiwidGltZXN0YW1wIiwiZm9ybWF0IiwibXVzdF9ub3QiLCJtaW5pbXVtX3Nob3VsZF9tYXRjaCIsInNob3VsZCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTyxTQUFTQSxJQUFULENBQWNDLE9BQWQsRUFBK0JDLE9BQS9CLEVBQTZDQyxHQUE3QyxFQUEwREMsR0FBMUQsRUFBdUVDLG1CQUF3QixHQUFHLElBQWxHLEVBQXdHO0FBQUE7O0FBQzdHLFFBQU1DLElBQUksR0FBRztBQUNYO0FBRUFDLElBQUFBLElBQUksRUFBRSxDQUhLO0FBSVhDLElBQUFBLElBQUksRUFBRSxHQUpLO0FBS1hDLElBQUFBLElBQUksRUFBRSxFQUxLO0FBTVhDLElBQUFBLElBQUksRUFBRSxFQU5LO0FBT1hDLElBQUFBLGFBQWEsRUFBRSxFQVBKO0FBUVhDLElBQUFBLEtBQUssRUFBRTtBQUNMQyxNQUFBQSxJQUFJLEVBQUU7QUFDSkMsUUFBQUEsSUFBSSxFQUFFLENBQ0o7QUFDRUMsVUFBQUEsWUFBWSxFQUFFO0FBQ1pILFlBQUFBLEtBQUssRUFBRVYsT0FESztBQUVaYyxZQUFBQSxnQkFBZ0IsRUFBRSxJQUZOO0FBR1pDLFlBQUFBLGFBQWEsRUFBRTtBQUhIO0FBRGhCLFNBREksRUFRSjtBQUNFQyxVQUFBQSxLQUFLLEVBQUU7QUFDTEMsWUFBQUEsU0FBUyxFQUFFO0FBQ1RoQixjQUFBQSxHQUFHLEVBQUVBLEdBREk7QUFFVEMsY0FBQUEsR0FBRyxFQUFFQSxHQUZJO0FBR1RnQixjQUFBQSxNQUFNLEVBQUU7QUFIQztBQUROO0FBRFQsU0FSSSxDQURGO0FBbUJKQyxRQUFBQSxRQUFRLEVBQUU7QUFuQk47QUFERDtBQVJJLEdBQWIsQ0FENkcsQ0FrQzdHOztBQUNBLE1BQUdoQixtQkFBSCxhQUFHQSxtQkFBSCx3Q0FBR0EsbUJBQW1CLENBQUVPLEtBQXhCLGtEQUFHLHNCQUE0QkMsSUFBL0IsRUFBb0M7QUFDbENQLElBQUFBLElBQUksQ0FBQ00sS0FBTCxDQUFXQyxJQUFYLENBQWdCUyxvQkFBaEIsR0FBdUNqQixtQkFBbUIsQ0FBQ08sS0FBcEIsQ0FBMEJDLElBQTFCLENBQStCUyxvQkFBdEU7QUFDQWhCLElBQUFBLElBQUksQ0FBQ00sS0FBTCxDQUFXQyxJQUFYLENBQWdCVSxNQUFoQixHQUF5QmxCLG1CQUFtQixDQUFDTyxLQUFwQixDQUEwQkMsSUFBMUIsQ0FBK0JVLE1BQXhEO0FBQ0Q7O0FBRUQsU0FBT2pCLElBQVA7QUFDRCIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBCYXNlIHF1ZXJ5IGZvciByZXBvcnRpbmcgcXVlcmllc1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBCYXNlKHBhdHRlcm46IHN0cmluZywgZmlsdGVyczogYW55LCBndGU6IG51bWJlciwgbHRlOiBudW1iZXIsIGFsbG93ZWRBZ2VudHNGaWx0ZXI6IGFueSA9IG51bGwpIHtcbiAgY29uc3QgYmFzZSA9IHtcbiAgICAvLyBpbmRleDogcGF0dGVybixcblxuICAgIGZyb206IDAsXG4gICAgc2l6ZTogNTAwLFxuICAgIGFnZ3M6IHt9LFxuICAgIHNvcnQ6IFtdLFxuICAgIHNjcmlwdF9maWVsZHM6IHt9LFxuICAgIHF1ZXJ5OiB7XG4gICAgICBib29sOiB7XG4gICAgICAgIG11c3Q6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBxdWVyeV9zdHJpbmc6IHtcbiAgICAgICAgICAgICAgcXVlcnk6IGZpbHRlcnMsXG4gICAgICAgICAgICAgIGFuYWx5emVfd2lsZGNhcmQ6IHRydWUsXG4gICAgICAgICAgICAgIGRlZmF1bHRfZmllbGQ6ICcqJ1xuICAgICAgICAgICAgfVxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgcmFuZ2U6IHtcbiAgICAgICAgICAgICAgdGltZXN0YW1wOiB7XG4gICAgICAgICAgICAgICAgZ3RlOiBndGUsXG4gICAgICAgICAgICAgICAgbHRlOiBsdGUsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiAnZXBvY2hfbWlsbGlzJ1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgICBdLFxuICAgICAgICBtdXN0X25vdDogW11cbiAgICAgIH1cbiAgICB9XG4gIH07XG5cbiAgLy9BZGQgYWxsb3dlZCBhZ2VudHMgZmlsdGVyXG4gIGlmKGFsbG93ZWRBZ2VudHNGaWx0ZXI/LnF1ZXJ5Py5ib29sKXtcbiAgICBiYXNlLnF1ZXJ5LmJvb2wubWluaW11bV9zaG91bGRfbWF0Y2ggPSBhbGxvd2VkQWdlbnRzRmlsdGVyLnF1ZXJ5LmJvb2wubWluaW11bV9zaG91bGRfbWF0Y2g7XG4gICAgYmFzZS5xdWVyeS5ib29sLnNob3VsZCA9IGFsbG93ZWRBZ2VudHNGaWx0ZXIucXVlcnkuYm9vbC5zaG91bGQ7XG4gIH1cblxuICByZXR1cm4gYmFzZTtcbn1cbiJdfQ==