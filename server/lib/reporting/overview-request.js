"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.topLevel15 = void 0;

var _baseQuery = require("./base-query");

var _settings = require("../../../common/services/settings");

/*
 * Wazuh app - Specific methods to fetch Wazuh overview data from Elasticsearch
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */

/**
 * Returns top 3 agents with level 15 alerts
 * @param {*} context Endpoint context
 * @param {Number} gte Timestamp (ms) from
 * @param {Number} lte Timestamp (ms) to
 * @param {String} filters E.g: cluster.name: wazuh AND rule.groups: vulnerability
 * @returns {Array<String>} E.g:['000','130','300']
 */
const topLevel15 = async (context, gte, lte, filters, allowedAgentsFilter, pattern = (0, _settings.getSettingDefaultValue)('pattern')) => {
  try {
    const base = {};
    Object.assign(base, (0, _baseQuery.Base)(pattern, filters, gte, lte, allowedAgentsFilter));
    Object.assign(base.aggs, {
      '2': {
        terms: {
          field: 'agent.id',
          size: 3,
          order: {
            _count: 'desc'
          }
        }
      }
    });
    base.query.bool.must.push({
      match_phrase: {
        'rule.level': {
          query: 15
        }
      }
    });
    const response = await context.core.elasticsearch.client.asCurrentUser.search({
      index: pattern,
      body: base
    });
    const {
      buckets
    } = response.body.aggregations['2'];
    return buckets.map(item => item.key);
  } catch (error) {
    return Promise.reject(error);
  }
};

exports.topLevel15 = topLevel15;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LXJlcXVlc3QudHMiXSwibmFtZXMiOlsidG9wTGV2ZWwxNSIsImNvbnRleHQiLCJndGUiLCJsdGUiLCJmaWx0ZXJzIiwiYWxsb3dlZEFnZW50c0ZpbHRlciIsInBhdHRlcm4iLCJiYXNlIiwiT2JqZWN0IiwiYXNzaWduIiwiYWdncyIsInRlcm1zIiwiZmllbGQiLCJzaXplIiwib3JkZXIiLCJfY291bnQiLCJxdWVyeSIsImJvb2wiLCJtdXN0IiwicHVzaCIsIm1hdGNoX3BocmFzZSIsInJlc3BvbnNlIiwiY29yZSIsImVsYXN0aWNzZWFyY2giLCJjbGllbnQiLCJhc0N1cnJlbnRVc2VyIiwic2VhcmNoIiwiaW5kZXgiLCJib2R5IiwiYnVja2V0cyIsImFnZ3JlZ2F0aW9ucyIsIm1hcCIsIml0ZW0iLCJrZXkiLCJlcnJvciIsIlByb21pc2UiLCJyZWplY3QiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFXQTs7QUFDQTs7QUFaQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUlBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTyxNQUFNQSxVQUFVLEdBQUcsT0FBT0MsT0FBUCxFQUFnQkMsR0FBaEIsRUFBcUJDLEdBQXJCLEVBQTBCQyxPQUExQixFQUFtQ0MsbUJBQW5DLEVBQXdEQyxPQUFPLEdBQUcsc0NBQXVCLFNBQXZCLENBQWxFLEtBQXdHO0FBQ2hJLE1BQUk7QUFDRixVQUFNQyxJQUFJLEdBQUcsRUFBYjtBQUVBQyxJQUFBQSxNQUFNLENBQUNDLE1BQVAsQ0FBY0YsSUFBZCxFQUFvQixxQkFBS0QsT0FBTCxFQUFjRixPQUFkLEVBQXVCRixHQUF2QixFQUE0QkMsR0FBNUIsRUFBaUNFLG1CQUFqQyxDQUFwQjtBQUVBRyxJQUFBQSxNQUFNLENBQUNDLE1BQVAsQ0FBY0YsSUFBSSxDQUFDRyxJQUFuQixFQUF5QjtBQUN2QixXQUFLO0FBQ0hDLFFBQUFBLEtBQUssRUFBRTtBQUNMQyxVQUFBQSxLQUFLLEVBQUUsVUFERjtBQUVMQyxVQUFBQSxJQUFJLEVBQUUsQ0FGRDtBQUdMQyxVQUFBQSxLQUFLLEVBQUU7QUFDTEMsWUFBQUEsTUFBTSxFQUFFO0FBREg7QUFIRjtBQURKO0FBRGtCLEtBQXpCO0FBWUFSLElBQUFBLElBQUksQ0FBQ1MsS0FBTCxDQUFXQyxJQUFYLENBQWdCQyxJQUFoQixDQUFxQkMsSUFBckIsQ0FBMEI7QUFDeEJDLE1BQUFBLFlBQVksRUFBRTtBQUNaLHNCQUFjO0FBQ1pKLFVBQUFBLEtBQUssRUFBRTtBQURLO0FBREY7QUFEVSxLQUExQjtBQU9BLFVBQU1LLFFBQVEsR0FBRyxNQUFNcEIsT0FBTyxDQUFDcUIsSUFBUixDQUFhQyxhQUFiLENBQTJCQyxNQUEzQixDQUFrQ0MsYUFBbEMsQ0FBZ0RDLE1BQWhELENBQXVEO0FBQzVFQyxNQUFBQSxLQUFLLEVBQUVyQixPQURxRTtBQUU1RXNCLE1BQUFBLElBQUksRUFBRXJCO0FBRnNFLEtBQXZELENBQXZCO0FBSUEsVUFBTTtBQUFFc0IsTUFBQUE7QUFBRixRQUFjUixRQUFRLENBQUNPLElBQVQsQ0FBY0UsWUFBZCxDQUEyQixHQUEzQixDQUFwQjtBQUVBLFdBQU9ELE9BQU8sQ0FBQ0UsR0FBUixDQUFZQyxJQUFJLElBQUlBLElBQUksQ0FBQ0MsR0FBekIsQ0FBUDtBQUNELEdBL0JELENBK0JFLE9BQU9DLEtBQVAsRUFBYztBQUNkLFdBQU9DLE9BQU8sQ0FBQ0MsTUFBUixDQUFlRixLQUFmLENBQVA7QUFDRDtBQUNGLENBbkNNIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIFNwZWNpZmljIG1ldGhvZHMgdG8gZmV0Y2ggV2F6dWggb3ZlcnZpZXcgZGF0YSBmcm9tIEVsYXN0aWNzZWFyY2hcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5pbXBvcnQgeyBCYXNlIH0gZnJvbSAnLi9iYXNlLXF1ZXJ5JztcbmltcG9ydCB7IGdldFNldHRpbmdEZWZhdWx0VmFsdWUgfSBmcm9tICcuLi8uLi8uLi9jb21tb24vc2VydmljZXMvc2V0dGluZ3MnO1xuXG4vKipcbiAqIFJldHVybnMgdG9wIDMgYWdlbnRzIHdpdGggbGV2ZWwgMTUgYWxlcnRzXG4gKiBAcGFyYW0geyp9IGNvbnRleHQgRW5kcG9pbnQgY29udGV4dFxuICogQHBhcmFtIHtOdW1iZXJ9IGd0ZSBUaW1lc3RhbXAgKG1zKSBmcm9tXG4gKiBAcGFyYW0ge051bWJlcn0gbHRlIFRpbWVzdGFtcCAobXMpIHRvXG4gKiBAcGFyYW0ge1N0cmluZ30gZmlsdGVycyBFLmc6IGNsdXN0ZXIubmFtZTogd2F6dWggQU5EIHJ1bGUuZ3JvdXBzOiB2dWxuZXJhYmlsaXR5XG4gKiBAcmV0dXJucyB7QXJyYXk8U3RyaW5nPn0gRS5nOlsnMDAwJywnMTMwJywnMzAwJ11cbiAqL1xuZXhwb3J0IGNvbnN0IHRvcExldmVsMTUgPSBhc3luYyAoY29udGV4dCwgZ3RlLCBsdGUsIGZpbHRlcnMsIGFsbG93ZWRBZ2VudHNGaWx0ZXIsIHBhdHRlcm4gPSBnZXRTZXR0aW5nRGVmYXVsdFZhbHVlKCdwYXR0ZXJuJykpID0+IHtcbiAgdHJ5IHtcbiAgICBjb25zdCBiYXNlID0ge307XG5cbiAgICBPYmplY3QuYXNzaWduKGJhc2UsIEJhc2UocGF0dGVybiwgZmlsdGVycywgZ3RlLCBsdGUsIGFsbG93ZWRBZ2VudHNGaWx0ZXIpKTtcblxuICAgIE9iamVjdC5hc3NpZ24oYmFzZS5hZ2dzLCB7XG4gICAgICAnMic6IHtcbiAgICAgICAgdGVybXM6IHtcbiAgICAgICAgICBmaWVsZDogJ2FnZW50LmlkJyxcbiAgICAgICAgICBzaXplOiAzLFxuICAgICAgICAgIG9yZGVyOiB7XG4gICAgICAgICAgICBfY291bnQ6ICdkZXNjJ1xuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIH0pO1xuXG4gICAgYmFzZS5xdWVyeS5ib29sLm11c3QucHVzaCh7XG4gICAgICBtYXRjaF9waHJhc2U6IHtcbiAgICAgICAgJ3J1bGUubGV2ZWwnOiB7XG4gICAgICAgICAgcXVlcnk6IDE1XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9KTtcbiAgICBjb25zdCByZXNwb25zZSA9IGF3YWl0IGNvbnRleHQuY29yZS5lbGFzdGljc2VhcmNoLmNsaWVudC5hc0N1cnJlbnRVc2VyLnNlYXJjaCh7XG4gICAgICBpbmRleDogcGF0dGVybixcbiAgICAgIGJvZHk6IGJhc2VcbiAgICB9KTtcbiAgICBjb25zdCB7IGJ1Y2tldHMgfSA9IHJlc3BvbnNlLmJvZHkuYWdncmVnYXRpb25zWycyJ107XG5cbiAgICByZXR1cm4gYnVja2V0cy5tYXAoaXRlbSA9PiBpdGVtLmtleSk7XG4gIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcbiAgfVxufVxuIl19