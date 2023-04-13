"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

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
class SummaryTable {
  constructor(context, gte, lte, filters, allowedAgentsFilter, summarySetup, pattern = (0, _settings.getSettingDefaultValue)('pattern')) {
    this._context = context;
    this._pattern = pattern;
    this._summarySetup = summarySetup;
    this._base = {
      aggs: {}
    };
    this._columns = [];
    this._rows = [];
    this._title = summarySetup.title;
    Object.assign(this._base, (0, _baseQuery.Base)(pattern, filters, gte, lte, allowedAgentsFilter));

    this._parseSummarySetup(summarySetup);
  }
  /**
   * Parse the summary table setup to build the query
   * @param summarySetup
   */


  _parseSummarySetup(summarySetup) {
    let baseAggRef = this._base.aggs;
    summarySetup.aggs.forEach((agg, key) => {
      this._columns.push(agg.customLabel);

      this._parseAggregation(baseAggRef, agg, key);

      if (summarySetup.aggs.length > key + 1) {
        baseAggRef[`${key + 2}`].aggs = {};
        baseAggRef = baseAggRef[`${key + 2}`].aggs;
      } else {
        this._columns.push('Count');
      }
    }, this);
  }
  /**
   * Parse each aggregation to build the query
   * @param baseAggRef
   * @param agg
   * @param key
   */


  _parseAggregation(baseAggRef, agg, key) {
    const {
      field,
      size,
      order,
      missing
    } = agg;
    baseAggRef[`${key + 2}`] = {
      terms: {
        field,
        order: {
          _count: order
        },
        size
      }
    };

    if (missing) {
      baseAggRef[`${key + 2}`].terms.missing = missing;
    }
  }
  /**
   * Returns the response formatted to a table
   * @description The response is an object with the following structure:{
   *  title: 'Alerts summary',
   *  columns: ['Rule ID','Description','Level', 'Count'],
   *  rows: [
   *    ['502', 'Ossec server started', 3, 22],
   *    ['502', 'Ossec server started', 3, 22],
   *  ]
   * }
   * @param rawResponse
   */


  _formatResponseToTable(rawResponse) {
    const firstKey = parseInt(Object.keys(rawResponse)[0]);
    this._rows = rawResponse[firstKey].buckets.reduce((totalRows, bucket) => {
      const nextKey = firstKey + 1;

      this._buildRow(bucket, nextKey, totalRows);

      return totalRows;
    }, []);
    return {
      rows: this._rows,
      columns: this._columns,
      title: this._title
    };
  }
  /**
   * Makes a row from the response
   * @param bucket
   * @param nextAggKey
   * @param row
   */


  _buildRow(bucket, nextAggKey, totalRows, row = []) {
    var _bucket$nextAggKey$to, _bucket$nextAggKey$to2;

    const newRow = [...row, bucket.key]; // If there is a next aggregation, repeat the process

    if ((_bucket$nextAggKey$to = bucket[nextAggKey.toString()]) !== null && _bucket$nextAggKey$to !== void 0 && (_bucket$nextAggKey$to2 = _bucket$nextAggKey$to.buckets) !== null && _bucket$nextAggKey$to2 !== void 0 && _bucket$nextAggKey$to2.length) {
      bucket[nextAggKey.toString()].buckets.forEach(newBucket => {
        this._buildRow(newBucket, nextAggKey + 1, totalRows, newRow);
      });
    } // Add the Count as the last item in the row
    else if (bucket.doc_count) {
      newRow.push(bucket.doc_count);
      totalRows.push(newRow);
    }
  }
  /**
   * Executes the query and returns the response
   */


  async fetch() {
    try {
      const response = await this._context.core.elasticsearch.client.asCurrentUser.search({
        index: this._pattern,
        body: this._base
      });

      const alertsTable = this._formatResponseToTable(response.body.aggregations);

      return alertsTable;
    } catch (error) {
      return Promise.reject(error);
    }
  }

}

exports.default = SummaryTable;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInN1bW1hcnktdGFibGUudHMiXSwibmFtZXMiOlsiU3VtbWFyeVRhYmxlIiwiY29uc3RydWN0b3IiLCJjb250ZXh0IiwiZ3RlIiwibHRlIiwiZmlsdGVycyIsImFsbG93ZWRBZ2VudHNGaWx0ZXIiLCJzdW1tYXJ5U2V0dXAiLCJwYXR0ZXJuIiwiX2NvbnRleHQiLCJfcGF0dGVybiIsIl9zdW1tYXJ5U2V0dXAiLCJfYmFzZSIsImFnZ3MiLCJfY29sdW1ucyIsIl9yb3dzIiwiX3RpdGxlIiwidGl0bGUiLCJPYmplY3QiLCJhc3NpZ24iLCJfcGFyc2VTdW1tYXJ5U2V0dXAiLCJiYXNlQWdnUmVmIiwiZm9yRWFjaCIsImFnZyIsImtleSIsInB1c2giLCJjdXN0b21MYWJlbCIsIl9wYXJzZUFnZ3JlZ2F0aW9uIiwibGVuZ3RoIiwiZmllbGQiLCJzaXplIiwib3JkZXIiLCJtaXNzaW5nIiwidGVybXMiLCJfY291bnQiLCJfZm9ybWF0UmVzcG9uc2VUb1RhYmxlIiwicmF3UmVzcG9uc2UiLCJmaXJzdEtleSIsInBhcnNlSW50Iiwia2V5cyIsImJ1Y2tldHMiLCJyZWR1Y2UiLCJ0b3RhbFJvd3MiLCJidWNrZXQiLCJuZXh0S2V5IiwiX2J1aWxkUm93Iiwicm93cyIsImNvbHVtbnMiLCJuZXh0QWdnS2V5Iiwicm93IiwibmV3Um93IiwidG9TdHJpbmciLCJuZXdCdWNrZXQiLCJkb2NfY291bnQiLCJmZXRjaCIsInJlc3BvbnNlIiwiY29yZSIsImVsYXN0aWNzZWFyY2giLCJjbGllbnQiLCJhc0N1cnJlbnRVc2VyIiwic2VhcmNoIiwiaW5kZXgiLCJib2R5IiwiYWxlcnRzVGFibGUiLCJhZ2dyZWdhdGlvbnMiLCJlcnJvciIsIlByb21pc2UiLCJyZWplY3QiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFXQTs7QUFDQTs7QUFaQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBU2UsTUFBTUEsWUFBTixDQUFtQjtBQUNoQ0MsRUFB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LENBQVlrQixNQUFNLENBQUNVLFNBQW5CO0FBQ0FYLE1BQUFBLFNBQVMsQ0FBQ2pCLElBQVYsQ0FBZXlCLE1BQWY7QUFDRDtBQUNGO0FBRUQ7QUFDRjtBQUNBOzs7QUFDYSxRQUFMSSxLQUFLLEdBQUc7QUFDWixRQUFJO0FBQ0YsWUFBTUMsUUFBUSxHQUFHLE1BQU0sS0FBSzlDLFFBQUwsQ0FBYytDLElBQWQsQ0FBbUJDLGFBQW5CLENBQWlDQyxNQUFqQyxDQUF3Q0MsYUFBeEMsQ0FBc0RDLE1BQXRELENBQTZEO0FBQ2xGQyxRQUFBQSxLQUFLLEVBQUUsS0FBS25ELFFBRHNFO0FBRWxGb0QsUUFBQUEsSUFBSSxFQUFFLEtBQUtsRDtBQUZ1RSxPQUE3RCxDQUF2Qjs7QUFJQSxZQUFNbUQsV0FBVyxHQUFHLEtBQUs1QixzQkFBTCxDQUE0Qm9CLFFBQVEsQ0FBQ08sSUFBVCxDQUFjRSxZQUExQyxDQUFwQjs7QUFDQSxhQUFPRCxXQUFQO0FBQ0QsS0FQRCxDQU9FLE9BQU9FLEtBQVAsRUFBYztBQUNkLGFBQU9DLE9BQU8sQ0FBQ0MsTUFBUixDQUFlRixLQUFmLENBQVA7QUFDRDtBQUNGOztBQWxJK0IiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gU3BlY2lmaWMgbWV0aG9kcyB0byBmZXRjaCBXYXp1aCBvdmVydmlldyBkYXRhIGZyb20gRWxhc3RpY3NlYXJjaFxuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmltcG9ydCB7IEJhc2UgfSBmcm9tICcuL2Jhc2UtcXVlcnknO1xuaW1wb3J0IHsgZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSB9IGZyb20gJy4uLy4uLy4uL2NvbW1vbi9zZXJ2aWNlcy9zZXR0aW5ncyc7XG5cbmludGVyZmFjZSBTdW1tYXJ5U2V0dXAge1xuICB0aXRsZTogc3RyaW5nO1xuICBhZ2dzOiBhbnlcbn1cblxuZXhwb3J0IGRlZmF1bHQgY2xhc3MgU3VtbWFyeVRhYmxlIHtcbiAgY29uc3RydWN0b3IoXG4gICAgY29udGV4dCxcbiAgICBndGUsXG4gICAgbHRlLFxuICAgIGZpbHRlcnMsXG4gICAgYWxsb3dlZEFnZW50c0ZpbHRlcixcbiAgICBzdW1tYXJ5U2V0dXA6IFN1bW1hcnlTZXR1cCxcbiAgICBwYXR0ZXJuID0gZ2V0U2V0dGluZ0RlZmF1bHRWYWx1ZSgncGF0dGVybicpXG4gICkge1xuXG4gICAgdGhpcy5fY29udGV4dCA9IGNvbnRleHQ7XG4gICAgdGhpcy5fcGF0dGVybiA9IHBhdHRlcm47XG4gICAgdGhpcy5fc3VtbWFyeVNldHVwID0gc3VtbWFyeVNldHVwO1xuICAgIHRoaXMuX2Jhc2UgPSB7IGFnZ3M6IHt9IH07XG4gICAgdGhpcy5fY29sdW1ucyA9IFtdO1xuICAgIHRoaXMuX3Jvd3MgPSBbXTtcbiAgICB0aGlzLl90aXRsZSA9IHN1bW1hcnlTZXR1cC50aXRsZTtcblxuICAgIE9iamVjdC5hc3NpZ24odGhpcy5fYmFzZSwgQmFzZShwYXR0ZXJuLCBmaWx0ZXJzLCBndGUsIGx0ZSwgYWxsb3dlZEFnZW50c0ZpbHRlcikpO1xuXG4gICAgdGhpcy5fcGFyc2VTdW1tYXJ5U2V0dXAoc3VtbWFyeVNldHVwKTtcblxuICB9XG5cbiAgLyoqXG4gICAqIFBhcnNlIHRoZSBzdW1tYXJ5IHRhYmxlIHNldHVwIHRvIGJ1aWxkIHRoZSBxdWVyeVxuICAgKiBAcGFyYW0gc3VtbWFyeVNldHVwXG4gICAqL1xuICBfcGFyc2VTdW1tYXJ5U2V0dXAoc3VtbWFyeVNldHVwOiBTdW1tYXJ5U2V0dXApIHtcbiAgICBsZXQgYmFzZUFnZ1JlZiA9IHRoaXMuX2Jhc2UuYWdncztcbiAgICBzdW1tYXJ5U2V0dXAuYWdncy5mb3JFYWNoKChhZ2csIGtleSkgPT4ge1xuICAgICAgdGhpcy5fY29sdW1ucy5wdXNoKGFnZy5jdXN0b21MYWJlbCk7XG4gICAgICB0aGlzLl9wYXJzZUFnZ3JlZ2F0aW9uKGJhc2VBZ2dSZWYsIGFnZywga2V5KTtcblxuICAgICAgaWYgKHN1bW1hcnlTZXR1cC5hZ2dzLmxlbmd0aCA+IGtleSArIDEpIHtcbiAgICAgICAgYmFzZUFnZ1JlZltgJHtrZXkgKyAyfWBdLmFnZ3MgPSB7fTtcbiAgICAgICAgYmFzZUFnZ1JlZiA9IGJhc2VBZ2dSZWZbYCR7a2V5ICsgMn1gXS5hZ2dzO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgdGhpcy5fY29sdW1ucy5wdXNoKCdDb3VudCcpO1xuICAgICAgfVxuICAgIH0sIHRoaXMpO1xuICB9XG5cbiAgLyoqXG4gICAqIFBhcnNlIGVhY2ggYWdncmVnYXRpb24gdG8gYnVpbGQgdGhlIHF1ZXJ5XG4gICAqIEBwYXJhbSBiYXNlQWdnUmVmXG4gICAqIEBwYXJhbSBhZ2dcbiAgICogQHBhcmFtIGtleVxuICAgKi9cbiAgX3BhcnNlQWdncmVnYXRpb24oYmFzZUFnZ1JlZjogYW55LCBhZ2c6IGFueSwga2V5OiBzdHJpbmcpIHtcbiAgICBjb25zdCB7IGZpZWxkLCBzaXplLCBvcmRlciwgbWlzc2luZyB9ID0gYWdnO1xuXG4gICAgYmFzZUFnZ1JlZltgJHtrZXkgKyAyfWBdID0ge1xuICAgICAgdGVybXM6IHtcbiAgICAgICAgZmllbGQsXG4gICAgICAgIG9yZGVyOiB7XG4gICAgICAgICAgX2NvdW50OiBvcmRlclxuICAgICAgICB9LFxuICAgICAgICBzaXplXG4gICAgICB9XG4gICAgfTtcbiAgICBpZiAobWlzc2luZykge1xuICAgICAgYmFzZUFnZ1JlZltgJHtrZXkgKyAyfWBdLnRlcm1zLm1pc3NpbmcgPSBtaXNzaW5nO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBSZXR1cm5zIHRoZSByZXNwb25zZSBmb3JtYXR0ZWQgdG8gYSB0YWJsZVxuICAgKiBAZGVzY3JpcHRpb24gVGhlIHJlc3BvbnNlIGlzIGFuIG9iamVjdCB3aXRoIHRoZSBmb2xsb3dpbmcgc3RydWN0dXJlOntcbiAgICogIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICAgKiAgY29sdW1uczogWydSdWxlIElEJywnRGVzY3JpcHRpb24nLCdMZXZlbCcsICdDb3VudCddLFxuICAgKiAgcm93czogW1xuICAgKiAgICBbJzUwMicsICdPc3NlYyBzZXJ2ZXIgc3RhcnRlZCcsIDMsIDIyXSxcbiAgICogICAgWyc1MDInLCAnT3NzZWMgc2VydmVyIHN0YXJ0ZWQnLCAzLCAyMl0sXG4gICAqICBdXG4gICAqIH1cbiAgICogQHBhcmFtIHJhd1Jlc3BvbnNlXG4gICAqL1xuICBfZm9ybWF0UmVzcG9uc2VUb1RhYmxlKHJhd1Jlc3BvbnNlKSB7XG4gICAgY29uc3QgZmlyc3RLZXkgPSBwYXJzZUludChPYmplY3Qua2V5cyhyYXdSZXNwb25zZSlbMF0pO1xuXG4gICAgdGhpcy5fcm93cyA9IHJhd1Jlc3BvbnNlW2ZpcnN0S2V5XS5idWNrZXRzLnJlZHVjZSgodG90YWxSb3dzLCBidWNrZXQpID0+IHtcbiAgICAgIGNvbnN0IG5leHRLZXkgPSBmaXJzdEtleSArIDE7XG4gICAgICB0aGlzLl9idWlsZFJvdyhidWNrZXQsIG5leHRLZXksIHRvdGFsUm93cyk7XG4gICAgICByZXR1cm4gdG90YWxSb3dzO1xuICAgIH0sIFtdKTtcblxuICAgIHJldHVybiB7XG4gICAgICByb3dzOiB0aGlzLl9yb3dzLFxuICAgICAgY29sdW1uczogdGhpcy5fY29sdW1ucyxcbiAgICAgIHRpdGxlOiB0aGlzLl90aXRsZSxcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogTWFrZXMgYSByb3cgZnJvbSB0aGUgcmVzcG9uc2VcbiAgICogQHBhcmFtIGJ1Y2tldFxuICAgKiBAcGFyYW0gbmV4dEFnZ0tleVxuICAgKiBAcGFyYW0gcm93XG4gICAqL1xuICBfYnVpbGRSb3coYnVja2V0OiBhbnksIG5leHRBZ2dLZXk6IG51bWJlciwgdG90YWxSb3dzOiBhbnlbXSwgcm93OiBhbnlbXSA9IFtdKTogYW55W10ge1xuICAgIGNvbnN0IG5ld1JvdyA9IFsuLi5yb3csIGJ1Y2tldC5rZXldO1xuICAgIC8vIElmIHRoZXJlIGlzIGEgbmV4dCBhZ2dyZWdhdGlvbiwgcmVwZWF0IHRoZSBwcm9jZXNzXG4gICAgaWYgKGJ1Y2tldFtuZXh0QWdnS2V5LnRvU3RyaW5nKCldPy5idWNrZXRzPy5sZW5ndGgpIHtcbiAgICAgIGJ1Y2tldFtuZXh0QWdnS2V5LnRvU3RyaW5nKCldLmJ1Y2tldHMuZm9yRWFjaChuZXdCdWNrZXQgPT4ge1xuICAgICAgICB0aGlzLl9idWlsZFJvdyhuZXdCdWNrZXQsIChuZXh0QWdnS2V5ICsgMSksIHRvdGFsUm93cywgbmV3Um93KTtcbiAgICAgIH0pO1xuICAgIH1cbiAgICAvLyBBZGQgdGhlIENvdW50IGFzIHRoZSBsYXN0IGl0ZW0gaW4gdGhlIHJvd1xuICAgIGVsc2UgaWYgKGJ1Y2tldC5kb2NfY291bnQpIHtcbiAgICAgIG5ld1Jvdy5wdXNoKGJ1Y2tldC5kb2NfY291bnQpO1xuICAgICAgdG90YWxSb3dzLnB1c2gobmV3Um93KTtcbiAgICB9XG4gIH1cblxuICAvKipcbiAgICogRXhlY3V0ZXMgdGhlIHF1ZXJ5IGFuZCByZXR1cm5zIHRoZSByZXNwb25zZVxuICAgKi9cbiAgYXN5bmMgZmV0Y2goKSB7XG4gICAgdHJ5IHtcbiAgICAgIGNvbnN0IHJlc3BvbnNlID0gYXdhaXQgdGhpcy5fY29udGV4dC5jb3JlLmVsYXN0aWNzZWFyY2guY2xpZW50LmFzQ3VycmVudFVzZXIuc2VhcmNoKHtcbiAgICAgICAgaW5kZXg6IHRoaXMuX3BhdHRlcm4sXG4gICAgICAgIGJvZHk6IHRoaXMuX2Jhc2VcbiAgICAgIH0pO1xuICAgICAgY29uc3QgYWxlcnRzVGFibGUgPSB0aGlzLl9mb3JtYXRSZXNwb25zZVRvVGFibGUocmVzcG9uc2UuYm9keS5hZ2dyZWdhdGlvbnMpO1xuICAgICAgcmV0dXJuIGFsZXJ0c1RhYmxlO1xuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xuICAgIH1cbiAgfVxuXG59XG4iXX0=