"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Agents/GitHub visualizations
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
var _default = [{
  _id: 'Wazuh-App-Agents-GitHub-Alerts-Evolution-By-Organization',
  _source: {
    title: 'Alerts evolution by organization',
    visState: JSON.stringify({
      "title": "Alerts evolution by organization",
      "type": "area",
      "aggs": [{
        "id": "1",
        "enabled": true,
        "type": "count",
        "params": {},
        "schema": "metric"
      }, {
        "id": "2",
        "enabled": true,
        "type": "date_histogram",
        "params": {
          "field": "timestamp",
          "timeRange": {
            "from": "now-7d",
            "to": "now"
          },
          "useNormalizedEsInterval": true,
          "scaleMetricValues": false,
          "interval": "auto",
          "drop_partials": false,
          "min_doc_count": 1,
          "extended_bounds": {},
          "customLabel": ""
        },
        "schema": "segment"
      }, {
        "id": "3",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "data.github.org",
          "orderBy": "1",
          "order": "desc",
          "size": 5,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "group"
      }],
      "params": {
        "type": "area",
        "grid": {
          "categoryLines": false
        },
        "categoryAxes": [{
          "id": "CategoryAxis-1",
          "type": "category",
          "position": "bottom",
          "show": true,
          "style": {},
          "scale": {
            "type": "linear"
          },
          "labels": {
            "show": true,
            "filter": true,
            "truncate": 100,
            "rotate": 0
          },
          "title": {}
        }],
        "valueAxes": [{
          "id": "ValueAxis-1",
          "name": "LeftAxis-1",
          "type": "value",
          "position": "left",
          "show": true,
          "style": {},
          "scale": {
            "type": "linear",
            "mode": "normal"
          },
          "labels": {
            "show": true,
            "rotate": 0,
            "filter": false,
            "truncate": 100
          },
          "title": {
            "text": "Count"
          }
        }],
        "seriesParams": [{
          "show": true,
          "type": "line",
          "mode": "normal",
          "data": {
            "label": "Count",
            "id": "1"
          },
          "drawLinesBetweenPoints": true,
          "lineWidth": 2,
          "showCircles": true,
          "interpolate": "linear",
          "valueAxis": "ValueAxis-1"
        }],
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": false,
        "thresholdLine": {
          "show": false,
          "value": 10,
          "width": 1,
          "style": "full",
          "color": "#E7664C"
        },
        "labels": {},
        "orderBucketsBySum": false
      }
    }),
    uiStateJSON: '',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-GitHub-Top-5-Organizations-By-Alerts',
  _source: {
    title: 'Top 5 organizations by alerts',
    visState: JSON.stringify({
      "title": "Top 5 organizations by alerts",
      "type": "pie",
      "aggs": [{
        "id": "1",
        "enabled": true,
        "type": "count",
        "params": {},
        "schema": "metric"
      }, {
        "id": "2",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "data.github.org",
          "orderBy": "1",
          "order": "desc",
          "size": 5,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "segment"
      }],
      "params": {
        "type": "pie",
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "isDonut": false,
        "labels": {
          "show": false,
          "values": true,
          "last_level": true,
          "truncate": 100
        }
      }
    }),
    uiStateJSON: '',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-GitHub-Users-With-More-Alerts',
  _source: {
    title: 'Users with more alerts',
    visState: JSON.stringify({
      "title": "Users with more alerts",
      "type": "line",
      "aggs": [{
        "id": "1",
        "enabled": true,
        "type": "count",
        "params": {},
        "schema": "metric"
      }, {
        "id": "4",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "data.github.org",
          "orderBy": "1",
          "order": "desc",
          "size": 5,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "segment"
      }, {
        "id": "3",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "data.github.actor",
          "orderBy": "1",
          "order": "desc",
          "size": 5,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "group"
      }],
      "params": {
        "type": "line",
        "grid": {
          "categoryLines": false
        },
        "categoryAxes": [{
          "id": "CategoryAxis-1",
          "type": "category",
          "position": "bottom",
          "show": true,
          "style": {},
          "scale": {
            "type": "linear"
          },
          "labels": {
            "show": true,
            "filter": true,
            "truncate": 100
          },
          "title": {}
        }],
        "valueAxes": [{
          "id": "ValueAxis-1",
          "name": "LeftAxis-1",
          "type": "value",
          "position": "left",
          "show": true,
          "style": {},
          "scale": {
            "type": "linear",
            "mode": "normal"
          },
          "labels": {
            "show": true,
            "rotate": 0,
            "filter": false,
            "truncate": 100
          },
          "title": {
            "text": "Count"
          }
        }],
        "seriesParams": [{
          "show": true,
          "type": "histogram",
          "mode": "stacked",
          "data": {
            "label": "Count",
            "id": "1"
          },
          "valueAxis": "ValueAxis-1",
          "drawLinesBetweenPoints": true,
          "lineWidth": 2,
          "interpolate": "linear",
          "showCircles": true
        }],
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": false,
        "labels": {},
        "thresholdLine": {
          "show": false,
          "value": 10,
          "width": 1,
          "style": "full",
          "color": "#E7664C"
        }
      }
    }),
    uiStateJSON: '',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-GitHub-Alert-Action-Type-By-Organization',
  _source: {
    title: 'Top alerts by alert action type and organization',
    visState: JSON.stringify({
      "title": "Top alerts by alert action type and organization",
      "type": "pie",
      "aggs": [{
        "id": "1",
        "enabled": true,
        "type": "count",
        "params": {},
        "schema": "metric"
      }, {
        "id": "3",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "data.github.org",
          "orderBy": "1",
          "order": "desc",
          "size": 5,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "segment"
      }, {
        "id": "2",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "data.github.action",
          "orderBy": "1",
          "order": "desc",
          "size": 3,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "segment"
      }],
      "params": {
        "type": "pie",
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "isDonut": true,
        "labels": {
          "show": false,
          "values": true,
          "last_level": true,
          "truncate": 100
        }
      }
    }),
    uiStateJSON: '',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-GitHub-Alert-Summary',
  _source: {
    title: 'Alerts summary',
    visState: JSON.stringify({
      "title": "Alerts summary",
      "type": "table",
      "aggs": [{
        "id": "1",
        "enabled": true,
        "type": "count",
        "params": {},
        "schema": "metric"
      }, {
        "id": "2",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "agent.name",
          "orderBy": "1",
          "order": "desc",
          "size": 50,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "bucket"
      }, {
        "id": "3",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "data.github.org",
          "orderBy": "1",
          "order": "desc",
          "size": 10,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "bucket"
      }, {
        "id": "4",
        "enabled": true,
        "type": "terms",
        "params": {
          "field": "rule.description",
          "orderBy": "1",
          "order": "desc",
          "size": 10,
          "otherBucket": false,
          "otherBucketLabel": "Other",
          "missingBucket": false,
          "missingBucketLabel": "Missing"
        },
        "schema": "bucket"
      }],
      "params": {
        "perPage": 10,
        "showPartialRows": false,
        "showMetricsAtAllLevels": false,
        "sort": {
          "columnIndex": null,
          "direction": null
        },
        "showTotal": false,
        "totalFunc": "sum",
        "percentageCol": ""
      }
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        params: {
          sort: {
            columnIndex: 3,
            direction: 'desc'
          }
        }
      }
    }),
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy1naXRodWIudHMiXSwibmFtZXMiOlsiX2lkIiwiX3NvdXJjZSIsInRpdGxlIiwidmlzU3RhdGUiLCJKU09OIiwic3RyaW5naWZ5IiwidWlTdGF0ZUpTT04iLCJkZXNjcmlwdGlvbiIsInZlcnNpb24iLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiX3R5cGUiLCJ2aXMiLCJwYXJhbXMiLCJzb3J0IiwiY29sdW1uSW5kZXgiLCJkaXJlY3Rpb24iXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO2VBRWUsQ0FDYjtBQUNFQSxFQUFBQSxHQUFHLEVBQUUsMERBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxrQ0FEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCLGVBQVMsa0NBRGM7QUFFdkIsY0FBUSxNQUZlO0FBR3ZCLGNBQVEsQ0FDTjtBQUNFLGNBQU0sR0FEUjtBQUVFLG1CQUFXLElBRmI7QUFHRSxnQkFBUSxPQUhWO0FBSUUsa0JBQVUsRUFKWjtBQUtFLGtCQUFVO0FBTFosT0FETSxFQVFOO0FBQ0UsY0FBTSxHQURSO0FBRUUsbUJBQVcsSUFGYjtBQUdFLGdCQUFRLGdCQUhWO0FBSUUsa0JBQVU7QUFDUixtQkFBUyxXQUREO0FBRVIsdUJBQWE7QUFDWCxvQkFBUSxRQURHO0FBRVgsa0JBQU07QUFGSyxXQUZMO0FBTVIscUNBQTJCLElBTm5CO0FBT1IsK0JBQXFCLEtBUGI7QUFRUixzQkFBWSxNQVJKO0FBU1IsMkJBQWlCLEtBVFQ7QUFVUiwyQkFBaUIsQ0FWVDtBQVdSLDZCQUFtQixFQVhYO0FBWVIseUJBQWU7QUFaUCxTQUpaO0FBa0JFLGtCQUFVO0FBbEJaLE9BUk0sRUE0Qk47QUFDRSxjQUFNLEdBRFI7QUFFRSxtQkFBVyxJQUZiO0FBR0Us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O0FBRlAsU0FKQTtBQVFSLHFCQUFhLEtBUkw7QUFTUixxQkFBYSxLQVRMO0FBVVIseUJBQWlCO0FBVlQ7QUE1RGEsS0FBZixDQUZIO0FBMkVQQyxJQUFBQSxXQUFXLEVBQUVGLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQzFCTyxNQUFBQSxHQUFHLEVBQUU7QUFBRUMsUUFBQUEsTUFBTSxFQUFFO0FBQUVDLFVBQUFBLElBQUksRUFBRTtBQUFFQyxZQUFBQSxXQUFXLEVBQUUsQ0FBZjtBQUFrQkMsWUFBQUEsU0FBUyxFQUFFO0FBQTdCO0FBQVI7QUFBVjtBQURxQixLQUFmLENBM0VOO0FBOEVQVCxJQUFBQSxXQUFXLEVBQUUsRUE5RU47QUErRVBDLElBQUFBLE9BQU8sRUFBRSxDQS9FRjtBQWdGUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUFFO0FBREc7QUFoRmhCLEdBRlg7QUFzRkVDLEVBQUFBLEtBQUssRUFBRTtBQXRGVCxDQWpaYSxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgQWdlbnRzL0dpdEh1YiB2aXN1YWxpemF0aW9uc1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cblxuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1HaXRIdWItQWxlcnRzLUV2b2x1dGlvbi1CeS1Pcmdhbml6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQWxlcnRzIGV2b2x1dGlvbiBieSBvcmdhbml6YXRpb24nLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgXCJ0aXRsZVwiOiBcIkFsZXJ0cyBldm9sdXRpb24gYnkgb3JnYW5pemF0aW9uXCIsXG4gICAgICAgIFwidHlwZVwiOiBcImFyZWFcIixcbiAgICAgICAgXCJhZ2dzXCI6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiMVwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJjb3VudFwiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge30sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcIm1ldHJpY1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiMlwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJkYXRlX2hpc3RvZ3JhbVwiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge1xuICAgICAgICAgICAgICBcImZpZWxkXCI6IFwidGltZXN0YW1wXCIsXG4gICAgICAgICAgICAgIFwidGltZVJhbmdlXCI6IHtcbiAgICAgICAgICAgICAgICBcImZyb21cIjogXCJub3ctN2RcIixcbiAgICAgICAgICAgICAgICBcInRvXCI6IFwibm93XCJcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgXCJ1c2VOb3JtYWxpemVkRXNJbnRlcnZhbFwiOiB0cnVlLFxuICAgICAgICAgICAgICBcInNjYWxlTWV0cmljVmFsdWVzXCI6IGZhbHNlLFxuICAgICAgICAgICAgICBcImludGVydmFsXCI6IFwiYXV0b1wiLFxuICAgICAgICAgICAgICBcImRyb3BfcGFydGlhbHNcIjogZmFsc2UsXG4gICAgICAgICAgICAgIFwibWluX2RvY19jb3VudFwiOiAxLFxuICAgICAgICAgICAgICBcImV4dGVuZGVkX2JvdW5kc1wiOiB7fSxcbiAgICAgICAgICAgICAgXCJjdXN0b21MYWJlbFwiOiBcIlwiXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgXCJzY2hlbWFcIjogXCJzZWdtZW50XCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIFwiaWRcIjogXCIzXCIsXG4gICAgICAgICAgICBcImVuYWJsZWRcIjogdHJ1ZSxcbiAgICAgICAgICAgIFwidHlwZVwiOiBcInRlcm1zXCIsXG4gICAgICAgICAgICBcInBhcmFtc1wiOiB7XG4gICAgICAgICAgICAgIFwiZmllbGRcIjogXCJkYXRhLmdpdGh1Yi5vcmdcIixcbiAgICAgICAgICAgICAgXCJvcmRlckJ5XCI6IFwiMVwiLFxuICAgICAgICAgICAgICBcIm9yZGVyXCI6IFwiZGVzY1wiLFxuICAgICAgICAgICAgICBcInNpemVcIjogNSxcbiAgICAgICAgICAgICAgXCJvdGhlckJ1Y2tldFwiOiBmYWxzZSxcbiAgICAgICAgICAgICAgXCJvdGhlckJ1Y2tldExhYmVsXCI6IFwiT3RoZXJcIixcbiAgICAgICAgICAgICAgXCJtaXNzaW5nQnVja2V0XCI6IGZhbHNlLFxuICAgICAgICAgICAgICBcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOiBcIk1pc3NpbmdcIlxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIFwic2NoZW1hXCI6IFwiZ3JvdXBcIlxuICAgICAgICAgIH1cbiAgICAgICAgXSxcbiAgICAgICAgXCJwYXJhbXNcIjoge1xuICAgICAgICAgIFwidHlwZVwiOiBcImFyZWFcIixcbiAgICAgICAgICBcImdyaWRcIjoge1xuICAgICAgICAgICAgXCJjYXRlZ29yeUxpbmVzXCI6IGZhbHNlXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImNhdGVnb3J5QXhlc1wiOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIFwiaWRcIjogXCJDYXRlZ29yeUF4aXMtMVwiLFxuICAgICAgICAgICAgICBcInR5cGVcIjogXCJjYXRlZ29yeVwiLFxuICAgICAgICAgICAgICBcInBvc2l0aW9uXCI6IFwiYm90dG9tXCIsXG4gICAgICAgICAgICAgIFwic2hvd1wiOiB0cnVlLFxuICAgICAgICAgICAgICBcInN0eWxlXCI6IHt9LFxuICAgICAgICAgICAgICBcInNjYWxlXCI6IHtcbiAgICAgICAgICAgICAgICBcInR5cGVcIjogXCJsaW5lYXJcIlxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBcImxhYmVsc1wiOiB7XG4gICAgICAgICAgICAgICAgXCJzaG93XCI6IHRydWUsXG4gICAgICAgICAgICAgICAgXCJmaWx0ZXJcIjogdHJ1ZSxcbiAgICAgICAgICAgICAgICBcInRydW5jYXRlXCI6IDEwMCxcbiAgICAgICAgICAgICAgICBcInJvdGF0ZVwiOiAwXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwidGl0bGVcIjoge31cbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdLFxuICAgICAgICAgIFwidmFsdWVBeGVzXCI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgXCJpZFwiOiBcIlZhbHVlQXhpcy0xXCIsXG4gICAgICAgICAgICAgIFwibmFtZVwiOiBcIkxlZnRBeGlzLTFcIixcbiAgICAgICAgICAgICAgXCJ0eXBlXCI6IFwidmFsdWVcIixcbiAgICAgICAgICAgICAgXCJwb3NpdGlvblwiOiBcImxlZnRcIixcbiAgICAgICAgICAgICAgXCJzaG93XCI6IHRydWUsXG4gICAgICAgICAgICAgIFwic3R5bGVcIjoge30sXG4gICAgICAgICAgICAgIFwic2NhbGVcIjoge1xuICAgICAgICAgICAgICAgIFwidHlwZVwiOiBcImxpbmVhclwiLFxuICAgICAgICAgICAgICAgIFwibW9kZVwiOiBcIm5vcm1hbFwiXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwibGFiZWxzXCI6IHtcbiAgICAgICAgICAgICAgICBcInNob3dcIjogdHJ1ZSxcbiAgICAgICAgICAgICAgICBcInJvdGF0ZVwiOiAwLFxuICAgICAgICAgICAgICAgIFwiZmlsdGVyXCI6IGZhbHNlLFxuICAgICAgICAgICAgICAgIFwidHJ1bmNhdGVcIjogMTAwXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwidGl0bGVcIjoge1xuICAgICAgICAgICAgICAgIFwidGV4dFwiOiBcIkNvdW50XCJcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICAgIF0sXG4gICAgICAgICAgXCJzZXJpZXNQYXJhbXNcIjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBcInNob3dcIjogdHJ1ZSxcbiAgICAgICAgICAgICAgXCJ0eXBlXCI6IFwibGluZVwiLFxuICAgICAgICAgICAgICBcIm1vZGVcIjogXCJub3JtYWxcIixcbiAgICAgICAgICAgICAgXCJkYXRhXCI6IHtcbiAgICAgICAgICAgICAgICBcImxhYmVsXCI6IFwiQ291bnRcIixcbiAgICAgICAgICAgICAgICBcImlkXCI6IFwiMVwiXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIFwiZHJhd0xpbmVzQmV0d2VlblBvaW50c1wiOiB0cnVlLFxuICAgICAgICAgICAgICBcImxpbmVXaWR0aFwiOiAyLFxuICAgICAgICAgICAgICBcInNob3dDaXJjbGVzXCI6IHRydWUsXG4gICAgICAgICAgICAgIFwiaW50ZXJwb2xhdGVcIjogXCJsaW5lYXJcIixcbiAgICAgICAgICAgICAgXCJ2YWx1ZUF4aXNcIjogXCJWYWx1ZUF4aXMtMVwiXG4gICAgICAgICAgICB9XG4gICAgICAgICAgXSxcbiAgICAgICAgICBcImFkZFRvb2x0aXBcIjogdHJ1ZSxcbiAgICAgICAgICBcImFkZExlZ2VuZFwiOiB0cnVlLFxuICAgICAgICAgIFwibGVnZW5kUG9zaXRpb25cIjogXCJyaWdodFwiLFxuICAgICAgICAgIFwidGltZXNcIjogW10sXG4gICAgICAgICAgXCJhZGRUaW1lTWFya2VyXCI6IGZhbHNlLFxuICAgICAgICAgIFwidGhyZXNob2xkTGluZVwiOiB7XG4gICAgICAgICAgICBcInNob3dcIjogZmFsc2UsXG4gICAgICAgICAgICBcInZhbHVlXCI6IDEwLFxuICAgICAgICAgICAgXCJ3aWR0aFwiOiAxLFxuICAgICAgICAgICAgXCJzdHlsZVwiOiBcImZ1bGxcIixcbiAgICAgICAgICAgIFwiY29sb3JcIjogXCIjRTc2NjRDXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwibGFiZWxzXCI6IHt9LFxuICAgICAgICAgIFwib3JkZXJCdWNrZXRzQnlTdW1cIjogZmFsc2VcbiAgICAgICAgfVxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJycsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046ICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wicXVlcnlcIjpcIlwiLFwibGFuZ3VhZ2VcIjpcImx1Y2VuZVwifX0nLFxuICAgICAgfVxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtR2l0SHViLVRvcC01LU9yZ2FuaXphdGlvbnMtQnktQWxlcnRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IG9yZ2FuaXphdGlvbnMgYnkgYWxlcnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIFwidGl0bGVcIjogXCJUb3AgNSBvcmdhbml6YXRpb25zIGJ5IGFsZXJ0c1wiLFxuICAgICAgICBcInR5cGVcIjogXCJwaWVcIixcbiAgICAgICAgXCJhZ2dzXCI6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiMVwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJjb3VudFwiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge30sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcIm1ldHJpY1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiMlwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJ0ZXJtc1wiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge1xuICAgICAgICAgICAgICBcImZpZWxkXCI6IFwiZGF0YS5naXRodWIub3JnXCIsXG4gICAgICAgICAgICAgIFwib3JkZXJCeVwiOiBcIjFcIixcbiAgICAgICAgICAgICAgXCJvcmRlclwiOiBcImRlc2NcIixcbiAgICAgICAgICAgICAgXCJzaXplXCI6IDUsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRcIjogZmFsc2UsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRMYWJlbFwiOiBcIk90aGVyXCIsXG4gICAgICAgICAgICAgIFwibWlzc2luZ0J1Y2tldFwiOiBmYWxzZSxcbiAgICAgICAgICAgICAgXCJtaXNzaW5nQnVja2V0TGFiZWxcIjogXCJNaXNzaW5nXCJcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcInNlZ21lbnRcIlxuICAgICAgICAgIH1cbiAgICAgICAgXSxcbiAgICAgICAgXCJwYXJhbXNcIjoge1xuICAgICAgICAgIFwidHlwZVwiOiBcInBpZVwiLFxuICAgICAgICAgIFwiYWRkVG9vbHRpcFwiOiB0cnVlLFxuICAgICAgICAgIFwiYWRkTGVnZW5kXCI6IHRydWUsXG4gICAgICAgICAgXCJsZWdlbmRQb3NpdGlvblwiOiBcInJpZ2h0XCIsXG4gICAgICAgICAgXCJpc0RvbnV0XCI6IGZhbHNlLFxuICAgICAgICAgIFwibGFiZWxzXCI6IHtcbiAgICAgICAgICAgIFwic2hvd1wiOiBmYWxzZSxcbiAgICAgICAgICAgIFwidmFsdWVzXCI6IHRydWUsXG4gICAgICAgICAgICBcImxhc3RfbGV2ZWxcIjogdHJ1ZSxcbiAgICAgICAgICAgIFwidHJ1bmNhdGVcIjogMTAwXG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAnJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogJ3tcImluZGV4XCI6XCJ3YXp1aC1hbGVydHNcIixcImZpbHRlclwiOltdLFwicXVlcnlcIjp7XCJxdWVyeVwiOlwiXCIsXCJsYW5ndWFnZVwiOlwibHVjZW5lXCJ9fScsXG4gICAgICB9XG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1HaXRIdWItVXNlcnMtV2l0aC1Nb3JlLUFsZXJ0cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdVc2VycyB3aXRoIG1vcmUgYWxlcnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIFwidGl0bGVcIjogXCJVc2VycyB3aXRoIG1vcmUgYWxlcnRzXCIsXG4gICAgICAgIFwidHlwZVwiOiBcImxpbmVcIixcbiAgICAgICAgXCJhZ2dzXCI6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiMVwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJjb3VudFwiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge30sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcIm1ldHJpY1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiNFwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJ0ZXJtc1wiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge1xuICAgICAgICAgICAgICBcImZpZWxkXCI6IFwiZGF0YS5naXRodWIub3JnXCIsXG4gICAgICAgICAgICAgIFwib3JkZXJCeVwiOiBcIjFcIixcbiAgICAgICAgICAgICAgXCJvcmRlclwiOiBcImRlc2NcIixcbiAgICAgICAgICAgICAgXCJzaXplXCI6IDUsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRcIjogZmFsc2UsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRMYWJlbFwiOiBcIk90aGVyXCIsXG4gICAgICAgICAgICAgIFwibWlzc2luZ0J1Y2tldFwiOiBmYWxzZSxcbiAgICAgICAgICAgICAgXCJtaXNzaW5nQnVja2V0TGFiZWxcIjogXCJNaXNzaW5nXCJcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcInNlZ21lbnRcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgXCJpZFwiOiBcIjNcIixcbiAgICAgICAgICAgIFwiZW5hYmxlZFwiOiB0cnVlLFxuICAgICAgICAgICAgXCJ0eXBlXCI6IFwidGVybXNcIixcbiAgICAgICAgICAgIFwicGFyYW1zXCI6IHtcbiAgICAgICAgICAgICAgXCJmaWVsZFwiOiBcImRhdGEuZ2l0aHViLmFjdG9yXCIsXG4gICAgICAgICAgICAgIFwib3JkZXJCeVwiOiBcIjFcIixcbiAgICAgICAgICAgICAgXCJvcmRlclwiOiBcImRlc2NcIixcbiAgICAgICAgICAgICAgXCJzaXplXCI6IDUsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRcIjogZmFsc2UsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRMYWJlbFwiOiBcIk90aGVyXCIsXG4gICAgICAgICAgICAgIFwibWlzc2luZ0J1Y2tldFwiOiBmYWxzZSxcbiAgICAgICAgICAgICAgXCJtaXNzaW5nQnVja2V0TGFiZWxcIjogXCJNaXNzaW5nXCJcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcImdyb3VwXCJcbiAgICAgICAgICB9XG4gICAgICAgIF0sXG4gICAgICAgIFwicGFyYW1zXCI6IHtcbiAgICAgICAgICBcInR5cGVcIjogXCJsaW5lXCIsXG4gICAgICAgICAgXCJncmlkXCI6IHtcbiAgICAgICAgICAgIFwiY2F0ZWdvcnlMaW5lc1wiOiBmYWxzZVxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJjYXRlZ29yeUF4ZXNcIjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBcImlkXCI6IFwiQ2F0ZWdvcnlBeGlzLTFcIixcbiAgICAgICAgICAgICAgXCJ0eXBlXCI6IFwiY2F0ZWdvcnlcIixcbiAgICAgICAgICAgICAgXCJwb3NpdGlvblwiOiBcImJvdHRvbVwiLFxuICAgICAgICAgICAgICBcInNob3dcIjogdHJ1ZSxcbiAgICAgICAgICAgICAgXCJzdHlsZVwiOiB7fSxcbiAgICAgICAgICAgICAgXCJzY2FsZVwiOiB7XG4gICAgICAgICAgICAgICAgXCJ0eXBlXCI6IFwibGluZWFyXCJcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgXCJsYWJlbHNcIjoge1xuICAgICAgICAgICAgICAgIFwic2hvd1wiOiB0cnVlLFxuICAgICAgICAgICAgICAgIFwiZmlsdGVyXCI6IHRydWUsXG4gICAgICAgICAgICAgICAgXCJ0cnVuY2F0ZVwiOiAxMDBcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgXCJ0aXRsZVwiOiB7fVxuICAgICAgICAgICAgfVxuICAgICAgICAgIF0sXG4gICAgICAgICAgXCJ2YWx1ZUF4ZXNcIjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBcImlkXCI6IFwiVmFsdWVBeGlzLTFcIixcbiAgICAgICAgICAgICAgXCJuYW1lXCI6IFwiTGVmdEF4aXMtMVwiLFxuICAgICAgICAgICAgICBcInR5cGVcIjogXCJ2YWx1ZVwiLFxuICAgICAgICAgICAgICBcInBvc2l0aW9uXCI6IFwibGVmdFwiLFxuICAgICAgICAgICAgICBcInNob3dcIjogdHJ1ZSxcbiAgICAgICAgICAgICAgXCJzdHlsZVwiOiB7fSxcbiAgICAgICAgICAgICAgXCJzY2FsZVwiOiB7XG4gICAgICAgICAgICAgICAgXCJ0eXBlXCI6IFwibGluZWFyXCIsXG4gICAgICAgICAgICAgICAgXCJtb2RlXCI6IFwibm9ybWFsXCJcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgXCJsYWJlbHNcIjoge1xuICAgICAgICAgICAgICAgIFwic2hvd1wiOiB0cnVlLFxuICAgICAgICAgICAgICAgIFwicm90YXRlXCI6IDAsXG4gICAgICAgICAgICAgICAgXCJmaWx0ZXJcIjogZmFsc2UsXG4gICAgICAgICAgICAgICAgXCJ0cnVuY2F0ZVwiOiAxMDBcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgXCJ0aXRsZVwiOiB7XG4gICAgICAgICAgICAgICAgXCJ0ZXh0XCI6IFwiQ291bnRcIlxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgICAgXSxcbiAgICAgICAgICBcInNlcmllc1BhcmFtc1wiOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIFwic2hvd1wiOiB0cnVlLFxuICAgICAgICAgICAgICBcInR5cGVcIjogXCJoaXN0b2dyYW1cIixcbiAgICAgICAgICAgICAgXCJtb2RlXCI6IFwic3RhY2tlZFwiLFxuICAgICAgICAgICAgICBcImRhdGFcIjoge1xuICAgICAgICAgICAgICAgIFwibGFiZWxcIjogXCJDb3VudFwiLFxuICAgICAgICAgICAgICAgIFwiaWRcIjogXCIxXCJcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgXCJ2YWx1ZUF4aXNcIjogXCJWYWx1ZUF4aXMtMVwiLFxuICAgICAgICAgICAgICBcImRyYXdMaW5lc0JldHdlZW5Qb2ludHNcIjogdHJ1ZSxcbiAgICAgICAgICAgICAgXCJsaW5lV2lkdGhcIjogMixcbiAgICAgICAgICAgICAgXCJpbnRlcnBvbGF0ZVwiOiBcImxpbmVhclwiLFxuICAgICAgICAgICAgICBcInNob3dDaXJjbGVzXCI6IHRydWVcbiAgICAgICAgICAgIH1cbiAgICAgICAgICBdLFxuICAgICAgICAgIFwiYWRkVG9vbHRpcFwiOiB0cnVlLFxuICAgICAgICAgIFwiYWRkTGVnZW5kXCI6IHRydWUsXG4gICAgICAgICAgXCJsZWdlbmRQb3NpdGlvblwiOiBcInJpZ2h0XCIsXG4gICAgICAgICAgXCJ0aW1lc1wiOiBbXSxcbiAgICAgICAgICBcImFkZFRpbWVNYXJrZXJcIjogZmFsc2UsXG4gICAgICAgICAgXCJsYWJlbHNcIjoge30sXG4gICAgICAgICAgXCJ0aHJlc2hvbGRMaW5lXCI6IHtcbiAgICAgICAgICAgIFwic2hvd1wiOiBmYWxzZSxcbiAgICAgICAgICAgIFwidmFsdWVcIjogMTAsXG4gICAgICAgICAgICBcIndpZHRoXCI6IDEsXG4gICAgICAgICAgICBcInN0eWxlXCI6IFwiZnVsbFwiLFxuICAgICAgICAgICAgXCJjb2xvclwiOiBcIiNFNzY2NENcIlxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJycsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046ICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wicXVlcnlcIjpcIlwiLFwibGFuZ3VhZ2VcIjpcImx1Y2VuZVwifX0nLFxuICAgICAgfVxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtR2l0SHViLUFsZXJ0LUFjdGlvbi1UeXBlLUJ5LU9yZ2FuaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgYWxlcnRzIGJ5IGFsZXJ0IGFjdGlvbiB0eXBlIGFuZCBvcmdhbml6YXRpb24nLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgXCJ0aXRsZVwiOiBcIlRvcCBhbGVydHMgYnkgYWxlcnQgYWN0aW9uIHR5cGUgYW5kIG9yZ2FuaXphdGlvblwiLFxuICAgICAgICBcInR5cGVcIjogXCJwaWVcIixcbiAgICAgICAgXCJhZ2dzXCI6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiMVwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJjb3VudFwiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge30sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcIm1ldHJpY1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiM1wiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJ0ZXJtc1wiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge1xuICAgICAgICAgICAgICBcImZpZWxkXCI6IFwiZGF0YS5naXRodWIub3JnXCIsXG4gICAgICAgICAgICAgIFwib3JkZXJCeVwiOiBcIjFcIixcbiAgICAgICAgICAgICAgXCJvcmRlclwiOiBcImRlc2NcIixcbiAgICAgICAgICAgICAgXCJzaXplXCI6IDUsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRcIjogZmFsc2UsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRMYWJlbFwiOiBcIk90aGVyXCIsXG4gICAgICAgICAgICAgIFwibWlzc2luZ0J1Y2tldFwiOiBmYWxzZSxcbiAgICAgICAgICAgICAgXCJtaXNzaW5nQnVja2V0TGFiZWxcIjogXCJNaXNzaW5nXCJcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcInNlZ21lbnRcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgXCJpZFwiOiBcIjJcIixcbiAgICAgICAgICAgIFwiZW5hYmxlZFwiOiB0cnVlLFxuICAgICAgICAgICAgXCJ0eXBlXCI6IFwidGVybXNcIixcbiAgICAgICAgICAgIFwicGFyYW1zXCI6IHtcbiAgICAgICAgICAgICAgXCJmaWVsZFwiOiBcImRhdGEuZ2l0aHViLmFjdGlvblwiLFxuICAgICAgICAgICAgICBcIm9yZGVyQnlcIjogXCIxXCIsXG4gICAgICAgICAgICAgIFwib3JkZXJcIjogXCJkZXNjXCIsXG4gICAgICAgICAgICAgIFwic2l6ZVwiOiAzLFxuICAgICAgICAgICAgICBcIm90aGVyQnVja2V0XCI6IGZhbHNlLFxuICAgICAgICAgICAgICBcIm90aGVyQnVja2V0TGFiZWxcIjogXCJPdGhlclwiLFxuICAgICAgICAgICAgICBcIm1pc3NpbmdCdWNrZXRcIjogZmFsc2UsXG4gICAgICAgICAgICAgIFwibWlzc2luZ0J1Y2tldExhYmVsXCI6IFwiTWlzc2luZ1wiXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgXCJzY2hlbWFcIjogXCJzZWdtZW50XCJcbiAgICAgICAgICB9XG4gICAgICAgIF0sXG4gICAgICAgIFwicGFyYW1zXCI6IHtcbiAgICAgICAgICBcInR5cGVcIjogXCJwaWVcIixcbiAgICAgICAgICBcImFkZFRvb2x0aXBcIjogdHJ1ZSxcbiAgICAgICAgICBcImFkZExlZ2VuZFwiOiB0cnVlLFxuICAgICAgICAgIFwibGVnZW5kUG9zaXRpb25cIjogXCJyaWdodFwiLFxuICAgICAgICAgIFwiaXNEb251dFwiOiB0cnVlLFxuICAgICAgICAgIFwibGFiZWxzXCI6IHtcbiAgICAgICAgICAgIFwic2hvd1wiOiBmYWxzZSxcbiAgICAgICAgICAgIFwidmFsdWVzXCI6IHRydWUsXG4gICAgICAgICAgICBcImxhc3RfbGV2ZWxcIjogdHJ1ZSxcbiAgICAgICAgICAgIFwidHJ1bmNhdGVcIjogMTAwXG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAnJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogJ3tcImluZGV4XCI6XCJ3YXp1aC1hbGVydHNcIixcImZpbHRlclwiOltdLFwicXVlcnlcIjp7XCJxdWVyeVwiOlwiXCIsXCJsYW5ndWFnZVwiOlwibHVjZW5lXCJ9fScsXG4gICAgICB9XG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1HaXRIdWItQWxlcnQtU3VtbWFyeScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICBcInRpdGxlXCI6IFwiQWxlcnRzIHN1bW1hcnlcIixcbiAgICAgICAgXCJ0eXBlXCI6IFwidGFibGVcIixcbiAgICAgICAgXCJhZ2dzXCI6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiMVwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJjb3VudFwiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge30sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcIm1ldHJpY1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiMlwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJ0ZXJtc1wiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge1xuICAgICAgICAgICAgICBcImZpZWxkXCI6IFwiYWdlbnQubmFtZVwiLFxuICAgICAgICAgICAgICBcIm9yZGVyQnlcIjogXCIxXCIsXG4gICAgICAgICAgICAgIFwib3JkZXJcIjogXCJkZXNjXCIsXG4gICAgICAgICAgICAgIFwic2l6ZVwiOiA1MCxcbiAgICAgICAgICAgICAgXCJvdGhlckJ1Y2tldFwiOiBmYWxzZSxcbiAgICAgICAgICAgICAgXCJvdGhlckJ1Y2tldExhYmVsXCI6IFwiT3RoZXJcIixcbiAgICAgICAgICAgICAgXCJtaXNzaW5nQnVja2V0XCI6IGZhbHNlLFxuICAgICAgICAgICAgICBcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOiBcIk1pc3NpbmdcIlxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIFwic2NoZW1hXCI6IFwiYnVja2V0XCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIFwiaWRcIjogXCIzXCIsXG4gICAgICAgICAgICBcImVuYWJsZWRcIjogdHJ1ZSxcbiAgICAgICAgICAgIFwidHlwZVwiOiBcInRlcm1zXCIsXG4gICAgICAgICAgICBcInBhcmFtc1wiOiB7XG4gICAgICAgICAgICAgIFwiZmllbGRcIjogXCJkYXRhLmdpdGh1Yi5vcmdcIixcbiAgICAgICAgICAgICAgXCJvcmRlckJ5XCI6IFwiMVwiLFxuICAgICAgICAgICAgICBcIm9yZGVyXCI6IFwiZGVzY1wiLFxuICAgICAgICAgICAgICBcInNpemVcIjogMTAsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRcIjogZmFsc2UsXG4gICAgICAgICAgICAgIFwib3RoZXJCdWNrZXRMYWJlbFwiOiBcIk90aGVyXCIsXG4gICAgICAgICAgICAgIFwibWlzc2luZ0J1Y2tldFwiOiBmYWxzZSxcbiAgICAgICAgICAgICAgXCJtaXNzaW5nQnVja2V0TGFiZWxcIjogXCJNaXNzaW5nXCJcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBcInNjaGVtYVwiOiBcImJ1Y2tldFwiXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBcImlkXCI6IFwiNFwiLFxuICAgICAgICAgICAgXCJlbmFibGVkXCI6IHRydWUsXG4gICAgICAgICAgICBcInR5cGVcIjogXCJ0ZXJtc1wiLFxuICAgICAgICAgICAgXCJwYXJhbXNcIjoge1xuICAgICAgICAgICAgICBcImZpZWxkXCI6IFwicnVsZS5kZXNjcmlwdGlvblwiLFxuICAgICAgICAgICAgICBcIm9yZGVyQnlcIjogXCIxXCIsXG4gICAgICAgICAgICAgIFwib3JkZXJcIjogXCJkZXNjXCIsXG4gICAgICAgICAgICAgIFwic2l6ZVwiOiAxMCxcbiAgICAgICAgICAgICAgXCJvdGhlckJ1Y2tldFwiOiBmYWxzZSxcbiAgICAgICAgICAgICAgXCJvdGhlckJ1Y2tldExhYmVsXCI6IFwiT3RoZXJcIixcbiAgICAgICAgICAgICAgXCJtaXNzaW5nQnVja2V0XCI6IGZhbHNlLFxuICAgICAgICAgICAgICBcIm1pc3NpbmdCdWNrZXRMYWJlbFwiOiBcIk1pc3NpbmdcIlxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIFwic2NoZW1hXCI6IFwiYnVja2V0XCJcbiAgICAgICAgICB9XG4gICAgICAgIF0sXG4gICAgICAgIFwicGFyYW1zXCI6IHtcbiAgICAgICAgICBcInBlclBhZ2VcIjogMTAsXG4gICAgICAgICAgXCJzaG93UGFydGlhbFJvd3NcIjogZmFsc2UsXG4gICAgICAgICAgXCJzaG93TWV0cmljc0F0QWxsTGV2ZWxzXCI6IGZhbHNlLFxuICAgICAgICAgIFwic29ydFwiOiB7XG4gICAgICAgICAgICBcImNvbHVtbkluZGV4XCI6IG51bGwsXG4gICAgICAgICAgICBcImRpcmVjdGlvblwiOiBudWxsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInNob3dUb3RhbFwiOiBmYWxzZSxcbiAgICAgICAgICBcInRvdGFsRnVuY1wiOiBcInN1bVwiLFxuICAgICAgICAgIFwicGVyY2VudGFnZUNvbFwiOiBcIlwiXG4gICAgICAgIH1cbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiAne1wiaW5kZXhcIjpcIndhenVoLWFsZXJ0c1wiLFwiZmlsdGVyXCI6W10sXCJxdWVyeVwiOntcInF1ZXJ5XCI6XCJcIixcImxhbmd1YWdlXCI6XCJsdWNlbmVcIn19JyxcbiAgICAgIH1cbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH1cbl07XG4iXX0=