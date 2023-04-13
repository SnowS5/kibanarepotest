"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview MITRE visualizations
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
  _id: 'Wazuh-App-Overview-MITRE',
  _source: {
    title: 'Mitre attack count',
    visState: JSON.stringify({
      aggs: [{
        enabled: true,
        id: '1',
        params: {},
        schema: 'metric',
        type: 'count'
      }, {
        enabled: true,
        id: '2',
        params: {
          field: 'rule.mitre.id',
          customLabel: 'Attack ID',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          size: 244
        },
        schema: 'bucket',
        type: 'terms'
      }],
      params: {
        dimensions: {
          buckets: [],
          metrics: [{
            accessor: 0,
            aggType: 'count',
            format: {
              id: 'number'
            },
            params: {}
          }]
        },
        perPage: 10,
        percentageCol: '',
        showMetricsAtAllLevels: false,
        showPartialRows: false,
        showTotal: false,
        showToolbar: true,
        sort: {
          columnIndex: null,
          direction: null
        },
        totalFunc: 'sum'
      },
      title: 'mitre',
      type: 'table'
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [],
        query: {
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-MITRE-Alerts-Evolution',
  _source: {
    title: 'Mitre alerts evolution',
    visState: JSON.stringify({
      title: 'Alert Evolution',
      type: 'line',
      params: {
        type: 'line',
        grid: {
          categoryLines: false
        },
        categoryAxes: [{
          id: 'CategoryAxis-1',
          type: 'category',
          position: 'bottom',
          show: true,
          style: {},
          scale: {
            type: 'linear'
          },
          labels: {
            show: true,
            filter: true,
            truncate: 100
          },
          title: {}
        }],
        valueAxes: [{
          id: 'ValueAxis-1',
          name: 'LeftAxis-1',
          type: 'value',
          position: 'left',
          show: true,
          style: {},
          scale: {
            type: 'linear',
            mode: 'normal'
          },
          labels: {
            show: true,
            rotate: 0,
            filter: false,
            truncate: 100
          },
          title: {
            text: 'Count'
          }
        }],
        seriesParams: [{
          show: 'true',
          type: 'line',
          mode: 'normal',
          data: {
            label: 'Count',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          showCircles: true,
          lineWidth: 2
        }],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false,
        labels: {},
        thresholdLine: {
          show: false,
          value: 10,
          width: 1,
          style: 'full',
          color: '#34130C'
        },
        dimensions: {
          x: {
            accessor: 0,
            format: {
              id: 'date',
              params: {
                pattern: 'YYYY-MM-DD HH:mm'
              }
            },
            params: {
              date: true,
              interval: 'PT3H',
              format: 'YYYY-MM-DD HH:mm',
              bounds: {
                min: '2019-11-07T15:45:45.770Z',
                max: '2019-11-14T15:45:45.770Z'
              }
            },
            aggType: 'date_histogram'
          },
          y: [{
            accessor: 2,
            format: {
              id: 'number'
            },
            params: {},
            aggType: 'count'
          }],
          series: [{
            accessor: 1,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing'
              }
            },
            params: {},
            aggType: 'terms'
          }]
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {}
      }, {
        id: '2',
        enabled: true,
        type: 'date_histogram',
        schema: 'segment',
        params: {
          field: 'timestamp',
          timeRange: {
            from: 'now-7d',
            to: 'now'
          },
          useNormalizedEsInterval: true,
          interval: 'auto',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {}
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'rule.mitre.technique',
          customLabel: 'Attack ID',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }]
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [],
        query: {
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-MITRE-Attacks-By-Agent',
  _source: {
    title: 'Mitre techniques by agent',
    visState: JSON.stringify({
      title: 'attack by agent',
      type: 'pie',
      params: {
        type: 'pie',
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        isDonut: true,
        labels: {
          show: false,
          values: true,
          last_level: true,
          truncate: 100
        },
        dimensions: {
          metric: {
            accessor: 0,
            format: {
              id: 'number'
            },
            params: {},
            aggType: 'count'
          }
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {}
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'agent.name',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'rule.mitre.technique',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }]
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [],
        query: {
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-MITRE-Attacks-By-Technique',
  _source: {
    title: 'Attacks by technique',
    visState: JSON.stringify({
      title: 'Attacks by tactic',
      type: 'histogram',
      params: {
        type: 'histogram',
        grid: {
          categoryLines: false
        },
        categoryAxes: [{
          id: 'CategoryAxis-1',
          type: 'category',
          position: 'bottom',
          show: true,
          style: {},
          scale: {
            type: 'linear'
          },
          labels: {
            show: true,
            filter: true,
            truncate: 100
          },
          title: {}
        }],
        valueAxes: [{
          id: 'ValueAxis-1',
          name: 'LeftAxis-1',
          type: 'value',
          position: 'left',
          show: true,
          style: {},
          scale: {
            type: 'linear',
            mode: 'normal'
          },
          labels: {
            show: true,
            rotate: 0,
            filter: false,
            truncate: 100
          },
          title: {
            text: 'Count'
          }
        }],
        seriesParams: [{
          show: 'true',
          type: 'histogram',
          mode: 'stacked',
          data: {
            label: 'Count',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          showCircles: true
        }],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false,
        labels: {
          show: false
        },
        thresholdLine: {
          show: false,
          value: 10,
          width: 1,
          style: 'full',
          color: '#34130C'
        },
        dimensions: {
          x: null,
          y: [{
            accessor: 1,
            format: {
              id: 'number'
            },
            params: {},
            aggType: 'count'
          }],
          series: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing'
              }
            },
            params: {},
            aggType: 'terms'
          }]
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {}
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'rule.mitre.technique',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'rule.mitre.tactic',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }]
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [],
        query: {
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-MITRE-Top-Tactics-By-Agent',
  _source: {
    title: 'Top tactics by agent',
    visState: JSON.stringify({
      title: 'Top tactics by agent - vertical',
      type: 'area',
      params: {
        addLegend: true,
        addTimeMarker: false,
        addTooltip: true,
        categoryAxes: [{
          id: 'CategoryAxis-1',
          labels: {
            filter: true,
            show: true,
            truncate: 10
          },
          position: 'bottom',
          scale: {
            type: 'linear'
          },
          show: true,
          style: {},
          title: {},
          type: 'category'
        }],
        dimensions: {
          x: {
            accessor: 1,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing'
              }
            },
            params: {},
            aggType: 'terms'
          },
          y: [{
            accessor: 2,
            format: {
              id: 'number'
            },
            params: {},
            aggType: 'count'
          }],
          series: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing'
              }
            },
            params: {},
            aggType: 'terms'
          }]
        },
        grid: {
          categoryLines: false,
          valueAxis: 'ValueAxis-1'
        },
        labels: {},
        legendPosition: 'right',
        seriesParams: [{
          data: {
            id: '1',
            label: 'Count'
          },
          drawLinesBetweenPoints: true,
          interpolate: 'linear',
          mode: 'normal',
          show: 'true',
          showCircles: true,
          type: 'histogram',
          valueAxis: 'ValueAxis-1'
        }],
        thresholdLine: {
          color: '#34130C',
          show: false,
          style: 'full',
          value: 10,
          width: 1
        },
        times: [],
        type: 'area',
        valueAxes: [{
          id: 'ValueAxis-1',
          labels: {
            filter: false,
            rotate: 0,
            show: true,
            truncate: 100
          },
          name: 'LeftAxis-1',
          position: 'left',
          scale: {
            mode: 'normal',
            type: 'linear'
          },
          show: true,
          style: {},
          title: {
            text: 'Count'
          },
          type: 'value'
        }]
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {}
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'rule.mitre.tactic',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'agent.name',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }]
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [],
        query: {
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-MITRE-Top-Tactics',
  _source: {
    title: 'Top tactics',
    visState: JSON.stringify({
      title: 'Top tactics PIE2',
      type: 'pie',
      params: {
        type: 'pie',
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        isDonut: false,
        labels: {
          show: false,
          values: true,
          last_level: true,
          truncate: 100
        },
        dimensions: {
          metric: {
            accessor: 1,
            format: {
              id: 'number'
            },
            params: {},
            aggType: 'count'
          },
          buckets: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing'
              }
            },
            params: {},
            aggType: 'terms'
          }]
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {}
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'rule.mitre.tactic',
          orderBy: '1',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }]
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [],
        query: {
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-MITRE-Alerts-summary',
  _type: 'visualization',
  _source: {
    title: 'Alerts summary',
    visState: JSON.stringify({
      title: 'Alerts summary',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMeticsAtAllLevels: false,
        sort: {
          columnIndex: 3,
          direction: 'desc'
        },
        showTotal: false,
        showToolbar: true,
        totalFunc: 'sum'
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {}
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.id',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 50,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Rule ID'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.description',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 20,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Description'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.level',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 12,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Level'
        }
      }]
    }),
    uiStateJSON: '{"vis":{"params":{"sort":{"columnIndex":3,"direction":"desc"}}}}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LW1pdHJlLnRzIl0sIm5hbWVzIjpbIl9pZCIsIl9zb3VyY2UiLCJ0aXRsZSIsInZpc1N0YXRlIiwiSlNPTiIsInN0cmluZ2lmeSIsImFnZ3MiLCJlbmFibGVkIiwiaWQiLCJwYXJhbXMiLCJzY2hlbWEiLCJ0eXBlIiwiZmllbGQiLCJjdXN0b21MYWJlbCIsIm1pc3NpbmdCdWNrZXQiLCJtaXNzaW5nQnVja2V0TGFiZWwiLCJvcmRlciIsIm9yZGVyQnkiLCJvdGhlckJ1Y2tldCIsIm90aGVyQnVja2V0TGFiZWwiLCJzaXplIiwiZGltZW5zaW9ucyIsImJ1Y2tldHMiLCJtZXRyaWNzIiwiYWNjZXNzb3IiLCJhZ2dUeXBlIiwiZm9ybWF0IiwicGVyUGFnZSIsInBlcmNlbnRhZ2VDb2wiLCJzaG93TWV0cmljc0F0QWxsTGV2ZWxzIiwic2hvd1BhcnRpYWxSb3dzIiwic2hvd1RvdGFsIiwic2hvd1Rvb2xiYXIiLCJzb3J0IiwiY29sdW1uSW5kZXgiLCJkaXJlY3Rpb24iLCJ0b3RhbEZ1bmMiLCJ1aVN0YXRlSlNPTiIsImRlc2NyaXB0aW9uIiwidmVyc2lvbiIsImtpYmFuYVNhdmVkT2JqZWN0TWV0YSIsInNlYXJjaFNvdXJjZUpTT04iLCJpbmRleCIsImZpbHRlciIsInF1ZXJ5IiwibGFuZ3VhZ2UiLCJfdHlwZSIsImdyaWQiLCJjYXRlZ29yeUxpbmVzIiwiY2F0ZWdvcnlBeGVzIiwicG9zaXRpb24iLCJzaG93Iiwic3R5bGUiLCJzY2FsZSIsImxhYmVscyIsInRydW5jYXRlIiwidmFsdWVBeGVzIiwibmFtZSIsIm1vZGUiLCJyb3RhdGUiLCJ0ZXh0Iiwic2VyaWVzUGFyYW1zIiwiZGF0YSIsImxhYmVsIiwidmFsdWVBeGlzIiwiZHJhd0xpbmVzQmV0d2VlblBvaW50cyIsInNob3dDaXJjbGVzIiwibGluZVdpZHRoIiwiYWRkVG9vbHRpcCIsImFkZExlZ2VuZCIsImxlZ2VuZFBvc2l0aW9uIiwidGltZXMiLCJhZGRUaW1lTWFya2VyIiwidGhyZXNob2xkTGluZSIsInZhbHVlIiwid2lkdGgiLCJjb2xvciIsIngiLCJwYXR0ZXJuIiwiZGF0ZSIsImludGVydmFsIiwiYm91bmRzIiwibWluIiwibWF4IiwieSIsInNlcmllcyIsInRpbWVSYW5nZSIsImZyb20iLCJ0byIsInVzZU5vcm1hbGl6ZWRFc0ludGVydmFsIiwiZHJvcF9wYXJ0aWFscyIsIm1pbl9kb2NfY291bnQiLCJleHRlbmRlZF9ib3VuZHMiLCJpc0RvbnV0IiwidmFsdWVzIiwibGFzdF9sZXZlbCIsIm1ldHJpYyIsImludGVycG9sYXRlIiwic2hvd01ldGljc0F0QWxsTGV2ZWxzIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtlQUNlLENBQ2I7QUFDRUEsRUFBQUEsR0FBRyxFQUFFLDBCQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsb0JBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkMsTUFBQUEsSUFBSSxFQUFFLENBQ0o7QUFBRUMsUUFBQUEsT0FBTyxFQUFFLElBQVg7QUFBaUJDLFFBQUFBLEVBQUUsRUFBRSxHQUFyQjtBQUEwQkMsUUFBQUEsTUFBTSxFQUFFLEVBQWxDO0FBQXNDQyxRQUFBQSxNQUFNLEVBQUUsUUFBOUM7QUFBd0RDLFFBQUFBLElBQUksRUFBRTtBQUE5RCxPQURJLEVBRUo7QUFDRUosUUFBQUEsT0FBTyxFQUFFLElBRFg7QUFFRUMsUUFBQUEsRUFBRSxFQUFFLEdBRk47QUFHRUMsUUFBQUEsTUFBTSxFQUFFO0FBQ05HLFVBQUFBLEtBQUssRUFBRSxlQUREO0FBRU5DLFVBQUFBLFdBQVcsRUFBRSxXQUZQO0FBR05DLFVBQUFBLGFBQWEsRUFBRSxLQUhUO0FBSU5DLFVBQUFBLGtCQUFrQixFQUFFLFNBSmQ7QUFLTkMsVUFBQUEsS0FBSyxFQUFFLE1BTEQ7QUFNTkMsVUFBQUEsT0FBTyxFQUFF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cHAgLSBNb2R1bGUgZm9yIE92ZXJ2aWV3IE1JVFJFIHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU1JVFJFJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ01pdHJlIGF0dGFjayBjb3VudCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBlbmFibGVkOiB0cnVlLCBpZDogJzEnLCBwYXJhbXM6IHt9LCBzY2hlbWE6ICdtZXRyaWMnLCB0eXBlOiAnY291bnQnIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLm1pdHJlLmlkJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdBdHRhY2sgSUQnLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBzaXplOiAyNDQsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgYnVja2V0czogW10sXG4gICAgICAgICAgICBtZXRyaWNzOiBbeyBhY2Nlc3NvcjogMCwgYWdnVHlwZTogJ2NvdW50JywgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9IH1dLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgcGVyY2VudGFnZUNvbDogJycsXG4gICAgICAgICAgc2hvd01ldHJpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IG51bGwsIGRpcmVjdGlvbjogbnVsbCB9LFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIHRpdGxlOiAnbWl0cmUnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IGxhbmd1YWdlOiAnbHVjZW5lJywgcXVlcnk6ICcnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctTUlUUkUtQWxlcnRzLUV2b2x1dGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdNaXRyZSBhbGVydHMgZXZvbHV0aW9uJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnQgRXZvbHV0aW9uJyxcbiAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiBmYWxzZSB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgICAgICAgIG1vZGU6ICdub3JtYWwnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGxpbmVXaWR0aDogMixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgbGFiZWxzOiB7fSxcbiAgICAgICAgICB0aHJlc2hvbGRMaW5lOiB7IHNob3c6IGZhbHNlLCB2YWx1ZTogMTAsIHdpZHRoOiAxLCBzdHlsZTogJ2Z1bGwnLCBjb2xvcjogJyMzNDEzMEMnIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDoge1xuICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgZm9ybWF0OiB7IGlkOiAnZGF0ZScsIHBhcmFtczogeyBwYXR0ZXJuOiAnWVlZWS1NTS1ERCBISDptbScgfSB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBkYXRlOiB0cnVlLFxuICAgICAgICAgICAgICAgIGludGVydmFsOiAnUFQzSCcsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiAnWVlZWS1NTS1ERCBISDptbScsXG4gICAgICAgICAgICAgICAgYm91bmRzOiB7IG1pbjogJzIwMTktMTEtMDdUMTU6NDU6NDUuNzcwWicsIG1heDogJzIwMTktMTEtMTRUMTU6NDU6NDUuNzcwWicgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB5OiBbeyBhY2Nlc3NvcjogMiwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH1dLFxuICAgICAgICAgICAgc2VyaWVzOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMSxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHsgZnJvbTogJ25vdy03ZCcsIHRvOiAnbm93JyB9LFxuICAgICAgICAgICAgICB1c2VOb3JtYWxpemVkRXNJbnRlcnZhbDogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgZHJvcF9wYXJ0aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5taXRyZS50ZWNobmlxdWUnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0F0dGFjayBJRCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1NSVRSRS1BdHRhY2tzLUJ5LUFnZW50JyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ01pdHJlIHRlY2huaXF1ZXMgYnkgYWdlbnQnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdhdHRhY2sgYnkgYWdlbnQnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UsIHZhbHVlczogdHJ1ZSwgbGFzdF9sZXZlbDogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIG1ldHJpYzogeyBhY2Nlc3NvcjogMCwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnYWdlbnQubmFtZScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLm1pdHJlLnRlY2huaXF1ZScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1NSVRSRS1BdHRhY2tzLUJ5LVRlY2huaXF1ZScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBdHRhY2tzIGJ5IHRlY2huaXF1ZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0F0dGFja3MgYnkgdGFjdGljJyxcbiAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogZmFsc2UgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgICAgIG1vZGU6ICdzdGFja2VkJyxcbiAgICAgICAgICAgICAgZGF0YTogeyBsYWJlbDogJ0NvdW50JywgaWQ6ICcxJyB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UgfSxcbiAgICAgICAgICB0aHJlc2hvbGRMaW5lOiB7IHNob3c6IGZhbHNlLCB2YWx1ZTogMTAsIHdpZHRoOiAxLCBzdHlsZTogJ2Z1bGwnLCBjb2xvcjogJyMzNDEzMEMnIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDogbnVsbCxcbiAgICAgICAgICAgIHk6IFt7IGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBzZXJpZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLm1pdHJlLnRlY2huaXF1ZScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLm1pdHJlLnRhY3RpYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1NSVRSRS1Ub3AtVGFjdGljcy1CeS1BZ2VudCcsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgdGFjdGljcyBieSBhZ2VudCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1RvcCB0YWN0aWNzIGJ5IGFnZW50IC0gdmVydGljYWwnLFxuICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IGZpbHRlcjogdHJ1ZSwgc2hvdzogdHJ1ZSwgdHJ1bmNhdGU6IDEwIH0sXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDoge1xuICAgICAgICAgICAgICBhY2Nlc3NvcjogMSxcbiAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7IGlkOiAnc3RyaW5nJywgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJywgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB5OiBbeyBhY2Nlc3NvcjogMiwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH1dLFxuICAgICAgICAgICAgc2VyaWVzOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogZmFsc2UsIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyB9LFxuICAgICAgICAgIGxhYmVsczoge30sXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRhdGE6IHsgaWQ6ICcxJywgbGFiZWw6ICdDb3VudCcgfSxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJwb2xhdGU6ICdsaW5lYXInLFxuICAgICAgICAgICAgICBtb2RlOiAnbm9ybWFsJyxcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICBzaG93Q2lyY2xlczogdHJ1ZSxcbiAgICAgICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB0aHJlc2hvbGRMaW5lOiB7IGNvbG9yOiAnIzM0MTMwQycsIHNob3c6IGZhbHNlLCBzdHlsZTogJ2Z1bGwnLCB2YWx1ZTogMTAsIHdpZHRoOiAxIH0sXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGxhYmVsczogeyBmaWx0ZXI6IGZhbHNlLCByb3RhdGU6IDAsIHNob3c6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzY2FsZTogeyBtb2RlOiAnbm9ybWFsJywgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLm1pdHJlLnRhY3RpYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdhZ2VudC5uYW1lJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBsYW5ndWFnZTogJ2x1Y2VuZScsIHF1ZXJ5OiAnJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU1JVFJFLVRvcC1UYWN0aWNzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCB0YWN0aWNzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnVG9wIHRhY3RpY3MgUElFMicsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UsIHZhbHVlczogdHJ1ZSwgbGFzdF9sZXZlbDogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIG1ldHJpYzogeyBhY2Nlc3NvcjogMSwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH0sXG4gICAgICAgICAgICBidWNrZXRzOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLm1pdHJlLnRhY3RpYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IGxhbmd1YWdlOiAnbHVjZW5lJywgcXVlcnk6ICcnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctTUlUUkUtQWxlcnRzLXN1bW1hcnknLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0aWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IDMsIGRpcmVjdGlvbjogJ2Rlc2MnIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaWQnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogNTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIElEJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5kZXNjcmlwdGlvbicsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiAyMCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0Rlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzQnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiAxMixcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0xldmVsJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7XCJ2aXNcIjp7XCJwYXJhbXNcIjp7XCJzb3J0XCI6e1wiY29sdW1uSW5kZXhcIjozLFwiZGlyZWN0aW9uXCI6XCJkZXNjXCJ9fX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXTtcbiJdfQ==