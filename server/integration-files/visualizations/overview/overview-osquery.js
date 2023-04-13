"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview/Osquery visualizations
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
  _id: 'Wazuh-App-Overview-Osquery-Alerts-over-time',
  _type: 'visualization',
  _source: {
    title: 'Alerts over time',
    visState: JSON.stringify({
      title: 'Alerts over time',
      type: 'area',
      params: {
        type: 'area',
        grid: {
          categoryLines: false,
          style: {
            color: '#eee'
          }
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
          type: 'area',
          mode: 'stacked',
          data: {
            label: 'Count',
            id: '1'
          },
          drawLinesBetweenPoints: true,
          showCircles: true,
          interpolate: 'linear',
          valueAxis: 'ValueAxis-1'
        }],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false
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
          interval: 'auto',
          customInterval: '2h',
          min_doc_count: 1,
          extended_bounds: {}
        }
      }]
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-Osquery-Top-5-added',
  _type: 'visualization',
  _source: {
    title: 'Top 5 added',
    visState: JSON.stringify({
      title: 'Top 5 added',
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
          field: 'data.osquery.name',
          size: 5,
          order: 'desc',
          orderBy: '1',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'data.osquery.action',
            value: 'added',
            params: {
              query: 'added',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.osquery.action': {
                query: 'added',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }]
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-Osquery-Top-5-removed',
  _type: 'visualization',
  _source: {
    title: 'Top 5 removed',
    visState: JSON.stringify({
      title: 'Top 5 removed',
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
          field: 'data.osquery.name',
          size: 5,
          order: 'desc',
          orderBy: '1',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'data.osquery.action',
            value: 'removed',
            params: {
              query: 'removed',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.osquery.action': {
                query: 'removed',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }]
      })
    }
  }
}, {
  _id: 'Wazuh-App-Agents-Osquery-Evolution',
  _type: 'visualization',
  _source: {
    title: 'Evolution over time',
    visState: JSON.stringify({
      title: 'Evolution over time',
      type: 'histogram',
      params: {
        type: 'histogram',
        grid: {
          categoryLines: true,
          style: {
            color: '#eee'
          },
          valueAxis: 'ValueAxis-1'
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
        addTimeMarker: false
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
            from: 'now-1h',
            to: 'now',
            mode: 'quick'
          },
          useNormalizedEsInterval: true,
          interval: 'auto',
          time_zone: 'Europe/Berlin',
          drop_partials: false,
          customInterval: '2h',
          min_doc_count: 1,
          extended_bounds: {}
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'data.osquery.name',
          size: 10,
          order: 'desc',
          orderBy: '1',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-Osquery-Most-common-packs',
  _type: 'visualization',
  _source: {
    title: 'Most common packs',
    visState: JSON.stringify({
      title: 'Most common packs',
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
          field: 'data.osquery.pack',
          size: 5,
          order: 'desc',
          orderBy: '1',
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
        query: {
          language: 'lucene',
          query: ''
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-Osquery-Top-5-rules',
  _type: 'visualization',
  _source: {
    title: 'Top 5 rules',
    visState: JSON.stringify({
      title: 'Top 5 rules',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: {
          columnIndex: 2,
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
          size: 5,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Rule ID'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.description',
          size: 1,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Description'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        params: {
          sort: {
            columnIndex: 2,
            direction: 'desc'
          }
        }
      }
    }),
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-Osquery-Top-5-Agents',
  _type: 'visualization',
  _source: {
    title: 'Top 5 Agents',
    visState: JSON.stringify({
      title: 'Top 5 Agents',
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
          size: 5,
          order: 'desc',
          orderBy: '1',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'rule.groups',
            value: 'osquery',
            params: {
              query: 'osquery',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'rule.groups': {
                query: 'osquery',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }]
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-Osquery-Agents-reporting',
  _type: 'visualization',
  _source: {
    title: 'Agents reporting',
    visState: JSON.stringify({
      title: 'Agents reporting',
      type: 'metric',
      params: {
        addTooltip: true,
        addLegend: false,
        type: 'metric',
        metric: {
          percentageMode: false,
          useRanges: false,
          colorSchema: 'Green to Red',
          metricColorMode: 'None',
          colorsRange: [{
            from: 0,
            to: 10000
          }],
          labels: {
            show: true
          },
          invertColors: false,
          style: {
            bgFill: '#000',
            bgColor: false,
            labelColor: false,
            subText: '',
            fontSize: 60
          }
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'cardinality',
        schema: 'metric',
        params: {
          field: 'agent.id'
        }
      }]
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-Osquery-Alerts-summary',
  _type: 'visualization',
  _source: {
    title: 'Alerts summary',
    visState: JSON.stringify({
      title: 'table',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: {
          columnIndex: 5,
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
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.osquery.name',
          size: 20,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Name'
        }
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.osquery.action',
          size: 5,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Action'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'agent.name',
          size: 5,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Agent'
        }
      }, {
        id: '5',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.osquery.pack',
          size: 5,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Pack'
        }
      }, {
        id: '6',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.osquery.calendarTime',
          size: 2,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Date'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        params: {
          sort: {
            columnIndex: 5,
            direction: 'desc'
          }
        }
      }
    }),
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LW9zcXVlcnkudHMiXSwibmFtZXMiOlsiX2lkIiwiX3R5cGUiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJzdHlsZSIsImNvbG9yIiwiY2F0ZWdvcnlBeGVzIiwiaWQiLCJwb3NpdGlvbiIsInNob3ciLCJzY2FsZSIsImxhYmVscyIsImZpbHRlciIsInRydW5jYXRlIiwidmFsdWVBeGVzIiwibmFtZSIsIm1vZGUiLCJyb3RhdGUiLCJ0ZXh0Iiwic2VyaWVzUGFyYW1zIiwiZGF0YSIsImxhYmVsIiwiZHJhd0xpbmVzQmV0d2VlblBvaW50cyIsInNob3dDaXJjbGVzIiwiaW50ZXJwb2xhdGUiLCJ2YWx1ZUF4aXMiLCJhZGRUb29sdGlwIiwiYWRkTGVnZW5kIiwibGVnZW5kUG9zaXRpb24iLCJ0aW1lcyIsImFkZFRpbWVNYXJrZXIiLCJhZ2dzIiwiZW5hYmxlZCIsInNjaGVtYSIsImZpZWxkIiwiaW50ZXJ2YWwiLCJjdXN0b21JbnRlcnZhbCIsIm1pbl9kb2NfY291bnQiLCJleHRlbmRlZF9ib3VuZHMiLCJ1aVN0YXRlSlNPTiIsImRlc2NyaXB0aW9uIiwidmVyc2lvbiIsImtpYmFuYVNhdmVkT2JqZWN0TWV0YSIsInNlYXJjaFNvdXJjZUpTT04iLCJpbmRleCIsInF1ZXJ5IiwibGFuZ3VhZ2UiLCJpc0RvbnV0IiwidmFsdWVzIiwibGFzdF9sZXZlbCIsInNpemUiLCJvcmRlciIsIm9yZGVyQnkiLCJvdGhlckJ1Y2tldCIsIm90aGVyQnVja2V0TGFiZWwiLCJtaXNzaW5nQnVja2V0IiwibWlzc2luZ0J1Y2tldExhYmVsIiwibWV0YSIsIm5lZ2F0ZSIsImRpc2FibGVkIiwiYWxpYXMiLCJrZXkiLCJ2YWx1ZSIsIm1hdGNoIiwiJHN0YXRlIiwic3RvcmUiLCJ0aW1lUmFuZ2UiLCJmcm9tIiwidG8iLCJ1c2VOb3JtYWxpemVkRXNJbnRlcnZhbCIsInRpbWVfem9uZSIsImRyb3BfcGFydGlhbHMiLCJwZXJQYWdlIiwic2hvd1BhcnRpYWxSb3dzIiwic2hvd01ldHJpY3NBdEFsbExldmVscyIsInNvcnQiLCJjb2x1bW5JbmRleCIsImRpcmVjdGlvbiIsInNob3dUb3RhbCIsInNob3dUb29sYmFyIiwidG90YWxGdW5jIiwiY3VzdG9tTGFiZWwiLCJ2aXMiLCJtZXRyaWMiLCJwZXJjZW50YWdlTW9kZSIsInVzZVJhbmdlcyIsImNvbG9yU2NoZW1hIiwibWV0cmljQ29sb3JNb2RlIiwiY29sb3JzUmFuZ2UiLCJpbnZlcnRDb2xvcnMiLCJiZ0ZpbGwiLCJiZ0NvbG9yIiwibGFiZWxDb2xvciIsInN1YlRleHQiLCJmb250U2l6ZSJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7ZUFDZSxDQUNiO0FBQ0VBLEVBQUFBLEdBQUcsRUFBRSw2Q0FEUDtBQUVFQyxFQUFBQSxLQUFLLEVBQUUsZUFGVDtBQUdFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLGtCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxrQkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxNQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05ELFFBQUFBLElBQUksRUFBRSxNQURBO0FBRU5FLFFBQUFBLElBQUksRUFBRTtBQUFFQyxVQUFBQSxhQUFhLEVBQUUsS0FBakI7QUFBd0JDLFVBQUFBLEtBQUssRUFBRTtBQUFFQyxZQUFBQSxLQUFLLEVBQUU7QUFBVDtBQUEvQixTQUZBO0FBR05DLFFBQUFBLFlBQVksRUFBRSxDQUNaO0FBQ0VDLFVBQUFBLEVBQUUsRUFBRSxnQkFETjtBQUVFUCxVQUFBQSxJQUFJLEVBQUUsVUFGUjtBQUdFUSxVQUFBQSxRQUFRLEVBQUUsUUFIWjtBQUlFQyxV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IC0gTW9kdWxlIGZvciBPdmVydmlldy9Pc3F1ZXJ5IHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9zcXVlcnktQWxlcnRzLW92ZXItdGltZScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBvdmVyIHRpbWUnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgb3ZlciB0aW1lJyxcbiAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiBmYWxzZSwgc3R5bGU6IHsgY29sb3I6ICcjZWVlJyB9IH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGZpbHRlcjogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIG1vZGU6ICdub3JtYWwnIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCByb3RhdGU6IDAsIGZpbHRlcjogZmFsc2UsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiAndHJ1ZScsXG4gICAgICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnBvbGF0ZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3RpbWVzdGFtcCcsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnYXV0bycsXG4gICAgICAgICAgICAgIGN1c3RvbUludGVydmFsOiAnMmgnLFxuICAgICAgICAgICAgICBtaW5fZG9jX2NvdW50OiAxLFxuICAgICAgICAgICAgICBleHRlbmRlZF9ib3VuZHM6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9zcXVlcnktVG9wLTUtYWRkZWQnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgNSBhZGRlZCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1RvcCA1IGFkZGVkJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vc3F1ZXJ5Lm5hbWUnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ2RhdGEub3NxdWVyeS5hY3Rpb24nLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnYWRkZWQnLFxuICAgICAgICAgICAgICAgIHBhcmFtczogeyBxdWVyeTogJ2FkZGVkJywgdHlwZTogJ3BocmFzZScgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHsgbWF0Y2g6IHsgJ2RhdGEub3NxdWVyeS5hY3Rpb24nOiB7IHF1ZXJ5OiAnYWRkZWQnLCB0eXBlOiAncGhyYXNlJyB9IH0gfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7IHN0b3JlOiAnYXBwU3RhdGUnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9zcXVlcnktVG9wLTUtcmVtb3ZlZCcsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IHJlbW92ZWQnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgNSByZW1vdmVkJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vc3F1ZXJ5Lm5hbWUnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ2RhdGEub3NxdWVyeS5hY3Rpb24nLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAncmVtb3ZlZCcsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7IHF1ZXJ5OiAncmVtb3ZlZCcsIHR5cGU6ICdwaHJhc2UnIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7IG1hdGNoOiB7ICdkYXRhLm9zcXVlcnkuYWN0aW9uJzogeyBxdWVyeTogJ3JlbW92ZWQnLCB0eXBlOiAncGhyYXNlJyB9IH0gfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7IHN0b3JlOiAnYXBwU3RhdGUnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1Pc3F1ZXJ5LUV2b2x1dGlvbicsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0V2b2x1dGlvbiBvdmVyIHRpbWUnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdFdm9sdXRpb24gb3ZlciB0aW1lJyxcbiAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogdHJ1ZSwgc3R5bGU6IHsgY29sb3I6ICcjZWVlJyB9LCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgICAgIG1vZGU6ICdzdGFja2VkJyxcbiAgICAgICAgICAgICAgZGF0YTogeyBsYWJlbDogJ0NvdW50JywgaWQ6ICcxJyB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAndGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgdGltZVJhbmdlOiB7IGZyb206ICdub3ctMWgnLCB0bzogJ25vdycsIG1vZGU6ICdxdWljaycgfSxcbiAgICAgICAgICAgICAgdXNlTm9ybWFsaXplZEVzSW50ZXJ2YWw6IHRydWUsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnYXV0bycsXG4gICAgICAgICAgICAgIHRpbWVfem9uZTogJ0V1cm9wZS9CZXJsaW4nLFxuICAgICAgICAgICAgICBkcm9wX3BhcnRpYWxzOiBmYWxzZSxcbiAgICAgICAgICAgICAgY3VzdG9tSW50ZXJ2YWw6ICcyaCcsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vc3F1ZXJ5Lm5hbWUnLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1Pc3F1ZXJ5LU1vc3QtY29tbW9uLXBhY2tzJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTW9zdCBjb21tb24gcGFja3MnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdNb3N0IGNvbW1vbiBwYWNrcycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSwgdmFsdWVzOiB0cnVlLCBsYXN0X2xldmVsOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub3NxdWVyeS5wYWNrJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1Pc3F1ZXJ5LVRvcC01LXJ1bGVzJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIDUgcnVsZXMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgNSBydWxlcycsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldHJpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogMiwgZGlyZWN0aW9uOiAnZGVzYycgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5pZCcsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUnVsZSBJRCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBzaXplOiAxLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0Rlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAyLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT3NxdWVyeS1Ub3AtNS1BZ2VudHMnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgNSBBZ2VudHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgNSBBZ2VudHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UsIHZhbHVlczogdHJ1ZSwgbGFzdF9sZXZlbDogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdhZ2VudC5uYW1lJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdydWxlLmdyb3VwcycsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICdvc3F1ZXJ5JyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHsgcXVlcnk6ICdvc3F1ZXJ5JywgdHlwZTogJ3BocmFzZScgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHsgbWF0Y2g6IHsgJ3J1bGUuZ3JvdXBzJzogeyBxdWVyeTogJ29zcXVlcnknLCB0eXBlOiAncGhyYXNlJyB9IH0gfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7IHN0b3JlOiAnYXBwU3RhdGUnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9zcXVlcnktQWdlbnRzLXJlcG9ydGluZycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FnZW50cyByZXBvcnRpbmcnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBZ2VudHMgcmVwb3J0aW5nJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnbWV0cmljJyxcbiAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIHVzZVJhbmdlczogZmFsc2UsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBtZXRyaWNDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbeyBmcm9tOiAwLCB0bzogMTAwMDAgfV0sXG4gICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSB9LFxuICAgICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICAgIHN0eWxlOiB7IGJnRmlsbDogJyMwMDAnLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnLCBmb250U2l6ZTogNjAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY2FyZGluYWxpdHknLFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICAgIHBhcmFtczogeyBmaWVsZDogJ2FnZW50LmlkJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT3NxdWVyeS1BbGVydHMtc3VtbWFyeScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAndGFibGUnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRyaWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IDUsIGRpcmVjdGlvbjogJ2Rlc2MnIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub3NxdWVyeS5uYW1lJyxcbiAgICAgICAgICAgICAgc2l6ZTogMjAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnTmFtZScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub3NxdWVyeS5hY3Rpb24nLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FjdGlvbicsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2FnZW50Lm5hbWUnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FnZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzUnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vc3F1ZXJ5LnBhY2snLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1BhY2snLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9zcXVlcnkuY2FsZW5kYXJUaW1lJyxcbiAgICAgICAgICAgICAgc2l6ZTogMixcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdEYXRlJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiA1LCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG5dO1xuIl19