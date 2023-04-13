"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Agents/Audit visualizations
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
  _id: 'Wazuh-App-Agents-Audit-New-files-metric',
  _source: {
    title: 'New files metric',
    visState: JSON.stringify({
      title: 'New files metric',
      type: 'metric',
      params: {
        addTooltip: true,
        addLegend: false,
        type: 'gauge',
        gauge: {
          verticalSplit: false,
          autoExtend: false,
          percentageMode: false,
          gaugeType: 'Metric',
          gaugeStyle: 'Full',
          backStyle: 'Full',
          orientation: 'vertical',
          colorSchema: 'Green to Red',
          gaugeColorMode: 'None',
          useRange: false,
          colorsRange: [{
            from: 0,
            to: 100
          }],
          invertColors: false,
          labels: {
            show: true,
            color: 'black'
          },
          scale: {
            show: false,
            labels: false,
            color: '#333',
            width: 2
          },
          type: 'simple',
          style: {
            fontSize: 20,
            bgColor: false,
            labelColor: false,
            subText: ''
          }
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {
          customLabel: 'New files'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        defaultColors: {
          '0 - 100': 'rgb(0,104,55)'
        }
      }
    }),
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'rule.id',
            value: '80790',
            params: {
              query: '80790',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'rule.id': {
                query: '80790',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-Audit-Read-files-metric',
  _source: {
    title: 'Read files metric',
    visState: JSON.stringify({
      title: 'Read files metric',
      type: 'metric',
      params: {
        addTooltip: true,
        addLegend: false,
        type: 'gauge',
        gauge: {
          verticalSplit: false,
          autoExtend: false,
          percentageMode: false,
          gaugeType: 'Metric',
          gaugeStyle: 'Full',
          backStyle: 'Full',
          orientation: 'vertical',
          colorSchema: 'Green to Red',
          gaugeColorMode: 'None',
          useRange: false,
          colorsRange: [{
            from: 0,
            to: 100
          }],
          invertColors: false,
          labels: {
            show: true,
            color: 'black'
          },
          scale: {
            show: false,
            labels: false,
            color: '#333',
            width: 2
          },
          type: 'simple',
          style: {
            fontSize: 20,
            bgColor: false,
            labelColor: false,
            subText: ''
          }
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {
          customLabel: 'Read files'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        defaultColors: {
          '0 - 100': 'rgb(0,104,55)'
        }
      }
    }),
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'rule.id',
            value: '80784',
            params: {
              query: '80784',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'rule.id': {
                query: '80784',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-Audit-Modified-files-metric',
  _source: {
    title: 'Modified files metric',
    visState: JSON.stringify({
      title: 'Modified files metric',
      type: 'metric',
      params: {
        addTooltip: true,
        addLegend: false,
        type: 'gauge',
        gauge: {
          verticalSplit: false,
          autoExtend: false,
          percentageMode: false,
          gaugeType: 'Metric',
          gaugeStyle: 'Full',
          backStyle: 'Full',
          orientation: 'vertical',
          colorSchema: 'Green to Red',
          gaugeColorMode: 'None',
          useRange: false,
          colorsRange: [{
            from: 0,
            to: 100
          }],
          invertColors: false,
          labels: {
            show: true,
            color: 'black'
          },
          scale: {
            show: false,
            labels: false,
            color: '#333',
            width: 2
          },
          type: 'simple',
          style: {
            fontSize: 20,
            bgColor: false,
            labelColor: false,
            subText: ''
          }
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {
          customLabel: 'Modified files'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        defaultColors: {
          '0 - 100': 'rgb(0,104,55)'
        }
      }
    }),
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            type: 'phrases',
            key: 'rule.id',
            value: '80781, 80787',
            params: ['80781', '80787'],
            negate: false,
            disabled: false,
            alias: null
          },
          query: {
            bool: {
              should: [{
                match_phrase: {
                  'rule.id': '80781'
                }
              }, {
                match_phrase: {
                  'rule.id': '80787'
                }
              }],
              minimum_should_match: 1
            }
          },
          $state: {
            store: 'appState'
          }
        }],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-Audit-Removed-files-metric',
  _source: {
    title: 'Removed files metric',
    visState: JSON.stringify({
      title: 'Removed files metric',
      type: 'metric',
      params: {
        addTooltip: true,
        addLegend: false,
        type: 'gauge',
        gauge: {
          verticalSplit: false,
          autoExtend: false,
          percentageMode: false,
          gaugeType: 'Metric',
          gaugeStyle: 'Full',
          backStyle: 'Full',
          orientation: 'vertical',
          colorSchema: 'Green to Red',
          gaugeColorMode: 'None',
          useRange: false,
          colorsRange: [{
            from: 0,
            to: 100
          }],
          invertColors: false,
          labels: {
            show: true,
            color: 'black'
          },
          scale: {
            show: false,
            labels: false,
            color: '#333',
            width: 2
          },
          type: 'simple',
          style: {
            fontSize: 20,
            bgColor: false,
            labelColor: false,
            subText: ''
          }
        }
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {
          customLabel: 'Removed files'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        defaultColors: {
          '0 - 100': 'rgb(0,104,55)'
        }
      }
    }),
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'rule.id',
            value: '80791',
            params: {
              query: '80791',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'rule.id': {
                query: '80791',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-Audit-Groups',
  _source: {
    title: 'Groups',
    visState: JSON.stringify({
      title: 'Groups',
      type: 'pie',
      params: {
        type: 'pie',
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        isDonut: true
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
          field: 'rule.groups',
          size: 5,
          order: 'desc',
          orderBy: '1'
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
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-Audit-Files',
  _source: {
    title: 'Files',
    visState: JSON.stringify({
      title: 'Files',
      type: 'pie',
      params: {
        type: 'pie',
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        isDonut: true
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
          field: 'data.audit.file.name',
          size: 5,
          order: 'desc',
          orderBy: '1'
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
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-Audit-Alerts-over-time',
  _source: {
    title: 'Alerts over time',
    visState: JSON.stringify({
      title: 'Alerts over time',
      type: 'area',
      params: {
        type: 'area',
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
          interpolate: 'cardinal',
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
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'rule.description',
          size: 5,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
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
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-Audit-Commands',
  _source: {
    title: 'Commands',
    visState: JSON.stringify({
      title: 'Commands',
      type: 'pie',
      params: {
        type: 'pie',
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        isDonut: true
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
          field: 'data.audit.command',
          size: 5,
          order: 'desc',
          orderBy: '1'
        }
      }]
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-Audit-Last-alerts',
  _type: 'visualization',
  _source: {
    title: 'Last alerts',
    visState: JSON.stringify({
      title: 'Last alerts',
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
          size: 50,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Event'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.audit.exe',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 10,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Command'
        }
      }, {
        id: '5',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.audit.type',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 5,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Type'
        }
      }]
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy1hdWRpdC50cyJdLCJuYW1lcyI6WyJfaWQiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwiYWRkVG9vbHRpcCIsImFkZExlZ2VuZCIsImdhdWdlIiwidmVydGljYWxTcGxpdCIsImF1dG9FeHRlbmQiLCJwZXJjZW50YWdlTW9kZSIsImdhdWdlVHlwZSIsImdhdWdlU3R5bGUiLCJiYWNrU3R5bGUiLCJvcmllbnRhdGlvbiIsImNvbG9yU2NoZW1hIiwiZ2F1Z2VDb2xvck1vZGUiLCJ1c2VSYW5nZSIsImNvbG9yc1JhbmdlIiwiZnJvbSIsInRvIiwiaW52ZXJ0Q29sb3JzIiwibGFiZWxzIiwic2hvdyIsImNvbG9yIiwic2NhbGUiLCJ3aWR0aCIsInN0eWxlIiwiZm9udFNpemUiLCJiZ0NvbG9yIiwibGFiZWxDb2xvciIsInN1YlRleHQiLCJhZ2dzIiwiaWQiLCJlbmFibGVkIiwic2NoZW1hIiwiY3VzdG9tTGFiZWwiLCJ1aVN0YXRlSlNPTiIsInZpcyIsImRlZmF1bHRDb2xvcnMiLCJkZXNjcmlwdGlvbiIsInZlcnNpb24iLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiaW5kZXgiLCJmaWx0ZXIiLCJtZXRhIiwibmVnYXRlIiwiZGlzYWJsZWQiLCJhbGlhcyIsImtleSIsInZhbHVlIiwicXVlcnkiLCJtYXRjaCIsIiRzdGF0ZSIsInN0b3JlIiwibGFuZ3VhZ2UiLCJfdHlwZSIsImJvb2wiLCJzaG91bGQiLCJtYXRjaF9waHJhc2UiLCJtaW5pbXVtX3Nob3VsZF9tYXRjaCIsImxlZ2VuZFBvc2l0aW9uIiwiaXNEb251dCIsImZpZWxkIiwic2l6ZSIsIm9yZGVyIiwib3JkZXJCeSIsImdyaWQiLCJjYXRlZ29yeUxpbmVzIiwidmFsdWVBeGlzIiwiY2F0ZWdvcnlBeGVzIiwicG9zaXRpb24iLCJ0cnVuY2F0ZSIsInZhbHVlQXhlcyIsIm5hbWUiLCJtb2RlIiwicm90YXRlIiwidGV4dCIsInNlcmllc1BhcmFtcyIsImRhdGEiLCJsYWJlbCIsImRyYXdMaW5lc0JldHdlZW5Qb2ludHMiLCJzaG93Q2lyY2xlcyIsImludGVycG9sYXRlIiwidGltZXMiLCJhZGRUaW1lTWFya2VyIiwib3RoZXJCdWNrZXQiLCJvdGhlckJ1Y2tldExhYmVsIiwibWlzc2luZ0J1Y2tldCIsIm1pc3NpbmdCdWNrZXRMYWJlbCIsInRpbWVSYW5nZSIsInVzZU5vcm1hbGl6ZWRFc0ludGVydmFsIiwiaW50ZXJ2YWwiLCJ0aW1lX3pvbmUiLCJkcm9wX3BhcnRpYWxzIiwiY3VzdG9tSW50ZXJ2YWwiLCJtaW5fZG9jX2NvdW50IiwiZXh0ZW5kZWRfYm91bmRzIiwicGVyUGFnZSIsInNob3dQYXJ0aWFsUm93cyIsInNob3dNZXRpY3NBdEFsbExldmVscyIsInNvcnQiLCJjb2x1bW5JbmRleCIsImRpcmVjdGlvbiIsInNob3dUb3RhbCIsInNob3dUb29sYmFyIiwidG90YWxGdW5jIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtlQUNlLENBQ2I7QUFDRUEsRUFBQUEsR0FBRyxFQUFFLHlDQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsa0JBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLGtCQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLFFBRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkMsUUFBQUEsVUFBVSxFQUFFLElBRE47QUFFTkMsUUFBQUEsU0FBUyxFQUFFLEtBRkw7QUFHTkgsUUFBQUEsSUFBSSxFQUFFLE9BSEE7QUFJTkksUUFBQUEsS0FBSyxFQUFFO0FBQ0xDLFVBQUFBLGFBQWEsRUFBRSxLQURWO0FBRUxDLFVBQUFBLFVBQVUsRUFBRSxLQUZQO0FBR0xD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L0IsVUFBQUEsV0FBVyxFQUFFO0FBVFA7QUFMVixPQXBDSTtBQVppQixLQUFmLENBRkg7QUFxRVBDLElBQUFBLFdBQVcsRUFBRXBDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQzFCb0MsTUFBQUEsR0FBRyxFQUFFO0FBQUVsQyxRQUFBQSxNQUFNLEVBQUU7QUFBRWtHLFVBQUFBLElBQUksRUFBRTtBQUFFQyxZQUFBQSxXQUFXLEVBQUUsQ0FBZjtBQUFrQkMsWUFBQUEsU0FBUyxFQUFFO0FBQTdCO0FBQVI7QUFBVjtBQURxQixLQUFmLENBckVOO0FBd0VQaEUsSUFBQUEsV0FBVyxFQUFFLEVBeEVOO0FBeUVQQyxJQUFBQSxPQUFPLEVBQUUsQ0F6RUY7QUEwRVBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRTFDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CMEMsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsRUFGdUI7QUFHL0JPLFFBQUFBLEtBQUssRUFBRTtBQUFFQSxVQUFBQSxLQUFLLEVBQUUsRUFBVDtBQUFhSSxVQUFBQSxRQUFRLEVBQUU7QUFBdkI7QUFId0IsT0FBZjtBQURHO0FBMUVoQjtBQUhYLENBN2hCYSxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgQWdlbnRzL0F1ZGl0IHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1BdWRpdC1OZXctZmlsZXMtbWV0cmljJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ05ldyBmaWxlcyBtZXRyaWMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdOZXcgZmlsZXMgbWV0cmljJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnZ2F1Z2UnLFxuICAgICAgICAgIGdhdWdlOiB7XG4gICAgICAgICAgICB2ZXJ0aWNhbFNwbGl0OiBmYWxzZSxcbiAgICAgICAgICAgIGF1dG9FeHRlbmQ6IGZhbHNlLFxuICAgICAgICAgICAgcGVyY2VudGFnZU1vZGU6IGZhbHNlLFxuICAgICAgICAgICAgZ2F1Z2VUeXBlOiAnTWV0cmljJyxcbiAgICAgICAgICAgIGdhdWdlU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIGJhY2tTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgb3JpZW50YXRpb246ICd2ZXJ0aWNhbCcsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBnYXVnZUNvbG9yTW9kZTogJ05vbmUnLFxuICAgICAgICAgICAgdXNlUmFuZ2U6IGZhbHNlLFxuICAgICAgICAgICAgY29sb3JzUmFuZ2U6IFt7IGZyb206IDAsIHRvOiAxMDAgfV0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGNvbG9yOiAnYmxhY2snIH0sXG4gICAgICAgICAgICBzY2FsZTogeyBzaG93OiBmYWxzZSwgbGFiZWxzOiBmYWxzZSwgY29sb3I6ICcjMzMzJywgd2lkdGg6IDIgfSxcbiAgICAgICAgICAgIHR5cGU6ICdzaW1wbGUnLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDIwLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgICBwYXJhbXM6IHsgY3VzdG9tTGFiZWw6ICdOZXcgZmlsZXMnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ3J1bGUuaWQnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnODA3OTAnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICc4MDc5MCcsXG4gICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICAgICAgICAncnVsZS5pZCc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICc4MDc5MCcsXG4gICAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAkc3RhdGU6IHtcbiAgICAgICAgICAgICAgICBzdG9yZTogJ2FwcFN0YXRlJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1BdWRpdC1SZWFkLWZpbGVzLW1ldHJpYycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSZWFkIGZpbGVzIG1ldHJpYycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1JlYWQgZmlsZXMgbWV0cmljJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnZ2F1Z2UnLFxuICAgICAgICAgIGdhdWdlOiB7XG4gICAgICAgICAgICB2ZXJ0aWNhbFNwbGl0OiBmYWxzZSxcbiAgICAgICAgICAgIGF1dG9FeHRlbmQ6IGZhbHNlLFxuICAgICAgICAgICAgcGVyY2VudGFnZU1vZGU6IGZhbHNlLFxuICAgICAgICAgICAgZ2F1Z2VUeXBlOiAnTWV0cmljJyxcbiAgICAgICAgICAgIGdhdWdlU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIGJhY2tTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgb3JpZW50YXRpb246ICd2ZXJ0aWNhbCcsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBnYXVnZUNvbG9yTW9kZTogJ05vbmUnLFxuICAgICAgICAgICAgdXNlUmFuZ2U6IGZhbHNlLFxuICAgICAgICAgICAgY29sb3JzUmFuZ2U6IFt7IGZyb206IDAsIHRvOiAxMDAgfV0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGNvbG9yOiAnYmxhY2snIH0sXG4gICAgICAgICAgICBzY2FsZTogeyBzaG93OiBmYWxzZSwgbGFiZWxzOiBmYWxzZSwgY29sb3I6ICcjMzMzJywgd2lkdGg6IDIgfSxcbiAgICAgICAgICAgIHR5cGU6ICdzaW1wbGUnLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDIwLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgICBwYXJhbXM6IHsgY3VzdG9tTGFiZWw6ICdSZWFkIGZpbGVzJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7IHZpczogeyBkZWZhdWx0Q29sb3JzOiB7ICcwIC0gMTAwJzogJ3JnYigwLDEwNCw1NSknIH0gfSB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdydWxlLmlkJyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJzgwNzg0JyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnODA3ODQnLFxuICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICAgICAgICBtYXRjaDoge1xuICAgICAgICAgICAgICAgICAgJ3J1bGUuaWQnOiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnODA3ODQnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtQXVkaXQtTW9kaWZpZWQtZmlsZXMtbWV0cmljJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ01vZGlmaWVkIGZpbGVzIG1ldHJpYycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ01vZGlmaWVkIGZpbGVzIG1ldHJpYycsXG4gICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogZmFsc2UsXG4gICAgICAgICAgdHlwZTogJ2dhdWdlJyxcbiAgICAgICAgICBnYXVnZToge1xuICAgICAgICAgICAgdmVydGljYWxTcGxpdDogZmFsc2UsXG4gICAgICAgICAgICBhdXRvRXh0ZW5kOiBmYWxzZSxcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIGdhdWdlVHlwZTogJ01ldHJpYycsXG4gICAgICAgICAgICBnYXVnZVN0eWxlOiAnRnVsbCcsXG4gICAgICAgICAgICBiYWNrU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIG9yaWVudGF0aW9uOiAndmVydGljYWwnLFxuICAgICAgICAgICAgY29sb3JTY2hlbWE6ICdHcmVlbiB0byBSZWQnLFxuICAgICAgICAgICAgZ2F1Z2VDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIHVzZVJhbmdlOiBmYWxzZSxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbeyBmcm9tOiAwLCB0bzogMTAwIH1dLFxuICAgICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBjb2xvcjogJ2JsYWNrJyB9LFxuICAgICAgICAgICAgc2NhbGU6IHsgc2hvdzogZmFsc2UsIGxhYmVsczogZmFsc2UsIGNvbG9yOiAnIzMzMycsIHdpZHRoOiAyIH0sXG4gICAgICAgICAgICB0eXBlOiAnc2ltcGxlJyxcbiAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAyMCwgYmdDb2xvcjogZmFsc2UsIGxhYmVsQ29sb3I6IGZhbHNlLCBzdWJUZXh0OiAnJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGN1c3RvbUxhYmVsOiAnTW9kaWZpZWQgZmlsZXMnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2VzJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdydWxlLmlkJyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJzgwNzgxLCA4MDc4NycsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiBbJzgwNzgxJywgJzgwNzg3J10sXG4gICAgICAgICAgICAgICAgbmVnYXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgYm9vbDoge1xuICAgICAgICAgICAgICAgICAgc2hvdWxkOiBbXG4gICAgICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgICAgICBtYXRjaF9waHJhc2U6IHtcbiAgICAgICAgICAgICAgICAgICAgICAgICdydWxlLmlkJzogJzgwNzgxJyxcbiAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgbWF0Y2hfcGhyYXNlOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAncnVsZS5pZCc6ICc4MDc4NycsXG4gICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgIF0sXG4gICAgICAgICAgICAgICAgICBtaW5pbXVtX3Nob3VsZF9tYXRjaDogMSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAkc3RhdGU6IHtcbiAgICAgICAgICAgICAgICBzdG9yZTogJ2FwcFN0YXRlJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1BdWRpdC1SZW1vdmVkLWZpbGVzLW1ldHJpYycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSZW1vdmVkIGZpbGVzIG1ldHJpYycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1JlbW92ZWQgZmlsZXMgbWV0cmljJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnZ2F1Z2UnLFxuICAgICAgICAgIGdhdWdlOiB7XG4gICAgICAgICAgICB2ZXJ0aWNhbFNwbGl0OiBmYWxzZSxcbiAgICAgICAgICAgIGF1dG9FeHRlbmQ6IGZhbHNlLFxuICAgICAgICAgICAgcGVyY2VudGFnZU1vZGU6IGZhbHNlLFxuICAgICAgICAgICAgZ2F1Z2VUeXBlOiAnTWV0cmljJyxcbiAgICAgICAgICAgIGdhdWdlU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIGJhY2tTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgb3JpZW50YXRpb246ICd2ZXJ0aWNhbCcsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBnYXVnZUNvbG9yTW9kZTogJ05vbmUnLFxuICAgICAgICAgICAgdXNlUmFuZ2U6IGZhbHNlLFxuICAgICAgICAgICAgY29sb3JzUmFuZ2U6IFt7IGZyb206IDAsIHRvOiAxMDAgfV0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGNvbG9yOiAnYmxhY2snIH0sXG4gICAgICAgICAgICBzY2FsZTogeyBzaG93OiBmYWxzZSwgbGFiZWxzOiBmYWxzZSwgY29sb3I6ICcjMzMzJywgd2lkdGg6IDIgfSxcbiAgICAgICAgICAgIHR5cGU6ICdzaW1wbGUnLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDIwLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgICBwYXJhbXM6IHsgY3VzdG9tTGFiZWw6ICdSZW1vdmVkIGZpbGVzJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7IHZpczogeyBkZWZhdWx0Q29sb3JzOiB7ICcwIC0gMTAwJzogJ3JnYigwLDEwNCw1NSknIH0gfSB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdydWxlLmlkJyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJzgwNzkxJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnODA3OTEnLFxuICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICAgICAgICBtYXRjaDoge1xuICAgICAgICAgICAgICAgICAgJ3J1bGUuaWQnOiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnODA3OTEnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtQXVkaXQtR3JvdXBzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0dyb3VwcycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0dyb3VwcycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdydWxlLmdyb3VwcycsIHNpemU6IDUsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtQXVkaXQtRmlsZXMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnRmlsZXMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdGaWxlcycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdkYXRhLmF1ZGl0LmZpbGUubmFtZScsIHNpemU6IDUsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtQXVkaXQtQWxlcnRzLW92ZXItdGltZScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydHMgb3ZlciB0aW1lJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnRzIG92ZXIgdGltZScsXG4gICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogdHJ1ZSwgc3R5bGU6IHsgY29sb3I6ICcjZWVlJyB9LCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIG1vZGU6ICdub3JtYWwnIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCByb3RhdGU6IDAsIGZpbHRlcjogZmFsc2UsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiAndHJ1ZScsXG4gICAgICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnBvbGF0ZTogJ2NhcmRpbmFsJyxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAndGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgdGltZVJhbmdlOiB7IGZyb206ICdub3ctMWgnLCB0bzogJ25vdycsIG1vZGU6ICdxdWljaycgfSxcbiAgICAgICAgICAgICAgdXNlTm9ybWFsaXplZEVzSW50ZXJ2YWw6IHRydWUsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnYXV0bycsXG4gICAgICAgICAgICAgIHRpbWVfem9uZTogJ0V1cm9wZS9CZXJsaW4nLFxuICAgICAgICAgICAgICBkcm9wX3BhcnRpYWxzOiBmYWxzZSxcbiAgICAgICAgICAgICAgY3VzdG9tSW50ZXJ2YWw6ICcyaCcsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtQXVkaXQtQ29tbWFuZHMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQ29tbWFuZHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdDb21tYW5kcycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdkYXRhLmF1ZGl0LmNvbW1hbmQnLCBzaXplOiA1LCBvcmRlcjogJ2Rlc2MnLCBvcmRlckJ5OiAnMScgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjpcbiAgICAgICAgICAne1wiaW5kZXhcIjpcIndhenVoLWFsZXJ0c1wiLFwiZmlsdGVyXCI6W10sXCJxdWVyeVwiOntcInF1ZXJ5XCI6XCJcIixcImxhbmd1YWdlXCI6XCJsdWNlbmVcIn19JyxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1BdWRpdC1MYXN0LWFsZXJ0cycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0xhc3QgYWxlcnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTGFzdCBhbGVydHMnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5kZXNjcmlwdGlvbicsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiA1MCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0V2ZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzQnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5hdWRpdC5leGUnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdDb21tYW5kJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzUnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5hdWRpdC50eXBlJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdUeXBlJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG5dO1xuIl19