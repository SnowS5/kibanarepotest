"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Agents/General visualizations
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
  _id: 'Wazuh-App-Agents-General-Top-5-alerts',
  _source: {
    title: 'Top 5 alerts',
    visState: JSON.stringify({
      title: 'Top 5 alerts',
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
          field: 'rule.description',
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
    uiStateJSON: JSON.stringify({
      vis: {
        legendOpen: true
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
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-General-Metric-alerts',
  _source: {
    title: 'Metric alerts',
    visState: JSON.stringify({
      title: 'Metric Alerts',
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
          customLabel: 'Alerts'
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
  _id: 'Wazuh-App-Agents-General-Level-12-alerts',
  _source: {
    title: 'Level 12 alerts',
    visState: JSON.stringify({
      title: 'Count Level 12 Alerts',
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
          customLabel: 'Level 12 or above alerts'
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
          $state: {
            store: 'appState'
          },
          meta: {
            alias: null,
            disabled: false,
            index: 'wazuh-alerts',
            key: 'rule.level',
            negate: false,
            params: {
              gte: 12,
              lt: null
            },
            type: 'range',
            value: '12 to +∞'
          },
          range: {
            'rule.level': {
              gte: 12,
              lt: null
            }
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
  _id: 'Wazuh-App-Agents-General-Authentication-failure',
  _source: {
    title: 'Authentication failure',
    visState: JSON.stringify({
      title: 'Count Authentication Failure',
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
          customLabel: 'Authentication failure'
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
            key: 'rule.groups',
            value: 'win_authentication_failed, authentication_failed, authentication_failures',
            params: ['win_authentication_failed', 'authentication_failed', 'authentication_failures'],
            negate: false,
            disabled: false,
            alias: null
          },
          query: {
            bool: {
              should: [{
                match_phrase: {
                  'rule.groups': 'win_authentication_failed'
                }
              }, {
                match_phrase: {
                  'rule.groups': 'authentication_failed'
                }
              }, {
                match_phrase: {
                  'rule.groups': 'authentication_failures'
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
  _id: 'Wazuh-App-Agents-General-Authentication-success',
  _source: {
    title: 'Authentication success',
    visState: JSON.stringify({
      title: 'Count Authentication Success',
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
          customLabel: 'Authentication success'
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
            key: 'rule.groups',
            value: 'authentication_success',
            params: {
              query: 'authentication_success',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'rule.groups': {
                query: 'authentication_success',
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
  _id: 'Wazuh-App-Agents-General-Top-10-groups',
  _source: {
    title: 'Top 5 rule groups',
    visState: JSON.stringify({
      title: 'Top 5 rule groups',
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
          field: 'rule.groups',
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
    uiStateJSON: JSON.stringify({
      vis: {
        legendOpen: true
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
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-General-Top-5-PCI-DSS-Requirements',
  _source: {
    title: 'Top 5 PCI DSS requirements',
    visState: JSON.stringify({
      title: 'Top 5 PCI DSS requirements',
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
          field: 'rule.pci_dss',
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
    uiStateJSON: '{"vis":{"legendOpen":true}}',
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
  _id: 'Wazuh-App-Agents-General-Alert-groups-evolution',
  _source: {
    title: 'Alert groups evolution',
    visState: JSON.stringify({
      title: 'Alerts by group over time',
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
        id: '2',
        enabled: true,
        type: 'date_histogram',
        schema: 'segment',
        params: {
          field: 'timestamp',
          timeRange: {
            from: 'now-24h',
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
          field: 'rule.groups',
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
  _id: 'Wazuh-App-Agents-General-Alerts',
  _source: {
    title: 'Alerts',
    visState: JSON.stringify({
      title: 'Alerts by action over time',
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
        id: '2',
        enabled: true,
        type: 'date_histogram',
        schema: 'segment',
        params: {
          field: 'timestamp',
          timeRange: {
            from: 'now-24h',
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
          field: 'rule.level',
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
  _id: 'Wazuh-App-Agents-General-Alerts-summary',
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
          size: 1,
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
          size: 1,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Level'
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
}, {
  _id: 'Wazuh-App-Agents-General-Groups-summary',
  _type: 'visualization',
  _source: {
    title: 'Groups summary',
    visState: JSON.stringify({
      title: 'Groups summary',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMeticsAtAllLevels: false,
        sort: {
          columnIndex: 1,
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
          field: 'rule.groups',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 50,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Group'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        params: {
          sort: {
            columnIndex: 1,
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy1nZW5lcmFsLnRzIl0sIm5hbWVzIjpbIl9pZCIsIl9zb3VyY2UiLCJ0aXRsZSIsInZpc1N0YXRlIiwiSlNPTiIsInN0cmluZ2lmeSIsInR5cGUiLCJwYXJhbXMiLCJhZGRUb29sdGlwIiwiYWRkTGVnZW5kIiwibGVnZW5kUG9zaXRpb24iLCJpc0RvbnV0IiwibGFiZWxzIiwic2hvdyIsInZhbHVlcyIsImxhc3RfbGV2ZWwiLCJ0cnVuY2F0ZSIsImFnZ3MiLCJpZCIsImVuYWJsZWQiLCJzY2hlbWEiLCJmaWVsZCIsInNpemUiLCJvcmRlciIsIm9yZGVyQnkiLCJvdGhlckJ1Y2tldCIsIm90aGVyQnVja2V0TGFiZWwiLCJtaXNzaW5nQnVja2V0IiwibWlzc2luZ0J1Y2tldExhYmVsIiwidWlTdGF0ZUpTT04iLCJ2aXMiLCJsZWdlbmRPcGVuIiwiZGVzY3JpcHRpb24iLCJ2ZXJzaW9uIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImluZGV4IiwiZmlsdGVyIiwicXVlcnkiLCJsYW5ndWFnZSIsIl90eXBlIiwiZ2F1Z2UiLCJ2ZXJ0aWNhbFNwbGl0IiwiYXV0b0V4dGVuZCIsInBlcmNlbnRhZ2VNb2RlIiwiZ2F1Z2VUeXBlIiwiZ2F1Z2VTdHlsZSIsImJhY2tTdHlsZSIsIm9yaWVudGF0aW9uIiwiY29sb3JTY2hlbWEiLCJnYXVnZUNvbG9yTW9kZSIsInVzZVJhbmdlIiwiY29sb3JzUmFuZ2UiLCJmcm9tIiwidG8iLCJpbnZlcnRDb2xvcnMiLCJjb2xvciIsInNjYWxlIiwid2lkdGgiLCJzdHlsZSIsImZvbnRTaXplIiwiYmdDb2xvciIsImxhYmVsQ29sb3IiLCJzdWJUZXh0IiwiY3VzdG9tTGFiZWwiLCJkZWZhdWx0Q29sb3JzIiwiJHN0YXRlIiwic3RvcmUiLCJtZXRhIiwiYWxpYXMiLCJkaXNhYmxlZCIsImtleSIsIm5lZ2F0ZSIsImd0ZSIsImx0IiwidmFsdWUiLCJyYW5nZSIsImJvb2wiLCJzaG91bGQiLCJtYXRjaF9waHJhc2UiLCJtaW5pbXVtX3Nob3VsZF9tYXRjaCIsIm1hdGNoIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJ2YWx1ZUF4aXMiLCJjYXRlZ29yeUF4ZXMiLCJwb3NpdGlvbiIsInZhbHVlQXhlcyIsIm5hbWUiLCJtb2RlIiwicm90YXRlIiwidGV4dCIsInNlcmllc1BhcmFtcyIsImRhdGEiLCJsYWJlbCIsImRyYXdMaW5lc0JldHdlZW5Qb2ludHMiLCJzaG93Q2lyY2xlcyIsImludGVycG9sYXRlIiwidGltZXMiLCJhZGRUaW1lTWFya2VyIiwidGltZVJhbmdlIiwidXNlTm9ybWFsaXplZEVzSW50ZXJ2YWwiLCJpbnRlcnZhbCIsInRpbWVfem9uZSIsImRyb3BfcGFydGlhbHMiLCJjdXN0b21JbnRlcnZhbCIsIm1pbl9kb2NfY291bnQiLCJleHRlbmRlZF9ib3VuZHMiLCJwZXJQYWdlIiwic2hvd1BhcnRpYWxSb3dzIiwic2hvd01ldGljc0F0QWxsTGV2ZWxzIiwic29ydCIsImNvbHVtbkluZGV4IiwiZGlyZWN0aW9uIiwic2hvd1RvdGFsIiwic2hvd1Rvb2xiYXIiLCJ0b3RhbEZ1bmMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO2VBQ2UsQ0FDYjtBQUNFQSxFQUFBQSxHQUFHLEVBQUUsdUNBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxjQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxjQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLEtBRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkQsUUFBQUEsSUFBSSxFQUFFLEtBREE7QUFFTkUsUUFBQUEsVUFBVSxFQUFFLElBRk47QUFHTkMsUUFBQUEsU0FBUyxFQUFFLElBSEw7QUFJTkMsUUFBQUEsY0FBYyxFQUFFLE9BSlY7QUFLTkMsUUFBQUEsT0FBTyxFQUFFLElBTEg7QUFNTkMsUUFBQUEsTUFBTSxFQUFFO0FBQUVDLFVBQUFBLElBQUksRUFBRSxLQUFSO0FBQWVDLFVBQUFBLE1BQU0sRUFBRSxJQUF2QjtBQUE2QkMsVUFBQUEsVUFBVSxFQUFFLElBQXpDO0FBQStDQyxVQUFBQSxRQUFRLEVBQUU7QUFBekQ7QUFORixPQUhlO0FBV3ZCQyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFQyxRQUFBQSxFQUFFLEVBQUUsR0FBTjtBQUFXQyxRQUFBQSxPQUFPLEVBQUUsSUFBcEI7QUFBMEJiLFFBQUFBLElBQUksRUFBRSxPQUFoQztBQUF5Q2MsUUFBQUEsTUFBTSxFQUFFLFFBQWpEO0FBQTJEYixRQUFBQSxNQUFNLEVBQUU7QUFBbkUsT0FESSxFQUVKO0FBQ0VXLFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxTQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUNOYyxVQUFBQSxLQUFLLEVBQUUsa0JBREQ7QUFFTkMsVUFBQUEsSUFBSSxFQUFFLENBRkE7QUFHTkMsVUFBQUEsS0FBSyxFQUFFLE1BSEQ7QUFJTkMsVUFBQUEsT0FBTyxFQUFFLEdBSkg7QUFLTkMsVUFBQUEsV0FBVyxFQUFFLEtBTFA7QUFNTkMsVUFBQUEsZ0JBQWdCLEVBQUUsT0FOWjtBQU9OQyxVQUFBQSxhQUFhLEVBQUUsS0FQVDtBQVFOQyxVQUFBQSxrQkFBa0IsRUFBRTtBQVJkO0FBTFYsT0FGSTtBQVhpQixLQUFmLENBRkg7QUFpQ1BDLElBQUFBLFdBQVcsRUFBRXpCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQUV5QixNQUFBQSxHQUFHLEVBQUU7QUFBRUMsUUFBQUEsVUFBVSxFQUFFO0FBQWQ7QUFBUCxLQUFmLENBakNOO0FBa0NQQyxJQUFBQSxXQUFXLEVBQUUsRUFsQ047QUFtQ1BDLElBQUFBLE9BQU8sRUFBRSxDQW5DRjtBQW9DUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUFFL0IsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDL0IrQixRQUFBQSxLQUFLLEVBQUUsY0FEd0I7QUFFL0JDLFFBQUFBLE1BQU0sRUFBRSxFQUZ1QjtBQUcvQkMsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQUh3QixPQUFmO0FBREc7QUFwQ2hCLEdBRlg7QUE4Q0VDLEVBQUFBLEtBQUssRUFBRTtBQTlDVCxDQURhLEVBaURiO0FBQ0V4QyxFQUFBQSxHQUFHLEVBQUUsd0NBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxlQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxlQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLFFBRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkMsUUFBQUEsVUFBVSxFQUFFLElBRE47QUFFTkMsUUFBQUEsU0FBUyxFQUFFLEtBRkw7QUFHTkgsUUFBQUEsSUFBSSxFQUFFLE9BSEE7QUFJTm1DLFFBQUFBLEtBQUssRUFBRTtBQUNMQyxVQUFBQSxhQUFhLEVBQUUsS0FEVjtBQUVMQyxVQUFBQSxVQUFVLEVBQUUsS0FGUDtBQUdMQyxVQUFBQSxjQUFjLEVBQUUsS0FIWDtBQUlMQyxVQUFBQSxTQUFTLEVBQUUsUUFKTjtBQUtMQyxVQUFBQSxVQUFVLEVBQUUsTUFMUDtBQU1MQyxVQUFBQSxTQUFTLEVBQUUsTUFOTjtBQU9MQyxVQUFBQSxXQUFXLEVBQUUsVUFQUjtBQVFMQyxVQUFBQSxXQUFXLEVBQUUsY0FSUjtBQVNMQyxVQUFBQSxjQUFjLEVBQUUsTUFUWDtBQVVMQyxVQUFBQSxRQUFRLEVBQUUsS0FWTDtBQVdMQyxVQUFBQSxXQUFXLEVBQUUsQ0FBQztBQUFFQyxZQUFBQSxJQUFJLEVBQUUsQ0FBUjtBQUFXQyxZQUFBQSxFQUFFLEVBQUU7QUFBZixXQUFELENBWFI7QUFZTEMsVUFBQUEsWUFBWSxFQUFFLEtBWlQ7QUFhTDNDLFVBQUFBLE1BQU0sRUFBRTtBQUFFQyxZQUFBQSxJQUFJLEVBQUUsSUFBUjtBQUFjMkMsWUFBQUEsS0FBSyxFQUFFO0FBQXJCLFdBYkg7QUFjTEMsVUFBQUEsS0FBSyxFQUFFO0FBQUU1QyxZQUFBQSxJQUFJLEVBQUUsS0FBUjtBQUFlRCxZQUFBQSxNQUFNLEVBQUUsS0FBdkI7QUFBOEI0QyxZQUFBQSxLQUFLLEVBQUUsTUFBckM7QUFBNkNFLFlBQUFBLEtBQUssRUFBRTtBQUFwRCxXQWRGO0FBZUxwRCxVQUFBQSxJQUFJLEVBQUUsUUFmRDtBQWdCTHFELFVBQUFBLEtBQUssRUFBRTtBQUFFQyxZQUFBQSxRQUFRLEVBQUUsRUFBWjtBQUFnQkMsWUFBQUEsT0FBTyxFQUFFLEtBQXpCO0FBQWdDQyxZQUFBQSxVQUFVLEVBQUUsS0FBNUM7QUFBbURDLFlBQUFBLE9BQU8sRUFBRTtBQUE1RDtBQWhCRjtBQUpELE9BSGU7QUEwQnZCOUMsTUFBQUEsSUFBSSxFQUFFLENBQ0o7QUFDRUMsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFFBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQUV5RCxVQUFBQSxXQUFXLEVBQUU7QUFBZjtBQUxWLE9BREk7QUExQmlCLEtBQWYsQ0FGSDtBQXNDUG5DLElBQUFBLFdBQVcsRUFBRXpCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQUV5QixNQUFBQSxHQUFHLEVBQUU7QUFBRW1DLFFBQUFBLGFBQWEsRUFBRTtBQUFFLHFCQUFXO0FBQWI7QUFBakI7QUFBUCxLQUFmLENBdENOO0FBdUNQakMsSUFBQUEsV0FBVyxFQUFFLEVBdkNOO0FBd0NQQyxJQUFBQSxPQUFPLEVBQUUsQ0F4Q0Y7QUF5Q1BDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRS9CLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CK0IsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsRUFGdUI7QUFHL0JDLFFBQUFBLEtBQUssRUFBRTtBQUFFQSxVQUFBQSxLQUFLLEVBQUUsRUFBVDtBQUFhQyxVQUFBQSxRQUFRLEVBQUU7QUFBdkI7QUFId0IsT0FBZjtBQURHO0FBekNoQixHQUZYO0FBbURFQyxFQUFBQSxLQUFLLEVBQUU7QUFuRFQsQ0FqRGEsRUFzR2I7QUFDRXhDLEVBQUFBLEdBQUcsRUFBRSwwQ0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLGlCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSx1QkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxRQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05DLFFBQUFBLFVBQVUsRUFBRSxJQUROO0FBRU5DLFFBQUFBLFNBQVMsRUFBRSxLQUZMO0FBR05ILFFBQUFBLElBQUksRUFBRSxPQUhBO0FBSU5tQyxRQUFBQSxLQUFLLEVBQUU7QUFDTEMsVUFBQUEsYUFBYSxFQUFFLEtBRFY7QUFFTEMsVUFBQUEsVUFBVSxFQUFFLEtBRlA7QUFHTEMsVUFBQUEsY0FBYyxFQUFFLEtBSFg7QUFJTEMsVUFBQUEsU0FBUyxFQUFFLFFBSk47QUFLTEMsVUFBQUEsVUFBVSxFQUFFLE1BTFA7QUFNTEMsVUFBQUEsU0FBUyxFQUFFLE1BTk47QUFPTEMsVUFBQUEsV0FBVyxFQUFFLFVBUFI7QUFRTEMsVUFBQUEsV0FBVyxFQUFFLGNBUlI7QUFTTEMsVUFBQUEsY0FBYyxFQUFFLE1BVFg7QUFVTEMsVUFBQUEsUUFBUSxFQUFFLEtBVkw7QUFXTEMsVUFBQUEsV0FBVyxFQUFFLENBQUM7QUFBRUMsWUFBQUEsSUFBSSxFQUFFLENBQVI7QUFBV0MsWUFBQUEsRUFBRSxFQUFFO0FBQWYsV0FBRCxDQVhSO0FBWUxDLFVBQUFBLFlBQVksRUFBRSxLQVpUO0FBYUwzQyxVQUFBQSxNQUFNLEVBQUU7QUFBRUMsWUFBQUEsSUFBSSxFQUFFLElBQVI7QUFBYzJDLFlBQUFBLEtBQUssRUFBRTtBQUFyQixXQWJIO0FBY0xDLFVBQUFBLEtBQUssRUFBRTtBQUFFNUMsWUFBQUEsSUFBSSxFQUFFLEtBQVI7QUFBZUQsWUFBQUEsTUFBTSxFQUFFLEtBQXZCO0FBQThCNEMsWUFBQUEsS0FBSyxFQUFFLE1BQXJDO0FBQTZDRSxZQUFBQSxLQUFLLEVBQUU7QUFBcEQsV0FkRjtBQWVMcEQsVUFBQUEsSUFBSSxFQUFFLFFBZkQ7QUFnQkxxRCxVQUFBQSxLQUFLLEVBQUU7QUFBRUMsWUFBQUEsUUFBUSxFQUFFLEVBQVo7QUFBZ0JDLFlBQUFBLE9BQU8sRUFBRSxLQUF6QjtBQUFnQ0MsWUFBQUEsVUFBVSxFQUFFLEtBQTVDO0FBQW1EQyxZQUFBQSxPQUFPLEVBQUU7QUFBNUQ7QUFoQkY7QUFKRCxPQUhlO0FBMEJ2QjlDLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQ0VDLFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxRQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUFFeUQsVUFBQUEsV0FBVyxFQUFFO0FBQWY7QUFMVixPQURJO0FBMUJpQixLQUFmLENBRkg7QUFzQ1BuQyxJQUFBQSxXQUFXLEVBQUV6QixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUFFeUIsTUFBQUEsR0FBRyxFQUFFO0FBQUVtQyxRQUFBQSxhQUFhLEVBQUU7QUFBRSxxQkFBVztBQUFiO0FBQWpCO0FBQVAsS0FBZixDQXRDTjtBQXVDUGpDLElBQUFBLFdBQVcsRUFBRSxFQXZDTjtBQXdDUEMsSUFBQUEsT0FBTyxFQUFFLENBeENGO0FBeUNQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUvQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQitCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRTZCLFVBQUFBLE1BQU0sRUFBRTtBQUNOQyxZQUFBQSxLQUFLLEVBQUU7QUFERCxXQURWO0FBSUVDLFVBQUFBLElBQUksRUFBRTtBQUNKQyxZQUFBQSxLQUFLLEVBQUUsSUFESDtBQUVKQyxZQUFBQSxRQUFRLEVBQUUsS0FGTjtBQUdKbEMsWUFBQUEsS0FBSyxFQUFFLGNBSEg7QUFJSm1DLFlBQUFBLEdBQUcsRUFBRSxZQUpEO0FBS0pDLFlBQUFBLE1BQU0sRUFBRSxLQUxKO0FBTUpqRSxZQUFBQSxNQUFNLEVBQUU7QUFDTmtFLGNBQUFBLEdBQUcsRUFBRSxFQURDO0FBRU5DLGNBQUFBLEVBQUUsRUFBRTtBQUZFLGFBTko7QUFVSnBFLFlBQUFBLElBQUksRUFBRSxPQVZGO0FBV0pxRSxZQUFBQSxLQUFLLEVBQUU7QUFYSCxXQUpSO0FBaUJFQyxVQUFBQSxLQUFLLEVBQUU7QUFDTCwwQkFBYztBQUNaSCxjQUFBQSxHQUFHLEVBQUUsRUFETztBQUVaQyxjQUFBQSxFQUFFLEVBQUU7QUFGUTtBQURUO0FBakJULFNBRE0sQ0FGdUI7QUE0Qi9CcEMsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQTVCd0IsT0FBZjtBQURHO0FBekNoQixHQUZYO0FBNEVFQyxFQUFBQSxLQUFLLEVBQUU7QUE1RVQsQ0F0R2EsRUFvTGI7QUFDRXhDLEVBQUFBLEdBQUcsRUFBRSxpREFEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLHdCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSw4QkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxRQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05DLFFBQUFBLFVBQVUsRUFBRSxJQUROO0FBRU5DLFFBQUFBLFNBQVMsRUFBRSxLQUZMO0FBR05ILFFBQUFBLElBQUksRUFBRSxPQUhBO0FBSU5tQyxRQUFBQSxLQUFLLEVBQUU7QUFDTEMsVUFBQUEsYUFBYSxFQUFFLEtBRFY7QUFFTEMsVUFBQUEsVUFBVSxFQUFFLEtBRlA7QUFHTEMsVUFBQUEsY0FBYyxFQUFFLEtBSFg7QUFJTEMsVUFBQUEsU0FBUyxFQUFFLFFBSk47QUFLTEMsVUFBQUEsVUFBVSxFQUFFLE1BTFA7QUFNTEMsVUFBQUEsU0FBUyxFQUFFLE1BTk47QUFPTEMsVUFBQUEsV0FBVyxFQUFFLFVBUFI7QUFRTEMsVUFBQUEsV0FBVyxFQUFFLGNBUlI7QUFTTEMsVUFBQUEsY0FBYyxFQUFFLE1BVFg7QUFVTEMsVUFBQUEsUUFBUSxFQUFFLEtBVkw7QUFXTEMsVUFBQUEsV0FBVyxFQUFFLENBQUM7QUFBRUMsWUFBQUEsSUFBSSxFQUFFLENBQVI7QUFBV0MsWUFBQUEsRUFBRSxFQUFFO0FBQWYsV0FBRCxDQVhSO0FBWUxDLFVBQUFBLFlBQVksRUFBRSxLQVpUO0FBYUwzQyxVQUFBQSxNQUFNLEVBQUU7QUFBRUMsWUFBQUEsSUFBSSxFQUFFLElBQVI7QUFBYzJDLFlBQUFBLEtBQUssRUFBRTtBQUFyQixXQWJIO0FBY0xDLFVBQUFBLEtBQUssRUFBRTtBQUFFNUMsWUFBQUEsSUFBSSxFQUFFLEtBQVI7QUFBZUQsWUFBQUEsTUFBTSxFQUFFLEtBQXZCO0FBQThCNEMsWUFBQUEsS0FBSyxFQUFFLE1BQXJDO0FBQTZDRSxZQUFBQSxLQUFLLEVBQUU7QUFBcEQsV0FkRjtBQWVMcEQsVUFBQUEsSUFBSSxFQUFFLFFBZkQ7QUFnQkxxRCxVQUFBQSxLQUFLLEVBQUU7QUFBRUMsWUFBQUEsUUFBUSxFQUFFLEVBQVo7QUFBZ0JDLFlBQUFBLE9BQU8sRUFBRSxLQUF6QjtBQUFnQ0MsWUFBQUEsVUFBVSxFQUFFLEtBQTVDO0FBQW1EQyxZQUFBQSxPQUFPLEVBQUU7QUFBNUQ7QUFoQkY7QUFKRCxPQUhlO0FBMEJ2QjlDLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQ0VDLFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxRQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUFFeUQsVUFBQUEsV0FBVyxFQUFFO0FBQWY7QUFMVixPQURJO0FBMUJpQixLQUFmLENBRkg7QUFzQ1BuQyxJQUFBQSxXQUFXLEVBQUV6QixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUFFeUIsTUFBQUEsR0FBRyxFQUFFO0FBQUVtQyxRQUFBQSxhQUFhLEVBQUU7QUFBRSxxQkFBVztBQUFiO0FBQWpCO0FBQVAsS0FBZixDQXRDTjtBQXVDUGpDLElBQUFBLFdBQVcsRUFBRSxFQXZDTjtBQXdDUEMsSUFBQUEsT0FBTyxFQUFFLENBeENGO0FBeUNQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUvQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQitCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRStCLFVBQUFBLElBQUksRUFBRTtBQUNKaEMsWUFBQUEsS0FBSyxFQUFFLGNBREg7QUFFSjlCLFlBQUFBLElBQUksRUFBRSxTQUZGO0FBR0ppRSxZQUFBQSxHQUFHLEVBQUUsYUFIRDtBQUlKSSxZQUFBQSxLQUFLLEVBQUUsMkVBSkg7QUFLSnBFLFlBQUFBLE1BQU0sRUFBRSxDQUNOLDJCQURNLEVBRU4sdUJBRk0sRUFHTix5QkFITSxDQUxKO0FBVUppRSxZQUFBQSxNQUFNLEVBQUUsS0FWSjtBQVdKRixZQUFBQSxRQUFRLEVBQUUsS0FYTjtBQVlKRCxZQUFBQSxLQUFLLEVBQUU7QUFaSCxXQURSO0FBZUUvQixVQUFBQSxLQUFLLEVBQUU7QUFDTHVDLFlBQUFBLElBQUksRUFBRTtBQUNKQyxjQUFBQSxNQUFNLEVBQUUsQ0FDTjtBQUNFQyxnQkFBQUEsWUFBWSxFQUFFO0FBQ1osaUNBQWU7QUFESDtBQURoQixlQURNLEVBTU47QUFDRUEsZ0JBQUFBLFlBQVksRUFBRTtBQUNaLGlDQUFlO0FBREg7QUFEaEIsZUFOTSxFQVdOO0FBQ0VBLGdCQUFBQSxZQUFZLEVBQUU7QUFDWixpQ0FBZTtBQURIO0FBRGhCLGVBWE0sQ0FESjtBQWtCSkMsY0FBQUEsb0JBQW9CLEVBQUU7QUFsQmxCO0FBREQsV0FmVDtBQXFDRWQsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLEtBQUssRUFBRTtBQUREO0FBckNWLFNBRE0sQ0FGdUI7QUE2Qy9CN0IsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQTdDd0IsT0FBZjtBQURHO0FBekNoQixHQUZYO0FBNkZFQyxFQUFBQSxLQUFLLEVBQUU7QUE3RlQsQ0FwTGEsRUFtUmI7QUFDRXhDLEVBQUFBLEdBQUcsRUFBRSxpREFEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLHdCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSw4QkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxRQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05DLFFBQUFBLFVBQVUsRUFBRSxJQUROO0FBRU5DLFFBQUFBLFNBQVMsRUFBRSxLQUZMO0FBR05ILFFBQUFBLElBQUksRUFBRSxPQUhBO0FBSU5tQyxRQUFBQSxLQUFLLEVBQUU7QUFDTEMsVUFBQUEsYUFBYSxFQUFFLEtBRFY7QUFFTEMsVUFBQUEsVUFBVSxFQUFFLEtBRlA7QUFHTEMsVUFBQUEsY0FBYyxFQUFFLEtBSFg7QUFJTEMsVUFBQUEsU0FBUyxFQUFFLFFBSk47QUFLTEMsVUFBQUEsVUFBVSxFQUFFLE1BTFA7QUFNTEMsVUFBQUEsU0FBUyxFQUFFLE1BTk47QUFPTEMsVUFBQUEsV0FBVyxFQUFFLFVBUFI7QUFRTEMsVUFBQUEsV0FBVyxFQUFFLGNBUlI7QUFTTEMsVUFBQUEsY0FBYyxFQUFFLE1BVFg7QUFVTEMsVUFBQUEsUUFBUSxFQUFFLEtBVkw7QUFXTEMsVUFBQUEsV0FBVyxFQUFFLENBQUM7QUFBRUMsWUFBQUEsSUFBSSxFQUFFLENBQVI7QUFBV0MsWUFBQUEsRUFBRSxFQUFFO0FBQWYsV0FBRCxDQVhSO0FBWUxDLFVBQUFBLFlBQVksRUFBRSxLQVpUO0FBYUwzQyxVQUFBQSxNQUFNLEVBQUU7QUFBRUMsWUFBQUEsSUFBSSxFQUFFLElBQVI7QUFBYzJDLFlBQUFBLEtBQUssRUFBRTtBQUFyQixXQWJIO0FBY0xDLFVBQUFBLEtBQUssRUFBRTtBQUFFNUMsWUFBQUEsSUFBSSxFQUFFLEtBQVI7QUFBZUQsWUFBQUEsTUFBTSxFQUFFLEtBQXZCO0FBQThCNEMsWUFBQUEsS0FBSyxFQUFFLE1BQXJDO0FBQTZDRSxZQUFBQSxLQUFLLEVBQUU7QUFBcEQsV0FkRjtBQWVMcEQsVUFBQUEsSUFBSSxFQUFFLFFBZkQ7QUFnQkxxRCxVQUFBQSxLQUFLLEVBQUU7QUFBRUMsWUFBQUEsUUFBUSxFQUFFLEVBQVo7QUFBZ0JDLFlBQUFBLE9BQU8sRUFBRSxLQUF6QjtBQUFnQ0MsWUFBQUEsVUFBVSxFQUFFLEtBQTVDO0FBQW1EQyxZQUFBQSxPQUFPLEVBQUU7QUFBNUQ7QUFoQkY7QUFKRCxPQUhlO0FBMEJ2QjlDLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQ0VDLFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxRQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUFFeUQsVUFBQUEsV0FBVyxFQUFFO0FBQWY7QUFMVixPQURJO0FBMUJpQixLQUFmLENBRkg7QUFzQ1BuQyxJQUFBQSxXQUFXLEVBQUV6QixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUFFeUIsTUFBQUEsR0FBRyxFQUFFO0FBQUVtQyxRQUFBQSxhQUFhLEVBQUU7QUFBRSxxQkFBVztBQUFiO0FBQWpCO0FBQVAsS0FBZixDQXRDTjtBQXVDUGpDLElBQUFBLFdBQVcsRUFBRSxFQXZDTjtBQXdDUEMsSUFBQUEsT0FBTyxFQUFFLENBeENGO0FBeUNQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUvQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQitCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRStCLFVBQUFBLElBQUksRUFBRTtBQUNKaEMsWUFBQUEsS0FBSyxFQUFFLGNBREg7QUFFSm9DLFlBQUFBLE1BQU0sRUFBRSxLQUZKO0FBR0pGLFlBQUFBLFFBQVEsRUFBRSxLQUhOO0FBSUpELFlBQUFBLEtBQUssRUFBRSxJQUpIO0FBS0ovRCxZQUFBQSxJQUFJLEVBQUUsUUFMRjtBQU1KaUUsWUFBQUEsR0FBRyxFQUFFLGFBTkQ7QUFPSkksWUFBQUEsS0FBSyxFQUFFLHdCQVBIO0FBUUpwRSxZQUFBQSxNQUFNLEVBQUU7QUFDTitCLGNBQUFBLEtBQUssRUFBRSx3QkFERDtBQUVOaEMsY0FBQUEsSUFBSSxFQUFFO0FBRkE7QUFSSixXQURSO0FBY0VnQyxVQUFBQSxLQUFLLEVBQUU7QUFDTDJDLFlBQUFBLEtBQUssRUFBRTtBQUNMLDZCQUFlO0FBQ2IzQyxnQkFBQUEsS0FBSyxFQUFFLHdCQURNO0FBRWJoQyxnQkFBQUEsSUFBSSxFQUFFO0FBRk87QUFEVjtBQURGLFdBZFQ7QUFzQkU0RCxVQUFBQSxNQUFNLEVBQUU7QUFDTkMsWUFBQUEsS0FBSyxFQUFFO0FBREQ7QUF0QlYsU0FETSxDQUZ1QjtBQThCL0I3QixRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBOUJ3QixPQUFmO0FBREc7QUF6Q2hCLEdBRlg7QUE4RUVDLEVBQUFBLEtBQUssRUFBRTtBQTlFVCxDQW5SYSxFQW1XYjtBQUNFeEMsRUFBQUEsR0FBRyxFQUFFLHdDQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsbUJBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLG1CQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLEtBRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkQsUUFBQUEsSUFBSSxFQUFFLEtBREE7QUFFTkUsUUFBQUEsVUFBVSxFQUFFLElBRk47QUFHTkMsUUFBQUEsU0FBUyxFQUFFLElBSEw7QUFJTkMsUUFBQUEsY0FBYyxFQUFFLE9BSlY7QUFLTkMsUUFBQUEsT0FBTyxFQUFFLEtBTEg7QUFNTkMsUUFBQUEsTUFBTSxFQUFFO0FBQUVDLFVBQUFBLElBQUksRUFBRSxLQUFSO0FBQWVDLFVBQUFBLE1BQU0sRUFBRSxJQUF2QjtBQUE2QkMsVUFBQUEsVUFBVSxFQUFFLElBQXpDO0FBQStDQyxVQUFBQSxRQUFRLEVBQUU7QUFBekQ7QUFORixPQUhlO0FBV3ZCQyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFQyxRQUFBQSxFQUFFLEVBQUUsR0FBTjtBQUFXQyxRQUFBQSxPQUFPLEVBQUUsSUFBcEI7QUFBMEJiLFFBQUFBLElBQUksRUFBRSxPQUFoQztBQUF5Q2MsUUFBQUEsTUFBTSxFQUFFLFFBQWpEO0FBQTJEYixRQUFBQSxNQUFNLEVBQUU7QUFBbkUsT0FESSxFQUVKO0FBQ0VXLFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxTQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUNOYyxVQUFBQSxLQUFLLEVBQUUsYUFERDtBQUVOQyxVQUFBQSxJQUFJLEVBQUUsQ0FGQTtBQUdOQyxVQUFBQSxLQUFLLEVBQUUsTUFIRDtBQUlOQyxVQUFBQSxPQUFPLEVBQUUsR0FKSDtBQUtOQyxVQUFBQSxXQUFXLEVBQUUsS0FMUDtBQU1OQyxVQUFBQSxnQkFBZ0IsRUFBRSxPQU5aO0FBT05DLFVBQUFBLGFBQWEsRUFBRSxLQVBUO0FBUU5DLFVBQUFBLGtCQUFrQixFQUFFO0FBUmQ7QUFMVixPQUZJO0FBWGlCLEtBQWYsQ0FGSDtBQWlDUEMsSUFBQUEsV0FBVyxFQUFFekIsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFBRXlCLE1BQUFBLEdBQUcsRUFBRTtBQUFFQyxRQUFBQSxVQUFVLEVBQUU7QUFBZDtBQUFQLEtBQWYsQ0FqQ047QUFrQ1BDLElBQUFBLFdBQVcsRUFBRSxFQWxDTjtBQW1DUEMsSUFBQUEsT0FBTyxFQUFFLENBbkNGO0FBb0NQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUvQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQitCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLEVBRnVCO0FBRy9CQyxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBSHdCLE9BQWY7QUFERztBQXBDaEIsR0FGWDtBQThDRUMsRUFBQUEsS0FBSyxFQUFFO0FBOUNULENBbldhLEVBbVpiO0FBQ0V4QyxFQUFBQSxHQUFHLEVBQUUscURBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSw0QkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUsNEJBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsS0FGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNORCxRQUFBQSxJQUFJLEVBQUUsS0FEQTtBQUVORSxRQUFBQSxVQUFVLEVBQUUsSUFGTjtBQUdOQyxRQUFBQSxTQUFTLEVBQUUsSUFITDtBQUlOQyxRQUFBQSxjQUFjLEVBQUUsT0FKVjtBQUtOQyxRQUFBQSxPQUFPLEVBQUUsSUFMSDtBQU1OQyxRQUFBQSxNQUFNLEVBQUU7QUFBRUMsVUFBQUEsSUFBSSxFQUFFLEtBQVI7QUFBZUMsVUFBQUEsTUFBTSxFQUFFLElBQXZCO0FBQTZCQyxVQUFBQSxVQUFVLEVBQUUsSUFBekM7QUFBK0NDLFVBQUFBLFFBQVEsRUFBRTtBQUF6RDtBQU5GLE9BSGU7QUFXdkJDLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQUVDLFFBQUFBLEVBQUUsRUFBRSxHQUFOO0FBQVdDLFFBQUFBLE9BQU8sRUFBRSxJQUFwQjtBQUEwQmIsUUFBQUEsSUFBSSxFQUFFLE9BQWhDO0FBQXlDYyxRQUFBQSxNQUFNLEVBQUUsUUFBakQ7QUFBMkRiLFFBQUFBLE1BQU0sRUFBRTtBQUFuRSxPQURJLEVBRUo7QUFDRVcsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFNBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQ05jLFVBQUFBLEtBQUssRUFBRSxjQUREO0FBRU5DLFVBQUFBLElBQUksRUFBRSxDQUZBO0FBR05DLFVBQUFBLEtBQUssRUFBRSxNQUhEO0FBSU5DLFVBQUFBLE9BQU8sRUFBRSxHQUpIO0FBS05DLFVBQUFBLFdBQVcsRUFBRSxLQUxQO0FBTU5DLFVBQUFBLGdCQUFnQixFQUFFLE9BTlo7QUFPTkMsVUFBQUEsYUFBYSxFQUFFLEtBUFQ7QUFRTkMsVUFBQUEsa0JBQWtCLEVBQUU7QUFSZDtBQUxWLE9BRkk7QUFYaUIsS0FBZixDQUZIO0FBaUNQQyxJQUFBQSxXQUFXLEVBQUUsNkJBakNOO0FBa0NQRyxJQUFBQSxXQUFXLEVBQUUsRUFsQ047QUFtQ1BDLElBQUFBLE9BQU8sRUFBRSxDQW5DRjtBQW9DUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUFFL0IsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDL0IrQixRQUFBQSxLQUFLLEVBQUUsY0FEd0I7QUFFL0JDLFFBQUFBLE1BQU0sRUFBRSxFQUZ1QjtBQUcvQkMsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQUh3QixPQUFmO0FBREc7QUFwQ2hCLEdBRlg7QUE4Q0VDLEVBQUFBLEtBQUssRUFBRTtBQTlDVCxDQW5aYSxFQW1jYjtBQUNFeEMsRUFBQUEsR0FBRyxFQUFFLGlEQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsd0JBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLDJCQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLE1BRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkQsUUFBQUEsSUFBSSxFQUFFLE1BREE7QUFFTjRFLFFBQUFBLElBQUksRUFBRTtBQUFFQyxVQUFBQSxhQUFhLEVBQUUsSUFBakI7QUFBdUJ4QixVQUFBQSxLQUFLLEVBQUU7QUFBRUgsWUFBQUEsS0FBSyxFQUFFO0FBQVQsV0FBOUI7QUFBaUQ0QixVQUFBQSxTQUFTLEVBQUU7QUFBNUQsU0FGQTtBQUdOQyxRQUFBQSxZQUFZLEVBQUUsQ0FDWjtBQUNFbkUsVUFBQUEsRUFBRSxFQUFFLGdCQUROO0FBRUVaLFVBQUFBLElBQUksRUFBRSxVQUZSO0FBR0VnRixVQUFBQSxRQUFRLEVBQUUsUUFIWjtBQUlFekUsVUFBQUEsSUFBSSxFQUFFLElBSlI7QUFLRThDLFVBQUFBLEtBQUssRUFBRSxFQUxUO0FBTUVGLFVBQUFBLEtBQUssRUFBRTtBQUFFbkQsWUFBQUEsSUFBSSxFQUFFO0FBQVIsV0FOVDtBQU9FTSxVQUFBQSxNQUFNLEVBQUU7QUFBRUMsWUFBQUEsSUFBSSxFQUFFLElBQVI7QUFBY3dCLFlBQUFBLE1BQU0sRUFBRSxJQUF0QjtBQUE0QnJCLFlBQUFBLFFBQVEsRUFBRTtBQUF0QyxXQVBWO0FBUUVkLFVBQUFBLEtBQUssRUFBRTtBQVJULFNBRFksQ0FIUjtBQWVOcUYsUUFBQUEsU0FBUyxFQUFFLENBQ1Q7QUFDRXJFLFVBQUFBLEVBQUUsRUFBRSxhQUROO0FBRUVzRSxVQUFBQSxJQUFJLEVBQUUsWUFGUjtBQUdFbEYsVUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWdGLFVBQUFBLFFBQVEsRUFBRSxNQUpaO0FBS0V6RSxVQUFBQSxJQUFJLEVBQUUsSUFMUjtBQU1FOEMsVUFBQUEsS0FBSyxFQUFFLEVBTlQ7QUFPRUYsVUFBQUEsS0FBSyxFQUFFO0FBQUVuRCxZQUFBQSxJQUFJLEVBQUUsUUFBUjtBQUFrQm1GLFlBQUFBLElBQUksRUFBRTtBQUF4QixXQVBUO0FBUUU3RSxVQUFBQSxNQUFNLEVBQUU7QUFBRUMsWUFBQUEsSUFBSSxFQUFFLElBQVI7QUFBYzZFLFlBQUFBLE1BQU0sRUFBRSxDQUF0QjtBQUF5QnJELFlBQUFBLE1BQU0sRUFBRSxLQUFqQztBQUF3Q3JCLFlBQUFBLFFBQVEsRUFBRTtBQUFsRCxXQVJWO0FBU0VkLFVBQUFBLEtBQUssRUFBRTtBQUFFeUYsWUFBQUEsSUFBSSxFQUFFO0FBQVI7QUFUVCxTQURTLENBZkw7QUE0Qk5DLFFBQUFBLFlBQVksRUFBRSxDQUNaO0FBQ0UvRSxVQUFBQSxJQUFJLEVBQUUsTUFEUjtBQUVFUCxVQUFBQSxJQUFJLEVBQUUsTUFGUjtBQUdFbUYsVUFBQUEsSUFBSSxFQUFFLFNBSFI7QUFJRUksVUFBQUEsSUFBSSxFQUFFO0FBQUVDLFlBQUFBLEtBQUssRUFBRSxPQUFUO0FBQWtCNUUsWUFBQUEsRUFBRSxFQUFFO0FBQXRCLFdBSlI7QUFLRTZFLFVBQUFBLHNCQUFzQixFQUFFLElBTDFCO0FBTUVDLFVBQUFBLFdBQVcsRUFBRSxJQU5mO0FBT0VDLFVBQUFBLFdBQVcsRUFBRSxVQVBmO0FBUUViLFVBQUFBLFNBQVMsRUFBRTtBQVJiLFNBRFksQ0E1QlI7QUF3Q041RSxRQUFBQSxVQUFVLEVBQUUsSUF4Q047QUF5Q05DLFFBQUFBLFNBQVMsRUFBRSxJQXpDTDtBQTBDTkMsUUFBQUEsY0FBYyxFQUFFLE9BMUNWO0FBMkNOd0YsUUFBQUEsS0FBSyxFQUFFLEVBM0NEO0FBNENOQyxRQUFBQSxhQUFhLEVBQUU7QUE1Q1QsT0FIZTtBQWlEdkJsRixNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFQyxRQUFBQSxFQUFFLEVBQUUsR0FBTjtBQUFXQyxRQUFBQSxPQUFPLEVBQUUsSUFBcEI7QUFBMEJiLFFBQUFBLElBQUksRUFBRSxPQUFoQztBQUF5Q2MsUUFBQUEsTUFBTSxFQUFFLFFBQWpEO0FBQTJEYixRQUFBQSxNQUFNLEVBQUU7QUFBbkUsT0FESSxFQUVKO0FBQ0VXLFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxnQkFIUjtBQUlFYyxRQUFBQSxNQUFNLEVBQUUsU0FKVjtBQUtFYixRQUFBQSxNQUFNLEVBQUU7QUFDTmMsVUFBQUEsS0FBSyxFQUFFLFdBREQ7QUFFTitFLFVBQUFBLFNBQVMsRUFBRTtBQUFFL0MsWUFBQUEsSUFBSSxFQUFFLFNBQVI7QUFBbUJDLFlBQUFBLEVBQUUsRUFBRSxLQUF2QjtBQUE4Qm1DLFlBQUFBLElBQUksRUFBRTtBQUFwQyxXQUZMO0FBR05ZLFVBQUFBLHVCQUF1QixFQUFFLElBSG5CO0FBSU5DLFVBQUFBLFFBQVEsRUFBRSxNQUpKO0FBS05DLFVBQUFBLFNBQVMsRUFBRSxlQUxMO0FBTU5DLFVBQUFBLGFBQWEsRUFBRSxLQU5UO0FBT05DLFVBQUFBLGNBQWMsRUFBRSxJQVBWO0FBUU5DLFVBQUFBLGFBQWEsRUFBRSxDQVJUO0FBU05DLFVBQUFBLGVBQWUsRUFBRTtBQVRYO0FBTFYsT0FGSSxFQW1CSjtBQUNFekYsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLE9BSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQ05jLFVBQUFBLEtBQUssRUFBRSxhQUREO0FBRU5DLFVBQUFBLElBQUksRUFBRSxDQUZBO0FBR05DLFVBQUFBLEtBQUssRUFBRSxNQUhEO0FBSU5DLFVBQUFBLE9BQU8sRUFBRSxHQUpIO0FBS05DLFVBQUFBLFdBQVcsRUFBRSxLQUxQO0FBTU5DLFVBQUFBLGdCQUFnQixFQUFFLE9BTlo7QUFPTkMsVUFBQUEsYUFBYSxFQUFFLEtBUFQ7QUFRTkMsVUFBQUEsa0JBQWtCLEVBQUU7QUFSZDtBQUxWLE9BbkJJO0FBakRpQixLQUFmLENBRkg7QUF3RlBDLElBQUFBLFdBQVcsRUFBRSxJQXhGTjtBQXlGUEcsSUFBQUEsV0FBVyxFQUFFLEVBekZOO0FBMEZQQyxJQUFBQSxPQUFPLEVBQUUsQ0ExRkY7QUEyRlBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRS9CLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CK0IsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsRUFGdUI7QUFHL0JDLFFBQUFBLEtBQUssRUFBRTtBQUFFQSxVQUFBQSxLQUFLLEVBQUUsRUFBVDtBQUFhQyxVQUFBQSxRQUFRLEVBQUU7QUFBdkI7QUFId0IsT0FBZjtBQURHO0FBM0ZoQixHQUZYO0FBcUdFQyxFQUFBQSxLQUFLLEVBQUU7QUFyR1QsQ0FuY2EsRUEwaUJiO0FBQ0V4QyxFQUFBQSxHQUFHLEVBQUUsaUNBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxRQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSw0QkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxNQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05ELFFBQUFBLElBQUksRUFBRSxNQURBO0FBRU40RSxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsYUFBYSxFQUFFLElBQWpCO0FBQXVCeEIsVUFBQUEsS0FBSyxFQUFFO0FBQUVILFlBQUFBLEtBQUssRUFBRTtBQUFULFdBQTlCO0FBQWlENEIsVUFBQUEsU0FBUyxFQUFFO0FBQTVELFNBRkE7QUFHTkMsUUFBQUEsWUFBWSxFQUFFLENBQ1o7QUFDRW5FLFVBQUFBLEVBQUUsRUFBRSxnQkFETjtBQUVFWixVQUFBQSxJQUFJLEVBQUUsVUFGUjtBQUdFZ0YsVUFBQUEsUUFBUSxFQUFFLFFBSFo7QUFJRXpFLFVBQUFBLElBQUksRUFBRSxJQUpSO0FBS0U4QyxVQUFBQSxLQUFLLEVBQUUsRUFMVDtBQU1FRixVQUFBQSxLQUFLLEVBQUU7QUFBRW5ELFlBQUFBLElBQUksRUFBRTtBQUFSLFdBTlQ7QUFPRU0sVUFBQUEsTUFBTSxFQUFFO0FBQUVDLFlBQUFBLElBQUksRUFBRSxJQUFSO0FBQWN3QixZQUFBQSxNQUFNLEVBQUUsSUFBdEI7QUFBNEJyQixZQUFBQSxRQUFRLEVBQUU7QUFBdEMsV0FQVjtBQVFFZCxVQUFBQSxLQUFLLEVBQUU7QUFSVCxTQURZLENBSFI7QUFlTnFGLFFBQUFBLFNBQVMsRUFBRSxDQUNUO0FBQ0VyRSxVQUFBQSxFQUFFLEVBQUUsYUFETjtBQUVFc0UsVUFBQUEsSUFBSSxFQUFFLFlBRlI7QUFHRWxGLFVBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVnRixVQUFBQSxRQUFRLEVBQUUsTUFKWjtBQUtFekUsVUFBQUEsSUFBSSxFQUFFLElBTFI7QUFNRThDLFVBQUFBLEtBQUssRUFBRSxFQU5UO0FBT0VGLFVBQUFBLEtBQUssRUFBRTtBQUFFbkQsWUFBQUEsSUFBSSxFQUFFLFFBQVI7QUFBa0JtRixZQUFBQSxJQUFJLEVBQUU7QUFBeEIsV0FQVDtBQVFFN0UsVUFBQUEsTUFBTSxFQUFFO0FBQUVDLFlBQUFBLElBQUksRUFBRSxJQUFSO0FBQWM2RSxZQUFBQSxNQUFNLEVBQUUsQ0FBdEI7QUFBeUJyRCxZQUFBQSxNQUFNLEVBQUUsS0FBakM7QUFBd0NyQixZQUFBQSxRQUFRLEVBQUU7QUFBbEQsV0FSVjtBQVNFZCxVQUFBQSxLQUFLLEVBQUU7QUFBRXlGLFlBQUFBLElBQUksRUFBRTtBQUFSO0FBVFQsU0FEUyxDQWZMO0FBNEJOQyxRQUFBQSxZQUFZLEVBQUUsQ0FDWjtBQUNFL0UsVUFBQUEsSUFBSSxFQUFFLE1BRFI7QUFFRVAsVUFBQUEsSUFBSSxFQUFFLE1BRlI7QUFHRW1GLFVBQUFBLElBQUksRUFBRSxTQUhSO0FBSUVJLFVBQUFBLElBQUksRUFBRTtBQUFFQyxZQUFBQSxLQUFLLEVBQUUsT0FBVDtBQUFrQjVFLFlBQUFBLEVBQUUsRUFBRTtBQUF0QixXQUpSO0FBS0U2RSxVQUFBQSxzQkFBc0IsRUFBRSxJQUwxQjtBQU1FQyxVQUFBQSxXQUFXLEVBQUUsSUFOZjtBQU9FQyxVQUFBQSxXQUFXLEVBQUUsVUFQZjtBQVFFYixVQUFBQSxTQUFTLEVBQUU7QUFSYixTQURZLENBNUJSO0FBd0NONUUsUUFBQUEsVUFBVSxFQUFFLElBeENOO0FBeUNOQyxRQUFBQSxTQUFTLEVBQUUsSUF6Q0w7QUEwQ05DLFFBQUFBLGNBQWMsRUFBRSxPQTFDVjtBQTJDTndGLFFBQUFBLEtBQUssRUFBRSxFQTNDRDtBQTRDTkMsUUFBQUEsYUFBYSxFQUFFO0FBNUNULE9BSGU7QUFpRHZCbEYsTUFBQUEsSUFBSSxFQUFFLENBQ0o7QUFBRUMsUUFBQUEsRUFBRSxFQUFFLEdBQU47QUFBV0MsUUFBQUEsT0FBTyxFQUFFLElBQXBCO0FBQTBCYixRQUFBQSxJQUFJLEVBQUUsT0FBaEM7QUFBeUNjLFFBQUFBLE1BQU0sRUFBRSxRQUFqRDtBQUEyRGIsUUFBQUEsTUFBTSxFQUFFO0FBQW5FLE9BREksRUFFSjtBQUNFVyxRQUFBQSxFQUFFLEVBQUUsR0FETjtBQUVFQyxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFYixRQUFBQSxJQUFJLEVBQUUsZ0JBSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFNBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQ05jLFVBQUFBLEtBQUssRUFBRSxXQUREO0FBRU4rRSxVQUFBQSxTQUFTLEVBQUU7QUFBRS9DLFlBQUFBLElBQUksRUFBRSxTQUFSO0FBQW1CQyxZQUFBQSxFQUFFLEVBQUUsS0FBdkI7QUFBOEJtQyxZQUFBQSxJQUFJLEVBQUU7QUFBcEMsV0FGTDtBQUdOWSxVQUFBQSx1QkFBdUIsRUFBRSxJQUhuQjtBQUlOQyxVQUFBQSxRQUFRLEVBQUUsTUFKSjtBQUtOQyxVQUFBQSxTQUFTLEVBQUUsZUFMTDtBQU1OQyxVQUFBQSxhQUFhLEVBQUUsS0FOVDtBQU9OQyxVQUFBQSxjQUFjLEVBQUUsSUFQVjtBQVFOQyxVQUFBQSxhQUFhLEVBQUUsQ0FSVDtBQVNOQyxVQUFBQSxlQUFlLEVBQUU7QUFUWDtBQUxWLE9BRkksRUFtQko7QUFDRXpGLFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxPQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUNOYyxVQUFBQSxLQUFLLEVBQUUsWUFERDtBQUVOQyxVQUFBQSxJQUFJLEVBQUUsQ0FGQTtBQUdOQyxVQUFBQSxLQUFLLEVBQUUsTUFIRDtBQUlOQyxVQUFBQSxPQUFPLEVBQUUsR0FKSDtBQUtOQyxVQUFBQSxXQUFXLEVBQUUsS0FMUDtBQU1OQyxVQUFBQSxnQkFBZ0IsRUFBRSxPQU5aO0FBT05DLFVBQUFBLGFBQWEsRUFBRSxLQVBUO0FBUU5DLFVBQUFBLGtCQUFrQixFQUFFO0FBUmQ7QUFMVixPQW5CSTtBQWpEaUIsS0FBZixDQUZIO0FBd0ZQQyxJQUFBQSxXQUFXLEVBQUUsSUF4Rk47QUF5RlBHLElBQUFBLFdBQVcsRUFBRSxFQXpGTjtBQTBGUEMsSUFBQUEsT0FBTyxFQUFFLENBMUZGO0FBMkZQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUvQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQitCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLEVBRnVCO0FBRy9CQyxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBSHdCLE9BQWY7QUFERztBQTNGaEIsR0FGWDtBQXFHRUMsRUFBQUEsS0FBSyxFQUFFO0FBckdULENBMWlCYSxFQWlwQmI7QUFDRXhDLEVBQUFBLEdBQUcsRUFBRSx5Q0FEUDtBQUVFd0MsRUFBQUEsS0FBSyxFQUFFLGVBRlQ7QUFHRXZDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsZ0JBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLGdCQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLE9BRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTnFHLFFBQUFBLE9BQU8sRUFBRSxFQURIO0FBRU5DLFFBQUFBLGVBQWUsRUFBRSxLQUZYO0FBR05DLFFBQUFBLHFCQUFxQixFQUFFLEtBSGpCO0FBSU5DLFFBQUFBLElBQUksRUFBRTtBQUFFQyxVQUFBQSxXQUFXLEVBQUUsQ0FBZjtBQUFrQkMsVUFBQUEsU0FBUyxFQUFFO0FBQTdCLFNBSkE7QUFLTkMsUUFBQUEsU0FBUyxFQUFFLEtBTEw7QUFNTkMsUUFBQUEsV0FBVyxFQUFFLElBTlA7QUFPTkMsUUFBQUEsU0FBUyxFQUFFO0FBUEwsT0FIZTtBQVl2Qm5HLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQUVDLFFBQUFBLEVBQUUsRUFBRSxHQUFOO0FBQVdDLFFBQUFBLE9BQU8sRUFBRSxJQUFwQjtBQUEwQmIsUUFBQUEsSUFBSSxFQUFFLE9BQWhDO0FBQXlDYyxRQUFBQSxNQUFNLEVBQUUsUUFBakQ7QUFBMkRiLFFBQUFBLE1BQU0sRUFBRTtBQUFuRSxPQURJLEVBRUo7QUFDRVcsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFFBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQ05jLFVBQUFBLEtBQUssRUFBRSxTQUREO0FBRU5JLFVBQUFBLFdBQVcsRUFBRSxLQUZQO0FBR05DLFVBQUFBLGdCQUFnQixFQUFFLE9BSFo7QUFJTkMsVUFBQUEsYUFBYSxFQUFFLEtBSlQ7QUFLTkMsVUFBQUEsa0JBQWtCLEVBQUUsU0FMZDtBQU1OTixVQUFBQSxJQUFJLEVBQUUsRUFOQTtBQU9OQyxVQUFBQSxLQUFLLEVBQUUsTUFQRDtBQVFOQyxVQUFBQSxPQUFPLEVBQUUsR0FSSDtBQVNOd0MsVUFBQUEsV0FBVyxFQUFFO0FBVFA7QUFMVixPQUZJLEVBbUJKO0FBQ0U5QyxRQUFBQSxFQUFFLEVBQUUsR0FETjtBQUVFQyxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFYixRQUFBQSxJQUFJLEVBQUUsT0FIUjtBQUlFYyxRQUFBQSxNQUFNLEVBQUUsUUFKVjtBQUtFYixRQUFBQSxNQUFNLEVBQUU7QUFDTmMsVUFBQUEsS0FBSyxFQUFFLGtCQUREO0FBRU5JLFVBQUFBLFdBQVcsRUFBRSxLQUZQO0FBR05DLFVBQUFBLGdCQUFnQixFQUFFLE9BSFo7QUFJTkMsVUFBQUEsYUFBYSxFQUFFLEtBSlQ7QUFLTkMsVUFBQUEsa0JBQWtCLEVBQUUsU0FMZDtBQU1OTixVQUFBQSxJQUFJLEVBQUUsQ0FOQTtBQU9OQyxVQUFBQSxLQUFLLEVBQUUsTUFQRDtBQVFOQyxVQUFBQSxPQUFPLEVBQUUsR0FSSDtBQVNOd0MsVUFBQUEsV0FBVyxFQUFFO0FBVFA7QUFMVixPQW5CSSxFQW9DSjtBQUNFOUMsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFFBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQ05jLFVBQUFBLEtBQUssRUFBRSxZQUREO0FBRU5JLFVBQUFBLFdBQVcsRUFBRSxLQUZQO0FBR05DLFVBQUFBLGdCQUFnQixFQUFFLE9BSFo7QUFJTkMsVUFBQUEsYUFBYSxFQUFFLEtBSlQ7QUFLTkMsVUFBQUEsa0JBQWtCLEVBQUUsU0FMZDtBQU1OTixVQUFBQSxJQUFJLEVBQUUsQ0FOQTtBQU9OQyxVQUFBQSxLQUFLLEVBQUUsTUFQRDtBQVFOQyxVQUFBQSxPQUFPLEVBQUUsR0FSSDtBQVNOd0MsVUFBQUEsV0FBVyxFQUFFO0FBVFA7QUFMVixPQXBDSTtBQVppQixLQUFmLENBRkg7QUFxRVBuQyxJQUFBQSxXQUFXLEVBQUV6QixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMxQnlCLE1BQUFBLEdBQUcsRUFBRTtBQUFFdkIsUUFBQUEsTUFBTSxFQUFFO0FBQUV3RyxVQUFBQSxJQUFJLEVBQUU7QUFBRUMsWUFBQUEsV0FBVyxFQUFFLENBQWY7QUFBa0JDLFlBQUFBLFNBQVMsRUFBRTtBQUE3QjtBQUFSO0FBQVY7QUFEcUIsS0FBZixDQXJFTjtBQXdFUGpGLElBQUFBLFdBQVcsRUFBRSxFQXhFTjtBQXlFUEMsSUFBQUEsT0FBTyxFQUFFLENBekVGO0FBMEVQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUvQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQitCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLEVBRnVCO0FBRy9CQyxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBSHdCLE9BQWY7QUFERztBQTFFaEI7QUFIWCxDQWpwQmEsRUF1dUJiO0FBQ0V2QyxFQUFBQSxHQUFHLEVBQUUseUNBRFA7QUFFRXdDLEVBQUFBLEtBQUssRUFBRSxlQUZUO0FBR0V2QyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLGdCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxnQkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxPQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05xRyxRQUFBQSxPQUFPLEVBQUUsRUFESDtBQUVOQyxRQUFBQSxlQUFlLEVBQUUsS0FGWDtBQUdOQyxRQUFBQSxxQkFBcUIsRUFBRSxLQUhqQjtBQUlOQyxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsV0FBVyxFQUFFLENBQWY7QUFBa0JDLFVBQUFBLFNBQVMsRUFBRTtBQUE3QixTQUpBO0FBS05DLFFBQUFBLFNBQVMsRUFBRSxLQUxMO0FBTU5DLFFBQUFBLFdBQVcsRUFBRSxJQU5QO0FBT05DLFFBQUFBLFNBQVMsRUFBRTtBQVBMLE9BSGU7QUFZdkJuRyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFQyxRQUFBQSxFQUFFLEVBQUUsR0FBTjtBQUFXQyxRQUFBQSxPQUFPLEVBQUUsSUFBcEI7QUFBMEJiLFFBQUFBLElBQUksRUFBRSxPQUFoQztBQUF5Q2MsUUFBQUEsTUFBTSxFQUFFLFFBQWpEO0FBQTJEYixRQUFBQSxNQUFNLEVBQUU7QUFBbkUsT0FESSxFQUVKO0FBQ0VXLFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxRQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUNOYyxVQUFBQSxLQUFLLEVBQUUsYUFERDtBQUVOSSxVQUFBQSxXQUFXLEVBQUUsS0FGUDtBQUdOQyxVQUFBQSxnQkFBZ0IsRUFBRSxPQUhaO0FBSU5DLFVBQUFBLGFBQWEsRUFBRSxLQUpUO0FBS05DLFVBQUFBLGtCQUFrQixFQUFFLFNBTGQ7QUFNTk4sVUFBQUEsSUFBSSxFQUFFLEVBTkE7QUFPTkMsVUFBQUEsS0FBSyxFQUFFLE1BUEQ7QUFRTkMsVUFBQUEsT0FBTyxFQUFFLEdBUkg7QUFTTndDLFVBQUFBLFdBQVcsRUFBRTtBQVRQO0FBTFYsT0FGSTtBQVppQixLQUFmLENBRkg7QUFtQ1BuQyxJQUFBQSxXQUFXLEVBQUV6QixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMxQnlCLE1BQUFBLEdBQUcsRUFBRTtBQUFFdkIsUUFBQUEsTUFBTSxFQUFFO0FBQUV3RyxVQUFBQSxJQUFJLEVBQUU7QUFBRUMsWUFBQUEsV0FBVyxFQUFFLENBQWY7QUFBa0JDLFlBQUFBLFNBQVMsRUFBRTtBQUE3QjtBQUFSO0FBQVY7QUFEcUIsS0FBZixDQW5DTjtBQXNDUGpGLElBQUFBLFdBQVcsRUFBRSxFQXRDTjtBQXVDUEMsSUFBQUEsT0FBTyxFQUFFLENBdkNGO0FBd0NQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUvQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQitCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLEVBRnVCO0FBRy9CQyxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBSHdCLE9BQWY7QUFERztBQXhDaEI7QUFIWCxDQXZ1QmEsQyIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgZm9yIEFnZW50cy9HZW5lcmFsIHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1HZW5lcmFsLVRvcC01LWFsZXJ0cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgNSBhbGVydHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgNSBhbGVydHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UsIHZhbHVlczogdHJ1ZSwgbGFzdF9sZXZlbDogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmRlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGxlZ2VuZE9wZW46IHRydWUgfSB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdlbmVyYWwtTWV0cmljLWFsZXJ0cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdNZXRyaWMgYWxlcnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTWV0cmljIEFsZXJ0cycsXG4gICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogZmFsc2UsXG4gICAgICAgICAgdHlwZTogJ2dhdWdlJyxcbiAgICAgICAgICBnYXVnZToge1xuICAgICAgICAgICAgdmVydGljYWxTcGxpdDogZmFsc2UsXG4gICAgICAgICAgICBhdXRvRXh0ZW5kOiBmYWxzZSxcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIGdhdWdlVHlwZTogJ01ldHJpYycsXG4gICAgICAgICAgICBnYXVnZVN0eWxlOiAnRnVsbCcsXG4gICAgICAgICAgICBiYWNrU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIG9yaWVudGF0aW9uOiAndmVydGljYWwnLFxuICAgICAgICAgICAgY29sb3JTY2hlbWE6ICdHcmVlbiB0byBSZWQnLFxuICAgICAgICAgICAgZ2F1Z2VDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIHVzZVJhbmdlOiBmYWxzZSxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbeyBmcm9tOiAwLCB0bzogMTAwIH1dLFxuICAgICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBjb2xvcjogJ2JsYWNrJyB9LFxuICAgICAgICAgICAgc2NhbGU6IHsgc2hvdzogZmFsc2UsIGxhYmVsczogZmFsc2UsIGNvbG9yOiAnIzMzMycsIHdpZHRoOiAyIH0sXG4gICAgICAgICAgICB0eXBlOiAnc2ltcGxlJyxcbiAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAyMCwgYmdDb2xvcjogZmFsc2UsIGxhYmVsQ29sb3I6IGZhbHNlLCBzdWJUZXh0OiAnJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGN1c3RvbUxhYmVsOiAnQWxlcnRzJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7IHZpczogeyBkZWZhdWx0Q29sb3JzOiB7ICcwIC0gMTAwJzogJ3JnYigwLDEwNCw1NSknIH0gfSB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdlbmVyYWwtTGV2ZWwtMTItYWxlcnRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0xldmVsIDEyIGFsZXJ0cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0NvdW50IExldmVsIDEyIEFsZXJ0cycsXG4gICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogZmFsc2UsXG4gICAgICAgICAgdHlwZTogJ2dhdWdlJyxcbiAgICAgICAgICBnYXVnZToge1xuICAgICAgICAgICAgdmVydGljYWxTcGxpdDogZmFsc2UsXG4gICAgICAgICAgICBhdXRvRXh0ZW5kOiBmYWxzZSxcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIGdhdWdlVHlwZTogJ01ldHJpYycsXG4gICAgICAgICAgICBnYXVnZVN0eWxlOiAnRnVsbCcsXG4gICAgICAgICAgICBiYWNrU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIG9yaWVudGF0aW9uOiAndmVydGljYWwnLFxuICAgICAgICAgICAgY29sb3JTY2hlbWE6ICdHcmVlbiB0byBSZWQnLFxuICAgICAgICAgICAgZ2F1Z2VDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIHVzZVJhbmdlOiBmYWxzZSxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbeyBmcm9tOiAwLCB0bzogMTAwIH1dLFxuICAgICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBjb2xvcjogJ2JsYWNrJyB9LFxuICAgICAgICAgICAgc2NhbGU6IHsgc2hvdzogZmFsc2UsIGxhYmVsczogZmFsc2UsIGNvbG9yOiAnIzMzMycsIHdpZHRoOiAyIH0sXG4gICAgICAgICAgICB0eXBlOiAnc2ltcGxlJyxcbiAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAyMCwgYmdDb2xvcjogZmFsc2UsIGxhYmVsQ29sb3I6IGZhbHNlLCBzdWJUZXh0OiAnJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGN1c3RvbUxhYmVsOiAnTGV2ZWwgMTIgb3IgYWJvdmUgYWxlcnRzJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7IHZpczogeyBkZWZhdWx0Q29sb3JzOiB7ICcwIC0gMTAwJzogJ3JnYigwLDEwNCw1NSknIH0gfSB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIG1ldGE6IHtcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIGtleTogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBndGU6IDEyLFxuICAgICAgICAgICAgICAgICAgbHQ6IG51bGwsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB0eXBlOiAncmFuZ2UnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnMTIgdG8gK+KInicsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHJhbmdlOiB7XG4gICAgICAgICAgICAgICAgJ3J1bGUubGV2ZWwnOiB7XG4gICAgICAgICAgICAgICAgICBndGU6IDEyLFxuICAgICAgICAgICAgICAgICAgbHQ6IG51bGwsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1HZW5lcmFsLUF1dGhlbnRpY2F0aW9uLWZhaWx1cmUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQXV0aGVudGljYXRpb24gZmFpbHVyZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0NvdW50IEF1dGhlbnRpY2F0aW9uIEZhaWx1cmUnLFxuICAgICAgICB0eXBlOiAnbWV0cmljJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IGZhbHNlLFxuICAgICAgICAgIHR5cGU6ICdnYXVnZScsXG4gICAgICAgICAgZ2F1Z2U6IHtcbiAgICAgICAgICAgIHZlcnRpY2FsU3BsaXQ6IGZhbHNlLFxuICAgICAgICAgICAgYXV0b0V4dGVuZDogZmFsc2UsXG4gICAgICAgICAgICBwZXJjZW50YWdlTW9kZTogZmFsc2UsXG4gICAgICAgICAgICBnYXVnZVR5cGU6ICdNZXRyaWMnLFxuICAgICAgICAgICAgZ2F1Z2VTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgYmFja1N0eWxlOiAnRnVsbCcsXG4gICAgICAgICAgICBvcmllbnRhdGlvbjogJ3ZlcnRpY2FsJyxcbiAgICAgICAgICAgIGNvbG9yU2NoZW1hOiAnR3JlZW4gdG8gUmVkJyxcbiAgICAgICAgICAgIGdhdWdlQ29sb3JNb2RlOiAnTm9uZScsXG4gICAgICAgICAgICB1c2VSYW5nZTogZmFsc2UsXG4gICAgICAgICAgICBjb2xvcnNSYW5nZTogW3sgZnJvbTogMCwgdG86IDEwMCB9XSxcbiAgICAgICAgICAgIGludmVydENvbG9yczogZmFsc2UsXG4gICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgY29sb3I6ICdibGFjaycgfSxcbiAgICAgICAgICAgIHNjYWxlOiB7IHNob3c6IGZhbHNlLCBsYWJlbHM6IGZhbHNlLCBjb2xvcjogJyMzMzMnLCB3aWR0aDogMiB9LFxuICAgICAgICAgICAgdHlwZTogJ3NpbXBsZScsXG4gICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMjAsIGJnQ29sb3I6IGZhbHNlLCBsYWJlbENvbG9yOiBmYWxzZSwgc3ViVGV4dDogJycgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICAgIHBhcmFtczogeyBjdXN0b21MYWJlbDogJ0F1dGhlbnRpY2F0aW9uIGZhaWx1cmUnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2VzJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdydWxlLmdyb3VwcycsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICd3aW5fYXV0aGVudGljYXRpb25fZmFpbGVkLCBhdXRoZW50aWNhdGlvbl9mYWlsZWQsIGF1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IFtcbiAgICAgICAgICAgICAgICAgICd3aW5fYXV0aGVudGljYXRpb25fZmFpbGVkJyxcbiAgICAgICAgICAgICAgICAgICdhdXRoZW50aWNhdGlvbl9mYWlsZWQnLFxuICAgICAgICAgICAgICAgICAgJ2F1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzJyxcbiAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIGJvb2w6IHtcbiAgICAgICAgICAgICAgICAgIHNob3VsZDogW1xuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgbWF0Y2hfcGhyYXNlOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAncnVsZS5ncm91cHMnOiAnd2luX2F1dGhlbnRpY2F0aW9uX2ZhaWxlZCcsXG4gICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgIG1hdGNoX3BocmFzZToge1xuICAgICAgICAgICAgICAgICAgICAgICAgJ3J1bGUuZ3JvdXBzJzogJ2F1dGhlbnRpY2F0aW9uX2ZhaWxlZCcsXG4gICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgIG1hdGNoX3BocmFzZToge1xuICAgICAgICAgICAgICAgICAgICAgICAgJ3J1bGUuZ3JvdXBzJzogJ2F1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzJyxcbiAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgICAgICAgIG1pbmltdW1fc2hvdWxkX21hdGNoOiAxLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdlbmVyYWwtQXV0aGVudGljYXRpb24tc3VjY2VzcycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBdXRoZW50aWNhdGlvbiBzdWNjZXNzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQ291bnQgQXV0aGVudGljYXRpb24gU3VjY2VzcycsXG4gICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogZmFsc2UsXG4gICAgICAgICAgdHlwZTogJ2dhdWdlJyxcbiAgICAgICAgICBnYXVnZToge1xuICAgICAgICAgICAgdmVydGljYWxTcGxpdDogZmFsc2UsXG4gICAgICAgICAgICBhdXRvRXh0ZW5kOiBmYWxzZSxcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIGdhdWdlVHlwZTogJ01ldHJpYycsXG4gICAgICAgICAgICBnYXVnZVN0eWxlOiAnRnVsbCcsXG4gICAgICAgICAgICBiYWNrU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIG9yaWVudGF0aW9uOiAndmVydGljYWwnLFxuICAgICAgICAgICAgY29sb3JTY2hlbWE6ICdHcmVlbiB0byBSZWQnLFxuICAgICAgICAgICAgZ2F1Z2VDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIHVzZVJhbmdlOiBmYWxzZSxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbeyBmcm9tOiAwLCB0bzogMTAwIH1dLFxuICAgICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBjb2xvcjogJ2JsYWNrJyB9LFxuICAgICAgICAgICAgc2NhbGU6IHsgc2hvdzogZmFsc2UsIGxhYmVsczogZmFsc2UsIGNvbG9yOiAnIzMzMycsIHdpZHRoOiAyIH0sXG4gICAgICAgICAgICB0eXBlOiAnc2ltcGxlJyxcbiAgICAgICAgICAgIHN0eWxlOiB7IGZvbnRTaXplOiAyMCwgYmdDb2xvcjogZmFsc2UsIGxhYmVsQ29sb3I6IGZhbHNlLCBzdWJUZXh0OiAnJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGN1c3RvbUxhYmVsOiAnQXV0aGVudGljYXRpb24gc3VjY2VzcycgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogSlNPTi5zdHJpbmdpZnkoeyB2aXM6IHsgZGVmYXVsdENvbG9yczogeyAnMCAtIDEwMCc6ICdyZ2IoMCwxMDQsNTUpJyB9IH0gfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIG1ldGE6IHtcbiAgICAgICAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgICAgICAgbmVnYXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAncnVsZS5ncm91cHMnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnYXV0aGVudGljYXRpb25fc3VjY2VzcycsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBxdWVyeTogJ2F1dGhlbnRpY2F0aW9uX3N1Y2Nlc3MnLFxuICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICAgICAgICBtYXRjaDoge1xuICAgICAgICAgICAgICAgICAgJ3J1bGUuZ3JvdXBzJzoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ2F1dGhlbnRpY2F0aW9uX3N1Y2Nlc3MnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtR2VuZXJhbC1Ub3AtMTAtZ3JvdXBzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IHJ1bGUgZ3JvdXBzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnVG9wIDUgcnVsZSBncm91cHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogZmFsc2UsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5ncm91cHMnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogSlNPTi5zdHJpbmdpZnkoeyB2aXM6IHsgbGVnZW5kT3BlbjogdHJ1ZSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtR2VuZXJhbC1Ub3AtNS1QQ0ktRFNTLVJlcXVpcmVtZW50cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgNSBQQ0kgRFNTIHJlcXVpcmVtZW50cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1RvcCA1IFBDSSBEU1MgcmVxdWlyZW1lbnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5wY2lfZHNzJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7XCJ2aXNcIjp7XCJsZWdlbmRPcGVuXCI6dHJ1ZX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdlbmVyYWwtQWxlcnQtZ3JvdXBzLWV2b2x1dGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydCBncm91cHMgZXZvbHV0aW9uJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnRzIGJ5IGdyb3VwIG92ZXIgdGltZScsXG4gICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogdHJ1ZSwgc3R5bGU6IHsgY29sb3I6ICcjZWVlJyB9LCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICAgICAgICBtb2RlOiAnc3RhY2tlZCcsXG4gICAgICAgICAgICAgIGRhdGE6IHsgbGFiZWw6ICdDb3VudCcsIGlkOiAnMScgfSxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGludGVycG9sYXRlOiAnY2FyZGluYWwnLFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIGFkZFRpbWVNYXJrZXI6IGZhbHNlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHsgZnJvbTogJ25vdy0yNGgnLCB0bzogJ25vdycsIG1vZGU6ICdxdWljaycgfSxcbiAgICAgICAgICAgICAgdXNlTm9ybWFsaXplZEVzSW50ZXJ2YWw6IHRydWUsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnYXV0bycsXG4gICAgICAgICAgICAgIHRpbWVfem9uZTogJ0V1cm9wZS9CZXJsaW4nLFxuICAgICAgICAgICAgICBkcm9wX3BhcnRpYWxzOiBmYWxzZSxcbiAgICAgICAgICAgICAgY3VzdG9tSW50ZXJ2YWw6ICcyaCcsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5ncm91cHMnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdlbmVyYWwtQWxlcnRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0FsZXJ0cyBieSBhY3Rpb24gb3ZlciB0aW1lJyxcbiAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiB0cnVlLCBzdHlsZTogeyBjb2xvcjogJyNlZWUnIH0sIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgICAgICAgIG1vZGU6ICdzdGFja2VkJyxcbiAgICAgICAgICAgICAgZGF0YTogeyBsYWJlbDogJ0NvdW50JywgaWQ6ICcxJyB9LFxuICAgICAgICAgICAgICBkcmF3TGluZXNCZXR3ZWVuUG9pbnRzOiB0cnVlLFxuICAgICAgICAgICAgICBzaG93Q2lyY2xlczogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJwb2xhdGU6ICdjYXJkaW5hbCcsXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3RpbWVzdGFtcCcsXG4gICAgICAgICAgICAgIHRpbWVSYW5nZTogeyBmcm9tOiAnbm93LTI0aCcsIHRvOiAnbm93JywgbW9kZTogJ3F1aWNrJyB9LFxuICAgICAgICAgICAgICB1c2VOb3JtYWxpemVkRXNJbnRlcnZhbDogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgdGltZV96b25lOiAnRXVyb3BlL0JlcmxpbicsXG4gICAgICAgICAgICAgIGRyb3BfcGFydGlhbHM6IGZhbHNlLFxuICAgICAgICAgICAgICBjdXN0b21JbnRlcnZhbDogJzJoJyxcbiAgICAgICAgICAgICAgbWluX2RvY19jb3VudDogMSxcbiAgICAgICAgICAgICAgZXh0ZW5kZWRfYm91bmRzOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmxldmVsJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1HZW5lcmFsLUFsZXJ0cy1zdW1tYXJ5JyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldGljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgc2hvd1Rvb2xiYXI6IHRydWUsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmlkJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIHNpemU6IDUwLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUnVsZSBJRCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0Rlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzQnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiAxLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnTGV2ZWwnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB2aXM6IHsgcGFyYW1zOiB7IHNvcnQ6IHsgY29sdW1uSW5kZXg6IDMsIGRpcmVjdGlvbjogJ2Rlc2MnIH0gfSB9LFxuICAgICAgfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtR2VuZXJhbC1Hcm91cHMtc3VtbWFyeScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0dyb3VwcyBzdW1tYXJ5JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnR3JvdXBzIHN1bW1hcnknLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogMSwgZGlyZWN0aW9uOiAnZGVzYycgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5ncm91cHMnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogNTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdHcm91cCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMSwgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXTtcbiJdfQ==