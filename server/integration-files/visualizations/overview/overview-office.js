"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

var _constants = require("../../../../common/constants");

/*
 * Wazuh app - Module for Overview/General visualizations
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
  _id: 'Wazuh-App-Overview-Office-Agents-status',
  _source: {
    title: 'Agents status',
    visState: JSON.stringify({
      title: 'Agents Status',
      type: 'histogram',
      params: {
        type: 'histogram',
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
          show: true,
          mode: 'normal',
          type: 'line',
          drawLinesBetweenPoints: true,
          showCircles: true,
          interpolate: 'cardinal',
          lineWidth: 3.5,
          data: {
            id: '4',
            label: 'Unique count of id'
          },
          valueAxis: 'ValueAxis-1'
        }],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false
      },
      aggs: [{
        id: '2',
        enabled: true,
        type: 'date_histogram',
        interval: '1ms',
        schema: 'segment',
        params: {
          field: 'timestamp',
          interval: '1ms',
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
          field: 'status',
          size: 5,
          order: 'desc',
          orderBy: '_term'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'cardinality',
        schema: 'metric',
        params: {
          field: 'id'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        colors: {
          active: _constants.UI_COLOR_AGENT_STATUS.active,
          disconnected: _constants.UI_COLOR_AGENT_STATUS.disconnected,
          pending: _constants.UI_COLOR_AGENT_STATUS.pending,
          never_connected: _constants.UI_COLOR_AGENT_STATUS.never_connected
        }
      }
    }),
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-monitoring',
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
  _id: 'Wazuh-App-Overview-Office-Metric-Alerts',
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
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-Office-Metric-Max-Rule-Level',
  _source: {
    title: 'Max Rule Level',
    visState: JSON.stringify({
      title: 'Max Rule Level',
      type: 'metric',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'max',
        params: {
          field: 'rule.level',
          customLabel: 'Max Rule Level'
        },
        schema: 'metric'
      }],
      params: {
        addTooltip: true,
        addLegend: false,
        type: 'metric',
        metric: {
          percentageMode: false,
          useRanges: false,
          colorSchema: 'Green to Red',
          metricColorMode: 'Labels',
          colorsRange: [{
            from: 0,
            to: 7
          }, {
            from: 7,
            to: 10
          }, {
            from: 10,
            to: 20
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
            fontSize: 26
          }
        }
      }
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
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-Office-Metric-Suspicious-Downloads',
  _source: {
    title: 'Suspicious Downloads',
    visState: JSON.stringify({
      title: 'Suspicious Downloads Count',
      type: 'metric',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'filters',
        params: {
          filters: [{
            input: {
              query: 'rule.id: "91724"',
              language: 'kuery'
            },
            label: 'Suspicious Downloads'
          }]
        },
        schema: 'group'
      }],
      params: {
        addTooltip: true,
        addLegend: false,
        type: 'metric',
        metric: {
          percentageMode: false,
          useRanges: false,
          colorSchema: 'Green to Red',
          metricColorMode: 'Labels',
          colorsRange: [{
            from: 0,
            to: 1
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
            fontSize: 26
          }
        }
      }
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
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-Office-Metric-Malware-Alerts',
  _source: {
    title: 'Malware Alerts',
    visState: JSON.stringify({
      title: 'Malware Alerts Count',
      type: 'metric',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'filters',
        params: {
          filters: [{
            input: {
              query: 'rule.id: "91556" or rule.id: "91575" or rule.id: "91700" ',
              language: 'kuery'
            },
            label: 'Malware Alerts'
          }]
        },
        schema: 'group'
      }],
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
            fontSize: 26
          }
        }
      }
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
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-Office-Metric-FullAccess-Permissions',
  _source: {
    title: 'Full Access Permissions',
    visState: JSON.stringify({
      title: 'Full Access Permission Count',
      type: 'metric',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'filters',
        params: {
          filters: [{
            input: {
              query: 'rule.id: "91725"',
              language: 'kuery'
            },
            label: 'Full Access Permissions'
          }]
        },
        schema: 'group'
      }],
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
            fontSize: 26
          }
        }
      }
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
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-Office-Level-12-Alerts',
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
  _id: 'Wazuh-App-Overview-Office-Authentication-failure',
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
  _id: 'Wazuh-App-Overview-Office-Authentication-success',
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
  _id: 'Wazuh-App-Overview-Office-Alert-Level-Evolution',
  _source: {
    title: 'Alert level evolution',
    visState: JSON.stringify({
      title: 'Alert level evolution',
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
          size: '15',
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
  _id: 'Wazuh-App-Overview-Office-Alerts-summary',
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
          size: 1000,
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
  _id: 'Wazuh-App-Overview-Office-Metric-Stats',
  _type: 'visualization',
  _source: {
    title: 'Stats',
    visState: JSON.stringify({
      title: 'Metric Stats',
      type: 'metric',
      aggs: [{
        id: '2',
        enabled: true,
        type: 'count',
        params: {
          customLabel: 'Total Alerts'
        },
        schema: 'metric'
      }, {
        id: '1',
        enabled: true,
        type: 'top_hits',
        params: {
          field: 'rule.level',
          aggregate: 'concat',
          size: 1,
          sortField: 'rule.level',
          sortOrder: 'desc',
          customLabel: 'Max rule level detected'
        },
        schema: 'metric'
      }],
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
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-IPs-By-User-Table',
  _type: 'visualization',
  _source: {
    title: 'Registered IPs for User',
    visState: JSON.stringify({
      title: 'Registered IPs for User',
      type: 'table',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.Actor.ID',
          orderBy: '_key',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Top Users'
        },
        schema: 'bucket'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'agent.id',
          orderBy: '_key',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Agent ID'
        },
        schema: 'bucket'
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        params: {
          field: 'agent.name',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Agent name'
        },
        schema: 'bucket'
      }],
      params: {
        perPage: 5,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: {
          columnIndex: null,
          direction: null
        },
        showTotal: false,
        totalFunc: 'sum',
        percentageCol: ''
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-User-Operation-Level-Table',
  _type: 'visualization',
  _source: {
    title: 'User Operations',
    visState: JSON.stringify({
      title: 'User Operation Level',
      type: 'table',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.UserId',
          orderBy: '1',
          order: 'desc',
          size: 500,
          otherBucket: true,
          otherBucketLabel: 'Others',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Users'
        },
        schema: 'bucket'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.Operation',
          orderBy: '1',
          order: 'desc',
          size: 100,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Operation'
        },
        schema: 'bucket'
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 20,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Rule level'
        },
        schema: 'bucket'
      }],
      params: {
        perPage: 5,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: {
          columnIndex: null,
          direction: null
        },
        showTotal: false,
        totalFunc: 'sum',
        percentageCol: ''
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Client-IP-Operation-Level-Table',
  _type: 'visualization',
  _source: {
    title: 'Client IP Operations',
    visState: JSON.stringify({
      title: 'Client IP Operation Level',
      type: 'table',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.ClientIP',
          orderBy: '1',
          order: 'desc',
          size: 500,
          otherBucket: true,
          otherBucketLabel: 'Others',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Client IP address'
        },
        schema: 'bucket'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.Operation',
          orderBy: '1',
          order: 'desc',
          size: 100,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Operation'
        },
        schema: 'bucket'
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 20,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Rule level'
        },
        schema: 'bucket'
      }],
      params: {
        perPage: 5,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: {
          columnIndex: null,
          direction: null
        },
        showTotal: false,
        totalFunc: 'sum',
        percentageCol: ''
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Top-Events-Pie',
  _type: 'visualization',
  _source: {
    title: 'Top Events',
    visState: JSON.stringify({
      title: 'Cake',
      type: 'pie',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: false,
        type: 'terms',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'segment'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'rule.description',
          orderBy: '1',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'segment'
      }],
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
        row: true
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Alerts-Evolution-By-User',
  _type: 'visualization',
  _source: {
    title: 'Alerts evolution over time',
    visState: JSON.stringify({
      title: 'Alerts evolution over time',
      type: 'line',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'date_histogram',
        params: {
          field: 'timestamp',
          timeRange: {
            from: 'now-1y',
            to: 'now'
          },
          useNormalizedEsInterval: true,
          scaleMetricValues: false,
          interval: 'h',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {}
        },
        schema: 'segment'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.Actor.ID',
          orderBy: '1',
          order: 'asc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'group'
      }],
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
          show: true,
          type: 'line',
          mode: 'normal',
          data: {
            label: 'Count',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          lineWidth: 2,
          interpolate: 'linear',
          showCircles: true
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
          color: '#E7664C'
        }
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-User-By-Operation-Result',
  _type: 'visualization',
  _source: {
    title: 'User by Operation result',
    visState: JSON.stringify({
      title: 'User By Operation result',
      type: 'table',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.Operation',
          orderBy: '1',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Operation'
        },
        schema: 'bucket'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.UserId',
          orderBy: '1',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'User'
        },
        schema: 'bucket'
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.ResultStatus',
          orderBy: '1',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Result Status'
        },
        schema: 'bucket'
      }],
      params: {
        perPage: 5,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: {
          columnIndex: null,
          direction: null
        },
        showTotal: false,
        totalFunc: 'sum',
        percentageCol: ''
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Rule-Description-Level-Table',
  _type: 'visualization',
  _source: {
    title: 'Rule Description by Level',
    visState: JSON.stringify({
      title: 'Rule Description Level Table',
      type: 'table',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'rule.description',
          orderBy: '1',
          order: 'desc',
          size: 500,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Rule Description'
        },
        schema: 'bucket'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 20,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Rule Level'
        },
        schema: 'bucket'
      }],
      params: {
        perPage: 5,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: {
          columnIndex: null,
          direction: null
        },
        showTotal: false,
        totalFunc: 'sum',
        percentageCol: ''
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Severity-By-User-Histogram',
  _type: 'visualization',
  _source: {
    title: 'Severity by user',
    visState: JSON.stringify({
      title: 'Severity by User',
      type: 'histogram',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'rule.level',
          orderBy: '_key',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Severity'
        },
        schema: 'segment'
      }],
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
          show: true,
          type: 'histogram',
          mode: 'stacked',
          data: {
            label: 'Count',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          lineWidth: 2,
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
          color: '#E7664C'
        }
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Rule-Level-Histogram',
  _type: 'visualization',
  _source: {
    title: 'Rule level histrogram',
    visState: JSON.stringify({
      title: 'Rule level histogram',
      type: 'area',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'date_histogram',
        params: {
          field: 'timestamp',
          timeRange: {
            from: 'now/w',
            to: 'now/w'
          },
          useNormalizedEsInterval: true,
          scaleMetricValues: false,
          interval: '3h',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {}
        },
        schema: 'segment'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'group'
      }],
      params: {
        type: 'area',
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
            truncate: 100,
            rotate: 0
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
          show: true,
          type: 'histogram',
          mode: 'stacked',
          data: {
            label: 'Count',
            id: '1'
          },
          drawLinesBetweenPoints: true,
          lineWidth: 2,
          showCircles: true,
          interpolate: 'linear',
          valueAxis: 'ValueAxis-1'
        }],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false,
        thresholdLine: {
          show: false,
          value: 10,
          width: 1,
          style: 'full',
          color: '#E7664C'
        },
        labels: {}
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-IPs-By-User-Barchart',
  _type: 'visualization',
  _source: {
    title: 'IPs by user',
    visState: JSON.stringify({
      title: 'IPs by User',
      type: 'horizontal_bar',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.ClientIP',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'IP'
        },
        schema: 'segment'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.UserId',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'group'
      }],
      params: {
        type: 'histogram',
        grid: {
          categoryLines: false
        },
        categoryAxes: [{
          id: 'CategoryAxis-1',
          type: 'category',
          position: 'left',
          show: true,
          style: {},
          scale: {
            type: 'linear'
          },
          labels: {
            show: true,
            rotate: 0,
            filter: false,
            truncate: 200
          },
          title: {}
        }],
        valueAxes: [{
          id: 'ValueAxis-1',
          name: 'LeftAxis-1',
          type: 'value',
          position: 'bottom',
          show: true,
          style: {},
          scale: {
            type: 'linear',
            mode: 'normal'
          },
          labels: {
            show: true,
            rotate: 75,
            filter: true,
            truncate: 100
          },
          title: {
            text: 'Count'
          }
        }],
        seriesParams: [{
          show: true,
          type: 'histogram',
          mode: 'stacked',
          data: {
            label: 'Count',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          lineWidth: 2,
          showCircles: true
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
          color: '#E7664C'
        }
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Severity-By-User-Barchart',
  _type: 'visualization',
  _source: {
    title: 'Severity by user',
    visState: JSON.stringify({
      title: 'Severity By User Barchart',
      type: 'histogram',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: true,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'segment'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.UserId',
          orderBy: '1',
          order: 'desc',
          size: 20,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'group'
      }],
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
          show: true,
          type: 'histogram',
          mode: 'stacked',
          data: {
            label: 'Count',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          lineWidth: 2,
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
          color: '#E7664C'
        }
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Top-Users-By-Subscription-Barchart',
  _type: 'visualization',
  _source: {
    title: 'Top User By Subscription',
    visState: JSON.stringify({
      title: 'Top User By Subscription',
      type: 'histogram',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.UserId',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'segment'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.Subscription',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'group'
      }],
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
            truncate: 100,
            rotate: 0
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
          show: true,
          type: 'histogram',
          mode: 'stacked',
          data: {
            label: 'Count',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          lineWidth: 2,
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
          color: '#E7664C'
        }
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Location',
  _type: 'visualization',
  _source: {
    title: 'Geolocation map',
    visState: JSON.stringify({
      title: 'Geolocation map',
      type: 'tile_map',
      params: {
        colorSchema: 'Green to Red',
        mapType: 'Scaled Circle Markers',
        isDesaturated: false,
        addTooltip: true,
        heatClusterSize: 1.5,
        legendPosition: 'bottomright',
        mapZoom: 1,
        mapCenter: [0, 0],
        wms: {
          enabled: false,
          options: {
            format: 'image/png',
            transparent: true
          }
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
          geohash: {
            accessor: 0,
            format: {
              id: 'string'
            },
            params: {
              precision: 2,
              useGeocentroid: true
            },
            aggType: 'geohash_grid'
          },
          geocentroid: {
            accessor: 2,
            format: {
              id: 'string'
            },
            params: {},
            aggType: 'geo_centroid'
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
        type: 'geohash_grid',
        schema: 'segment',
        params: {
          field: 'GeoLocation.location',
          autoPrecision: true,
          precision: 2,
          useGeocentroid: true,
          isFilteredByCollar: true,
          mapZoom: 1,
          mapCenter: [0, 0]
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      mapZoom: 2,
      mapCenter: [38.685509760012025, -31.816406250000004]
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
  _id: 'Wazuh-App-Overview-Office-Country-Tag-Cloud',
  _type: 'visualization',
  _source: {
    title: 'Country of origin',
    visState: JSON.stringify({
      title: 'Country tag cloud',
      type: 'tagcloud',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'GeoLocation.country_name',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'segment'
      }],
      params: {
        scale: 'linear',
        orientation: 'right angled',
        minFontSize: 18,
        maxFontSize: 72,
        showLabel: false
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Alerts-Evolution-By-UserID',
  _type: 'visualization',
  _source: {
    title: 'Alerts by user',
    visState: JSON.stringify({
      title: 'Alerts evolution over time',
      type: 'line',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {
          customLabel: 'Alerts'
        },
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'date_histogram',
        params: {
          field: 'timestamp',
          timeRange: {
            from: 'now-1w',
            to: 'now'
          },
          useNormalizedEsInterval: true,
          scaleMetricValues: false,
          interval: 'auto',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {}
        },
        schema: 'segment'
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.UserId',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'User ID'
        },
        schema: 'group'
      }],
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
            text: 'Alerts'
          }
        }],
        seriesParams: [{
          show: true,
          type: 'line',
          mode: 'normal',
          data: {
            label: 'Alerts',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          lineWidth: 2,
          interpolate: 'linear',
          showCircles: true
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
          color: '#E7664C'
        },
        row: true
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Top-Users',
  _type: 'visualization',
  _source: {
    title: 'Top Office Users',
    visState: JSON.stringify({
      title: 'Alerts by user',
      type: 'pie',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.UserId',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        },
        schema: 'segment'
      }],
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
      }
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
  }
}, {
  _id: 'Wazuh-App-Overview-Office-Top-Operations',
  _type: 'visualization',
  _source: {
    title: 'Top Operations',
    visState: JSON.stringify({
      title: 'Top Operations',
      type: 'pie',
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        params: {},
        schema: 'metric'
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        params: {
          field: 'data.office365.Operation',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Operation'
        },
        schema: 'segment'
      }],
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
      }
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
  }
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LW9mZmljZS50cyJdLCJuYW1lcyI6WyJfaWQiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJzdHlsZSIsImNvbG9yIiwiY2F0ZWdvcnlBeGVzIiwiaWQiLCJwb3NpdGlvbiIsInNob3ciLCJzY2FsZSIsImxhYmVscyIsImZpbHRlciIsInRydW5jYXRlIiwidmFsdWVBeGVzIiwibmFtZSIsIm1vZGUiLCJyb3RhdGUiLCJ0ZXh0Iiwic2VyaWVzUGFyYW1zIiwiZHJhd0xpbmVzQmV0d2VlblBvaW50cyIsInNob3dDaXJjbGVzIiwiaW50ZXJwb2xhdGUiLCJsaW5lV2lkdGgiLCJkYXRhIiwibGFiZWwiLCJ2YWx1ZUF4aXMiLCJhZGRUb29sdGlwIiwiYWRkTGVnZW5kIiwibGVnZW5kUG9zaXRpb24iLCJ0aW1lcyIsImFkZFRpbWVNYXJrZXIiLCJhZ2dzIiwiZW5hYmxlZCIsImludGVydmFsIiwic2NoZW1hIiwiZmllbGQiLCJjdXN0b21JbnRlcnZhbCIsIm1pbl9kb2NfY291bnQiLCJleHRlbmRlZF9ib3VuZHMiLCJzaXplIiwib3JkZXIiLCJvcmRlckJ5IiwidWlTdGF0ZUpTT04iLCJ2aXMiLCJjb2xvcnMiLCJhY3RpdmUiLCJVSV9DT0xPUl9BR0VOVF9TVEFUVVMiLCJkaXNjb25uZWN0ZWQiLCJwZW5kaW5nIiwibmV2ZXJfY29ubmVjdGVkIiwiZGVzY3JpcHRpb24iLCJ2ZXJzaW9uIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImluZGV4IiwicXVlcnkiLCJsYW5ndWFnZSIsIl90eXBlIiwiZ2F1Z2UiLCJ2ZXJ0aWNhbFNwbGl0IiwiYXV0b0V4dGVuZCIsInBlcmNlbnRhZ2VNb2RlIiwiZ2F1Z2VUeXBlIiwiZ2F1Z2VTdHlsZSIsImJhY2tTdHlsZSIsIm9yaWVudGF0aW9uIiwiY29sb3JTY2hlbWEiLCJnYXVnZUNvbG9yTW9kZSIsInVzZVJhbmdlIiwiY29sb3JzUmFuZ2UiLCJmcm9tIiwidG8iLCJpbnZlcnRDb2xvcnMiLCJ3aWR0aCIsImZvbnRTaXplIiwiYmdDb2xvciIsImxhYmVsQ29sb3IiLCJzdWJUZXh0IiwiY3VzdG9tTGFiZWwiLCJkZWZhdWx0Q29sb3JzIiwibWV0cmljIiwidXNlUmFuZ2VzIiwibWV0cmljQ29sb3JNb2RlIiwiYmdGaWxsIiwiZmlsdGVycyIsImlucHV0IiwiJHN0YXRlIiwic3RvcmUiLCJtZXRhIiwiYWxpYXMiLCJkaXNhYmxlZCIsImtleSIsIm5lZ2F0ZSIsImd0ZSIsImx0IiwidmFsdWUiLCJyYW5nZSIsImJvb2wiLCJzaG91bGQiLCJtYXRjaF9waHJhc2UiLCJtaW5pbXVtX3Nob3VsZF9tYXRjaCIsIm1hdGNoIiwidGltZVJhbmdlIiwidXNlTm9ybWFsaXplZEVzSW50ZXJ2YWwiLCJ0aW1lX3pvbmUiLCJkcm9wX3BhcnRpYWxzIiwib3RoZXJCdWNrZXQiLCJvdGhlckJ1Y2tldExhYmVsIiwibWlzc2luZ0J1Y2tldCIsIm1pc3NpbmdCdWNrZXRMYWJlbCIsInBlclBhZ2UiLCJzaG93UGFydGlhbFJvd3MiLCJzaG93TWV0aWNzQXRBbGxMZXZlbHMiLCJzb3J0IiwiY29sdW1uSW5kZXgiLCJkaXJlY3Rpb24iLCJzaG93VG90YWwiLCJzaG93VG9vbGJhciIsInRvdGFsRnVuYyIsImFnZ3JlZ2F0ZSIsInNvcnRGaWVsZCIsInNvcnRPcmRlciIsInNob3dNZXRyaWNzQXRBbGxMZXZlbHMiLCJwZXJjZW50YWdlQ29sIiwiaXNEb251dCIsInZhbHVlcyIsImxhc3RfbGV2ZWwiLCJyb3ciLCJzY2FsZU1ldHJpY1ZhbHVlcyIsInRocmVzaG9sZExpbmUiLCJtYXBUeXBlIiwiaXNEZXNhdHVyYXRlZCIsImhlYXRDbHVzdGVyU2l6ZSIsIm1hcFpvb20iLCJtYXBDZW50ZXIiLCJ3bXMiLCJvcHRpb25zIiwiZm9ybWF0IiwidHJhbnNwYXJlbnQiLCJkaW1lbnNpb25zIiwiYWNjZXNzb3IiLCJhZ2dUeXBlIiwiZ2VvaGFzaCIsInByZWNpc2lvbiIsInVzZUdlb2NlbnRyb2lkIiwiZ2VvY2VudHJvaWQiLCJhdXRvUHJlY2lzaW9uIiwiaXNGaWx0ZXJlZEJ5Q29sbGFyIiwibWluRm9udFNpemUiLCJtYXhGb250U2l6ZSIsInNob3dMYWJlbCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQVdBOztBQVhBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7ZUFHZSxDQUNiO0FBQ0VBLEVBQUFBLEdBQUcsRUFBRSx5Q0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLGVBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLGVBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsV0FGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNORCxRQUFBQSxJQUFJLEVBQUUsV0FEQTtBQUVORSxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsYUFBYSxFQUFFLEtBQWpCO0FBQXdCQyxVQUFBQSxLQUFLLEVBQUU7QUFBRUMsWUFBQUEsS0FBSyxFQUFFO0FBQVQ7QUFBL0IsU0FGQTtBQUdOQyxRQUFBQSxZQUFZLEVBQUUsQ0FDWjtBQUNFQyxVQUFBQSxFQUFFLEVBQUUsZ0JBRE47QUFFRVAsVUFBQUEsSUFBSSxFQUFFLFVBRlI7QUFHRVEsVUFBQUEsUUFBUSxFQUFFLFFBSFo7QUFJRUMsVUFBQUEsSUFBSSxFQUFFLElBSlI7QUFLRUwsVUFBQUEsS0FBSyxFQUFFLEVBTFQ7QUFNRU0sVUFBQUEsS0FBSyxFQUFFO0FBQUVWLFlBQUFBLElBQUksRUFBRTtBQUFSLFdBTlQ7QUFPRVcsVUFBQUEsTUFBTSxFQUFFO0FBQUVGLFlBQUFBLElBQUksRUFBRSxJQUFSO0FBQWNHLFlBQUFBLE1BQU0sRUFBRSxJQUF0QjtBQUE0QkMsWUFBQUEsUUFBUSxFQUFFO0FBQXRDLFdB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QWYsQ0FGSDtBQTZDUDhCLElBQUFBLFdBQVcsRUFBRSxJQTdDTjtBQThDUFEsSUFBQUEsV0FBVyxFQUFFLEVBOUNOO0FBK0NQQyxJQUFBQSxPQUFPLEVBQUUsQ0EvQ0Y7QUFnRFBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRXhELElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9Cd0QsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CM0MsUUFBQUEsTUFBTSxFQUFFLEVBRnVCO0FBRy9CNEMsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQUh3QixPQUFmO0FBREc7QUFoRGhCO0FBSFgsQ0EvakZhLEMiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTW9kdWxlIGZvciBPdmVydmlldy9HZW5lcmFsIHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuaW1wb3J0IHsgVUlfQ09MT1JfQUdFTlRfU1RBVFVTIH0gZnJvbSBcIi4uLy4uLy4uLy4uL2NvbW1vbi9jb25zdGFudHNcIjtcblxuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1BZ2VudHMtc3RhdHVzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FnZW50cyBzdGF0dXMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBZ2VudHMgU3RhdHVzJyxcbiAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogZmFsc2UsIHN0eWxlOiB7IGNvbG9yOiAnI2VlZScgfSB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgbW9kZTogJ25vcm1hbCcsXG4gICAgICAgICAgICAgIHR5cGU6ICdsaW5lJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGludGVycG9sYXRlOiAnY2FyZGluYWwnLFxuICAgICAgICAgICAgICBsaW5lV2lkdGg6IDMuNSxcbiAgICAgICAgICAgICAgZGF0YTogeyBpZDogJzQnLCBsYWJlbDogJ1VuaXF1ZSBjb3VudCBvZiBpZCcgfSxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIGludGVydmFsOiAnMW1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAndGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICcxbXMnLFxuICAgICAgICAgICAgICBjdXN0b21JbnRlcnZhbDogJzJoJyxcbiAgICAgICAgICAgICAgbWluX2RvY19jb3VudDogMSxcbiAgICAgICAgICAgICAgZXh0ZW5kZWRfYm91bmRzOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdzdGF0dXMnLCBzaXplOiA1LCBvcmRlcjogJ2Rlc2MnLCBvcmRlckJ5OiAnX3Rlcm0nIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzQnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjYXJkaW5hbGl0eScsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnaWQnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IGNvbG9yczogeyBhY3RpdmU6IFVJX0NPTE9SX0FHRU5UX1NUQVRVUy5hY3RpdmUsIGRpc2Nvbm5lY3RlZDogVUlfQ09MT1JfQUdFTlRfU1RBVFVTLmRpc2Nvbm5lY3RlZCwgcGVuZGluZzogVUlfQ09MT1JfQUdFTlRfU1RBVFVTLnBlbmRpbmcsIG5ldmVyX2Nvbm5lY3RlZDogVUlfQ09MT1JfQUdFTlRfU1RBVFVTLm5ldmVyX2Nvbm5lY3RlZCB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtbW9uaXRvcmluZycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1NZXRyaWMtQWxlcnRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ01ldHJpYyBhbGVydHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdNZXRyaWMgQWxlcnRzJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnZ2F1Z2UnLFxuICAgICAgICAgIGdhdWdlOiB7XG4gICAgICAgICAgICB2ZXJ0aWNhbFNwbGl0OiBmYWxzZSxcbiAgICAgICAgICAgIGF1dG9FeHRlbmQ6IGZhbHNlLFxuICAgICAgICAgICAgcGVyY2VudGFnZU1vZGU6IGZhbHNlLFxuICAgICAgICAgICAgZ2F1Z2VUeXBlOiAnTWV0cmljJyxcbiAgICAgICAgICAgIGdhdWdlU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIGJhY2tTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgb3JpZW50YXRpb246ICd2ZXJ0aWNhbCcsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBnYXVnZUNvbG9yTW9kZTogJ05vbmUnLFxuICAgICAgICAgICAgdXNlUmFuZ2U6IGZhbHNlLFxuICAgICAgICAgICAgY29sb3JzUmFuZ2U6IFt7IGZyb206IDAsIHRvOiAxMDAgfV0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGNvbG9yOiAnYmxhY2snIH0sXG4gICAgICAgICAgICBzY2FsZTogeyBzaG93OiBmYWxzZSwgbGFiZWxzOiBmYWxzZSwgY29sb3I6ICcjMzMzJywgd2lkdGg6IDIgfSxcbiAgICAgICAgICAgIHR5cGU6ICdzaW1wbGUnLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDIwLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgICBwYXJhbXM6IHsgY3VzdG9tTGFiZWw6ICdBbGVydHMnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOlxuICAgICAgICAgICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wicXVlcnlcIjpcIlwiLFwibGFuZ3VhZ2VcIjpcImx1Y2VuZVwifX0nLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLU1ldHJpYy1NYXgtUnVsZS1MZXZlbCcsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdNYXggUnVsZSBMZXZlbCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ01heCBSdWxlIExldmVsJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdtYXgnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnTWF4IFJ1bGUgTGV2ZWwnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IGZhbHNlLFxuICAgICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICAgIG1ldHJpYzoge1xuICAgICAgICAgICAgcGVyY2VudGFnZU1vZGU6IGZhbHNlLFxuICAgICAgICAgICAgdXNlUmFuZ2VzOiBmYWxzZSxcbiAgICAgICAgICAgIGNvbG9yU2NoZW1hOiAnR3JlZW4gdG8gUmVkJyxcbiAgICAgICAgICAgIG1ldHJpY0NvbG9yTW9kZTogJ0xhYmVscycsXG4gICAgICAgICAgICBjb2xvcnNSYW5nZTogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgZnJvbTogMCxcbiAgICAgICAgICAgICAgICB0bzogNyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGZyb206IDcsXG4gICAgICAgICAgICAgICAgdG86IDEwLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgZnJvbTogMTAsXG4gICAgICAgICAgICAgICAgdG86IDIwLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGludmVydENvbG9yczogZmFsc2UsXG4gICAgICAgICAgICBzdHlsZToge1xuICAgICAgICAgICAgICBiZ0ZpbGw6ICcjMDAwJyxcbiAgICAgICAgICAgICAgYmdDb2xvcjogZmFsc2UsXG4gICAgICAgICAgICAgIGxhYmVsQ29sb3I6IGZhbHNlLFxuICAgICAgICAgICAgICBzdWJUZXh0OiAnJyxcbiAgICAgICAgICAgICAgZm9udFNpemU6IDI2LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogSlNPTi5zdHJpbmdpZnkoeyB2aXM6IHsgZGVmYXVsdENvbG9yczogeyAnMCAtIDEwMCc6ICdyZ2IoMCwxMDQsNTUpJyB9IH0gfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046XG4gICAgICAgICAgJ3tcImluZGV4XCI6XCJ3YXp1aC1hbGVydHNcIixcImZpbHRlclwiOltdLFwicXVlcnlcIjp7XCJxdWVyeVwiOlwiXCIsXCJsYW5ndWFnZVwiOlwibHVjZW5lXCJ9fScsXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PZmZpY2UtTWV0cmljLVN1c3BpY2lvdXMtRG93bmxvYWRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1N1c3BpY2lvdXMgRG93bmxvYWRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnU3VzcGljaW91cyBEb3dubG9hZHMgQ291bnQnLFxuICAgICAgICB0eXBlOiAnbWV0cmljJyxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZmlsdGVycycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmlsdGVyczogW1xuICAgICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICAgIGlucHV0OiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAncnVsZS5pZDogXCI5MTcyNFwiJyxcbiAgICAgICAgICAgICAgICAgICAgbGFuZ3VhZ2U6ICdrdWVyeScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgbGFiZWw6ICdTdXNwaWNpb3VzIERvd25sb2FkcycsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IGZhbHNlLFxuICAgICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICAgIG1ldHJpYzoge1xuICAgICAgICAgICAgcGVyY2VudGFnZU1vZGU6IGZhbHNlLFxuICAgICAgICAgICAgdXNlUmFuZ2VzOiBmYWxzZSxcbiAgICAgICAgICAgIGNvbG9yU2NoZW1hOiAnR3JlZW4gdG8gUmVkJyxcbiAgICAgICAgICAgIG1ldHJpY0NvbG9yTW9kZTogJ0xhYmVscycsXG4gICAgICAgICAgICBjb2xvcnNSYW5nZTogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgZnJvbTogMCxcbiAgICAgICAgICAgICAgICB0bzogMSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgc3R5bGU6IHtcbiAgICAgICAgICAgICAgYmdGaWxsOiAnIzAwMCcsXG4gICAgICAgICAgICAgIGJnQ29sb3I6IGZhbHNlLFxuICAgICAgICAgICAgICBsYWJlbENvbG9yOiBmYWxzZSxcbiAgICAgICAgICAgICAgc3ViVGV4dDogJycsXG4gICAgICAgICAgICAgIGZvbnRTaXplOiAyNixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOlxuICAgICAgICAgICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wicXVlcnlcIjpcIlwiLFwibGFuZ3VhZ2VcIjpcImx1Y2VuZVwifX0nLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLU1ldHJpYy1NYWx3YXJlLUFsZXJ0cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdNYWx3YXJlIEFsZXJ0cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ01hbHdhcmUgQWxlcnRzIENvdW50JyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2ZpbHRlcnMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpbHRlcnM6IFtcbiAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICBpbnB1dDoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ3J1bGUuaWQ6IFwiOTE1NTZcIiBvciBydWxlLmlkOiBcIjkxNTc1XCIgb3IgcnVsZS5pZDogXCI5MTcwMFwiICcsXG4gICAgICAgICAgICAgICAgICAgIGxhbmd1YWdlOiAna3VlcnknLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgIGxhYmVsOiAnTWFsd2FyZSBBbGVydHMnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIF0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnbWV0cmljJyxcbiAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIHVzZVJhbmdlczogZmFsc2UsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBtZXRyaWNDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBmcm9tOiAwLFxuICAgICAgICAgICAgICAgIHRvOiAxMDAwMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgc3R5bGU6IHtcbiAgICAgICAgICAgICAgYmdGaWxsOiAnIzAwMCcsXG4gICAgICAgICAgICAgIGJnQ29sb3I6IGZhbHNlLFxuICAgICAgICAgICAgICBsYWJlbENvbG9yOiBmYWxzZSxcbiAgICAgICAgICAgICAgc3ViVGV4dDogJycsXG4gICAgICAgICAgICAgIGZvbnRTaXplOiAyNixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOlxuICAgICAgICAgICd7XCJpbmRleFwiOlwid2F6dWgtYWxlcnRzXCIsXCJmaWx0ZXJcIjpbXSxcInF1ZXJ5XCI6e1wicXVlcnlcIjpcIlwiLFwibGFuZ3VhZ2VcIjpcImx1Y2VuZVwifX0nLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLU1ldHJpYy1GdWxsQWNjZXNzLVBlcm1pc3Npb25zJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0Z1bGwgQWNjZXNzIFBlcm1pc3Npb25zJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnRnVsbCBBY2Nlc3MgUGVybWlzc2lvbiBDb3VudCcsXG4gICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdmaWx0ZXJzJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWx0ZXJzOiBbXG4gICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgaW5wdXQ6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdydWxlLmlkOiBcIjkxNzI1XCInLFxuICAgICAgICAgICAgICAgICAgICBsYW5ndWFnZTogJ2t1ZXJ5JyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICBsYWJlbDogJ0Z1bGwgQWNjZXNzIFBlcm1pc3Npb25zJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBdLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogZmFsc2UsXG4gICAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgICAgbWV0cmljOiB7XG4gICAgICAgICAgICBwZXJjZW50YWdlTW9kZTogZmFsc2UsXG4gICAgICAgICAgICB1c2VSYW5nZXM6IGZhbHNlLFxuICAgICAgICAgICAgY29sb3JTY2hlbWE6ICdHcmVlbiB0byBSZWQnLFxuICAgICAgICAgICAgbWV0cmljQ29sb3JNb2RlOiAnTm9uZScsXG4gICAgICAgICAgICBjb2xvcnNSYW5nZTogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgZnJvbTogMCxcbiAgICAgICAgICAgICAgICB0bzogMTAwMDAsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgICAgbGFiZWxzOiB7XG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICAgIHN0eWxlOiB7XG4gICAgICAgICAgICAgIGJnRmlsbDogJyMwMDAnLFxuICAgICAgICAgICAgICBiZ0NvbG9yOiBmYWxzZSxcbiAgICAgICAgICAgICAgbGFiZWxDb2xvcjogZmFsc2UsXG4gICAgICAgICAgICAgIHN1YlRleHQ6ICcnLFxuICAgICAgICAgICAgICBmb250U2l6ZTogMjYsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7IHZpczogeyBkZWZhdWx0Q29sb3JzOiB7ICcwIC0gMTAwJzogJ3JnYigwLDEwNCw1NSknIH0gfSB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjpcbiAgICAgICAgICAne1wiaW5kZXhcIjpcIndhenVoLWFsZXJ0c1wiLFwiZmlsdGVyXCI6W10sXCJxdWVyeVwiOntcInF1ZXJ5XCI6XCJcIixcImxhbmd1YWdlXCI6XCJsdWNlbmVcIn19JyxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1MZXZlbC0xMi1BbGVydHMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTGV2ZWwgMTIgYWxlcnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQ291bnQgTGV2ZWwgMTIgQWxlcnRzJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnZ2F1Z2UnLFxuICAgICAgICAgIGdhdWdlOiB7XG4gICAgICAgICAgICB2ZXJ0aWNhbFNwbGl0OiBmYWxzZSxcbiAgICAgICAgICAgIGF1dG9FeHRlbmQ6IGZhbHNlLFxuICAgICAgICAgICAgcGVyY2VudGFnZU1vZGU6IGZhbHNlLFxuICAgICAgICAgICAgZ2F1Z2VUeXBlOiAnTWV0cmljJyxcbiAgICAgICAgICAgIGdhdWdlU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIGJhY2tTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgb3JpZW50YXRpb246ICd2ZXJ0aWNhbCcsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBnYXVnZUNvbG9yTW9kZTogJ05vbmUnLFxuICAgICAgICAgICAgdXNlUmFuZ2U6IGZhbHNlLFxuICAgICAgICAgICAgY29sb3JzUmFuZ2U6IFt7IGZyb206IDAsIHRvOiAxMDAgfV0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGNvbG9yOiAnYmxhY2snIH0sXG4gICAgICAgICAgICBzY2FsZTogeyBzaG93OiBmYWxzZSwgbGFiZWxzOiBmYWxzZSwgY29sb3I6ICcjMzMzJywgd2lkdGg6IDIgfSxcbiAgICAgICAgICAgIHR5cGU6ICdzaW1wbGUnLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDIwLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgICBwYXJhbXM6IHsgY3VzdG9tTGFiZWw6ICdMZXZlbCAxMiBvciBhYm92ZSBhbGVydHMnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAkc3RhdGU6IHtcbiAgICAgICAgICAgICAgICBzdG9yZTogJ2FwcFN0YXRlJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgICAgICAga2V5OiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgICAgbmVnYXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIGd0ZTogMTIsXG4gICAgICAgICAgICAgICAgICBsdDogbnVsbCxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHR5cGU6ICdyYW5nZScsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICcxMiB0byAr4oieJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcmFuZ2U6IHtcbiAgICAgICAgICAgICAgICAncnVsZS5sZXZlbCc6IHtcbiAgICAgICAgICAgICAgICAgIGd0ZTogMTIsXG4gICAgICAgICAgICAgICAgICBsdDogbnVsbCxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLUF1dGhlbnRpY2F0aW9uLWZhaWx1cmUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQXV0aGVudGljYXRpb24gZmFpbHVyZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0NvdW50IEF1dGhlbnRpY2F0aW9uIEZhaWx1cmUnLFxuICAgICAgICB0eXBlOiAnbWV0cmljJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IGZhbHNlLFxuICAgICAgICAgIHR5cGU6ICdnYXVnZScsXG4gICAgICAgICAgZ2F1Z2U6IHtcbiAgICAgICAgICAgIHZlcnRpY2FsU3BsaXQ6IGZhbHNlLFxuICAgICAgICAgICAgYXV0b0V4dGVuZDogZmFsc2UsXG4gICAgICAgICAgICBwZXJjZW50YWdlTW9kZTogZmFsc2UsXG4gICAgICAgICAgICBnYXVnZVR5cGU6ICdNZXRyaWMnLFxuICAgICAgICAgICAgZ2F1Z2VTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgYmFja1N0eWxlOiAnRnVsbCcsXG4gICAgICAgICAgICBvcmllbnRhdGlvbjogJ3ZlcnRpY2FsJyxcbiAgICAgICAgICAgIGNvbG9yU2NoZW1hOiAnR3JlZW4gdG8gUmVkJyxcbiAgICAgICAgICAgIGdhdWdlQ29sb3JNb2RlOiAnTm9uZScsXG4gICAgICAgICAgICB1c2VSYW5nZTogZmFsc2UsXG4gICAgICAgICAgICBjb2xvcnNSYW5nZTogW3sgZnJvbTogMCwgdG86IDEwMCB9XSxcbiAgICAgICAgICAgIGludmVydENvbG9yczogZmFsc2UsXG4gICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgY29sb3I6ICdibGFjaycgfSxcbiAgICAgICAgICAgIHNjYWxlOiB7IHNob3c6IGZhbHNlLCBsYWJlbHM6IGZhbHNlLCBjb2xvcjogJyMzMzMnLCB3aWR0aDogMiB9LFxuICAgICAgICAgICAgdHlwZTogJ3NpbXBsZScsXG4gICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMjAsIGJnQ29sb3I6IGZhbHNlLCBsYWJlbENvbG9yOiBmYWxzZSwgc3ViVGV4dDogJycgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICAgIHBhcmFtczogeyBjdXN0b21MYWJlbDogJ0F1dGhlbnRpY2F0aW9uIGZhaWx1cmUnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2VzJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdydWxlLmdyb3VwcycsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICd3aW5fYXV0aGVudGljYXRpb25fZmFpbGVkLCBhdXRoZW50aWNhdGlvbl9mYWlsZWQsIGF1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IFtcbiAgICAgICAgICAgICAgICAgICd3aW5fYXV0aGVudGljYXRpb25fZmFpbGVkJyxcbiAgICAgICAgICAgICAgICAgICdhdXRoZW50aWNhdGlvbl9mYWlsZWQnLFxuICAgICAgICAgICAgICAgICAgJ2F1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzJyxcbiAgICAgICAgICAgICAgICBdLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIGJvb2w6IHtcbiAgICAgICAgICAgICAgICAgIHNob3VsZDogW1xuICAgICAgICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgICAgICAgbWF0Y2hfcGhyYXNlOiB7XG4gICAgICAgICAgICAgICAgICAgICAgICAncnVsZS5ncm91cHMnOiAnd2luX2F1dGhlbnRpY2F0aW9uX2ZhaWxlZCcsXG4gICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgIG1hdGNoX3BocmFzZToge1xuICAgICAgICAgICAgICAgICAgICAgICAgJ3J1bGUuZ3JvdXBzJzogJ2F1dGhlbnRpY2F0aW9uX2ZhaWxlZCcsXG4gICAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgICAgICAgIG1hdGNoX3BocmFzZToge1xuICAgICAgICAgICAgICAgICAgICAgICAgJ3J1bGUuZ3JvdXBzJzogJ2F1dGhlbnRpY2F0aW9uX2ZhaWx1cmVzJyxcbiAgICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgXSxcbiAgICAgICAgICAgICAgICAgIG1pbmltdW1fc2hvdWxkX21hdGNoOiAxLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLUF1dGhlbnRpY2F0aW9uLXN1Y2Nlc3MnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQXV0aGVudGljYXRpb24gc3VjY2VzcycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0NvdW50IEF1dGhlbnRpY2F0aW9uIFN1Y2Nlc3MnLFxuICAgICAgICB0eXBlOiAnbWV0cmljJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IGZhbHNlLFxuICAgICAgICAgIHR5cGU6ICdnYXVnZScsXG4gICAgICAgICAgZ2F1Z2U6IHtcbiAgICAgICAgICAgIHZlcnRpY2FsU3BsaXQ6IGZhbHNlLFxuICAgICAgICAgICAgYXV0b0V4dGVuZDogZmFsc2UsXG4gICAgICAgICAgICBwZXJjZW50YWdlTW9kZTogZmFsc2UsXG4gICAgICAgICAgICBnYXVnZVR5cGU6ICdNZXRyaWMnLFxuICAgICAgICAgICAgZ2F1Z2VTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgYmFja1N0eWxlOiAnRnVsbCcsXG4gICAgICAgICAgICBvcmllbnRhdGlvbjogJ3ZlcnRpY2FsJyxcbiAgICAgICAgICAgIGNvbG9yU2NoZW1hOiAnR3JlZW4gdG8gUmVkJyxcbiAgICAgICAgICAgIGdhdWdlQ29sb3JNb2RlOiAnTm9uZScsXG4gICAgICAgICAgICB1c2VSYW5nZTogZmFsc2UsXG4gICAgICAgICAgICBjb2xvcnNSYW5nZTogW3sgZnJvbTogMCwgdG86IDEwMCB9XSxcbiAgICAgICAgICAgIGludmVydENvbG9yczogZmFsc2UsXG4gICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgY29sb3I6ICdibGFjaycgfSxcbiAgICAgICAgICAgIHNjYWxlOiB7IHNob3c6IGZhbHNlLCBsYWJlbHM6IGZhbHNlLCBjb2xvcjogJyMzMzMnLCB3aWR0aDogMiB9LFxuICAgICAgICAgICAgdHlwZTogJ3NpbXBsZScsXG4gICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMjAsIGJnQ29sb3I6IGZhbHNlLCBsYWJlbENvbG9yOiBmYWxzZSwgc3ViVGV4dDogJycgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICAgIHBhcmFtczogeyBjdXN0b21MYWJlbDogJ0F1dGhlbnRpY2F0aW9uIHN1Y2Nlc3MnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGRlZmF1bHRDb2xvcnM6IHsgJzAgLSAxMDAnOiAncmdiKDAsMTA0LDU1KScgfSB9IH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ3J1bGUuZ3JvdXBzJyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2F1dGhlbnRpY2F0aW9uX3N1Y2Nlc3MnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdhdXRoZW50aWNhdGlvbl9zdWNjZXNzJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdydWxlLmdyb3Vwcyc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdhdXRoZW50aWNhdGlvbl9zdWNjZXNzJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLUFsZXJ0LUxldmVsLUV2b2x1dGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydCBsZXZlbCBldm9sdXRpb24nLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydCBsZXZlbCBldm9sdXRpb24nLFxuICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IHRydWUsIHN0eWxlOiB7IGNvbG9yOiAnI2VlZScgfSwgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnIH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGZpbHRlcjogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIG1vZGU6ICdub3JtYWwnIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCByb3RhdGU6IDAsIGZpbHRlcjogZmFsc2UsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiAndHJ1ZScsXG4gICAgICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnBvbGF0ZTogJ2NhcmRpbmFsJyxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAndGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgdGltZVJhbmdlOiB7IGZyb206ICdub3ctMjRoJywgdG86ICdub3cnLCBtb2RlOiAncXVpY2snIH0sXG4gICAgICAgICAgICAgIHVzZU5vcm1hbGl6ZWRFc0ludGVydmFsOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ2F1dG8nLFxuICAgICAgICAgICAgICB0aW1lX3pvbmU6ICdFdXJvcGUvQmVybGluJyxcbiAgICAgICAgICAgICAgZHJvcF9wYXJ0aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIGN1c3RvbUludGVydmFsOiAnMmgnLFxuICAgICAgICAgICAgICBtaW5fZG9jX2NvdW50OiAxLFxuICAgICAgICAgICAgICBleHRlbmRlZF9ib3VuZHM6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBzaXplOiAnMTUnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLUFsZXJ0cy1zdW1tYXJ5JyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldGljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgc2hvd1Rvb2xiYXI6IHRydWUsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmlkJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIHNpemU6IDEwMDAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIElEJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5kZXNjcmlwdGlvbicsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiAyMCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0Rlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzQnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiAxMixcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0xldmVsJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLU1ldHJpYy1TdGF0cycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1N0YXRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTWV0cmljIFN0YXRzJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdUb3RhbCBBbGVydHMnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0b3BfaGl0cycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmxldmVsJyxcbiAgICAgICAgICAgICAgYWdncmVnYXRlOiAnY29uY2F0JyxcbiAgICAgICAgICAgICAgc2l6ZTogMSxcbiAgICAgICAgICAgICAgc29ydEZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIHNvcnRPcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ01heCBydWxlIGxldmVsIGRldGVjdGVkJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnbWV0cmljJyxcbiAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIHVzZVJhbmdlczogZmFsc2UsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBtZXRyaWNDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBmcm9tOiAwLFxuICAgICAgICAgICAgICAgIHRvOiAxMDAwMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgc3R5bGU6IHtcbiAgICAgICAgICAgICAgYmdGaWxsOiAnIzAwMCcsXG4gICAgICAgICAgICAgIGJnQ29sb3I6IGZhbHNlLFxuICAgICAgICAgICAgICBsYWJlbENvbG9yOiBmYWxzZSxcbiAgICAgICAgICAgICAgc3ViVGV4dDogJycsXG4gICAgICAgICAgICAgIGZvbnRTaXplOiA2MCxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PZmZpY2UtSVBzLUJ5LVVzZXItVGFibGUnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSZWdpc3RlcmVkIElQcyBmb3IgVXNlcicsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1JlZ2lzdGVyZWQgSVBzIGZvciBVc2VyJyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vZmZpY2UzNjUuQWN0b3IuSUQnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnX2tleScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1RvcCBVc2VycycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2FnZW50LmlkJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJ19rZXknLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdBZ2VudCBJRCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNCcsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2FnZW50Lm5hbWUnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FnZW50IG5hbWUnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogNSxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRyaWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHtcbiAgICAgICAgICAgIGNvbHVtbkluZGV4OiBudWxsLFxuICAgICAgICAgICAgZGlyZWN0aW9uOiBudWxsLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICAgIHBlcmNlbnRhZ2VDb2w6ICcnLFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1Vc2VyLU9wZXJhdGlvbi1MZXZlbC1UYWJsZScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1VzZXIgT3BlcmF0aW9ucycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1VzZXIgT3BlcmF0aW9uIExldmVsJyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vZmZpY2UzNjUuVXNlcklkJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1MDAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiB0cnVlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXJzJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1VzZXJzJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vZmZpY2UzNjUuT3BlcmF0aW9uJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAxMDAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ09wZXJhdGlvbicsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNCcsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDIwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIGxldmVsJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDUsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0cmljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7XG4gICAgICAgICAgICBjb2x1bW5JbmRleDogbnVsbCxcbiAgICAgICAgICAgIGRpcmVjdGlvbjogbnVsbCxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgICBwZXJjZW50YWdlQ29sOiAnJyxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PZmZpY2UtQ2xpZW50LUlQLU9wZXJhdGlvbi1MZXZlbC1UYWJsZScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0NsaWVudCBJUCBPcGVyYXRpb25zJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQ2xpZW50IElQIE9wZXJhdGlvbiBMZXZlbCcsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub2ZmaWNlMzY1LkNsaWVudElQJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1MDAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiB0cnVlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXJzJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0NsaWVudCBJUCBhZGRyZXNzJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vZmZpY2UzNjUuT3BlcmF0aW9uJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAxMDAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ09wZXJhdGlvbicsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNCcsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDIwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIGxldmVsJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDUsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0cmljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7XG4gICAgICAgICAgICBjb2x1bW5JbmRleDogbnVsbCxcbiAgICAgICAgICAgIGRpcmVjdGlvbjogbnVsbCxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgICBwZXJjZW50YWdlQ29sOiAnJyxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PZmZpY2UtVG9wLUV2ZW50cy1QaWUnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgRXZlbnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQ2FrZScsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogZmFsc2UsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmRlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogZmFsc2UsXG4gICAgICAgICAgbGFiZWxzOiB7XG4gICAgICAgICAgICBzaG93OiBmYWxzZSxcbiAgICAgICAgICAgIHZhbHVlczogdHJ1ZSxcbiAgICAgICAgICAgIGxhc3RfbGV2ZWw6IHRydWUsXG4gICAgICAgICAgICB0cnVuY2F0ZTogMTAwLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgcm93OiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1BbGVydHMtRXZvbHV0aW9uLUJ5LVVzZXInLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydHMgZXZvbHV0aW9uIG92ZXIgdGltZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0FsZXJ0cyBldm9sdXRpb24gb3ZlciB0aW1lJyxcbiAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHtcbiAgICAgICAgICAgICAgICBmcm9tOiAnbm93LTF5JyxcbiAgICAgICAgICAgICAgICB0bzogJ25vdycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHVzZU5vcm1hbGl6ZWRFc0ludGVydmFsOiB0cnVlLFxuICAgICAgICAgICAgICBzY2FsZU1ldHJpY1ZhbHVlczogZmFsc2UsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnaCcsXG4gICAgICAgICAgICAgIGRyb3BfcGFydGlhbHM6IGZhbHNlLFxuICAgICAgICAgICAgICBtaW5fZG9jX2NvdW50OiAxLFxuICAgICAgICAgICAgICBleHRlbmRlZF9ib3VuZHM6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vZmZpY2UzNjUuQWN0b3IuSUQnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnYXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdsaW5lJyxcbiAgICAgICAgICBncmlkOiB7XG4gICAgICAgICAgICBjYXRlZ29yeUxpbmVzOiBmYWxzZSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7XG4gICAgICAgICAgICAgICAgdHlwZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgICAgZmlsdGVyOiB0cnVlLFxuICAgICAgICAgICAgICAgIHRydW5jYXRlOiAxMDAsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZToge1xuICAgICAgICAgICAgICAgIHR5cGU6ICdsaW5lYXInLFxuICAgICAgICAgICAgICAgIG1vZGU6ICdub3JtYWwnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICAgIHJvdGF0ZTogMCxcbiAgICAgICAgICAgICAgICBmaWx0ZXI6IGZhbHNlLFxuICAgICAgICAgICAgICAgIHRydW5jYXRlOiAxMDAsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7XG4gICAgICAgICAgICAgICAgdGV4dDogJ0NvdW50JyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICAgICAgICBtb2RlOiAnbm9ybWFsJyxcbiAgICAgICAgICAgICAgZGF0YToge1xuICAgICAgICAgICAgICAgIGxhYmVsOiAnQ291bnQnLFxuICAgICAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgbGluZVdpZHRoOiAyLFxuICAgICAgICAgICAgICBpbnRlcnBvbGF0ZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHt9LFxuICAgICAgICAgIHRocmVzaG9sZExpbmU6IHtcbiAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgICAgdmFsdWU6IDEwLFxuICAgICAgICAgICAgd2lkdGg6IDEsXG4gICAgICAgICAgICBzdHlsZTogJ2Z1bGwnLFxuICAgICAgICAgICAgY29sb3I6ICcjRTc2NjRDJyxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1Vc2VyLUJ5LU9wZXJhdGlvbi1SZXN1bHQnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdVc2VyIGJ5IE9wZXJhdGlvbiByZXN1bHQnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdVc2VyIEJ5IE9wZXJhdGlvbiByZXN1bHQnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9mZmljZTM2NS5PcGVyYXRpb24nLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDEwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdPcGVyYXRpb24nLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9mZmljZTM2NS5Vc2VySWQnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDEwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdVc2VyJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vZmZpY2UzNjUuUmVzdWx0U3RhdHVzJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUmVzdWx0IFN0YXR1cycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiA1LFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldHJpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDoge1xuICAgICAgICAgICAgY29sdW1uSW5kZXg6IG51bGwsXG4gICAgICAgICAgICBkaXJlY3Rpb246IG51bGwsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgICAgcGVyY2VudGFnZUNvbDogJycsXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLVJ1bGUtRGVzY3JpcHRpb24tTGV2ZWwtVGFibGUnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSdWxlIERlc2NyaXB0aW9uIGJ5IExldmVsJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnUnVsZSBEZXNjcmlwdGlvbiBMZXZlbCBUYWJsZScsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUwMCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUnVsZSBEZXNjcmlwdGlvbicsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDIwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIExldmVsJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDUsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0cmljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7XG4gICAgICAgICAgICBjb2x1bW5JbmRleDogbnVsbCxcbiAgICAgICAgICAgIGRpcmVjdGlvbjogbnVsbCxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgICBwZXJjZW50YWdlQ29sOiAnJyxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PZmZpY2UtU2V2ZXJpdHktQnktVXNlci1IaXN0b2dyYW0nLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdTZXZlcml0eSBieSB1c2VyJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnU2V2ZXJpdHkgYnkgVXNlcicsXG4gICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmxldmVsJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJ19rZXknLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnU2V2ZXJpdHknLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgIGdyaWQ6IHtcbiAgICAgICAgICAgIGNhdGVnb3J5TGluZXM6IGZhbHNlLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHtcbiAgICAgICAgICAgICAgICB0eXBlOiAnbGluZWFyJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7XG4gICAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgICBmaWx0ZXI6IHRydWUsXG4gICAgICAgICAgICAgICAgdHJ1bmNhdGU6IDEwMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7XG4gICAgICAgICAgICAgICAgdHlwZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgICAgbW9kZTogJ25vcm1hbCcsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgICAgcm90YXRlOiAwLFxuICAgICAgICAgICAgICAgIGZpbHRlcjogZmFsc2UsXG4gICAgICAgICAgICAgICAgdHJ1bmNhdGU6IDEwMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHtcbiAgICAgICAgICAgICAgICB0ZXh0OiAnQ291bnQnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7XG4gICAgICAgICAgICAgICAgbGFiZWw6ICdDb3VudCcsXG4gICAgICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBkcmF3TGluZXNCZXR3ZWVuUG9pbnRzOiB0cnVlLFxuICAgICAgICAgICAgICBsaW5lV2lkdGg6IDIsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgdGhyZXNob2xkTGluZToge1xuICAgICAgICAgICAgc2hvdzogZmFsc2UsXG4gICAgICAgICAgICB2YWx1ZTogMTAsXG4gICAgICAgICAgICB3aWR0aDogMSxcbiAgICAgICAgICAgIHN0eWxlOiAnZnVsbCcsXG4gICAgICAgICAgICBjb2xvcjogJyNFNzY2NEMnLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLVJ1bGUtTGV2ZWwtSGlzdG9ncmFtJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUnVsZSBsZXZlbCBoaXN0cm9ncmFtJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnUnVsZSBsZXZlbCBoaXN0b2dyYW0nLFxuICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3RpbWVzdGFtcCcsXG4gICAgICAgICAgICAgIHRpbWVSYW5nZToge1xuICAgICAgICAgICAgICAgIGZyb206ICdub3cvdycsXG4gICAgICAgICAgICAgICAgdG86ICdub3cvdycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHVzZU5vcm1hbGl6ZWRFc0ludGVydmFsOiB0cnVlLFxuICAgICAgICAgICAgICBzY2FsZU1ldHJpY1ZhbHVlczogZmFsc2UsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnM2gnLFxuICAgICAgICAgICAgICBkcm9wX3BhcnRpYWxzOiBmYWxzZSxcbiAgICAgICAgICAgICAgbWluX2RvY19jb3VudDogMSxcbiAgICAgICAgICAgICAgZXh0ZW5kZWRfYm91bmRzOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgICAgZ3JpZDoge1xuICAgICAgICAgICAgY2F0ZWdvcnlMaW5lczogZmFsc2UsXG4gICAgICAgICAgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZToge1xuICAgICAgICAgICAgICAgIHR5cGU6ICdsaW5lYXInLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICAgIGZpbHRlcjogdHJ1ZSxcbiAgICAgICAgICAgICAgICB0cnVuY2F0ZTogMTAwLFxuICAgICAgICAgICAgICAgIHJvdGF0ZTogMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7XG4gICAgICAgICAgICAgICAgdHlwZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgICAgbW9kZTogJ25vcm1hbCcsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgICAgcm90YXRlOiAwLFxuICAgICAgICAgICAgICAgIGZpbHRlcjogZmFsc2UsXG4gICAgICAgICAgICAgICAgdHJ1bmNhdGU6IDEwMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHtcbiAgICAgICAgICAgICAgICB0ZXh0OiAnQ291bnQnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7XG4gICAgICAgICAgICAgICAgbGFiZWw6ICdDb3VudCcsXG4gICAgICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgbGluZVdpZHRoOiAyLFxuICAgICAgICAgICAgICBzaG93Q2lyY2xlczogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJwb2xhdGU6ICdsaW5lYXInLFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIGFkZFRpbWVNYXJrZXI6IGZhbHNlLFxuICAgICAgICAgIHRocmVzaG9sZExpbmU6IHtcbiAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgICAgdmFsdWU6IDEwLFxuICAgICAgICAgICAgd2lkdGg6IDEsXG4gICAgICAgICAgICBzdHlsZTogJ2Z1bGwnLFxuICAgICAgICAgICAgY29sb3I6ICcjRTc2NjRDJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGxhYmVsczoge30sXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLUlQcy1CeS1Vc2VyLUJhcmNoYXJ0JyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnSVBzIGJ5IHVzZXInLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdJUHMgYnkgVXNlcicsXG4gICAgICAgIHR5cGU6ICdob3Jpem9udGFsX2JhcicsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub2ZmaWNlMzY1LkNsaWVudElQJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdJUCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9mZmljZTM2NS5Vc2VySWQnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICBncmlkOiB7XG4gICAgICAgICAgICBjYXRlZ29yeUxpbmVzOiBmYWxzZSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZToge1xuICAgICAgICAgICAgICAgIHR5cGU6ICdsaW5lYXInLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICAgIHJvdGF0ZTogMCxcbiAgICAgICAgICAgICAgICBmaWx0ZXI6IGZhbHNlLFxuICAgICAgICAgICAgICAgIHRydW5jYXRlOiAyMDAsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7XG4gICAgICAgICAgICAgICAgdHlwZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgICAgbW9kZTogJ25vcm1hbCcsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgICAgcm90YXRlOiA3NSxcbiAgICAgICAgICAgICAgICBmaWx0ZXI6IHRydWUsXG4gICAgICAgICAgICAgICAgdHJ1bmNhdGU6IDEwMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHtcbiAgICAgICAgICAgICAgICB0ZXh0OiAnQ291bnQnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7XG4gICAgICAgICAgICAgICAgbGFiZWw6ICdDb3VudCcsXG4gICAgICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBkcmF3TGluZXNCZXR3ZWVuUG9pbnRzOiB0cnVlLFxuICAgICAgICAgICAgICBsaW5lV2lkdGg6IDIsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHt9LFxuICAgICAgICAgIHRocmVzaG9sZExpbmU6IHtcbiAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgICAgdmFsdWU6IDEwLFxuICAgICAgICAgICAgd2lkdGg6IDEsXG4gICAgICAgICAgICBzdHlsZTogJ2Z1bGwnLFxuICAgICAgICAgICAgY29sb3I6ICcjRTc2NjRDJyxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1TZXZlcml0eS1CeS1Vc2VyLUJhcmNoYXJ0JyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnU2V2ZXJpdHkgYnkgdXNlcicsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1NldmVyaXR5IEJ5IFVzZXIgQmFyY2hhcnQnLFxuICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IHRydWUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub2ZmaWNlMzY1LlVzZXJJZCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogMjAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICBncmlkOiB7XG4gICAgICAgICAgICBjYXRlZ29yeUxpbmVzOiBmYWxzZSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7XG4gICAgICAgICAgICAgICAgdHlwZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgICAgZmlsdGVyOiB0cnVlLFxuICAgICAgICAgICAgICAgIHRydW5jYXRlOiAxMDAsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZToge1xuICAgICAgICAgICAgICAgIHR5cGU6ICdsaW5lYXInLFxuICAgICAgICAgICAgICAgIG1vZGU6ICdub3JtYWwnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICAgIHJvdGF0ZTogMCxcbiAgICAgICAgICAgICAgICBmaWx0ZXI6IGZhbHNlLFxuICAgICAgICAgICAgICAgIHRydW5jYXRlOiAxMDAsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7XG4gICAgICAgICAgICAgICAgdGV4dDogJ0NvdW50JyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgICAgIG1vZGU6ICdzdGFja2VkJyxcbiAgICAgICAgICAgICAgZGF0YToge1xuICAgICAgICAgICAgICAgIGxhYmVsOiAnQ291bnQnLFxuICAgICAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgbGluZVdpZHRoOiAyLFxuICAgICAgICAgICAgICBzaG93Q2lyY2xlczogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgbGFiZWxzOiB7XG4gICAgICAgICAgICBzaG93OiBmYWxzZSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHRocmVzaG9sZExpbmU6IHtcbiAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgICAgdmFsdWU6IDEwLFxuICAgICAgICAgICAgd2lkdGg6IDEsXG4gICAgICAgICAgICBzdHlsZTogJ2Z1bGwnLFxuICAgICAgICAgICAgY29sb3I6ICcjRTc2NjRDJyxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1Ub3AtVXNlcnMtQnktU3Vic2NyaXB0aW9uLUJhcmNoYXJ0JyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIFVzZXIgQnkgU3Vic2NyaXB0aW9uJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnVG9wIFVzZXIgQnkgU3Vic2NyaXB0aW9uJyxcbiAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub2ZmaWNlMzY1LlVzZXJJZCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9mZmljZTM2NS5TdWJzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICBncmlkOiB7XG4gICAgICAgICAgICBjYXRlZ29yeUxpbmVzOiBmYWxzZSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7XG4gICAgICAgICAgICAgICAgdHlwZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgICAgZmlsdGVyOiB0cnVlLFxuICAgICAgICAgICAgICAgIHRydW5jYXRlOiAxMDAsXG4gICAgICAgICAgICAgICAgcm90YXRlOiAwLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHtcbiAgICAgICAgICAgICAgICB0eXBlOiAnbGluZWFyJyxcbiAgICAgICAgICAgICAgICBtb2RlOiAnbm9ybWFsJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7XG4gICAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgICByb3RhdGU6IDAsXG4gICAgICAgICAgICAgICAgZmlsdGVyOiBmYWxzZSxcbiAgICAgICAgICAgICAgICB0cnVuY2F0ZTogMTAwLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB0aXRsZToge1xuICAgICAgICAgICAgICAgIHRleHQ6ICdDb3VudCcsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgICAgICBtb2RlOiAnc3RhY2tlZCcsXG4gICAgICAgICAgICAgIGRhdGE6IHtcbiAgICAgICAgICAgICAgICBsYWJlbDogJ0NvdW50JyxcbiAgICAgICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIGxpbmVXaWR0aDogMixcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIGFkZFRpbWVNYXJrZXI6IGZhbHNlLFxuICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgc2hvdzogZmFsc2UsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB0aHJlc2hvbGRMaW5lOiB7XG4gICAgICAgICAgICBzaG93OiBmYWxzZSxcbiAgICAgICAgICAgIHZhbHVlOiAxMCxcbiAgICAgICAgICAgIHdpZHRoOiAxLFxuICAgICAgICAgICAgc3R5bGU6ICdmdWxsJyxcbiAgICAgICAgICAgIGNvbG9yOiAnI0U3NjY0QycsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PZmZpY2UtTG9jYXRpb24nLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdHZW9sb2NhdGlvbiBtYXAnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdHZW9sb2NhdGlvbiBtYXAnLFxuICAgICAgICB0eXBlOiAndGlsZV9tYXAnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgbWFwVHlwZTogJ1NjYWxlZCBDaXJjbGUgTWFya2VycycsXG4gICAgICAgICAgaXNEZXNhdHVyYXRlZDogZmFsc2UsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBoZWF0Q2x1c3RlclNpemU6IDEuNSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ2JvdHRvbXJpZ2h0JyxcbiAgICAgICAgICBtYXBab29tOiAxLFxuICAgICAgICAgIG1hcENlbnRlcjogWzAsIDBdLFxuICAgICAgICAgIHdtczogeyBlbmFibGVkOiBmYWxzZSwgb3B0aW9uczogeyBmb3JtYXQ6ICdpbWFnZS9wbmcnLCB0cmFuc3BhcmVudDogdHJ1ZSB9IH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljOiB7IGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfSxcbiAgICAgICAgICAgIGdlb2hhc2g6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ3N0cmluZycgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7IHByZWNpc2lvbjogMiwgdXNlR2VvY2VudHJvaWQ6IHRydWUgfSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2dlb2hhc2hfZ3JpZCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgZ2VvY2VudHJvaWQ6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDIsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ3N0cmluZycgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2dlb19jZW50cm9pZCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdnZW9oYXNoX2dyaWQnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdHZW9Mb2NhdGlvbi5sb2NhdGlvbicsXG4gICAgICAgICAgICAgIGF1dG9QcmVjaXNpb246IHRydWUsXG4gICAgICAgICAgICAgIHByZWNpc2lvbjogMixcbiAgICAgICAgICAgICAgdXNlR2VvY2VudHJvaWQ6IHRydWUsXG4gICAgICAgICAgICAgIGlzRmlsdGVyZWRCeUNvbGxhcjogdHJ1ZSxcbiAgICAgICAgICAgICAgbWFwWm9vbTogMSxcbiAgICAgICAgICAgICAgbWFwQ2VudGVyOiBbMCwgMF0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIG1hcFpvb206IDIsXG4gICAgICAgIG1hcENlbnRlcjogWzM4LjY4NTUwOTc2MDAxMjAyNSwgLTMxLjgxNjQwNjI1MDAwMDAwNF0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1Db3VudHJ5LVRhZy1DbG91ZCcsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0NvdW50cnkgb2Ygb3JpZ2luJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQ291bnRyeSB0YWcgY2xvdWQnLFxuICAgICAgICB0eXBlOiAndGFnY2xvdWQnLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdHZW9Mb2NhdGlvbi5jb3VudHJ5X25hbWUnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHNjYWxlOiAnbGluZWFyJyxcbiAgICAgICAgICBvcmllbnRhdGlvbjogJ3JpZ2h0IGFuZ2xlZCcsXG4gICAgICAgICAgbWluRm9udFNpemU6IDE4LFxuICAgICAgICAgIG1heEZvbnRTaXplOiA3MixcbiAgICAgICAgICBzaG93TGFiZWw6IGZhbHNlLFxuICAgICAgICB9LFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9mZmljZS1BbGVydHMtRXZvbHV0aW9uLUJ5LVVzZXJJRCcsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBieSB1c2VyJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnRzIGV2b2x1dGlvbiBvdmVyIHRpbWUnLFxuICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdBbGVydHMnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHtcbiAgICAgICAgICAgICAgICBmcm9tOiAnbm93LTF3JyxcbiAgICAgICAgICAgICAgICB0bzogJ25vdycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHVzZU5vcm1hbGl6ZWRFc0ludGVydmFsOiB0cnVlLFxuICAgICAgICAgICAgICBzY2FsZU1ldHJpY1ZhbHVlczogZmFsc2UsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnYXV0bycsXG4gICAgICAgICAgICAgIGRyb3BfcGFydGlhbHM6IGZhbHNlLFxuICAgICAgICAgICAgICBtaW5fZG9jX2NvdW50OiAxLFxuICAgICAgICAgICAgICBleHRlbmRlZF9ib3VuZHM6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vZmZpY2UzNjUuVXNlcklkJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdVc2VyIElEJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICAgIGdyaWQ6IHtcbiAgICAgICAgICAgIGNhdGVnb3J5TGluZXM6IGZhbHNlLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHtcbiAgICAgICAgICAgICAgICB0eXBlOiAnbGluZWFyJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7XG4gICAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgICBmaWx0ZXI6IHRydWUsXG4gICAgICAgICAgICAgICAgdHJ1bmNhdGU6IDEwMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7XG4gICAgICAgICAgICAgICAgdHlwZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgICAgbW9kZTogJ25vcm1hbCcsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGxhYmVsczoge1xuICAgICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgICAgcm90YXRlOiAwLFxuICAgICAgICAgICAgICAgIGZpbHRlcjogZmFsc2UsXG4gICAgICAgICAgICAgICAgdHJ1bmNhdGU6IDEwMCxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHtcbiAgICAgICAgICAgICAgICB0ZXh0OiAnQWxlcnRzJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICAgICAgICBtb2RlOiAnbm9ybWFsJyxcbiAgICAgICAgICAgICAgZGF0YToge1xuICAgICAgICAgICAgICAgIGxhYmVsOiAnQWxlcnRzJyxcbiAgICAgICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIGxpbmVXaWR0aDogMixcbiAgICAgICAgICAgICAgaW50ZXJwb2xhdGU6ICdsaW5lYXInLFxuICAgICAgICAgICAgICBzaG93Q2lyY2xlczogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgbGFiZWxzOiB7fSxcbiAgICAgICAgICB0aHJlc2hvbGRMaW5lOiB7XG4gICAgICAgICAgICBzaG93OiBmYWxzZSxcbiAgICAgICAgICAgIHZhbHVlOiAxMCxcbiAgICAgICAgICAgIHdpZHRoOiAxLFxuICAgICAgICAgICAgc3R5bGU6ICdmdWxsJyxcbiAgICAgICAgICAgIGNvbG9yOiAnI0U3NjY0QycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICByb3c6IHRydWUsXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLVRvcC1Vc2VycycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCBPZmZpY2UgVXNlcnMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgYnkgdXNlcicsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9mZmljZTM2NS5Vc2VySWQnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7XG4gICAgICAgICAgICBzaG93OiBmYWxzZSxcbiAgICAgICAgICAgIHZhbHVlczogdHJ1ZSxcbiAgICAgICAgICAgIGxhc3RfbGV2ZWw6IHRydWUsXG4gICAgICAgICAgICB0cnVuY2F0ZTogMTAwLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT2ZmaWNlLVRvcC1PcGVyYXRpb25zJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIE9wZXJhdGlvbnMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgT3BlcmF0aW9ucycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnY291bnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9mZmljZTM2NS5PcGVyYXRpb24nLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ09wZXJhdGlvbicsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHtcbiAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgICAgdmFsdWVzOiB0cnVlLFxuICAgICAgICAgICAgbGFzdF9sZXZlbDogdHJ1ZSxcbiAgICAgICAgICAgIHRydW5jYXRlOiAxMDAsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbl07XG4iXX0=