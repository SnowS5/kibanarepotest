"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Agents/OSCAP visualizations
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
  _id: 'Wazuh-App-Agents-OSCAP-Higher-score-metric',
  _source: {
    title: 'Higher score metric',
    visState: JSON.stringify({
      title: 'Higher score metric',
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
        type: 'max',
        schema: 'metric',
        params: {
          field: 'data.oscap.scan.score',
          customLabel: 'Higher score'
        }
      }]
    }),
    uiStateJSON: '{"vis":{"defaultColors":{"0 - 100":"rgb(0,104,55)"}}}',
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
  _id: 'Wazuh-App-Agents-OSCAP-Lower-score-metric',
  _source: {
    title: 'Lower score metric',
    visState: JSON.stringify({
      title: 'Lower score metric',
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
        type: 'min',
        schema: 'metric',
        params: {
          field: 'data.oscap.scan.score',
          customLabel: 'Lower score'
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
  _id: 'Wazuh-App-Agents-OSCAP-Last-score',
  _source: {
    title: 'Last score',
    visState: JSON.stringify({
      title: 'Last score',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMeticsAtAllLevels: false,
        sort: {
          columnIndex: null,
          direction: null
        },
        showTotal: false,
        showToolbar: true,
        totalFunc: 'sum'
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'max',
        schema: 'metric',
        params: {
          field: 'timestamp'
        }
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.oscap.scan.score',
          size: 1,
          order: 'desc',
          orderBy: '1'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        params: {
          sort: {
            columnIndex: null,
            direction: null
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
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-OSCAP-Last-scan-profile',
  _source: {
    title: 'Last scan profile',
    visState: JSON.stringify({
      title: 'Last scan profile',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMeticsAtAllLevels: false,
        sort: {
          columnIndex: null,
          direction: null
        },
        showTotal: false,
        showToolbar: true,
        totalFunc: 'sum'
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'max',
        schema: 'metric',
        params: {
          field: 'timestamp'
        }
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.oscap.scan.profile.title',
          size: 1,
          order: 'desc',
          orderBy: '1'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        params: {
          sort: {
            columnIndex: null,
            direction: null
          }
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
            key: 'data.oscap.check.result',
            value: 'fail',
            params: {
              query: 'fail',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.result': {
                query: 'fail',
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
  _id: 'Wazuh-App-Agents-OSCAP-Scans',
  _source: {
    title: 'Scans',
    visState: JSON.stringify({
      title: 'Scans',
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
          field: 'data.oscap.scan.id',
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
  _id: 'Wazuh-App-Agents-OSCAP-Profiles',
  _source: {
    title: 'Profiles',
    visState: JSON.stringify({
      title: 'Profiles',
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
          field: 'data.oscap.scan.profile.title',
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
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'data.oscap.check.result',
            value: 'fail',
            params: {
              query: 'fail',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.result': {
                query: 'fail',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }, {
          meta: {
            index: 'wazuh-alerts',
            negate: true,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'rule.groups',
            value: 'syslog',
            params: {
              query: 'syslog',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'rule.groups': {
                query: 'syslog',
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
  _id: 'Wazuh-App-Agents-OSCAP-Content',
  _source: {
    title: 'Content',
    visState: JSON.stringify({
      title: 'Content',
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
          field: 'data.oscap.scan.content',
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
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'data.oscap.check.result',
            value: 'fail',
            params: {
              query: 'fail',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.result': {
                query: 'fail',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }, {
          meta: {
            index: 'wazuh-alerts',
            negate: true,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'rule.groups',
            value: 'syslog',
            params: {
              query: 'syslog',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'rule.groups': {
                query: 'syslog',
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
  _id: 'Wazuh-App-Agents-OSCAP-Severity',
  _source: {
    title: 'Severity',
    visState: JSON.stringify({
      title: 'Severity',
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
          field: 'data.oscap.check.severity',
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
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'data.oscap.check.result',
            value: 'fail',
            params: {
              query: 'fail',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.result': {
                query: 'fail',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }, {
          meta: {
            index: 'wazuh-alerts',
            negate: true,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'rule.groups',
            value: 'syslog',
            params: {
              query: 'syslog',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'rule.groups': {
                query: 'syslog',
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
  _id: 'Wazuh-App-Agents-OSCAP-Daily-scans-evolution',
  _source: {
    title: 'Daily scans evolution',
    visState: JSON.stringify({
      title: 'Daily scans evolution',
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
        addLegend: false,
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
          extended_bounds: {},
          customLabel: 'Daily scans'
        }
      }]
    }),
    uiStateJSON: '{}',
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
            key: 'data.oscap.check.result',
            value: 'fail',
            params: {
              query: 'fail',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.result': {
                query: 'fail',
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
  _id: 'Wazuh-App-Agents-OSCAP-Top-5-Alerts',
  _source: {
    title: 'Top 5 Alerts',
    visState: JSON.stringify({
      title: 'Top 5 Alerts',
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
          field: 'data.oscap.check.title',
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
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'data.oscap.check.result',
            value: 'fail',
            params: {
              query: 'fail',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.result': {
                query: 'fail',
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
  _id: 'Wazuh-App-Agents-OSCAP-Top-5-High-risk-alerts',
  _source: {
    title: 'Top 5 High risk alerts',
    visState: JSON.stringify({
      title: 'Top 5 High risk alerts',
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
          field: 'data.oscap.check.title',
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
        filter: [{
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'data.oscap.check.result',
            value: 'fail',
            params: {
              query: 'fail',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.result': {
                query: 'fail',
                type: 'phrase'
              }
            }
          },
          $state: {
            store: 'appState'
          }
        }, {
          meta: {
            index: 'wazuh-alerts',
            negate: false,
            disabled: false,
            alias: null,
            type: 'phrase',
            key: 'data.oscap.check.severity',
            value: 'high',
            params: {
              query: 'high',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.severity': {
                query: 'high',
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
  _id: 'Wazuh-App-Agents-OSCAP-Top-alert',
  _source: {
    title: 'Top alert',
    visState: JSON.stringify({
      title: 'Top alert',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMeticsAtAllLevels: false,
        sort: {
          columnIndex: null,
          direction: null
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
          field: 'data.oscap.check.title',
          size: 1,
          order: 'desc',
          orderBy: '1'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        params: {
          sort: {
            columnIndex: null,
            direction: null
          }
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
            key: 'data.oscap.check.result',
            value: 'fail',
            params: {
              query: 'fail',
              type: 'phrase'
            }
          },
          query: {
            match: {
              'data.oscap.check.result': {
                query: 'fail',
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
  _id: 'Wazuh-App-Agents-OSCAP-Last-alerts',
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
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.oscap.check.title',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 50,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Title'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.oscap.scan.profile.title',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 5,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Profile'
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy1vc2NhcC50cyJdLCJuYW1lcyI6WyJfaWQiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwiYWRkVG9vbHRpcCIsImFkZExlZ2VuZCIsImdhdWdlIiwidmVydGljYWxTcGxpdCIsImF1dG9FeHRlbmQiLCJwZXJjZW50YWdlTW9kZSIsImdhdWdlVHlwZSIsImdhdWdlU3R5bGUiLCJiYWNrU3R5bGUiLCJvcmllbnRhdGlvbiIsImNvbG9yU2NoZW1hIiwiZ2F1Z2VDb2xvck1vZGUiLCJ1c2VSYW5nZSIsImNvbG9yc1JhbmdlIiwiZnJvbSIsInRvIiwiaW52ZXJ0Q29sb3JzIiwibGFiZWxzIiwic2hvdyIsImNvbG9yIiwic2NhbGUiLCJ3aWR0aCIsInN0eWxlIiwiZm9udFNpemUiLCJiZ0NvbG9yIiwibGFiZWxDb2xvciIsInN1YlRleHQiLCJhZ2dzIiwiaWQiLCJlbmFibGVkIiwic2NoZW1hIiwiZmllbGQiLCJjdXN0b21MYWJlbCIsInVpU3RhdGVKU09OIiwiZGVzY3JpcHRpb24iLCJ2ZXJzaW9uIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImluZGV4IiwiZmlsdGVyIiwicXVlcnkiLCJsYW5ndWFnZSIsIl90eXBlIiwidmlzIiwiZGVmYXVsdENvbG9ycyIsInBlclBhZ2UiLCJzaG93UGFydGlhbFJvd3MiLCJzaG93TWV0aWNzQXRBbGxMZXZlbHMiLCJzb3J0IiwiY29sdW1uSW5kZXgiLCJkaXJlY3Rpb24iLCJzaG93VG90YWwiLCJzaG93VG9vbGJhciIsInRvdGFsRnVuYyIsInNpemUiLCJvcmRlciIsIm9yZGVyQnkiLCJtZXRhIiwibmVnYXRlIiwiZGlzYWJsZWQiLCJhbGlhcyIsImtleSIsInZhbHVlIiwibWF0Y2giLCIkc3RhdGUiLCJzdG9yZSIsImxlZ2VuZFBvc2l0aW9uIiwiaXNEb251dCIsImdyaWQiLCJjYXRlZ29yeUxpbmVzIiwiY2F0ZWdvcnlBeGVzIiwicG9zaXRpb24iLCJ0cnVuY2F0ZSIsInZhbHVlQXhlcyIsIm5hbWUiLCJtb2RlIiwicm90YXRlIiwidGV4dCIsInNlcmllc1BhcmFtcyIsImRhdGEiLCJsYWJlbCIsInZhbHVlQXhpcyIsImRyYXdMaW5lc0JldHdlZW5Qb2ludHMiLCJzaG93Q2lyY2xlcyIsInRpbWVzIiwiYWRkVGltZU1hcmtlciIsImludGVydmFsIiwiY3VzdG9tSW50ZXJ2YWwiLCJtaW5fZG9jX2NvdW50IiwiZXh0ZW5kZWRfYm91bmRzIiwib3RoZXJCdWNrZXQiLCJvdGhlckJ1Y2tldExhYmVsIiwibWlzc2luZ0J1Y2tldCIsIm1pc3NpbmdCdWNrZXRMYWJlbCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7ZUFDZSxDQUNiO0FBQ0VBLEVBQUFBLEdBQUcsRUFBRSw0Q0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLHFCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxxQkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxRQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05DLFFBQUFBLFVBQVUsRUFBRSxJQUROO0FBRU5DLFFBQUFBLFNBQVMsRUFBRSxLQUZMO0FBR05ILFFBQUFBLElBQUksRUFBRSxPQUhBO0FBSU5JLFFBQUFBLEtBQUssRUFBRTtBQUNMQyxVQUFBQSxhQUFhLEVBQUUsS0FEVjtBQUVMQyxVQUFBQSxVQUFVLEVBQUUsS0FGUDtBQUdMQyxVQUFBQSxjQUFjLEVBQUUsS0FIWDtBQUlMQyxVQUFBQSxTQUFTLEVBQUUsUUFKTjtBQUtMQyxVQUFBQSxVQUFVLEVBQUUsTUFMUDtBQU1MQyxVQUFBQSxTQUFTLEVBQUUsTUFOTjtBQU9MQyxVQUFBQSxXQUFXLEVBQUUsVUFQUjtBQVFM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RUFBRSxRQUpWO0FBS0UvQixRQUFBQSxNQUFNLEVBQUU7QUFDTmdDLFVBQUFBLEtBQUssRUFBRSwrQkFERDtBQUVOMkQsVUFBQUEsV0FBVyxFQUFFLEtBRlA7QUFHTkMsVUFBQUEsZ0JBQWdCLEVBQUUsT0FIWjtBQUlOQyxVQUFBQSxhQUFhLEVBQUUsS0FKVDtBQUtOQyxVQUFBQSxrQkFBa0IsRUFBRSxTQUxkO0FBTU52QyxVQUFBQSxJQUFJLEVBQUUsQ0FOQTtBQU9OQyxVQUFBQSxLQUFLLEVBQUUsTUFQRDtBQVFOQyxVQUFBQSxPQUFPLEVBQUUsR0FSSDtBQVNOeEIsVUFBQUEsV0FBVyxFQUFFO0FBVFA7QUFMVixPQW5CSTtBQVppQixLQUFmLENBRkg7QUFvRFBDLElBQUFBLFdBQVcsRUFBRXJDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQzFCOEMsTUFBQUEsR0FBRyxFQUFFO0FBQUU1QyxRQUFBQSxNQUFNLEVBQUU7QUFBRWlELFVBQUFBLElBQUksRUFBRTtBQUFFQyxZQUFBQSxXQUFXLEVBQUUsQ0FBZjtBQUFrQkMsWUFBQUEsU0FBUyxFQUFFO0FBQTdCO0FBQVI7QUFBVjtBQURxQixLQUFmLENBcEROO0FBdURQaEIsSUFBQUEsV0FBVyxFQUFFLEVBdkROO0FBd0RQQyxJQUFBQSxPQUFPLEVBQUUsQ0F4REY7QUF5RFBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRXpDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CeUMsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsRUFGdUI7QUFHL0JDLFFBQUFBLEtBQUssRUFBRTtBQUFFQSxVQUFBQSxLQUFLLEVBQUUsRUFBVDtBQUFhQyxVQUFBQSxRQUFRLEVBQUU7QUFBdkI7QUFId0IsT0FBZjtBQURHO0FBekRoQjtBQUhYLENBMTJCYSxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgQWdlbnRzL09TQ0FQIHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1PU0NBUC1IaWdoZXItc2NvcmUtbWV0cmljJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0hpZ2hlciBzY29yZSBtZXRyaWMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdIaWdoZXIgc2NvcmUgbWV0cmljJyxcbiAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICB0eXBlOiAnZ2F1Z2UnLFxuICAgICAgICAgIGdhdWdlOiB7XG4gICAgICAgICAgICB2ZXJ0aWNhbFNwbGl0OiBmYWxzZSxcbiAgICAgICAgICAgIGF1dG9FeHRlbmQ6IGZhbHNlLFxuICAgICAgICAgICAgcGVyY2VudGFnZU1vZGU6IGZhbHNlLFxuICAgICAgICAgICAgZ2F1Z2VUeXBlOiAnTWV0cmljJyxcbiAgICAgICAgICAgIGdhdWdlU3R5bGU6ICdGdWxsJyxcbiAgICAgICAgICAgIGJhY2tTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgb3JpZW50YXRpb246ICd2ZXJ0aWNhbCcsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBnYXVnZUNvbG9yTW9kZTogJ05vbmUnLFxuICAgICAgICAgICAgdXNlUmFuZ2U6IGZhbHNlLFxuICAgICAgICAgICAgY29sb3JzUmFuZ2U6IFt7IGZyb206IDAsIHRvOiAxMDAgfV0sXG4gICAgICAgICAgICBpbnZlcnRDb2xvcnM6IGZhbHNlLFxuICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGNvbG9yOiAnYmxhY2snIH0sXG4gICAgICAgICAgICBzY2FsZTogeyBzaG93OiBmYWxzZSwgbGFiZWxzOiBmYWxzZSwgY29sb3I6ICcjMzMzJywgd2lkdGg6IDIgfSxcbiAgICAgICAgICAgIHR5cGU6ICdzaW1wbGUnLFxuICAgICAgICAgICAgc3R5bGU6IHsgZm9udFNpemU6IDIwLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ21heCcsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5zY2FuLnNjb3JlJywgY3VzdG9tTGFiZWw6ICdIaWdoZXIgc2NvcmUnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7XCJ2aXNcIjp7XCJkZWZhdWx0Q29sb3JzXCI6e1wiMCAtIDEwMFwiOlwicmdiKDAsMTA0LDU1KVwifX19JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU9TQ0FQLUxvd2VyLXNjb3JlLW1ldHJpYycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdMb3dlciBzY29yZSBtZXRyaWMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdMb3dlciBzY29yZSBtZXRyaWMnLFxuICAgICAgICB0eXBlOiAnbWV0cmljJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IGZhbHNlLFxuICAgICAgICAgIHR5cGU6ICdnYXVnZScsXG4gICAgICAgICAgZ2F1Z2U6IHtcbiAgICAgICAgICAgIHZlcnRpY2FsU3BsaXQ6IGZhbHNlLFxuICAgICAgICAgICAgYXV0b0V4dGVuZDogZmFsc2UsXG4gICAgICAgICAgICBwZXJjZW50YWdlTW9kZTogZmFsc2UsXG4gICAgICAgICAgICBnYXVnZVR5cGU6ICdNZXRyaWMnLFxuICAgICAgICAgICAgZ2F1Z2VTdHlsZTogJ0Z1bGwnLFxuICAgICAgICAgICAgYmFja1N0eWxlOiAnRnVsbCcsXG4gICAgICAgICAgICBvcmllbnRhdGlvbjogJ3ZlcnRpY2FsJyxcbiAgICAgICAgICAgIGNvbG9yU2NoZW1hOiAnR3JlZW4gdG8gUmVkJyxcbiAgICAgICAgICAgIGdhdWdlQ29sb3JNb2RlOiAnTm9uZScsXG4gICAgICAgICAgICB1c2VSYW5nZTogZmFsc2UsXG4gICAgICAgICAgICBjb2xvcnNSYW5nZTogW3sgZnJvbTogMCwgdG86IDEwMCB9XSxcbiAgICAgICAgICAgIGludmVydENvbG9yczogZmFsc2UsXG4gICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgY29sb3I6ICdibGFjaycgfSxcbiAgICAgICAgICAgIHNjYWxlOiB7IHNob3c6IGZhbHNlLCBsYWJlbHM6IGZhbHNlLCBjb2xvcjogJyMzMzMnLCB3aWR0aDogMiB9LFxuICAgICAgICAgICAgdHlwZTogJ3NpbXBsZScsXG4gICAgICAgICAgICBzdHlsZTogeyBmb250U2l6ZTogMjAsIGJnQ29sb3I6IGZhbHNlLCBsYWJlbENvbG9yOiBmYWxzZSwgc3ViVGV4dDogJycgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcxJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnbWluJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdkYXRhLm9zY2FwLnNjYW4uc2NvcmUnLCBjdXN0b21MYWJlbDogJ0xvd2VyIHNjb3JlJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7IHZpczogeyBkZWZhdWx0Q29sb3JzOiB7ICcwIC0gMTAwJzogJ3JnYigwLDEwNCw1NSknIH0gfSB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU9TQ0FQLUxhc3Qtc2NvcmUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTGFzdCBzY29yZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0xhc3Qgc2NvcmUnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogbnVsbCwgZGlyZWN0aW9uOiBudWxsIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnbWF4Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7IGZpZWxkOiAndGltZXN0YW1wJyB9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczogeyBmaWVsZDogJ2RhdGEub3NjYXAuc2Nhbi5zY29yZScsIHNpemU6IDEsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogbnVsbCwgZGlyZWN0aW9uOiBudWxsIH0gfSB9LFxuICAgICAgfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1PU0NBUC1MYXN0LXNjYW4tcHJvZmlsZScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdMYXN0IHNjYW4gcHJvZmlsZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0xhc3Qgc2NhbiBwcm9maWxlJyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0aWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IG51bGwsIGRpcmVjdGlvbjogbnVsbCB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgc2hvd1Rvb2xiYXI6IHRydWUsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ21heCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczogeyBmaWVsZDogJ3RpbWVzdGFtcCcgfSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9zY2FwLnNjYW4ucHJvZmlsZS50aXRsZScsXG4gICAgICAgICAgICAgIHNpemU6IDEsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCcsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICAgICAgICAnZGF0YS5vc2NhcC5jaGVjay5yZXN1bHQnOiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAkc3RhdGU6IHtcbiAgICAgICAgICAgICAgICBzdG9yZTogJ2FwcFN0YXRlJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1PU0NBUC1TY2FucycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdTY2FucycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1NjYW5zJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczogeyBmaWVsZDogJ2RhdGEub3NjYXAuc2Nhbi5pZCcsIHNpemU6IDUsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtT1NDQVAtUHJvZmlsZXMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUHJvZmlsZXMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdQcm9maWxlcycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9zY2FwLnNjYW4ucHJvZmlsZS50aXRsZScsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIG1ldGE6IHtcbiAgICAgICAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgICAgICAgbmVnYXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAnZGF0YS5vc2NhcC5jaGVjay5yZXN1bHQnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBxdWVyeTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICAgICAgICBtYXRjaDoge1xuICAgICAgICAgICAgICAgICAgJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0Jzoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogdHJ1ZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAncnVsZS5ncm91cHMnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdydWxlLmdyb3Vwcyc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdzeXNsb2cnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtT1NDQVAtQ29udGVudCcsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdDb250ZW50JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQ29udGVudCcsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdkYXRhLm9zY2FwLnNjYW4uY29udGVudCcsIHNpemU6IDUsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0JyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IHRydWUsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ3J1bGUuZ3JvdXBzJyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ3N5c2xvZycsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBxdWVyeTogJ3N5c2xvZycsXG4gICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICAgICAgICAncnVsZS5ncm91cHMnOiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU9TQ0FQLVNldmVyaXR5JyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1NldmVyaXR5JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnU2V2ZXJpdHknLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5jaGVjay5zZXZlcml0eScsIHNpemU6IDUsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0JyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IHRydWUsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ3J1bGUuZ3JvdXBzJyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ3N5c2xvZycsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBxdWVyeTogJ3N5c2xvZycsXG4gICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICAgICAgICAncnVsZS5ncm91cHMnOiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU9TQ0FQLURhaWx5LXNjYW5zLWV2b2x1dGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdEYWlseSBzY2FucyBldm9sdXRpb24nLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdEYWlseSBzY2FucyBldm9sdXRpb24nLFxuICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiBmYWxzZSwgc3R5bGU6IHsgY29sb3I6ICcjZWVlJyB9IH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGZpbHRlcjogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIG1vZGU6ICdub3JtYWwnIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCByb3RhdGU6IDAsIGZpbHRlcjogZmFsc2UsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiAndHJ1ZScsXG4gICAgICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgICAgICBtb2RlOiAnc3RhY2tlZCcsXG4gICAgICAgICAgICAgIGRhdGE6IHsgbGFiZWw6ICdDb3VudCcsIGlkOiAnMScgfSxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBkcmF3TGluZXNCZXR3ZWVuUG9pbnRzOiB0cnVlLFxuICAgICAgICAgICAgICBzaG93Q2lyY2xlczogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogZmFsc2UsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIGFkZFRpbWVNYXJrZXI6IGZhbHNlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ2F1dG8nLFxuICAgICAgICAgICAgICBjdXN0b21JbnRlcnZhbDogJzJoJyxcbiAgICAgICAgICAgICAgbWluX2RvY19jb3VudDogMSxcbiAgICAgICAgICAgICAgZXh0ZW5kZWRfYm91bmRzOiB7fSxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdEYWlseSBzY2FucycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0JyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU9TQ0FQLVRvcC01LUFsZXJ0cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgNSBBbGVydHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgNSBBbGVydHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5jaGVjay50aXRsZScsIHNpemU6IDUsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0JyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU9TQ0FQLVRvcC01LUhpZ2gtcmlzay1hbGVydHMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIDUgSGlnaCByaXNrIGFsZXJ0cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1RvcCA1IEhpZ2ggcmlzayBhbGVydHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5jaGVjay50aXRsZScsIHNpemU6IDUsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0JyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdkYXRhLm9zY2FwLmNoZWNrLnNldmVyaXR5JyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2hpZ2gnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdoaWdoJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdkYXRhLm9zY2FwLmNoZWNrLnNldmVyaXR5Jzoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ2hpZ2gnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtT1NDQVAtVG9wLWFsZXJ0JyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCBhbGVydCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1RvcCBhbGVydCcsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldGljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5jaGVjay50aXRsZScsIHNpemU6IDEsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogbnVsbCwgZGlyZWN0aW9uOiBudWxsIH0gfSB9LFxuICAgICAgfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIG1ldGE6IHtcbiAgICAgICAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgICAgICAgbmVnYXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAnZGF0YS5vc2NhcC5jaGVjay5yZXN1bHQnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBxdWVyeTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICAgICAgICBtYXRjaDoge1xuICAgICAgICAgICAgICAgICAgJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0Jzoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtT1NDQVAtTGFzdC1hbGVydHMnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdMYXN0IGFsZXJ0cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0xhc3QgYWxlcnRzJyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0aWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IDIsIGRpcmVjdGlvbjogJ2Rlc2MnIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub3NjYXAuY2hlY2sudGl0bGUnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogNTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdUaXRsZScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEub3NjYXAuc2Nhbi5wcm9maWxlLnRpdGxlJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdQcm9maWxlJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAyLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG5dO1xuIl19