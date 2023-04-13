"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview/OSCAP visualizations
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
  _id: 'Wazuh-App-Overview-OSCAP-Last-score',
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
  _id: 'Wazuh-App-Overview-OSCAP-Last-agent-scanned',
  _source: {
    title: 'Last agent scanned',
    visState: JSON.stringify({
      title: 'Last agent scanned',
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
          field: 'agent.name',
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
  _id: 'Wazuh-App-Overview-OSCAP-Last-scan-profile',
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
      searchSourceJSON: '{"index":"wazuh-alerts","filter":[],"query":{"query":"","language":"lucene"}}'
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-OSCAP-Agents',
  _source: {
    title: 'Agents',
    visState: JSON.stringify({
      params: {
        isDonut: false,
        shareYAxis: true,
        addTooltip: true,
        addLegend: true
      },
      listeners: {},
      type: 'pie',
      aggs: [{
        type: 'count',
        enabled: true,
        id: '1',
        params: {},
        schema: 'metric'
      }, {
        type: 'terms',
        enabled: true,
        id: '2',
        params: {
          orderBy: '1',
          field: 'agent.name',
          order: 'desc',
          size: 5
        },
        schema: 'segment'
      }],
      title: 'Agents'
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
  _id: 'Wazuh-App-Overview-OSCAP-Profiles',
  _source: {
    title: 'Profiles',
    visState: JSON.stringify({
      params: {
        isDonut: false,
        legendPosition: 'right',
        shareYAxis: true,
        addTooltip: true,
        addLegend: true
      },
      listeners: {},
      type: 'pie',
      aggs: [{
        type: 'count',
        enabled: true,
        id: '1',
        params: {},
        schema: 'metric'
      }, {
        type: 'terms',
        enabled: true,
        id: '3',
        params: {
          orderBy: '1',
          field: 'data.oscap.scan.profile.title',
          order: 'desc',
          size: 5
        },
        schema: 'segment'
      }],
      title: 'Profiles'
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
  _id: 'Wazuh-App-Overview-OSCAP-Content',
  _source: {
    title: 'Content',
    visState: JSON.stringify({
      params: {
        isDonut: false,
        legendPosition: 'right',
        shareYAxis: true,
        addTooltip: true,
        addLegend: true
      },
      listeners: {},
      type: 'pie',
      aggs: [{
        type: 'count',
        enabled: true,
        id: '1',
        params: {},
        schema: 'metric'
      }, {
        type: 'terms',
        enabled: true,
        id: '2',
        params: {
          orderBy: '1',
          field: 'data.oscap.scan.content',
          order: 'desc',
          size: 5
        },
        schema: 'segment'
      }],
      title: 'Content'
    }),
    uiStateJSON: '{}',
    version: 1,
    description: '',
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-alerts',
        filter: [{
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
  _id: 'Wazuh-App-Overview-OSCAP-Severity',
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
  _id: 'Wazuh-App-Overview-OSCAP-Top-5-agents-Severity-high',
  _source: {
    title: 'Top 5 agents - Severity high',
    visState: JSON.stringify({
      title: 'Top 5 Agents - Severity high',
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
            truncate: 25,
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
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'agent.name',
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
  _id: 'Wazuh-App-Overview-OSCAP-Top-10-alerts',
  _source: {
    title: 'Top 10 alerts',
    visState: JSON.stringify({
      title: 'Wazuh App OSCAP Top 10 alerts',
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
          size: 10,
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
  _id: 'Wazuh-App-Overview-OSCAP-Top-10-high-risk-alerts',
  _source: {
    title: 'Top 10 high risk alerts',
    visState: JSON.stringify({
      title: 'Wazuh App OSCAP Top 10 high risk alerts',
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
          size: 10,
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
  _id: 'Wazuh-App-Overview-OSCAP-Highest-score',
  _source: {
    title: 'Highest score',
    visState: JSON.stringify({
      title: 'Highest score',
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
          field: 'data.oscap.scan.score'
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
            columnIndex: 0,
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
  _id: 'Wazuh-App-Overview-OSCAP-Lowest-score',
  _source: {
    title: 'Lowest score',
    visState: JSON.stringify({
      title: 'Lowest score',
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
        type: 'min',
        schema: 'metric',
        params: {
          field: 'data.oscap.scan.score'
        }
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'data.oscap.scan.score',
          size: 1,
          order: 'asc',
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
  _id: 'Wazuh-App-Overview-OSCAP-Latest-alert',
  _source: {
    title: 'Latest alert',
    visState: JSON.stringify({
      title: 'Latest alert',
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
  _id: 'Wazuh-App-Overview-OSCAP-Last-alerts',
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
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'agent.name',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 40,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Agent'
        }
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
          size: 5,
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LW9zY2FwLnRzIl0sIm5hbWVzIjpbIl9pZCIsIl9zb3VyY2UiLCJ0aXRsZSIsInZpc1N0YXRlIiwiSlNPTiIsInN0cmluZ2lmeSIsInR5cGUiLCJwYXJhbXMiLCJwZXJQYWdlIiwic2hvd1BhcnRpYWxSb3dzIiwic2hvd01ldGljc0F0QWxsTGV2ZWxzIiwic29ydCIsImNvbHVtbkluZGV4IiwiZGlyZWN0aW9uIiwic2hvd1RvdGFsIiwic2hvd1Rvb2xiYXIiLCJ0b3RhbEZ1bmMiLCJhZ2dzIiwiaWQiLCJlbmFibGVkIiwic2NoZW1hIiwiZmllbGQiLCJzaXplIiwib3JkZXIiLCJvcmRlckJ5IiwidWlTdGF0ZUpTT04iLCJ2aXMiLCJkZXNjcmlwdGlvbiIsInZlcnNpb24iLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiaW5kZXgiLCJmaWx0ZXIiLCJxdWVyeSIsImxhbmd1YWdlIiwiX3R5cGUiLCJtZXRhIiwibmVnYXRlIiwiZGlzYWJsZWQiLCJhbGlhcyIsImtleSIsInZhbHVlIiwibWF0Y2giLCIkc3RhdGUiLCJzdG9yZSIsImlzRG9udXQiLCJzaGFyZVlBeGlzIiwiYWRkVG9vbHRpcCIsImFkZExlZ2VuZCIsImxpc3RlbmVycyIsImxlZ2VuZFBvc2l0aW9uIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJzdHlsZSIsImNvbG9yIiwiY2F0ZWdvcnlBeGVzIiwicG9zaXRpb24iLCJzaG93Iiwic2NhbGUiLCJsYWJlbHMiLCJ0cnVuY2F0ZSIsInJvdGF0ZSIsInZhbHVlQXhlcyIsIm5hbWUiLCJtb2RlIiwidGV4dCIsInNlcmllc1BhcmFtcyIsImRhdGEiLCJsYWJlbCIsInZhbHVlQXhpcyIsImRyYXdMaW5lc0JldHdlZW5Qb2ludHMiLCJzaG93Q2lyY2xlcyIsInRpbWVzIiwiYWRkVGltZU1hcmtlciIsIm90aGVyQnVja2V0Iiwib3RoZXJCdWNrZXRMYWJlbCIsIm1pc3NpbmdCdWNrZXQiLCJtaXNzaW5nQnVja2V0TGFiZWwiLCJjdXN0b21MYWJlbCJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7ZUFDZSxDQUNiO0FBQ0VBLEVBQUFBLEdBQUcsRUFBRSxxQ0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLFlBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLFlBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsT0FGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNOQyxRQUFBQSxPQUFPLEVBQUUsRUFESDtBQUVOQyxRQUFBQSxlQUFlLEVBQUUsS0FGWDtBQUdOQyxRQUFBQSxxQkFBcUIsRUFBRSxLQUhqQjtBQUlOQyxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsV0FBVyxFQUFFLElBQWY7QUFBcUJDLFVBQUFBLFNBQVMsRUFBRTtBQUFoQyxTQUpBO0FBS05DLFFBQUFBLFNBQVMsRUFBRSxLQUxMO0FBTU5DLFFBQUFBLFdBQVcsRUFBRSxJQU5QO0FBT05DLFFBQUFBLFNBQVMsRUFBRTtBQVBMLE9BSGU7QUFZdkJDLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQUVDLFFBQUFBLEVBQUUsRUFBRSxHQUFOO0FBQVdDLFFBQUFBLE9BQU8sRUFBRSxJQUFwQjtBQUEwQmIsUUFBQUEsSUFBSSxFQUFFLEtBQWhDO0FBQXVDYyxRQUFBQSxNQUFNLEVBQUUsUUFBL0M7QUFBeURiLFFBQUFBLE1BQU0sRUFBRTtBQUFFYyxVQUFBQSxLQUFLLEVBQUU7QUFBVDtBQUFqRSxPQURJLEVBRUo7QUFDRUgsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFFBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQUVjLFVBQUFBLEtBQUssRUFBRSx1QkFBVDtBQUFrQ0MsVUFBQUEsSUFBSSxFQUFFLENBQXhDO0FBQTJDQyxVQUFBQSxLQUFLLEVBQUUsTUFBbEQ7QUFBMERDLFVBQUFBLE9BQU8sRUFBRTtBQUFuRTtBQUxWLE9BRkk7QUFaaUIsS0FBZixDQUZIO0FBeUJQQyxJQUFBQSxXQUFXLEVBQUVyQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMxQnFCLE1BQUFBLEdBQUcsRUFBRTtBQUFFbkIsUUFBQUEsTUFBTSxFQUFFO0FBQUVJLFVBQUFBLElBQUksRUFBRTtBQUFFQyxZQUFBQSxXQUFXLEVBQUUsSUFBZjtBQUFxQkMsWUFBQUEsU0FBUyxFQUFFO0FBQWhDO0FBQVI7QUFBVjtBQURxQixLQUFmLENBekJOO0FBNEJQYyxJQUFBQSxXQUFXLEVBQUUsRUE1Qk47QUE2QlBDLElBQUFBLE9BQU8sRUFBRSxDQTdCRjtBQThCUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUFFMUIsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDL0IwQixRQUFBQSxLQUFLLEVBQUUsY0FEd0I7QUFFL0JDLFFBQUFBLE1BQU0sRUFBRSxFQUZ1QjtBQUcvQkMsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQUh3QixPQUFmO0FBREc7QUE5QmhCLEdBRlg7QUF3Q0VDLEVBQUFBLEtBQUssRUFBRTtBQXhDVCxDQURhLEVBMkNiO0FBQ0VuQyxFQUFBQSxHQUFHLEVBQUUsNkNBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxvQkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUsb0JBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsT0FGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNOQyxRQUFBQSxPQUFPLEVBQUUsRUFESDtBQUVOQyxRQUFBQSxlQUFlLEVBQUUsS0FGWDtBQUdOQyxRQUFBQSxxQkFBcUIsRUFBRSxLQUhqQjtBQUlOQyxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsV0FBVyxFQUFFLElBQWY7QUFBcUJDLFVBQUFBLFNBQVMsRUFBRTtBQUFoQyxTQUpBO0FBS05DLFFBQUFBLFNBQVMsRUFBRSxLQUxMO0FBTU5DLFFBQUFBLFdBQVcsRUFBRSxJQU5QO0FBT05DLFFBQUFBLFNBQVMsRUFBRTtBQVBMLE9BSGU7QUFZdkJDLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQUVDLFFBQUFBLEVBQUUsRUFBRSxHQUFOO0FBQVdDLFFBQUFBLE9BQU8sRUFBRSxJQUFwQjtBQUEwQmIsUUFBQUEsSUFBSSxFQUFFLEtBQWhDO0FBQXVDYyxRQUFBQSxNQUFNLEVBQUUsUUFBL0M7QUFBeURiLFFBQUFBLE1BQU0sRUFBRTtBQUFFYyxVQUFBQSxLQUFLLEVBQUU7QUFBVDtBQUFqRSxPQURJLEVBRUo7QUFDRUgsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFFBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQUVjLFVBQUFBLEtBQUssRUFBRSxZQUFUO0FBQXVCQyxVQUFBQSxJQUFJLEVBQUUsQ0FBN0I7QUFBZ0NDLFVBQUFBLEtBQUssRUFBRSxNQUF2QztBQUErQ0MsVUFBQUEsT0FBTyxFQUFFO0FBQXhEO0FBTFYsT0FGSTtBQVppQixLQUFmLENBRkg7QUF5QlBDLElBQUFBLFdBQVcsRUFBRXJCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQzFCcUIsTUFBQUEsR0FBRyxFQUFFO0FBQUVuQixRQUFBQSxNQUFNLEVBQUU7QUFBRUksVUFBQUEsSUFBSSxFQUFFO0FBQUVDLFlBQUFBLFdBQVcsRUFBRSxJQUFmO0FBQXFCQyxZQUFBQSxTQUFTLEVBQUU7QUFBaEM7QUFBUjtBQUFWO0FBRHFCLEtBQWYsQ0F6Qk47QUE0QlBjLElBQUFBLFdBQVcsRUFBRSxFQTVCTjtBQTZCUEMsSUFBQUEsT0FBTyxFQUFFLENBN0JGO0FBOEJQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUxQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQjBCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRUksVUFBQUEsSUFBSSxFQUFFO0FBQ0pMLFlBQUFBLEtBQUssRUFBRSxjQURIO0FBRUpNLFlBQUFBLE1BQU0sRUFBRSxLQUZKO0FBR0pDLFlBQUFBLFFBQVEsRUFBRSxLQUhOO0FBSUpDLFlBQUFBLEtBQUssRUFBRSxJQUpIO0FBS0pqQyxZQUFBQSxJQUFJLEVBQUUsUUFMRjtBQU1Ka0MsWUFBQUEsR0FBRyxFQUFFLHlCQU5EO0FBT0pDLFlBQUFBLEtBQUssRUFBRSxNQVBIO0FBUUpsQyxZQUFBQSxNQUFNLEVBQUU7QUFDTjBCLGNBQUFBLEtBQUssRUFBRSxNQUREO0FBRU4zQixjQUFBQSxJQUFJLEVBQUU7QUFGQTtBQVJKLFdBRFI7QUFjRTJCLFVBQUFBLEtBQUssRUFBRTtBQUNMUyxZQUFBQSxLQUFLLEVBQUU7QUFDTCx5Q0FBMkI7QUFDekJULGdCQUFBQSxLQUFLLEVBQUUsTUFEa0I7QUFFekIzQixnQkFBQUEsSUFBSSxFQUFFO0FBRm1CO0FBRHRCO0FBREYsV0FkVDtBQXNCRXFDLFVBQUFBLE1BQU0sRUFBRTtBQUNOQyxZQUFBQSxLQUFLLEVBQUU7QUFERDtBQXRCVixTQURNLENBRnVCO0FBOEIvQlgsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQTlCd0IsT0FBZjtBQURHO0FBOUJoQixHQUZYO0FBbUVFQyxFQUFBQSxLQUFLLEVBQUU7QUFuRVQsQ0EzQ2EsRUFnSGI7QUFDRW5DLEVBQUFBLEdBQUcsRUFBRSw0Q0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLG1CQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxtQkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxPQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05DLFFBQUFBLE9BQU8sRUFBRSxFQURIO0FBRU5DLFFBQUFBLGVBQWUsRUFBRSxLQUZYO0FBR05DLFFBQUFBLHFCQUFxQixFQUFFLEtBSGpCO0FBSU5DLFFBQUFBLElBQUksRUFBRTtBQUFFQyxVQUFBQSxXQUFXLEVBQUUsSUFBZjtBQUFxQkMsVUFBQUEsU0FBUyxFQUFFO0FBQWhDLFNBSkE7QUFLTkMsUUFBQUEsU0FBUyxFQUFFLEtBTEw7QUFNTkMsUUFBQUEsV0FBVyxFQUFFLElBTlA7QUFPTkMsUUFBQUEsU0FBUyxFQUFFO0FBUEwsT0FIZTtBQVl2QkMsTUFBQUEsSUFBSSxFQUFFLENBQ0o7QUFBRUMsUUFBQUEsRUFBRSxFQUFFLEdBQU47QUFBV0MsUUFBQUEsT0FBTyxFQUFFLElBQXBCO0FBQTBCYixRQUFBQSxJQUFJLEVBQUUsS0FBaEM7QUFBdUNjLFFBQUFBLE1BQU0sRUFBRSxRQUEvQztBQUF5RGIsUUFBQUEsTUFBTSxFQUFFO0FBQUVjLFVBQUFBLEtBQUssRUFBRTtBQUFUO0FBQWpFLE9BREksRUFFSjtBQUNFSCxRQUFBQSxFQUFFLEVBQUUsR0FETjtBQUVFQyxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFYixRQUFBQSxJQUFJLEVBQUUsT0FIUjtBQUlFYyxRQUFBQSxNQUFNLEVBQUUsUUFKVjtBQUtFYixRQUFBQSxNQUFNLEVBQUU7QUFDTmMsVUFBQUEsS0FBSyxFQUFFLCtCQUREO0FBRU5DLFVBQUFBLElBQUksRUFBRSxDQUZBO0FBR05DLFVBQUFBLEtBQUssRUFBRSxNQUhEO0FBSU5DLFVBQUFBLE9BQU8sRUFBRTtBQUpIO0FBTFYsT0FGSTtBQVppQixLQUFmLENBRkg7QUE4QlBDLElBQUFBLFdBQVcsRUFBRXJCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQzFCcUIsTUFBQUEsR0FBRyxFQUFFO0FBQUVuQixRQUFBQSxNQUFNLEVBQUU7QUFBRUksVUFBQUEsSUFBSSxFQUFFO0FBQUVDLFlBQUFBLFdBQVcsRUFBRSxJQUFmO0FBQXFCQyxZQUFBQSxTQUFTLEVBQUU7QUFBaEM7QUFBUjtBQUFWO0FBRHFCLEtBQWYsQ0E5Qk47QUFpQ1BjLElBQUFBLFdBQVcsRUFBRSxFQWpDTjtBQWtDUEMsSUFBQUEsT0FBTyxFQUFFLENBbENGO0FBbUNQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQ2Q7QUFGbUI7QUFuQ2hCLEdBRlg7QUEwQ0VLLEVBQUFBLEtBQUssRUFBRTtBQTFDVCxDQWhIYSxFQTRKYjtBQUNFbkMsRUFBQUEsR0FBRyxFQUFFLGlDQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsUUFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCRSxNQUFBQSxNQUFNLEVBQUU7QUFBRXNDLFFBQUFBLE9BQU8sRUFBRSxLQUFYO0FBQWtCQyxRQUFBQSxVQUFVLEVBQUUsSUFBOUI7QUFBb0NDLFFBQUFBLFVBQVUsRUFBRSxJQUFoRDtBQUFzREMsUUFBQUEsU0FBUyxFQUFFO0FBQWpFLE9BRGU7QUFFdkJDLE1BQUFBLFNBQVMsRUFBRSxFQUZZO0FBR3ZCM0MsTUFBQUEsSUFBSSxFQUFFLEtBSGlCO0FBSXZCVyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFWCxRQUFBQSxJQUFJLEVBQUUsT0FBUjtBQUFpQmEsUUFBQUEsT0FBTyxFQUFFLElBQTFCO0FBQWdDRCxRQUFBQSxFQUFFLEVBQUUsR0FBcEM7QUFBeUNYLFFBQUFBLE1BQU0sRUFBRSxFQUFqRDtBQUFxRGEsUUFBQUEsTUFBTSxFQUFFO0FBQTdELE9BREksRUFFSjtBQUNFZCxRQUFBQSxJQUFJLEVBQUUsT0FEUjtBQUVFYSxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFRCxRQUFBQSxFQUFFLEVBQUUsR0FITjtBQUlFWCxRQUFBQSxNQUFNLEVBQUU7QUFBRWlCLFVBQUFBLE9BQU8sRUFBRSxHQUFYO0FBQWdCSCxVQUFBQSxLQUFLLEVBQUUsWUFBdkI7QUFBcUNFLFVBQUFBLEtBQUssRUFBRSxNQUE1QztBQUFvREQsVUFBQUEsSUFBSSxFQUFFO0FBQTFELFNBSlY7QUFLRUYsUUFBQUEsTUFBTSxFQUFFO0FBTFYsT0FGSSxDQUppQjtBQWN2QmxCLE1BQUFBLEtBQUssRUFBRTtBQWRnQixLQUFmLENBRkg7QUFrQlB1QixJQUFBQSxXQUFXLEVBQUUsSUFsQk47QUFtQlBFLElBQUFBLFdBQVcsRUFBRSxFQW5CTjtBQW9CUEMsSUFBQUEsT0FBTyxFQUFFLENBcEJGO0FBcUJQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUxQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQjBCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRUksVUFBQUEsSUFBSSxFQUFFO0FBQ0pMLFlBQUFBLEtBQUssRUFBRSxjQURIO0FBRUpNLFlBQUFBLE1BQU0sRUFBRSxJQUZKO0FBR0pDLFlBQUFBLFFBQVEsRUFBRSxLQUhOO0FBSUpDLFlBQUFBLEtBQUssRUFBRSxJQUpIO0FBS0pqQyxZQUFBQSxJQUFJLEVBQUUsUUFMRjtBQU1Ka0MsWUFBQUEsR0FBRyxFQUFFLGFBTkQ7QUFPSkMsWUFBQUEsS0FBSyxFQUFFLFFBUEg7QUFRSmxDLFlBQUFBLE1BQU0sRUFBRTtBQUNOMEIsY0FBQUEsS0FBSyxFQUFFLFFBREQ7QUFFTjNCLGNBQUFBLElBQUksRUFBRTtBQUZBO0FBUkosV0FEUjtBQWNFMkIsVUFBQUEsS0FBSyxFQUFFO0FBQ0xTLFlBQUFBLEtBQUssRUFBRTtBQUNMLDZCQUFlO0FBQ2JULGdCQUFBQSxLQUFLLEVBQUUsUUFETTtBQUViM0IsZ0JBQUFBLElBQUksRUFBRTtBQUZPO0FBRFY7QUFERixXQWRUO0FBc0JFcUMsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLEtBQUssRUFBRTtBQUREO0FBdEJWLFNBRE0sQ0FGdUI7QUE4Qi9CWCxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBOUJ3QixPQUFmO0FBREc7QUFyQmhCLEdBRlg7QUEwREVDLEVBQUFBLEtBQUssRUFBRTtBQTFEVCxDQTVKYSxFQXdOYjtBQUNFbkMsRUFBQUEsR0FBRyxFQUFFLG1DQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsVUFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCRSxNQUFBQSxNQUFNLEVBQUU7QUFDTnNDLFFBQUFBLE9BQU8sRUFBRSxLQURIO0FBRU5LLFFBQUFBLGNBQWMsRUFBRSxPQUZWO0FBR05KLFFBQUFBLFVBQVUsRUFBRSxJQUhOO0FBSU5DLFFBQUFBLFVBQVUsRUFBRSxJQUpOO0FBS05DLFFBQUFBLFNBQVMsRUFBRTtBQUxMLE9BRGU7QUFRdkJDLE1BQUFBLFNBQVMsRUFBRSxFQVJZO0FBU3ZCM0MsTUFBQUEsSUFBSSxFQUFFLEtBVGlCO0FBVXZCVyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFWCxRQUFBQSxJQUFJLEVBQUUsT0FBUjtBQUFpQmEsUUFBQUEsT0FBTyxFQUFFLElBQTFCO0FBQWdDRCxRQUFBQSxFQUFFLEVBQUUsR0FBcEM7QUFBeUNYLFFBQUFBLE1BQU0sRUFBRSxFQUFqRDtBQUFxRGEsUUFBQUEsTUFBTSxFQUFFO0FBQTdELE9BREksRUFFSjtBQUNFZCxRQUFBQSxJQUFJLEVBQUUsT0FEUjtBQUVFYSxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFRCxRQUFBQSxFQUFFLEVBQUUsR0FITjtBQUlFWCxRQUFBQSxNQUFNLEVBQUU7QUFDTmlCLFVBQUFBLE9BQU8sRUFBRSxHQURIO0FBRU5ILFVBQUFBLEtBQUssRUFBRSwrQkFGRDtBQUdORSxVQUFBQSxLQUFLLEVBQUUsTUFIRDtBQUlORCxVQUFBQSxJQUFJLEVBQUU7QUFKQSxTQUpWO0FBVUVGLFFBQUFBLE1BQU0sRUFBRTtBQVZWLE9BRkksQ0FWaUI7QUF5QnZCbEIsTUFBQUEsS0FBSyxFQUFFO0FBekJnQixLQUFmLENBRkg7QUE2QlB1QixJQUFBQSxXQUFXLEVBQUUsSUE3Qk47QUE4QlBFLElBQUFBLFdBQVcsRUFBRSxFQTlCTjtBQStCUEMsSUFBQUEsT0FBTyxFQUFFLENBL0JGO0FBZ0NQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUxQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQjBCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRUksVUFBQUEsSUFBSSxFQUFFO0FBQ0pMLFlBQUFBLEtBQUssRUFBRSxjQURIO0FBRUpNLFlBQUFBLE1BQU0sRUFBRSxJQUZKO0FBR0pDLFlBQUFBLFFBQVEsRUFBRSxLQUhOO0FBSUpDLFlBQUFBLEtBQUssRUFBRSxJQUpIO0FBS0pqQyxZQUFBQSxJQUFJLEVBQUUsUUFMRjtBQU1Ka0MsWUFBQUEsR0FBRyxFQUFFLGFBTkQ7QUFPSkMsWUFBQUEsS0FBSyxFQUFFLFFBUEg7QUFRSmxDLFlBQUFBLE1BQU0sRUFBRTtBQUNOMEIsY0FBQUEsS0FBSyxFQUFFLFFBREQ7QUFFTjNCLGNBQUFBLElBQUksRUFBRTtBQUZBO0FBUkosV0FEUjtBQWNFMkIsVUFBQUEsS0FBSyxFQUFFO0FBQ0xTLFlBQUFBLEtBQUssRUFBRTtBQUNMLDZCQUFlO0FBQ2JULGdCQUFBQSxLQUFLLEVBQUUsUUFETTtBQUViM0IsZ0JBQUFBLElBQUksRUFBRTtBQUZPO0FBRFY7QUFERixXQWRUO0FBc0JFcUMsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLEtBQUssRUFBRTtBQUREO0FBdEJWLFNBRE0sQ0FGdUI7QUE4Qi9CWCxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBOUJ3QixPQUFmO0FBREc7QUFoQ2hCLEdBRlg7QUFxRUVDLEVBQUFBLEtBQUssRUFBRTtBQXJFVCxDQXhOYSxFQStSYjtBQUNFbkMsRUFBQUEsR0FBRyxFQUFFLGtDQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsU0FEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCRSxNQUFBQSxNQUFNLEVBQUU7QUFDTnNDLFFBQUFBLE9BQU8sRUFBRSxLQURIO0FBRU5LLFFBQUFBLGNBQWMsRUFBRSxPQUZWO0FBR05KLFFBQUFBLFVBQVUsRUFBRSxJQUhOO0FBSU5DLFFBQUFBLFVBQVUsRUFBRSxJQUpOO0FBS05DLFFBQUFBLFNBQVMsRUFBRTtBQUxMLE9BRGU7QUFRdkJDLE1BQUFBLFNBQVMsRUFBRSxFQVJZO0FBU3ZCM0MsTUFBQUEsSUFBSSxFQUFFLEtBVGlCO0FBVXZCVyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFWCxRQUFBQSxJQUFJLEVBQUUsT0FBUjtBQUFpQmEsUUFBQUEsT0FBTyxFQUFFLElBQTFCO0FBQWdDRCxRQUFBQSxFQUFFLEVBQUUsR0FBcEM7QUFBeUNYLFFBQUFBLE1BQU0sRUFBRSxFQUFqRDtBQUFxRGEsUUFBQUEsTUFBTSxFQUFFO0FBQTdELE9BREksRUFFSjtBQUNFZCxRQUFBQSxJQUFJLEVBQUUsT0FEUjtBQUVFYSxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFRCxRQUFBQSxFQUFFLEVBQUUsR0FITjtBQUlFWCxRQUFBQSxNQUFNLEVBQUU7QUFBRWlCLFVBQUFBLE9BQU8sRUFBRSxHQUFYO0FBQWdCSCxVQUFBQSxLQUFLLEVBQUUseUJBQXZCO0FBQWtERSxVQUFBQSxLQUFLLEVBQUUsTUFBekQ7QUFBaUVELFVBQUFBLElBQUksRUFBRTtBQUF2RSxTQUpWO0FBS0VGLFFBQUFBLE1BQU0sRUFBRTtBQUxWLE9BRkksQ0FWaUI7QUFvQnZCbEIsTUFBQUEsS0FBSyxFQUFFO0FBcEJnQixLQUFmLENBRkg7QUF3QlB1QixJQUFBQSxXQUFXLEVBQUUsSUF4Qk47QUF5QlBHLElBQUFBLE9BQU8sRUFBRSxDQXpCRjtBQTBCUEQsSUFBQUEsV0FBVyxFQUFFLEVBMUJOO0FBMkJQRSxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUxQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQjBCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRUksVUFBQUEsSUFBSSxFQUFFO0FBQ0pMLFlBQUFBLEtBQUssRUFBRSxjQURIO0FBRUpNLFlBQUFBLE1BQU0sRUFBRSxJQUZKO0FBR0pDLFlBQUFBLFFBQVEsRUFBRSxLQUhOO0FBSUpDLFlBQUFBLEtBQUssRUFBRSxJQUpIO0FBS0pqQyxZQUFBQSxJQUFJLEVBQUUsUUFMRjtBQU1Ka0MsWUFBQUEsR0FBRyxFQUFFLGFBTkQ7QUFPSkMsWUFBQUEsS0FBSyxFQUFFLFFBUEg7QUFRSmxDLFlBQUFBLE1BQU0sRUFBRTtBQUNOMEIsY0FBQUEsS0FBSyxFQUFFLFFBREQ7QUFFTjNCLGNBQUFBLElBQUksRUFBRTtBQUZBO0FBUkosV0FEUjtBQWNFMkIsVUFBQUEsS0FBSyxFQUFFO0FBQ0xTLFlBQUFBLEtBQUssRUFBRTtBQUNMLDZCQUFlO0FBQ2JULGdCQUFBQSxLQUFLLEVBQUUsUUFETTtBQUViM0IsZ0JBQUFBLElBQUksRUFBRTtBQUZPO0FBRFY7QUFERixXQWRUO0FBc0JFcUMsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLEtBQUssRUFBRTtBQUREO0FBdEJWLFNBRE0sQ0FGdUI7QUE4Qi9CWCxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBOUJ3QixPQUFmO0FBREc7QUEzQmhCLEdBRlg7QUFnRUVDLEVBQUFBLEtBQUssRUFBRTtBQWhFVCxDQS9SYSxFQWlXYjtBQUNFbkMsRUFBQUEsR0FBRyxFQUFFLG1DQURQO0FBRUVDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsVUFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUsVUFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxLQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05ELFFBQUFBLElBQUksRUFBRSxLQURBO0FBRU55QyxRQUFBQSxVQUFVLEVBQUUsSUFGTjtBQUdOQyxRQUFBQSxTQUFTLEVBQUUsSUFITDtBQUlORSxRQUFBQSxjQUFjLEVBQUUsT0FKVjtBQUtOTCxRQUFBQSxPQUFPLEVBQUU7QUFMSCxPQUhlO0FBVXZCNUIsTUFBQUEsSUFBSSxFQUFFLENBQ0o7QUFBRUMsUUFBQUEsRUFBRSxFQUFFLEdBQU47QUFBV0MsUUFBQUEsT0FBTyxFQUFFLElBQXBCO0FBQTBCYixRQUFBQSxJQUFJLEVBQUUsT0FBaEM7QUFBeUNjLFFBQUFBLE1BQU0sRUFBRSxRQUFqRDtBQUEyRGIsUUFBQUEsTUFBTSxFQUFFO0FBQW5FLE9BREksRUFFSjtBQUNFVyxRQUFBQSxFQUFFLEVBQUUsR0FETjtBQUVFQyxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFYixRQUFBQSxJQUFJLEVBQUUsT0FIUjtBQUlFYyxRQUFBQSxNQUFNLEVBQUUsU0FKVjtBQUtFYixRQUFBQSxNQUFNLEVBQUU7QUFBRWMsVUFBQUEsS0FBSyxFQUFFLDJCQUFUO0FBQXNDQyxVQUFBQSxJQUFJLEVBQUUsQ0FBNUM7QUFBK0NDLFVBQUFBLEtBQUssRUFBRSxNQUF0RDtBQUE4REMsVUFBQUEsT0FBTyxFQUFFO0FBQXZFO0FBTFYsT0FGSTtBQVZpQixLQUFmLENBRkg7QUF1QlBDLElBQUFBLFdBQVcsRUFBRSxJQXZCTjtBQXdCUEUsSUFBQUEsV0FBVyxFQUFFLEVBeEJOO0FBeUJQQyxJQUFBQSxPQUFPLEVBQUUsQ0F6QkY7QUEwQlBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRTFCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CMEIsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsQ0FDTjtBQUNFSSxVQUFBQSxJQUFJLEVBQUU7QUFDSkwsWUFBQUEsS0FBSyxFQUFFLGNBREg7QUFFSk0sWUFBQUEsTUFBTSxFQUFFLEtBRko7QUFHSkMsWUFBQUEsUUFBUSxFQUFFLEtBSE47QUFJSkMsWUFBQUEsS0FBSyxFQUFFLElBSkg7QUFLSmpDLFlBQUFBLElBQUksRUFBRSxRQUxGO0FBTUprQyxZQUFBQSxHQUFHLEVBQUUseUJBTkQ7QUFPSkMsWUFBQUEsS0FBSyxFQUFFLE1BUEg7QUFRSmxDLFlBQUFBLE1BQU0sRUFBRTtBQUNOMEIsY0FBQUEsS0FBSyxFQUFFLE1BREQ7QUFFTjNCLGNBQUFBLElBQUksRUFBRTtBQUZBO0FBUkosV0FEUjtBQWNFMkIsVUFBQUEsS0FBSyxFQUFFO0FBQ0xTLFlBQUFBLEtBQUssRUFBRTtBQUNMLHlDQUEyQjtBQUN6QlQsZ0JBQUFBLEtBQUssRUFBRSxNQURrQjtBQUV6QjNCLGdCQUFBQSxJQUFJLEVBQUU7QUFGbUI7QUFEdEI7QUFERixXQWRUO0FBc0JFcUMsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLEtBQUssRUFBRTtBQUREO0FBdEJWLFNBRE0sRUEyQk47QUFDRVIsVUFBQUEsSUFBSSxFQUFFO0FBQ0pMLFlBQUFBLEtBQUssRUFBRSxjQURIO0FBRUpNLFlBQUFBLE1BQU0sRUFBRSxJQUZKO0FBR0pDLFlBQUFBLFFBQVEsRUFBRSxLQUhOO0FBSUpDLFlBQUFBLEtBQUssRUFBRSxJQUpIO0FBS0pqQyxZQUFBQSxJQUFJLEVBQUUsUUFMRjtBQU1Ka0MsWUFBQUEsR0FBRyxFQUFFLGFBTkQ7QUFPSkMsWUFBQUEsS0FBSyxFQUFFLFFBUEg7QUFRSmxDLFlBQUFBLE1BQU0sRUFBRTtBQUNOMEIsY0FBQUEsS0FBSyxFQUFFLFFBREQ7QUFFTjNCLGNBQUFBLElBQUksRUFBRTtBQUZBO0FBUkosV0FEUjtBQWNFMkIsVUFBQUEsS0FBSyxFQUFFO0FBQ0xTLFlBQUFBLEtBQUssRUFBRTtBQUNMLDZCQUFlO0FBQ2JULGdCQUFBQSxLQUFLLEVBQUUsUUFETTtBQUViM0IsZ0JBQUFBLElBQUksRUFBRTtBQUZPO0FBRFY7QUFERixXQWRUO0FBc0JFcUMsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLEtBQUssRUFBRTtBQUREO0FBdEJWLFNBM0JNLENBRnVCO0FBd0QvQlgsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQXhEd0IsT0FBZjtBQURHO0FBMUJoQixHQUZYO0FBeUZFQyxFQUFBQSxLQUFLLEVBQUU7QUF6RlQsQ0FqV2EsRUE0YmI7QUFDRW5DLEVBQUFBLEdBQUcsRUFBRSxxREFEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLDhCQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSw4QkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxXQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05ELFFBQUFBLElBQUksRUFBRSxXQURBO0FBRU42QyxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsYUFBYSxFQUFFLEtBQWpCO0FBQXdCQyxVQUFBQSxLQUFLLEVBQUU7QUFBRUMsWUFBQUEsS0FBSyxFQUFFO0FBQVQ7QUFBL0IsU0FGQTtBQUdOQyxRQUFBQSxZQUFZLEVBQUUsQ0FDWjtBQUNFckMsVUFBQUEsRUFBRSxFQUFFLGdCQUROO0FBRUVaLFVBQUFBLElBQUksRUFBRSxVQUZSO0FBR0VrRCxVQUFBQSxRQUFRLEVBQUUsUUFIWjtBQUlFQyxVQUFBQSxJQUFJLEVBQUUsSUFKUjtBQUtFSixVQUFBQSxLQUFLLEVBQUUsRUFMVDtBQU1FSyxVQUFBQSxLQUFLLEVBQUU7QUFBRXBELFlBQUFBLElBQUksRUFBRTtBQUFSLFdBTlQ7QUFPRXFELFVBQUFBLE1BQU0sRUFBRTtBQUFFRixZQUFBQSxJQUFJLEVBQUUsSUFBUjtBQUFjekIsWUFBQUEsTUFBTSxFQUFFLElBQXRCO0FBQTRCNEIsWUFBQUEsUUFBUSxFQUFFLEVBQXRDO0FBQTBDQyxZQUFBQSxNQUFNLEVBQUU7QUFBbEQsV0FQVjtBQVFFM0QsVUFBQUEsS0FBSyxFQUFFO0FBUlQsU0FEWSxDQUhSO0FBZU40RCxRQUFBQSxTQUFTLEVBQUUsQ0FDVDtBQUNFNUMsVUFBQUEsRUFBRSxFQUFFLGFBRE47QUFFRTZDLFVBQUFBLElBQUksRUFBRSxZQUZSO0FBR0V6RCxVQUFBQSxJQUFJLEVBQUUsT0FIUjtBQUlFa0QsVUFBQUEsUUFBUSxFQUFFLE1BSlo7QUFLRUMsVUFBQUEsSUFBSSxFQUFFLElBTFI7QUFNRUosVUFBQUEsS0FBSyxFQUFFLEVBTlQ7QUFPRUssVUFBQUEsS0FBSyxFQUFFO0FBQUVwRCxZQUFBQSxJQUFJLEVBQUUsUUFBUjtBQUFrQjBELFlBQUFBLElBQUksRUFBRTtBQUF4QixXQVBUO0FBUUVMLFVBQUFBLE1BQU0sRUFBRTtBQUFFRixZQUFBQSxJQUFJLEVBQUUsSUFBUjtBQUFjSSxZQUFBQSxNQUFNLEVBQUUsQ0FBdEI7QUFBeUI3QixZQUFBQSxNQUFNLEVBQUUsS0FBakM7QUFBd0M0QixZQUFBQSxRQUFRLEVBQUU7QUFBbEQsV0FSVjtBQVNFMUQsVUFBQUEsS0FBSyxFQUFFO0FBQUUrRCxZQUFBQSxJQUFJLEVBQUU7QUFBUjtBQVRULFNBRFMsQ0FmTDtBQTRCTkMsUUFBQUEsWUFBWSxFQUFFLENBQ1o7QUFDRVQsVUFBQUEsSUFBSSxFQUFFLE1BRFI7QUFFRW5ELFVBQUFBLElBQUksRUFBRSxXQUZSO0FBR0UwRCxVQUFBQSxJQUFJLEVBQUUsU0FIUjtBQUlFRyxVQUFBQSxJQUFJLEVBQUU7QUFBRUMsWUFBQUEsS0FBSyxFQUFFLE9BQVQ7QUFBa0JsRCxZQUFBQSxFQUFFLEVBQUU7QUFBdEIsV0FKUjtBQUtFbUQsVUFBQUEsU0FBUyxFQUFFLGFBTGI7QUFNRUMsVUFBQUEsc0JBQXNCLEVBQUUsSUFOMUI7QUFPRUMsVUFBQUEsV0FBVyxFQUFFO0FBUGYsU0FEWSxDQTVCUjtBQXVDTnhCLFFBQUFBLFVBQVUsRUFBRSxJQXZDTjtBQXdDTkMsUUFBQUEsU0FBUyxFQUFFLEtBeENMO0FBeUNORSxRQUFBQSxjQUFjLEVBQUUsT0F6Q1Y7QUEwQ05zQixRQUFBQSxLQUFLLEVBQUUsRUExQ0Q7QUEyQ05DLFFBQUFBLGFBQWEsRUFBRTtBQTNDVCxPQUhlO0FBZ0R2QnhELE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQUVDLFFBQUFBLEVBQUUsRUFBRSxHQUFOO0FBQVdDLFFBQUFBLE9BQU8sRUFBRSxJQUFwQjtBQUEwQmIsUUFBQUEsSUFBSSxFQUFFLE9BQWhDO0FBQXlDYyxRQUFBQSxNQUFNLEVBQUUsUUFBakQ7QUFBMkRiLFFBQUFBLE1BQU0sRUFBRTtBQUFuRSxPQURJLEVBRUo7QUFDRVcsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFNBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQUVjLFVBQUFBLEtBQUssRUFBRSxZQUFUO0FBQXVCQyxVQUFBQSxJQUFJLEVBQUUsQ0FBN0I7QUFBZ0NDLFVBQUFBLEtBQUssRUFBRSxNQUF2QztBQUErQ0MsVUFBQUEsT0FBTyxFQUFFO0FBQXhEO0FBTFYsT0FGSTtBQWhEaUIsS0FBZixDQUZIO0FBNkRQQyxJQUFBQSxXQUFXLEVBQUUsSUE3RE47QUE4RFBFLElBQUFBLFdBQVcsRUFBRSxFQTlETjtBQStEUEMsSUFBQUEsT0FBTyxFQUFFLENBL0RGO0FBZ0VQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUxQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQjBCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRUksVUFBQUEsSUFBSSxFQUFFO0FBQ0pMLFlBQUFBLEtBQUssRUFBRSxjQURIO0FBRUpNLFlBQUFBLE1BQU0sRUFBRSxLQUZKO0FBR0pDLFlBQUFBLFFBQVEsRUFBRSxLQUhOO0FBSUpDLFlBQUFBLEtBQUssRUFBRSxJQUpIO0FBS0pqQyxZQUFBQSxJQUFJLEVBQUUsUUFMRjtBQU1Ka0MsWUFBQUEsR0FBRyxFQUFFLDJCQU5EO0FBT0pDLFlBQUFBLEtBQUssRUFBRSxNQVBIO0FBUUpsQyxZQUFBQSxNQUFNLEVBQUU7QUFDTjBCLGNBQUFBLEtBQUssRUFBRSxNQUREO0FBRU4zQixjQUFBQSxJQUFJLEVBQUU7QUFGQTtBQVJKLFdBRFI7QUFjRTJCLFVBQUFBLEtBQUssRUFBRTtBQUNMUyxZQUFBQSxLQUFLLEVBQUU7QUFDTCwyQ0FBNkI7QUFDM0JULGdCQUFBQSxLQUFLLEVBQUUsTUFEb0I7QUFFM0IzQixnQkFBQUEsSUFBSSxFQUFFO0FBRnFCO0FBRHhCO0FBREYsV0FkVDtBQXNCRXFDLFVBQUFBLE1BQU0sRUFBRTtBQUNOQyxZQUFBQSxLQUFLLEVBQUU7QUFERDtBQXRCVixTQURNLENBRnVCO0FBOEIvQlgsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQTlCd0IsT0FBZjtBQURHO0FBaEVoQixHQUZYO0FBcUdFQyxFQUFBQSxLQUFLLEVBQUU7QUFyR1QsQ0E1YmEsRUFtaUJiO0FBQ0VuQyxFQUFBQSxHQUFHLEVBQUUsd0NBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxlQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSwrQkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxLQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05ELFFBQUFBLElBQUksRUFBRSxLQURBO0FBRU55QyxRQUFBQSxVQUFVLEVBQUUsSUFGTjtBQUdOQyxRQUFBQSxTQUFTLEVBQUUsSUFITDtBQUlORSxRQUFBQSxjQUFjLEVBQUUsT0FKVjtBQUtOTCxRQUFBQSxPQUFPLEVBQUU7QUFMSCxPQUhlO0FBVXZCNUIsTUFBQUEsSUFBSSxFQUFFLENBQ0o7QUFBRUMsUUFBQUEsRUFBRSxFQUFFLEdBQU47QUFBV0MsUUFBQUEsT0FBTyxFQUFFLElBQXBCO0FBQTBCYixRQUFBQSxJQUFJLEVBQUUsT0FBaEM7QUFBeUNjLFFBQUFBLE1BQU0sRUFBRSxRQUFqRDtBQUEyRGIsUUFBQUEsTUFBTSxFQUFFO0FBQW5FLE9BREksRUFFSjtBQUNFVyxRQUFBQSxFQUFFLEVBQUUsR0FETjtBQUVFQyxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFYixRQUFBQSxJQUFJLEVBQUUsT0FIUjtBQUlFYyxRQUFBQSxNQUFNLEVBQUUsU0FKVjtBQUtFYixRQUFBQSxNQUFNLEVBQUU7QUFBRWMsVUFBQUEsS0FBSyxFQUFFLHdCQUFUO0FBQW1DQyxVQUFBQSxJQUFJLEVBQUUsRUFBekM7QUFBNkNDLFVBQUFBLEtBQUssRUFBRSxNQUFwRDtBQUE0REMsVUFBQUEsT0FBTyxFQUFFO0FBQXJFO0FBTFYsT0FGSTtBQVZpQixLQUFmLENBRkg7QUF1QlBDLElBQUFBLFdBQVcsRUFBRSxJQXZCTjtBQXdCUEUsSUFBQUEsV0FBVyxFQUFFLEVBeEJOO0FBeUJQQyxJQUFBQSxPQUFPLEVBQUUsQ0F6QkY7QUEwQlBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRTFCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CMEIsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsQ0FDTjtBQUNFSSxVQUFBQSxJQUFJLEVBQUU7QUFDSkwsWUFBQUEsS0FBSyxFQUFFLGNBREg7QUFFSk0sWUFBQUEsTUFBTSxFQUFFLEtBRko7QUFHSkMsWUFBQUEsUUFBUSxFQUFFLEtBSE47QUFJSkMsWUFBQUEsS0FBSyxFQUFFLElBSkg7QUFLSmpDLFlBQUFBLElBQUksRUFBRSxRQUxGO0FBTUprQyxZQUFBQSxHQUFHLEVBQUUseUJBTkQ7QUFPSkMsWUFBQUEsS0FBSyxFQUFFLE1BUEg7QUFRSmxDLFlBQUFBLE1BQU0sRUFBRTtBQUNOMEIsY0FBQUEsS0FBSyxFQUFFLE1BREQ7QUFFTjNCLGNBQUFBLElBQUksRUFBRTtBQUZBO0FBUkosV0FEUjtBQWNFMkIsVUFBQUEsS0FBSyxFQUFFO0FBQ0xTLFlBQUFBLEtBQUssRUFBRTtBQUNMLHlDQUEyQjtBQUN6QlQsZ0JBQUFBLEtBQUssRUFBRSxNQURrQjtBQUV6QjNCLGdCQUFBQSxJQUFJLEVBQUU7QUFGbUI7QUFEdEI7QUFERixXQWRUO0FBc0JFcUMsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLEtBQUssRUFBRTtBQUREO0FBdEJWLFNBRE0sQ0FGdUI7QUE4Qi9CWCxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBOUJ3QixPQUFmO0FBREc7QUExQmhCLEdBRlg7QUErREVDLEVBQUFBLEtBQUssRUFBRTtBQS9EVCxDQW5pQmEsRUFvbUJiO0FBQ0VuQyxFQUFBQSxHQUFHLEVBQUUsa0RBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSx5QkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUseUNBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsS0FGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNORCxRQUFBQSxJQUFJLEVBQUUsS0FEQTtBQUVOeUMsUUFBQUEsVUFBVSxFQUFFLElBRk47QUFHTkMsUUFBQUEsU0FBUyxFQUFFLElBSEw7QUFJTkUsUUFBQUEsY0FBYyxFQUFFLE9BSlY7QUFLTkwsUUFBQUEsT0FBTyxFQUFFO0FBTEgsT0FIZTtBQVV2QjVCLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQUVDLFFBQUFBLEVBQUUsRUFBRSxHQUFOO0FBQVdDLFFBQUFBLE9BQU8sRUFBRSxJQUFwQjtBQUEwQmIsUUFBQUEsSUFBSSxFQUFFLE9BQWhDO0FBQXlDYyxRQUFBQSxNQUFNLEVBQUUsUUFBakQ7QUFBMkRiLFFBQUFBLE1BQU0sRUFBRTtBQUFuRSxPQURJLEVBRUo7QUFDRVcsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFNBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQUVjLFVBQUFBLEtBQUssRUFBRSx3QkFBVDtBQUFtQ0MsVUFBQUEsSUFBSSxFQUFFLEVBQXpDO0FBQTZDQyxVQUFBQSxLQUFLLEVBQUUsTUFBcEQ7QUFBNERDLFVBQUFBLE9BQU8sRUFBRTtBQUFyRTtBQUxWLE9BRkk7QUFWaUIsS0FBZixDQUZIO0FBdUJQQyxJQUFBQSxXQUFXLEVBQUUsSUF2Qk47QUF3QlBFLElBQUFBLFdBQVcsRUFBRSxFQXhCTjtBQXlCUEMsSUFBQUEsT0FBTyxFQUFFLENBekJGO0FBMEJQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUUxQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQjBCLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLENBQ047QUFDRUksVUFBQUEsSUFBSSxFQUFFO0FBQ0pMLFlBQUFBLEtBQUssRUFBRSxjQURIO0FBRUpNLFlBQUFBLE1BQU0sRUFBRSxLQUZKO0FBR0pDLFlBQUFBLFFBQVEsRUFBRSxLQUhOO0FBSUpDLFlBQUFBLEtBQUssRUFBRSxJQUpIO0FBS0pqQyxZQUFBQSxJQUFJLEVBQUUsUUFMRjtBQU1Ka0MsWUFBQUEsR0FBRyxFQUFFLHlCQU5EO0FBT0pDLFlBQUFBLEtBQUssRUFBRSxNQVBIO0FBUUpsQyxZQUFBQSxNQUFNLEVBQUU7QUFDTjBCLGNBQUFBLEtBQUssRUFBRSxNQUREO0FBRU4zQixjQUFBQSxJQUFJLEVBQUU7QUFGQTtBQVJKLFdBRFI7QUFjRTJCLFVBQUFBLEtBQUssRUFBRTtBQUNMUyxZQUFBQSxLQUFLLEVBQUU7QUFDTCx5Q0FBMkI7QUFDekJULGdCQUFBQSxLQUFLLEVBQUUsTUFEa0I7QUFFekIzQixnQkFBQUEsSUFBSSxFQUFFO0FBRm1CO0FBRHRCO0FBREYsV0FkVDtBQXNCRXFDLFVBQUFBLE1BQU0sRUFBRTtBQUNOQyxZQUFBQSxLQUFLLEVBQUU7QUFERDtBQXRCVixTQURNLEVBMkJOO0FBQ0VSLFVBQUFBLElBQUksRUFBRTtBQUNKTCxZQUFBQSxLQUFLLEVBQUUsY0FESDtBQUVKTSxZQUFBQSxNQUFNLEVBQUUsS0FGSjtBQUdKQyxZQUFBQSxRQUFRLEVBQUUsS0FITjtBQUlKQyxZQUFBQSxLQUFLLEVBQUUsSUFKSDtBQUtKakMsWUFBQUEsSUFBSSxFQUFFLFFBTEY7QUFNSmtDLFlBQUFBLEdBQUcsRUFBRSwyQkFORDtBQU9KQyxZQUFBQSxLQUFLLEVBQUUsTUFQSDtBQVFKbEMsWUFBQUEsTUFBTSxFQUFFO0FBQ04wQixjQUFBQSxLQUFLLEVBQUUsTUFERDtBQUVOM0IsY0FBQUEsSUFBSSxFQUFFO0FBRkE7QUFSSixXQURSO0FBY0UyQixVQUFBQSxLQUFLLEVBQUU7QUFDTFMsWUFBQUEsS0FBSyxFQUFFO0FBQ0wsMkNBQTZCO0FBQzNCVCxnQkFBQUEsS0FBSyxFQUFFLE1BRG9CO0FBRTNCM0IsZ0JBQUFBLElBQUksRUFBRTtBQUZxQjtBQUR4QjtBQURGLFdBZFQ7QUFzQkVxQyxVQUFBQSxNQUFNLEVBQUU7QUFDTkMsWUFBQUEsS0FBSyxFQUFFO0FBREQ7QUF0QlYsU0EzQk0sQ0FGdUI7QUF3RC9CWCxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBeER3QixPQUFmO0FBREc7QUExQmhCLEdBRlg7QUF5RkVDLEVBQUFBLEtBQUssRUFBRTtBQXpGVCxDQXBtQmEsRUErckJiO0FBQ0VuQyxFQUFBQSxHQUFHLEVBQUUsd0NBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxlQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxlQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLE9BRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkMsUUFBQUEsT0FBTyxFQUFFLEVBREg7QUFFTkMsUUFBQUEsZUFBZSxFQUFFLEtBRlg7QUFHTkMsUUFBQUEscUJBQXFCLEVBQUUsS0FIakI7QUFJTkMsUUFBQUEsSUFBSSxFQUFFO0FBQUVDLFVBQUFBLFdBQVcsRUFBRSxJQUFmO0FBQXFCQyxVQUFBQSxTQUFTLEVBQUU7QUFBaEMsU0FKQTtBQUtOQyxRQUFBQSxTQUFTLEVBQUUsS0FMTDtBQU1OQyxRQUFBQSxXQUFXLEVBQUUsSUFOUDtBQU9OQyxRQUFBQSxTQUFTLEVBQUU7QUFQTCxPQUhlO0FBWXZCQyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUNFQyxRQUFBQSxFQUFFLEVBQUUsR0FETjtBQUVFQyxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFYixRQUFBQSxJQUFJLEVBQUUsS0FIUjtBQUlFYyxRQUFBQSxNQUFNLEVBQUUsUUFKVjtBQUtFYixRQUFBQSxNQUFNLEVBQUU7QUFBRWMsVUFBQUEsS0FBSyxFQUFFO0FBQVQ7QUFMVixPQURJLEVBUUo7QUFDRUgsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFFBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQUVjLFVBQUFBLEtBQUssRUFBRSx1QkFBVDtBQUFrQ0MsVUFBQUEsSUFBSSxFQUFFLENBQXhDO0FBQTJDQyxVQUFBQSxLQUFLLEVBQUUsTUFBbEQ7QUFBMERDLFVBQUFBLE9BQU8sRUFBRTtBQUFuRTtBQUxWLE9BUkk7QUFaaUIsS0FBZixDQUZIO0FBK0JQQyxJQUFBQSxXQUFXLEVBQUVyQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMxQnFCLE1BQUFBLEdBQUcsRUFBRTtBQUFFbkIsUUFBQUEsTUFBTSxFQUFFO0FBQUVJLFVBQUFBLElBQUksRUFBRTtBQUFFQyxZQUFBQSxXQUFXLEVBQUUsQ0FBZjtBQUFrQkMsWUFBQUEsU0FBUyxFQUFFO0FBQTdCO0FBQVI7QUFBVjtBQURxQixLQUFmLENBL0JOO0FBa0NQYyxJQUFBQSxXQUFXLEVBQUUsRUFsQ047QUFtQ1BDLElBQUFBLE9BQU8sRUFBRSxDQW5DRjtBQW9DUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUFFMUIsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDL0IwQixRQUFBQSxLQUFLLEVBQUUsY0FEd0I7QUFFL0JDLFFBQUFBLE1BQU0sRUFBRSxFQUZ1QjtBQUcvQkMsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQUh3QixPQUFmO0FBREc7QUFwQ2hCLEdBRlg7QUE4Q0VDLEVBQUFBLEtBQUssRUFBRTtBQTlDVCxDQS9yQmEsRUErdUJiO0FBQ0VuQyxFQUFBQSxHQUFHLEVBQUUsdUNBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxjQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxjQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLE9BRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkMsUUFBQUEsT0FBTyxFQUFFLEVBREg7QUFFTkMsUUFBQUEsZUFBZSxFQUFFLEtBRlg7QUFHTkMsUUFBQUEscUJBQXFCLEVBQUUsS0FIakI7QUFJTkMsUUFBQUEsSUFBSSxFQUFFO0FBQUVDLFVBQUFBLFdBQVcsRUFBRSxJQUFmO0FBQXFCQyxVQUFBQSxTQUFTLEVBQUU7QUFBaEMsU0FKQTtBQUtOQyxRQUFBQSxTQUFTLEVBQUUsS0FMTDtBQU1OQyxRQUFBQSxXQUFXLEVBQUUsSUFOUDtBQU9OQyxRQUFBQSxTQUFTLEVBQUU7QUFQTCxPQUhlO0FBWXZCQyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUNFQyxRQUFBQSxFQUFFLEVBQUUsR0FETjtBQUVFQyxRQUFBQSxPQUFPLEVBQUUsSUFGWDtBQUdFYixRQUFBQSxJQUFJLEVBQUUsS0FIUjtBQUlFYyxRQUFBQSxNQUFNLEVBQUUsUUFKVjtBQUtFYixRQUFBQSxNQUFNLEVBQUU7QUFBRWMsVUFBQUEsS0FBSyxFQUFFO0FBQVQ7QUFMVixPQURJLEVBUUo7QUFDRUgsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFFBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQUVjLFVBQUFBLEtBQUssRUFBRSx1QkFBVDtBQUFrQ0MsVUFBQUEsSUFBSSxFQUFFLENBQXhDO0FBQTJDQyxVQUFBQSxLQUFLLEVBQUUsS0FBbEQ7QUFBeURDLFVBQUFBLE9BQU8sRUFBRTtBQUFsRTtBQUxWLE9BUkk7QUFaaUIsS0FBZixDQUZIO0FBK0JQQyxJQUFBQSxXQUFXLEVBQUVyQixJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMxQnFCLE1BQUFBLEdBQUcsRUFBRTtBQUFFbkIsUUFBQUEsTUFBTSxFQUFFO0FBQUVJLFVBQUFBLElBQUksRUFBRTtBQUFFQyxZQUFBQSxXQUFXLEVBQUUsSUFBZjtBQUFxQkMsWUFBQUEsU0FBUyxFQUFFO0FBQWhDO0FBQVI7QUFBVjtBQURxQixLQUFmLENBL0JOO0FBa0NQYyxJQUFBQSxXQUFXLEVBQUUsRUFsQ047QUFtQ1BDLElBQUFBLE9BQU8sRUFBRSxDQW5DRjtBQW9DUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUFFMUIsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDL0IwQixRQUFBQSxLQUFLLEVBQUUsY0FEd0I7QUFFL0JDLFFBQUFBLE1BQU0sRUFBRSxFQUZ1QjtBQUcvQkMsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQUh3QixPQUFmO0FBREc7QUFwQ2hCLEdBRlg7QUE4Q0VDLEVBQUFBLEtBQUssRUFBRTtBQTlDVCxDQS91QmEsRUEreEJiO0FBQ0VuQyxFQUFBQSxHQUFHLEVBQUUsdUNBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxjQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxjQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLE9BRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkMsUUFBQUEsT0FBTyxFQUFFLEVBREg7QUFFTkMsUUFBQUEsZUFBZSxFQUFFLEtBRlg7QUFHTkMsUUFBQUEscUJBQXFCLEVBQUUsS0FIakI7QUFJTkMsUUFBQUEsSUFBSSxFQUFFO0FBQUVDLFVBQUFBLFdBQVcsRUFBRSxJQUFmO0FBQXFCQyxVQUFBQSxTQUFTLEVBQUU7QUFBaEMsU0FKQTtBQUtOQyxRQUFBQSxTQUFTLEVBQUUsS0FMTDtBQU1OQyxRQUFBQSxXQUFXLEVBQUUsSUFOUDtBQU9OQyxRQUFBQSxTQUFTLEVBQUU7QUFQTCxPQUhlO0FBWXZCQyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFQyxRQUFBQSxFQUFFLEVBQUUsR0FBTjtBQUFXQyxRQUFBQSxPQUFPLEVBQUUsSUFBcEI7QUFBMEJiLFFBQUFBLElBQUksRUFBRSxLQUFoQztBQUF1Q2MsUUFBQUEsTUFBTSxFQUFFLFFBQS9DO0FBQXlEYixRQUFBQSxNQUFNLEVBQUU7QUFBRWMsVUFBQUEsS0FBSyxFQUFFO0FBQVQ7QUFBakUsT0FESSxFQUVKO0FBQ0VILFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxRQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUFFYyxVQUFBQSxLQUFLLEVBQUUsd0JBQVQ7QUFBbUNDLFVBQUFBLElBQUksRUFBRSxDQUF6QztBQUE0Q0MsVUFBQUEsS0FBSyxFQUFFLE1BQW5EO0FBQTJEQyxVQUFBQSxPQUFPLEVBQUU7QUFBcEU7QUFMVixPQUZJO0FBWmlCLEtBQWYsQ0FGSDtBQXlCUEMsSUFBQUEsV0FBVyxFQUFFckIsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDMUJxQixNQUFBQSxHQUFHLEVBQUU7QUFBRW5CLFFBQUFBLE1BQU0sRUFBRTtBQUFFSSxVQUFBQSxJQUFJLEVBQUU7QUFBRUMsWUFBQUEsV0FBVyxFQUFFLElBQWY7QUFBcUJDLFlBQUFBLFNBQVMsRUFBRTtBQUFoQztBQUFSO0FBQVY7QUFEcUIsS0FBZixDQXpCTjtBQTRCUGMsSUFBQUEsV0FBVyxFQUFFLEVBNUJOO0FBNkJQQyxJQUFBQSxPQUFPLEVBQUUsQ0E3QkY7QUE4QlBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRTFCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CMEIsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsQ0FDTjtBQUNFSSxVQUFBQSxJQUFJLEVBQUU7QUFDSkwsWUFBQUEsS0FBSyxFQUFFLGNBREg7QUFFSk0sWUFBQUEsTUFBTSxFQUFFLEtBRko7QUFHSkMsWUFBQUEsUUFBUSxFQUFFLEtBSE47QUFJSkMsWUFBQUEsS0FBSyxFQUFFLElBSkg7QUFLSmpDLFlBQUFBLElBQUksRUFBRSxRQUxGO0FBTUprQyxZQUFBQSxHQUFHLEVBQUUseUJBTkQ7QUFPSkMsWUFBQUEsS0FBSyxFQUFFLE1BUEg7QUFRSmxDLFlBQUFBLE1BQU0sRUFBRTtBQUNOMEIsY0FBQUEsS0FBSyxFQUFFLE1BREQ7QUFFTjNCLGNBQUFBLElBQUksRUFBRTtBQUZBO0FBUkosV0FEUjtBQWNFMkIsVUFBQUEsS0FBSyxFQUFFO0FBQ0xTLFlBQUFBLEtBQUssRUFBRTtBQUNMLHlDQUEyQjtBQUN6QlQsZ0JBQUFBLEtBQUssRUFBRSxNQURrQjtBQUV6QjNCLGdCQUFBQSxJQUFJLEVBQUU7QUFGbUI7QUFEdEI7QUFERixXQWRUO0FBc0JFcUMsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLEtBQUssRUFBRTtBQUREO0FBdEJWLFNBRE0sQ0FGdUI7QUE4Qi9CWCxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBOUJ3QixPQUFmO0FBREc7QUE5QmhCLEdBRlg7QUFtRUVDLEVBQUFBLEtBQUssRUFBRTtBQW5FVCxDQS94QmEsRUFvMkJiO0FBQ0VuQyxFQUFBQSxHQUFHLEVBQUUsc0NBRFA7QUFFRW1DLEVBQUFBLEtBQUssRUFBRSxlQUZUO0FBR0VsQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLGFBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLGFBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsT0FGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNOQyxRQUFBQSxPQUFPLEVBQUUsRUFESDtBQUVOQyxRQUFBQSxlQUFlLEVBQUUsS0FGWDtBQUdOQyxRQUFBQSxxQkFBcUIsRUFBRSxLQUhqQjtBQUlOQyxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsV0FBVyxFQUFFLENBQWY7QUFBa0JDLFVBQUFBLFNBQVMsRUFBRTtBQUE3QixTQUpBO0FBS05DLFFBQUFBLFNBQVMsRUFBRSxLQUxMO0FBTU5DLFFBQUFBLFdBQVcsRUFBRSxJQU5QO0FBT05DLFFBQUFBLFNBQVMsRUFBRTtBQVBMLE9BSGU7QUFZdkJDLE1BQUFBLElBQUksRUFBRSxDQUNKO0FBQUVDLFFBQUFBLEVBQUUsRUFBRSxHQUFOO0FBQVdDLFFBQUFBLE9BQU8sRUFBRSxJQUFwQjtBQUEwQmIsUUFBQUEsSUFBSSxFQUFFLE9BQWhDO0FBQXlDYyxRQUFBQSxNQUFNLEVBQUUsUUFBakQ7QUFBMkRiLFFBQUFBLE1BQU0sRUFBRTtBQUFuRSxPQURJLEVBRUo7QUFDRVcsUUFBQUEsRUFBRSxFQUFFLEdBRE47QUFFRUMsUUFBQUEsT0FBTyxFQUFFLElBRlg7QUFHRWIsUUFBQUEsSUFBSSxFQUFFLE9BSFI7QUFJRWMsUUFBQUEsTUFBTSxFQUFFLFFBSlY7QUFLRWIsUUFBQUEsTUFBTSxFQUFFO0FBQ05jLFVBQUFBLEtBQUssRUFBRSxZQUREO0FBRU5xRCxVQUFBQSxXQUFXLEVBQUUsS0FGUDtBQUdOQyxVQUFBQSxnQkFBZ0IsRUFBRSxPQUhaO0FBSU5DLFVBQUFBLGFBQWEsRUFBRSxLQUpUO0FBS05DLFVBQUFBLGtCQUFrQixFQUFFLFNBTGQ7QUFNTnZELFVBQUFBLElBQUksRUFBRSxFQU5BO0FBT05DLFVBQUFBLEtBQUssRUFBRSxNQVBEO0FBUU5DLFVBQUFBLE9BQU8sRUFBRSxHQVJIO0FBU05zRCxVQUFBQSxXQUFXLEVBQUU7QUFUUDtBQUxWLE9BRkksRUFtQko7QUFDRTVELFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxRQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUNOYyxVQUFBQSxLQUFLLEVBQUUsd0JBREQ7QUFFTnFELFVBQUFBLFdBQVcsRUFBRSxLQUZQO0FBR05DLFVBQUFBLGdCQUFnQixFQUFFLE9BSFo7QUFJTkMsVUFBQUEsYUFBYSxFQUFFLEtBSlQ7QUFLTkMsVUFBQUEsa0JBQWtCLEVBQUUsU0FMZDtBQU1OdkQsVUFBQUEsSUFBSSxFQUFFLENBTkE7QUFPTkMsVUFBQUEsS0FBSyxFQUFFLE1BUEQ7QUFRTkMsVUFBQUEsT0FBTyxFQUFFLEdBUkg7QUFTTnNELFVBQUFBLFdBQVcsRUFBRTtBQVRQO0FBTFYsT0FuQkksRUFvQ0o7QUFDRTVELFFBQUFBLEVBQUUsRUFBRSxHQUROO0FBRUVDLFFBQUFBLE9BQU8sRUFBRSxJQUZYO0FBR0ViLFFBQUFBLElBQUksRUFBRSxPQUhSO0FBSUVjLFFBQUFBLE1BQU0sRUFBRSxRQUpWO0FBS0ViLFFBQUFBLE1BQU0sRUFBRTtBQUNOYyxVQUFBQSxLQUFLLEVBQUUsK0JBREQ7QUFFTnFELFVBQUFBLFdBQVcsRUFBRSxLQUZQO0FBR05DLFVBQUFBLGdCQUFnQixFQUFFLE9BSFo7QUFJTkMsVUFBQUEsYUFBYSxFQUFFLEtBSlQ7QUFLTkMsVUFBQUEsa0JBQWtCLEVBQUUsU0FMZDtBQU1OdkQsVUFBQUEsSUFBSSxFQUFFLENBTkE7QUFPTkMsVUFBQUEsS0FBSyxFQUFFLE1BUEQ7QUFRTkMsVUFBQUEsT0FBTyxFQUFFLEdBUkg7QUFTTnNELFVBQUFBLFdBQVcsRUFBRTtBQVRQO0FBTFYsT0FwQ0k7QUFaaUIsS0FBZixDQUZIO0FBcUVQckQsSUFBQUEsV0FBVyxFQUFFckIsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDMUJxQixNQUFBQSxHQUFHLEVBQUU7QUFBRW5CLFFBQUFBLE1BQU0sRUFBRTtBQUFFSSxVQUFBQSxJQUFJLEVBQUU7QUFBRUMsWUFBQUEsV0FBVyxFQUFFLENBQWY7QUFBa0JDLFlBQUFBLFNBQVMsRUFBRTtBQUE3QjtBQUFSO0FBQVY7QUFEcUIsS0FBZixDQXJFTjtBQXdFUGMsSUFBQUEsV0FBVyxFQUFFLEVBeEVOO0FBeUVQQyxJQUFBQSxPQUFPLEVBQUUsQ0F6RUY7QUEwRVBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRTFCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CMEIsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsRUFGdUI7QUFHL0JDLFFBQUFBLEtBQUssRUFBRTtBQUFFQSxVQUFBQSxLQUFLLEVBQUUsRUFBVDtBQUFhQyxVQUFBQSxRQUFRLEVBQUU7QUFBdkI7QUFId0IsT0FBZjtBQURHO0FBMUVoQjtBQUhYLENBcDJCYSxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgT3ZlcnZpZXcvT1NDQVAgdmlzdWFsaXphdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgZGVmYXVsdCBbXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT1NDQVAtTGFzdC1zY29yZScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdMYXN0IHNjb3JlJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTGFzdCBzY29yZScsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldGljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdtYXgnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHsgZmllbGQ6ICd0aW1lc3RhbXAnIH0gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5zY2FuLnNjb3JlJywgc2l6ZTogMSwgb3JkZXI6ICdkZXNjJywgb3JkZXJCeTogJzEnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT1NDQVAtTGFzdC1hZ2VudC1zY2FubmVkJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0xhc3QgYWdlbnQgc2Nhbm5lZCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0xhc3QgYWdlbnQgc2Nhbm5lZCcsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldGljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdtYXgnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHsgZmllbGQ6ICd0aW1lc3RhbXAnIH0gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnYWdlbnQubmFtZScsIHNpemU6IDEsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogbnVsbCwgZGlyZWN0aW9uOiBudWxsIH0gfSB9LFxuICAgICAgfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIG1ldGE6IHtcbiAgICAgICAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgICAgICAgbmVnYXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAnZGF0YS5vc2NhcC5jaGVjay5yZXN1bHQnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBxdWVyeTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICAgICAgICBtYXRjaDoge1xuICAgICAgICAgICAgICAgICAgJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0Jzoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PU0NBUC1MYXN0LXNjYW4tcHJvZmlsZScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdMYXN0IHNjYW4gcHJvZmlsZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0xhc3Qgc2NhbiBwcm9maWxlJyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0aWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IG51bGwsIGRpcmVjdGlvbjogbnVsbCB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgc2hvd1Rvb2xiYXI6IHRydWUsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ21heCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczogeyBmaWVsZDogJ3RpbWVzdGFtcCcgfSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9zY2FwLnNjYW4ucHJvZmlsZS50aXRsZScsXG4gICAgICAgICAgICAgIHNpemU6IDEsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjpcbiAgICAgICAgICAne1wiaW5kZXhcIjpcIndhenVoLWFsZXJ0c1wiLFwiZmlsdGVyXCI6W10sXCJxdWVyeVwiOntcInF1ZXJ5XCI6XCJcIixcImxhbmd1YWdlXCI6XCJsdWNlbmVcIn19JyxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9TQ0FQLUFnZW50cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBZ2VudHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgcGFyYW1zOiB7IGlzRG9udXQ6IGZhbHNlLCBzaGFyZVlBeGlzOiB0cnVlLCBhZGRUb29sdGlwOiB0cnVlLCBhZGRMZWdlbmQ6IHRydWUgfSxcbiAgICAgICAgbGlzdGVuZXJzOiB7fSxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IHR5cGU6ICdjb3VudCcsIGVuYWJsZWQ6IHRydWUsIGlkOiAnMScsIHBhcmFtczoge30sIHNjaGVtYTogJ21ldHJpYycgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBwYXJhbXM6IHsgb3JkZXJCeTogJzEnLCBmaWVsZDogJ2FnZW50Lm5hbWUnLCBvcmRlcjogJ2Rlc2MnLCBzaXplOiA1IH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICB0aXRsZTogJ0FnZW50cycsXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogdHJ1ZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAncnVsZS5ncm91cHMnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdydWxlLmdyb3Vwcyc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdzeXNsb2cnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PU0NBUC1Qcm9maWxlcycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdQcm9maWxlcycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBpc0RvbnV0OiBmYWxzZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBzaGFyZVlBeGlzOiB0cnVlLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICBsaXN0ZW5lcnM6IHt9LFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgdHlwZTogJ2NvdW50JywgZW5hYmxlZDogdHJ1ZSwgaWQ6ICcxJywgcGFyYW1zOiB7fSwgc2NoZW1hOiAnbWV0cmljJyB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vc2NhcC5zY2FuLnByb2ZpbGUudGl0bGUnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHRpdGxlOiAnUHJvZmlsZXMnLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IHRydWUsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ3J1bGUuZ3JvdXBzJyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ3N5c2xvZycsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBxdWVyeTogJ3N5c2xvZycsXG4gICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICAgICAgICAncnVsZS5ncm91cHMnOiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT1NDQVAtQ29udGVudCcsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdDb250ZW50JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGlzRG9udXQ6IGZhbHNlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHNoYXJlWUF4aXM6IHRydWUsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgIH0sXG4gICAgICAgIGxpc3RlbmVyczoge30sXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyB0eXBlOiAnY291bnQnLCBlbmFibGVkOiB0cnVlLCBpZDogJzEnLCBwYXJhbXM6IHt9LCBzY2hlbWE6ICdtZXRyaWMnIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgcGFyYW1zOiB7IG9yZGVyQnk6ICcxJywgZmllbGQ6ICdkYXRhLm9zY2FwLnNjYW4uY29udGVudCcsIG9yZGVyOiAnZGVzYycsIHNpemU6IDUgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHRpdGxlOiAnQ29udGVudCcsXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogdHJ1ZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAncnVsZS5ncm91cHMnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnc3lzbG9nJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdydWxlLmdyb3Vwcyc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdzeXNsb2cnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PU0NBUC1TZXZlcml0eScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdTZXZlcml0eScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1NldmVyaXR5JyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczogeyBmaWVsZDogJ2RhdGEub3NjYXAuY2hlY2suc2V2ZXJpdHknLCBzaXplOiA1LCBvcmRlcjogJ2Rlc2MnLCBvcmRlckJ5OiAnMScgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCcsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICAgICAgICAnZGF0YS5vc2NhcC5jaGVjay5yZXN1bHQnOiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAkc3RhdGU6IHtcbiAgICAgICAgICAgICAgICBzdG9yZTogJ2FwcFN0YXRlJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIG1ldGE6IHtcbiAgICAgICAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgICAgICAgbmVnYXRlOiB0cnVlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdydWxlLmdyb3VwcycsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICdzeXNsb2cnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdzeXNsb2cnLFxuICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICAgICAgICBtYXRjaDoge1xuICAgICAgICAgICAgICAgICAgJ3J1bGUuZ3JvdXBzJzoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ3N5c2xvZycsXG4gICAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAkc3RhdGU6IHtcbiAgICAgICAgICAgICAgICBzdG9yZTogJ2FwcFN0YXRlJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU9TQ0FQLVRvcC01LWFnZW50cy1TZXZlcml0eS1oaWdoJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IGFnZW50cyAtIFNldmVyaXR5IGhpZ2gnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgNSBBZ2VudHMgLSBTZXZlcml0eSBoaWdoJyxcbiAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogZmFsc2UsIHN0eWxlOiB7IGNvbG9yOiAnI2VlZScgfSB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAyNSwgcm90YXRlOiAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgICAgIG1vZGU6ICdzdGFja2VkJyxcbiAgICAgICAgICAgICAgZGF0YTogeyBsYWJlbDogJ0NvdW50JywgaWQ6ICcxJyB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiBmYWxzZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczogeyBmaWVsZDogJ2FnZW50Lm5hbWUnLCBzaXplOiA1LCBvcmRlcjogJ2Rlc2MnLCBvcmRlckJ5OiAnMScgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdkYXRhLm9zY2FwLmNoZWNrLnNldmVyaXR5JyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2hpZ2gnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdoaWdoJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdkYXRhLm9zY2FwLmNoZWNrLnNldmVyaXR5Jzoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ2hpZ2gnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PU0NBUC1Ub3AtMTAtYWxlcnRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCAxMCBhbGVydHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgT1NDQVAgVG9wIDEwIGFsZXJ0cycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdkYXRhLm9zY2FwLmNoZWNrLnRpdGxlJywgc2l6ZTogMTAsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBtZXRhOiB7XG4gICAgICAgICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgICAgICAgIG5lZ2F0ZTogZmFsc2UsXG4gICAgICAgICAgICAgICAgZGlzYWJsZWQ6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGFsaWFzOiBudWxsLFxuICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIGtleTogJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0JyxcbiAgICAgICAgICAgICAgICB2YWx1ZTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHF1ZXJ5OiB7XG4gICAgICAgICAgICAgICAgbWF0Y2g6IHtcbiAgICAgICAgICAgICAgICAgICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT1NDQVAtVG9wLTEwLWhpZ2gtcmlzay1hbGVydHMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIDEwIGhpZ2ggcmlzayBhbGVydHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgT1NDQVAgVG9wIDEwIGhpZ2ggcmlzayBhbGVydHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5jaGVjay50aXRsZScsIHNpemU6IDEwLCBvcmRlcjogJ2Rlc2MnLCBvcmRlckJ5OiAnMScgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgbWV0YToge1xuICAgICAgICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICAgICAgICBuZWdhdGU6IGZhbHNlLFxuICAgICAgICAgICAgICAgIGRpc2FibGVkOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBhbGlhczogbnVsbCxcbiAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICBrZXk6ICdkYXRhLm9zY2FwLmNoZWNrLnJlc3VsdCcsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICdmYWlsJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICAgICAgICAnZGF0YS5vc2NhcC5jaGVjay5yZXN1bHQnOiB7XG4gICAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgICAgIHR5cGU6ICdwaHJhc2UnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAkc3RhdGU6IHtcbiAgICAgICAgICAgICAgICBzdG9yZTogJ2FwcFN0YXRlJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIG1ldGE6IHtcbiAgICAgICAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgICAgICAgbmVnYXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAnZGF0YS5vc2NhcC5jaGVjay5zZXZlcml0eScsXG4gICAgICAgICAgICAgICAgdmFsdWU6ICdoaWdoJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgIHF1ZXJ5OiAnaGlnaCcsXG4gICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBxdWVyeToge1xuICAgICAgICAgICAgICAgIG1hdGNoOiB7XG4gICAgICAgICAgICAgICAgICAnZGF0YS5vc2NhcC5jaGVjay5zZXZlcml0eSc6IHtcbiAgICAgICAgICAgICAgICAgICAgcXVlcnk6ICdoaWdoJyxcbiAgICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICRzdGF0ZToge1xuICAgICAgICAgICAgICAgIHN0b3JlOiAnYXBwU3RhdGUnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT1NDQVAtSGlnaGVzdC1zY29yZScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdIaWdoZXN0IHNjb3JlJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnSGlnaGVzdCBzY29yZScsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldGljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdtYXgnLFxuICAgICAgICAgICAgc2NoZW1hOiAnbWV0cmljJyxcbiAgICAgICAgICAgIHBhcmFtczogeyBmaWVsZDogJ2RhdGEub3NjYXAuc2Nhbi5zY29yZScgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdkYXRhLm9zY2FwLnNjYW4uc2NvcmUnLCBzaXplOiAxLCBvcmRlcjogJ2Rlc2MnLCBvcmRlckJ5OiAnMScgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB2aXM6IHsgcGFyYW1zOiB7IHNvcnQ6IHsgY29sdW1uSW5kZXg6IDAsIGRpcmVjdGlvbjogbnVsbCB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PU0NBUC1Mb3dlc3Qtc2NvcmUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTG93ZXN0IHNjb3JlJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTG93ZXN0IHNjb3JlJyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0aWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IG51bGwsIGRpcmVjdGlvbjogbnVsbCB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgc2hvd1Rvb2xiYXI6IHRydWUsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ21pbicsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5zY2FuLnNjb3JlJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczogeyBmaWVsZDogJ2RhdGEub3NjYXAuc2Nhbi5zY29yZScsIHNpemU6IDEsIG9yZGVyOiAnYXNjJywgb3JkZXJCeTogJzEnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctT1NDQVAtTGF0ZXN0LWFsZXJ0JyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0xhdGVzdCBhbGVydCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0xhdGVzdCBhbGVydCcsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldGljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdtYXgnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHsgZmllbGQ6ICd0aW1lc3RhbXAnIH0gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnZGF0YS5vc2NhcC5jaGVjay50aXRsZScsIHNpemU6IDEsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogbnVsbCwgZGlyZWN0aW9uOiBudWxsIH0gfSB9LFxuICAgICAgfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIG1ldGE6IHtcbiAgICAgICAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgICAgICAgbmVnYXRlOiBmYWxzZSxcbiAgICAgICAgICAgICAgICBkaXNhYmxlZDogZmFsc2UsXG4gICAgICAgICAgICAgICAgYWxpYXM6IG51bGwsXG4gICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAga2V5OiAnZGF0YS5vc2NhcC5jaGVjay5yZXN1bHQnLFxuICAgICAgICAgICAgICAgIHZhbHVlOiAnZmFpbCcsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICBxdWVyeTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgICAgdHlwZTogJ3BocmFzZScsXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcXVlcnk6IHtcbiAgICAgICAgICAgICAgICBtYXRjaDoge1xuICAgICAgICAgICAgICAgICAgJ2RhdGEub3NjYXAuY2hlY2sucmVzdWx0Jzoge1xuICAgICAgICAgICAgICAgICAgICBxdWVyeTogJ2ZhaWwnLFxuICAgICAgICAgICAgICAgICAgICB0eXBlOiAncGhyYXNlJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgJHN0YXRlOiB7XG4gICAgICAgICAgICAgICAgc3RvcmU6ICdhcHBTdGF0ZScsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1PU0NBUC1MYXN0LWFsZXJ0cycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0xhc3QgYWxlcnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTGFzdCBhbGVydHMnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnYWdlbnQubmFtZScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiA0MCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FnZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5vc2NhcC5jaGVjay50aXRsZScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnVGl0bGUnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNCcsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLm9zY2FwLnNjYW4ucHJvZmlsZS50aXRsZScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUHJvZmlsZScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXTtcbiJdfQ==