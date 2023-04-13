"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Agents/MITRE visualizations
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
  _id: 'Wazuh-App-Agents-MITRE',
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
  _id: 'Wazuh-App-Agents-MITRE-Alerts-Evolution',
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
  _id: 'Wazuh-App-Agents-MITRE-Attacks-By-Agent',
  _source: {
    title: 'Attacks count by agent',
    visState: JSON.stringify({
      title: 'Attacks count by agent',
      type: 'pie',
      params: {
        addLegend: true,
        addTooltip: true,
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
          }, {
            accessor: 2,
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
        isDonut: true,
        labels: {
          last_level: true,
          show: false,
          truncate: 100,
          values: true
        },
        legendPosition: 'right',
        type: 'pie'
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
          customLabel: 'Agent name',
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
          field: 'rule.mitre.id',
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
  _id: 'Wazuh-App-Agents-MITRE-Level-By-Tactic',
  _source: {
    title: 'Alerts level by tactic',
    visState: JSON.stringify({
      title: 'Alerts level by tactic',
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
          }, {
            accessor: 2,
            format: {
              id: 'terms',
              params: {
                id: 'number',
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
          missingBucketLabel: 'Missing',
          customLabel: 'Attack ID'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Rule level'
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
  _id: 'Wazuh-App-Agents-MITRE-Level-By-Attack',
  _source: {
    title: 'Alerts level by attack',
    visState: JSON.stringify({
      title: 'Alerts level by attack',
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
          }, {
            accessor: 2,
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
          }, {
            accessor: 4,
            format: {
              id: 'terms',
              params: {
                id: 'number',
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
          missingBucketLabel: 'Missing',
          customLabel: 'Attack ID'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Rule level'
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
  _id: 'Wazuh-App-Agents-MITRE-Attacks-By-Tactic',
  _source: {
    title: 'Top tactics',
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
  _id: 'Wazuh-App-Agents-MITRE-Top-Tactics',
  _source: {
    title: 'Top tactics pie',
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
  _id: 'Wazuh-App-Agents-MITRE-Alerts-summary',
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
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy1taXRyZS50cyJdLCJuYW1lcyI6WyJfaWQiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJhZ2dzIiwiZW5hYmxlZCIsImlkIiwicGFyYW1zIiwic2NoZW1hIiwidHlwZSIsImZpZWxkIiwiY3VzdG9tTGFiZWwiLCJtaXNzaW5nQnVja2V0IiwibWlzc2luZ0J1Y2tldExhYmVsIiwib3JkZXIiLCJvcmRlckJ5Iiwib3RoZXJCdWNrZXQiLCJvdGhlckJ1Y2tldExhYmVsIiwic2l6ZSIsImRpbWVuc2lvbnMiLCJidWNrZXRzIiwibWV0cmljcyIsImFjY2Vzc29yIiwiYWdnVHlwZSIsImZvcm1hdCIsInBlclBhZ2UiLCJwZXJjZW50YWdlQ29sIiwic2hvd01ldHJpY3NBdEFsbExldmVscyIsInNob3dQYXJ0aWFsUm93cyIsInNob3dUb3RhbCIsInNob3dUb29sYmFyIiwic29ydCIsImNvbHVtbkluZGV4IiwiZGlyZWN0aW9uIiwidG90YWxGdW5jIiwidWlTdGF0ZUpTT04iLCJkZXNjcmlwdGlvbiIsInZlcnNpb24iLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiaW5kZXgiLCJmaWx0ZXIiLCJxdWVyeSIsImxhbmd1YWdlIiwiX3R5cGUiLCJncmlkIiwiY2F0ZWdvcnlMaW5lcyIsImNhdGVnb3J5QXhlcyIsInBvc2l0aW9uIiwic2hvdyIsInN0eWxlIiwic2NhbGUiLCJsYWJlbHMiLCJ0cnVuY2F0ZSIsInZhbHVlQXhlcyIsIm5hbWUiLCJtb2RlIiwicm90YXRlIiwidGV4dCIsInNlcmllc1BhcmFtcyIsImRhdGEiLCJsYWJlbCIsInZhbHVlQXhpcyIsImRyYXdMaW5lc0JldHdlZW5Qb2ludHMiLCJzaG93Q2lyY2xlcyIsImxpbmVXaWR0aCIsImFkZFRvb2x0aXAiLCJhZGRMZWdlbmQiLCJsZWdlbmRQb3NpdGlvbiIsInRpbWVzIiwiYWRkVGltZU1hcmtlciIsInRocmVzaG9sZExpbmUiLCJ2YWx1ZSIsIndpZHRoIiwiY29sb3IiLCJ4IiwicGF0dGVybiIsImRhdGUiLCJpbnRlcnZhbCIsImJvdW5kcyIsIm1pbiIsIm1heCIsInkiLCJzZXJpZXMiLCJ0aW1lUmFuZ2UiLCJmcm9tIiwidG8iLCJ1c2VOb3JtYWxpemVkRXNJbnRlcnZhbCIsImRyb3BfcGFydGlhbHMiLCJtaW5fZG9jX2NvdW50IiwiZXh0ZW5kZWRfYm91bmRzIiwibWV0cmljIiwiaXNEb251dCIsImxhc3RfbGV2ZWwiLCJ2YWx1ZXMiLCJzaG93TWV0aWNzQXRBbGxMZXZlbHMiLCJ2aXMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO2VBQ2UsQ0FDYjtBQUNFQSxFQUFBQSxHQUFHLEVBQUUsd0JBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxvQkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCQyxNQUFBQSxJQUFJLEVBQUUsQ0FDSjtBQUFFQyxRQUFBQSxPQUFPLEVBQUUsSUFBWDtBQUFpQkMsUUFBQUEsRUFBRSxFQUFFLEdBQXJCO0FBQTBCQyxRQUFBQSxNQUFNLEVBQUUsRUFBbEM7QUFBc0NDLFFBQUFBLE1BQU0sRUFBRSxRQUE5QztBQUF3REMsUUFBQUEsSUFBSSxFQUFFO0FBQTlELE9BREksRUFFSjtBQUNFSixRQUFBQSxPQUFPLEVBQUUsSUFEWDtBQUVFQyxRQUFBQSxFQUFFLEVBQUUsR0FGTjtBQUdFQyxRQUFBQSxNQUFNLEVBQUU7QUFDTkcsVUFBQUEsS0FBSyxFQUFFLGVBREQ7QUFFTkMsVUFBQUEsV0FBVyxFQUFFLFdBRlA7QUFHTkMsVUFBQUEsYUFBYSxFQUFFLEtBSFQ7QUFJTkMsVUFBQUEsa0JBQWtCLEVBQUUsU0FKZDtBQUtOQyxVQUFBQSxLQUFLLEVBQUUsTUFMRDtBQU1OQyxVQUFBQSxPQUFPLEVBQUUsR0FOSDtBQU9O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MUI2RixNQUFBQSxHQUFHLEVBQUU7QUFBRXpGLFFBQUFBLE1BQU0sRUFBRTtBQUFFd0IsVUFBQUEsSUFBSSxFQUFFO0FBQUVDLFlBQUFBLFdBQVcsRUFBRSxDQUFmO0FBQWtCQyxZQUFBQSxTQUFTLEVBQUU7QUFBN0I7QUFBUjtBQUFWO0FBRHFCLEtBQWYsQ0FyRU47QUF3RVBHLElBQUFBLFdBQVcsRUFBRSxFQXhFTjtBQXlFUEMsSUFBQUEsT0FBTyxFQUFFLENBekVGO0FBMEVQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUVyQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQnFDLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQkMsUUFBQUEsTUFBTSxFQUFFLEVBRnVCO0FBRy9CQyxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCO0FBSHdCLE9BQWY7QUFERztBQTFFaEI7QUFIWCxDQXpxQmEsQyIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgZm9yIEFnZW50cy9NSVRSRSB2aXN1YWxpemF0aW9uc1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmV4cG9ydCBkZWZhdWx0IFtcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtTUlUUkUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTWl0cmUgYXR0YWNrIGNvdW50JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGVuYWJsZWQ6IHRydWUsIGlkOiAnMScsIHBhcmFtczoge30sIHNjaGVtYTogJ21ldHJpYycsIHR5cGU6ICdjb3VudCcgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubWl0cmUuaWQnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0F0dGFjayBJRCcsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIHNpemU6IDI0NCxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBidWNrZXRzOiBbXSxcbiAgICAgICAgICAgIG1ldHJpY3M6IFt7IGFjY2Vzc29yOiAwLCBhZ2dUeXBlOiAnY291bnQnLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30gfV0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBwZXJjZW50YWdlQ29sOiAnJyxcbiAgICAgICAgICBzaG93TWV0cmljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgc2hvd1Rvb2xiYXI6IHRydWUsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogbnVsbCwgZGlyZWN0aW9uOiBudWxsIH0sXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgfSxcbiAgICAgICAgdGl0bGU6ICdtaXRyZScsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtTUlUUkUtQWxlcnRzLUV2b2x1dGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdNaXRyZSBhbGVydHMgZXZvbHV0aW9uJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnQgRXZvbHV0aW9uJyxcbiAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiBmYWxzZSB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgICAgICAgIG1vZGU6ICdub3JtYWwnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGxpbmVXaWR0aDogMixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgbGFiZWxzOiB7fSxcbiAgICAgICAgICB0aHJlc2hvbGRMaW5lOiB7IHNob3c6IGZhbHNlLCB2YWx1ZTogMTAsIHdpZHRoOiAxLCBzdHlsZTogJ2Z1bGwnLCBjb2xvcjogJyMzNDEzMEMnIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDoge1xuICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgZm9ybWF0OiB7IGlkOiAnZGF0ZScsIHBhcmFtczogeyBwYXR0ZXJuOiAnWVlZWS1NTS1ERCBISDptbScgfSB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBkYXRlOiB0cnVlLFxuICAgICAgICAgICAgICAgIGludGVydmFsOiAnUFQzSCcsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiAnWVlZWS1NTS1ERCBISDptbScsXG4gICAgICAgICAgICAgICAgYm91bmRzOiB7IG1pbjogJzIwMTktMTEtMDdUMTU6NDU6NDUuNzcwWicsIG1heDogJzIwMTktMTEtMTRUMTU6NDU6NDUuNzcwWicgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB5OiBbeyBhY2Nlc3NvcjogMiwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH1dLFxuICAgICAgICAgICAgc2VyaWVzOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMSxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHsgZnJvbTogJ25vdy03ZCcsIHRvOiAnbm93JyB9LFxuICAgICAgICAgICAgICB1c2VOb3JtYWxpemVkRXNJbnRlcnZhbDogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgZHJvcF9wYXJ0aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5taXRyZS50ZWNobmlxdWUnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0F0dGFjayBJRCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtTUlUUkUtQXR0YWNrcy1CeS1BZ2VudCcsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBdHRhY2tzIGNvdW50IGJ5IGFnZW50JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQXR0YWNrcyBjb3VudCBieSBhZ2VudCcsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAyLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHsgbGFzdF9sZXZlbDogdHJ1ZSwgc2hvdzogZmFsc2UsIHRydW5jYXRlOiAxMDAsIHZhbHVlczogdHJ1ZSB9LFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdhZ2VudC5uYW1lJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdBZ2VudCBuYW1lJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubWl0cmUuaWQnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0F0dGFjayBJRCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtTUlUUkUtTGV2ZWwtQnktVGFjdGljJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBsZXZlbCBieSB0YWN0aWMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgbGV2ZWwgYnkgdGFjdGljJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAyLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdudW1iZXInLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubWl0cmUudGFjdGljJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdBdHRhY2sgSUQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNCcsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUnVsZSBsZXZlbCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtTUlUUkUtTGV2ZWwtQnktQXR0YWNrJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBsZXZlbCBieSBhdHRhY2snLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgbGV2ZWwgYnkgYXR0YWNrJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAyLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogNCxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnbnVtYmVyJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLm1pdHJlLnRlY2huaXF1ZScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnQXR0YWNrIElEJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzQnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1J1bGUgbGV2ZWwnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IGxhbmd1YWdlOiAnbHVjZW5lJywgcXVlcnk6ICcnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLU1JVFJFLUF0dGFja3MtQnktVGFjdGljJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCB0YWN0aWNzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQXR0YWNrcyBieSB0YWN0aWMnLFxuICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiBmYWxzZSB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIGFkZFRpbWVNYXJrZXI6IGZhbHNlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSB9LFxuICAgICAgICAgIHRocmVzaG9sZExpbmU6IHsgc2hvdzogZmFsc2UsIHZhbHVlOiAxMCwgd2lkdGg6IDEsIHN0eWxlOiAnZnVsbCcsIGNvbG9yOiAnIzM0MTMwQycgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiBudWxsLFxuICAgICAgICAgICAgeTogW3sgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9XSxcbiAgICAgICAgICAgIHNlcmllczogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubWl0cmUudGVjaG5pcXVlJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubWl0cmUudGFjdGljJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBsYW5ndWFnZTogJ2x1Y2VuZScsIHF1ZXJ5OiAnJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1NSVRSRS1Ub3AtVGFjdGljcycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgdGFjdGljcyBwaWUnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgdGFjdGljcyBQSUUyJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IGZhbHNlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSwgdmFsdWVzOiB0cnVlLCBsYXN0X2xldmVsOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljOiB7IGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfSxcbiAgICAgICAgICAgIGJ1Y2tldHM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubWl0cmUudGFjdGljJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtTUlUUkUtQWxlcnRzLXN1bW1hcnknLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0aWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IDMsIGRpcmVjdGlvbjogJ2Rlc2MnIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaWQnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogNTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIElEJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5kZXNjcmlwdGlvbicsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiAxLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnRGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNCcsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmxldmVsJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIHNpemU6IDEsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdMZXZlbCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXTtcbiJdfQ==