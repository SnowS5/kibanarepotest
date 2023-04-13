"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview/NIST visualizations
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
  _id: 'Wazuh-App-Overview-NIST-Requirements-over-time',
  _source: {
    title: 'Requirements over time',
    visState: JSON.stringify({
      title: 'NIST-Requirements-over-time',
      type: 'histogram',
      params: {
        type: 'histogram',
        grid: {
          categoryLines: true,
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
          type: 'line',
          mode: 'normal',
          data: {
            label: 'Count',
            id: '1'
          },
          valueAxis: 'ValueAxis-1',
          drawLinesBetweenPoints: true,
          showCircles: true,
          interpolate: 'linear'
        }],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false,
        labels: {
          show: false
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
              interval: 'PT1H',
              format: 'YYYY-MM-DD HH:mm',
              bounds: {
                min: '2019-08-20T12:33:23.360Z',
                max: '2019-08-22T12:33:23.360Z'
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
            from: 'now-2d',
            to: 'now'
          },
          useNormalizedEsInterval: true,
          interval: 'auto',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {}
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'rule.nist_800_53',
          orderBy: '1',
          order: 'desc',
          size: 50,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Requirement'
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
  _id: 'Wazuh-App-Overview-NIST-Requirements-Agents-heatmap',
  _type: 'visualization',
  _source: {
    title: 'Alerts volume by agent',
    visState: JSON.stringify({
      aggs: [{
        enabled: true,
        id: '1',
        params: {},
        schema: 'metric',
        type: 'count'
      }, {
        enabled: true,
        id: '3',
        params: {
          customLabel: 'Requirement',
          field: 'rule.nist_800_53',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          size: 10
        },
        schema: 'group',
        type: 'terms'
      }, {
        enabled: true,
        id: '2',
        params: {
          customLabel: 'Agent',
          field: 'agent.id',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          size: 5
        },
        schema: 'segment',
        type: 'terms'
      }],
      params: {
        addLegend: true,
        addTooltip: true,
        colorSchema: 'Blues',
        colorsNumber: 10,
        colorsRange: [],
        dimensions: {
          series: [{
            accessor: 0,
            aggType: 'terms',
            format: {
              id: 'terms',
              params: {
                id: 'string',
                missingBucketLabel: 'Missing',
                otherBucketLabel: 'Other'
              }
            },
            params: {}
          }],
          x: {
            accessor: 1,
            aggType: 'terms',
            format: {
              id: 'terms',
              params: {
                id: 'string',
                missingBucketLabel: 'Missing',
                otherBucketLabel: 'Other'
              }
            },
            params: {}
          },
          y: [{
            accessor: 2,
            aggType: 'count',
            format: {
              id: 'number'
            },
            params: {}
          }]
        },
        enableHover: false,
        invertColors: false,
        legendPosition: 'right',
        percentageMode: false,
        setColorRange: false,
        times: [],
        type: 'heatmap',
        valueAxes: [{
          id: 'ValueAxis-1',
          labels: {
            color: 'black',
            overwriteColor: false,
            rotate: 0,
            show: false
          },
          scale: {
            defaultYExtents: false,
            type: 'linear'
          },
          show: false,
          type: 'value'
        }]
      },
      title: 'NIST-Last-alerts',
      type: 'heatmap'
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        defaultColors: {
          '0 - 160': 'rgb(247,251,255)',
          '160 - 320': 'rgb(227,238,249)',
          '320 - 480': 'rgb(208,225,242)',
          '480 - 640': 'rgb(182,212,233)',
          '640 - 800': 'rgb(148,196,223)',
          '800 - 960': 'rgb(107,174,214)',
          '960 - 1,120': 'rgb(74,152,201)',
          '1,120 - 1,280': 'rgb(46,126,188)',
          '1,280 - 1,440': 'rgb(23,100,171)',
          '1,440 - 1,600': 'rgb(8,74,145)'
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
  _id: 'Wazuh-App-Overview-NIST-requirements-by-agents',
  _source: {
    title: 'Requirements distribution by agent',
    visState: JSON.stringify({
      title: 'NIST-Top-requirements-by-agent',
      type: 'area',
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
          drawLinesBetweenPoints: true,
          showCircles: true,
          interpolate: 'linear',
          valueAxis: 'ValueAxis-1'
        }],
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        times: [],
        addTimeMarker: false,
        dimensions: {
          x: {
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
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'agent.id',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Agent'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'rule.nist_800_53',
          orderBy: '1',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Requirement'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        legendOpen: false
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
  _id: 'Wazuh-App-Overview-NIST-Metrics',
  _source: {
    title: 'Stats',
    visState: JSON.stringify({
      title: 'nist-metrics',
      type: 'metric',
      params: {
        metric: {
          percentageMode: false,
          useRanges: false,
          colorSchema: 'Green to Red',
          metricColorMode: 'None',
          colorsRange: [{
            type: 'range',
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
            fontSize: 20
          }
        },
        dimensions: {
          metrics: [{
            type: 'vis_dimension',
            accessor: 0,
            format: {
              id: 'number',
              params: {}
            }
          }, {
            type: 'vis_dimension',
            accessor: 1,
            format: {
              id: 'number',
              params: {}
            }
          }]
        },
        addTooltip: true,
        addLegend: false,
        type: 'metric'
      },
      aggs: [{
        id: '1',
        enabled: true,
        type: 'count',
        schema: 'metric',
        params: {
          customLabel: 'Total alerts'
        }
      }, {
        id: '2',
        enabled: true,
        type: 'max',
        schema: 'metric',
        params: {
          field: 'rule.level',
          customLabel: 'Max rule level detected'
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
  _id: 'Wazuh-App-Overview-NIST-Top-10-requirements',
  _source: {
    title: 'Top 10 requirements',
    visState: JSON.stringify({
      title: 'NIST-Top-10-requirements',
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
          field: 'rule.nist_800_53',
          orderBy: '1',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Requirement'
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
  _id: 'Wazuh-App-Overview-NIST-Agents',
  _source: {
    title: 'Most active agents',
    visState: JSON.stringify({
      title: 'NIST-Top-10-agents',
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
          field: 'agent.name',
          orderBy: '1',
          order: 'desc',
          size: 10,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Agent'
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
  _id: 'Wazuh-App-Overview-NIST-Alerts-summary',
  _type: 'visualization',
  _source: {
    title: 'Alerts summary',
    visState: JSON.stringify({
      title: 'NIST-Alerts-summary',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
        sort: {
          columnIndex: 3,
          direction: 'desc'
        },
        showTotal: false,
        showToolbar: true,
        totalFunc: 'sum',
        dimensions: {
          metrics: [{
            accessor: 3,
            format: {
              id: 'number'
            },
            params: {},
            aggType: 'count'
          }],
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
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'agent.name',
          orderBy: '1',
          order: 'desc',
          size: 50,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Agent'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.nist_800_53',
          orderBy: '1',
          order: 'desc',
          size: 20,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Requirement'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LW5pc3QudHMiXSwibmFtZXMiOlsiX2lkIiwiX3NvdXJjZSIsInRpdGxlIiwidmlzU3RhdGUiLCJKU09OIiwic3RyaW5naWZ5IiwidHlwZSIsInBhcmFtcyIsImdyaWQiLCJjYXRlZ29yeUxpbmVzIiwidmFsdWVBeGlzIiwiY2F0ZWdvcnlBeGVzIiwiaWQiLCJwb3NpdGlvbiIsInNob3ciLCJzdHlsZSIsInNjYWxlIiwibGFiZWxzIiwiZmlsdGVyIiwidHJ1bmNhdGUiLCJ2YWx1ZUF4ZXMiLCJuYW1lIiwibW9kZSIsInJvdGF0ZSIsInRleHQiLCJzZXJpZXNQYXJhbXMiLCJkYXRhIiwibGFiZWwiLCJkcmF3TGluZXNCZXR3ZWVuUG9pbnRzIiwic2hvd0NpcmNsZXMiLCJpbnRlcnBvbGF0ZSIsImFkZFRvb2x0aXAiLCJhZGRMZWdlbmQiLCJsZWdlbmRQb3NpdGlvbiIsInRpbWVzIiwiYWRkVGltZU1hcmtlciIsImRpbWVuc2lvbnMiLCJ4IiwiYWNjZXNzb3IiLCJmb3JtYXQiLCJwYXR0ZXJuIiwiZGF0ZSIsImludGVydmFsIiwiYm91bmRzIiwibWluIiwibWF4IiwiYWdnVHlwZSIsInkiLCJzZXJpZXMiLCJvdGhlckJ1Y2tldExhYmVsIiwibWlzc2luZ0J1Y2tldExhYmVsIiwiYWdncyIsImVuYWJsZWQiLCJzY2hlbWEiLCJmaWVsZCIsInRpbWVSYW5nZSIsImZyb20iLCJ0byIsInVzZU5vcm1hbGl6ZWRFc0ludGVydmFsIiwiZHJvcF9wYXJ0aWFscyIsIm1pbl9kb2NfY291bnQiLCJleHRlbmRlZF9ib3VuZHMiLCJvcmRlckJ5Iiwib3JkZXIiLCJzaXplIiwib3RoZXJCdWNrZXQiLCJtaXNzaW5nQnVja2V0IiwiY3VzdG9tTGFiZWwiLCJ1aVN0YXRlSlNPTiIsImRlc2NyaXB0aW9uIiwidmVyc2lvbiIsImtpYmFuYVNhdmVkT2JqZWN0TWV0YSIsInNlYXJjaFNvdXJjZUpTT04iLCJpbmRleCIsInF1ZXJ5IiwibGFuZ3VhZ2UiLCJfdHlwZSIsImNvbG9yU2NoZW1hIiwiY29sb3JzTnVtYmVyIiwiY29sb3JzUmFuZ2UiLCJlbmFibGVIb3ZlciIsImludmVydENvbG9ycyIsInBlcmNlbnRhZ2VNb2RlIiwic2V0Q29sb3JSYW5nZSIsImNvbG9yIiwib3ZlcndyaXRlQ29sb3IiLCJkZWZhdWx0WUV4dGVudHMiLCJ2aXMiLCJkZWZhdWx0Q29sb3JzIiwibGVnZW5kT3BlbiIsIm1ldHJpYyIsInVzZVJhbmdlcyIsIm1ldHJpY0NvbG9yTW9kZSIsImJnRmlsbCIsImJnQ29sb3IiLCJsYWJlbENvbG9yIiwic3ViVGV4dCIsImZvbnRTaXplIiwibWV0cmljcyIsImlzRG9udXQiLCJ2YWx1ZXMiLCJsYXN0X2xldmVsIiwiYnVja2V0cyIsInBlclBhZ2UiLCJzaG93UGFydGlhbFJvd3MiLCJzaG93TWV0cmljc0F0QWxsTGV2ZWxzIiwic29ydCIsImNvbHVtbkluZGV4IiwiZGlyZWN0aW9uIiwic2hvd1RvdGFsIiwic2hvd1Rvb2xiYXIiLCJ0b3RhbEZ1bmMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO2VBQ2UsQ0FDYjtBQUNFQSxFQUFBQSxHQUFHLEVBQUUsZ0RBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSx3QkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUsNkJBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsV0FGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNORCxRQUFBQSxJQUFJLEVBQUUsV0FEQTtBQUVORSxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsYUFBYSxFQUFFLElBQWpCO0FBQXVCQyxVQUFBQSxTQUFTLEVBQUU7QUFBbEMsU0FGQTtBQUdOQyxRQUFBQSxZQUFZLEVBQUUsQ0FDWjtBQUNFQyxVQUFBQSxFQUFFLEVBQUUs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c0hQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUVwRSxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQm9FLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQnZELFFBQUFBLE1BQU0sRUFBRSxFQUZ1QjtBQUcvQndELFFBQUFBLEtBQUssRUFBRTtBQUFFQSxVQUFBQSxLQUFLLEVBQUUsRUFBVDtBQUFhQyxVQUFBQSxRQUFRLEVBQUU7QUFBdkI7QUFId0IsT0FBZjtBQURHO0FBdEhoQjtBQUhYLENBbmtCYSxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgT3ZlcnZpZXcvTklTVCB2aXN1YWxpemF0aW9uc1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmV4cG9ydCBkZWZhdWx0IFtcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1OSVNULVJlcXVpcmVtZW50cy1vdmVyLXRpbWUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUmVxdWlyZW1lbnRzIG92ZXIgdGltZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ05JU1QtUmVxdWlyZW1lbnRzLW92ZXItdGltZScsXG4gICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IHRydWUsIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgICAgICAgIG1vZGU6ICdub3JtYWwnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGludGVycG9sYXRlOiAnbGluZWFyJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDoge1xuICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgZm9ybWF0OiB7IGlkOiAnZGF0ZScsIHBhcmFtczogeyBwYXR0ZXJuOiAnWVlZWS1NTS1ERCBISDptbScgfSB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBkYXRlOiB0cnVlLFxuICAgICAgICAgICAgICAgIGludGVydmFsOiAnUFQxSCcsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiAnWVlZWS1NTS1ERCBISDptbScsXG4gICAgICAgICAgICAgICAgYm91bmRzOiB7IG1pbjogJzIwMTktMDgtMjBUMTI6MzM6MjMuMzYwWicsIG1heDogJzIwMTktMDgtMjJUMTI6MzM6MjMuMzYwWicgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB5OiBbeyBhY2Nlc3NvcjogMiwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH1dLFxuICAgICAgICAgICAgc2VyaWVzOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMSxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHsgZnJvbTogJ25vdy0yZCcsIHRvOiAnbm93JyB9LFxuICAgICAgICAgICAgICB1c2VOb3JtYWxpemVkRXNJbnRlcnZhbDogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgZHJvcF9wYXJ0aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5uaXN0XzgwMF81MycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNTAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBsYW5ndWFnZTogJ2x1Y2VuZScsIHF1ZXJ5OiAnJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU5JU1QtUmVxdWlyZW1lbnRzLUFnZW50cy1oZWF0bWFwJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQWxlcnRzIHZvbHVtZSBieSBhZ2VudCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBlbmFibGVkOiB0cnVlLCBpZDogJzEnLCBwYXJhbXM6IHt9LCBzY2hlbWE6ICdtZXRyaWMnLCB0eXBlOiAnY291bnQnIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSZXF1aXJlbWVudCcsXG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5uaXN0XzgwMF81MycsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIHNpemU6IDEwLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FnZW50JyxcbiAgICAgICAgICAgICAgZmllbGQ6ICdhZ2VudC5pZCcsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGNvbG9yU2NoZW1hOiAnQmx1ZXMnLFxuICAgICAgICAgIGNvbG9yc051bWJlcjogMTAsXG4gICAgICAgICAgY29sb3JzUmFuZ2U6IFtdLFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIHNlcmllczogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgICB4OiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHsgaWQ6ICdzdHJpbmcnLCBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJywgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHk6IFt7IGFjY2Vzc29yOiAyLCBhZ2dUeXBlOiAnY291bnQnLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30gfV0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBlbmFibGVIb3ZlcjogZmFsc2UsXG4gICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBwZXJjZW50YWdlTW9kZTogZmFsc2UsXG4gICAgICAgICAgc2V0Q29sb3JSYW5nZTogZmFsc2UsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIHR5cGU6ICdoZWF0bWFwJyxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGxhYmVsczogeyBjb2xvcjogJ2JsYWNrJywgb3ZlcndyaXRlQ29sb3I6IGZhbHNlLCByb3RhdGU6IDAsIHNob3c6IGZhbHNlIH0sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IGRlZmF1bHRZRXh0ZW50czogZmFsc2UsIHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICB9LFxuICAgICAgICB0aXRsZTogJ05JU1QtTGFzdC1hbGVydHMnLFxuICAgICAgICB0eXBlOiAnaGVhdG1hcCcsXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczoge1xuICAgICAgICAgIGRlZmF1bHRDb2xvcnM6IHtcbiAgICAgICAgICAgICcwIC0gMTYwJzogJ3JnYigyNDcsMjUxLDI1NSknLFxuICAgICAgICAgICAgJzE2MCAtIDMyMCc6ICdyZ2IoMjI3LDIzOCwyNDkpJyxcbiAgICAgICAgICAgICczMjAgLSA0ODAnOiAncmdiKDIwOCwyMjUsMjQyKScsXG4gICAgICAgICAgICAnNDgwIC0gNjQwJzogJ3JnYigxODIsMjEyLDIzMyknLFxuICAgICAgICAgICAgJzY0MCAtIDgwMCc6ICdyZ2IoMTQ4LDE5NiwyMjMpJyxcbiAgICAgICAgICAgICc4MDAgLSA5NjAnOiAncmdiKDEwNywxNzQsMjE0KScsXG4gICAgICAgICAgICAnOTYwIC0gMSwxMjAnOiAncmdiKDc0LDE1MiwyMDEpJyxcbiAgICAgICAgICAgICcxLDEyMCAtIDEsMjgwJzogJ3JnYig0NiwxMjYsMTg4KScsXG4gICAgICAgICAgICAnMSwyODAgLSAxLDQ0MCc6ICdyZ2IoMjMsMTAwLDE3MSknLFxuICAgICAgICAgICAgJzEsNDQwIC0gMSw2MDAnOiAncmdiKDgsNzQsMTQ1KScsXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctTklTVC1yZXF1aXJlbWVudHMtYnktYWdlbnRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1JlcXVpcmVtZW50cyBkaXN0cmlidXRpb24gYnkgYWdlbnQnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdOSVNULVRvcC1yZXF1aXJlbWVudHMtYnktYWdlbnQnLFxuICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IGZhbHNlIH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGZpbHRlcjogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIG1vZGU6ICdub3JtYWwnIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCByb3RhdGU6IDAsIGZpbHRlcjogZmFsc2UsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiAndHJ1ZScsXG4gICAgICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgICAgICBtb2RlOiAnc3RhY2tlZCcsXG4gICAgICAgICAgICAgIGRhdGE6IHsgbGFiZWw6ICdDb3VudCcsIGlkOiAnMScgfSxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGludGVycG9sYXRlOiAnbGluZWFyJyxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHsgaWQ6ICdzdHJpbmcnLCBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLCBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHk6IFt7IGFjY2Vzc29yOiAyLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBzZXJpZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2FnZW50LmlkJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdBZ2VudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5uaXN0XzgwMF81MycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHsgdmlzOiB7IGxlZ2VuZE9wZW46IGZhbHNlIH0gfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU5JU1QtTWV0cmljcycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdTdGF0cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ25pc3QtbWV0cmljcycsXG4gICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIHVzZVJhbmdlczogZmFsc2UsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBtZXRyaWNDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbeyB0eXBlOiAncmFuZ2UnLCBmcm9tOiAwLCB0bzogMTAwMDAgfV0sXG4gICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSB9LFxuICAgICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICAgIHN0eWxlOiB7IGJnRmlsbDogJyMwMDAnLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnLCBmb250U2l6ZTogMjAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIG1ldHJpY3M6IFtcbiAgICAgICAgICAgICAgeyB0eXBlOiAndmlzX2RpbWVuc2lvbicsIGFjY2Vzc29yOiAwLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInLCBwYXJhbXM6IHt9IH0gfSxcbiAgICAgICAgICAgICAgeyB0eXBlOiAndmlzX2RpbWVuc2lvbicsIGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInLCBwYXJhbXM6IHt9IH0gfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogZmFsc2UsXG4gICAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGN1c3RvbUxhYmVsOiAnVG90YWwgYWxlcnRzJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnbWF4JyxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdydWxlLmxldmVsJywgY3VzdG9tTGFiZWw6ICdNYXggcnVsZSBsZXZlbCBkZXRlY3RlZCcgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctTklTVC1Ub3AtMTAtcmVxdWlyZW1lbnRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCAxMCByZXF1aXJlbWVudHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdOSVNULVRvcC0xMC1yZXF1aXJlbWVudHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UsIHZhbHVlczogdHJ1ZSwgbGFzdF9sZXZlbDogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIG1ldHJpYzogeyBhY2Nlc3NvcjogMSwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH0sXG4gICAgICAgICAgICBidWNrZXRzOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLm5pc3RfODAwXzUzJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUmVxdWlyZW1lbnQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctTklTVC1BZ2VudHMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTW9zdCBhY3RpdmUgYWdlbnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTklTVC1Ub3AtMTAtYWdlbnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnYWdlbnQubmFtZScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FnZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LU5JU1QtQWxlcnRzLXN1bW1hcnknLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ05JU1QtQWxlcnRzLXN1bW1hcnknLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRyaWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IDMsIGRpcmVjdGlvbjogJ2Rlc2MnIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIG1ldHJpY3M6IFt7IGFjY2Vzc29yOiAzLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBidWNrZXRzOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDEsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAyLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdudW1iZXInLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnYWdlbnQubmFtZScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNTAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FnZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5uaXN0XzgwMF81MycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogMjAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzQnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5sZXZlbCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUnVsZSBsZXZlbCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXTtcbiJdfQ==