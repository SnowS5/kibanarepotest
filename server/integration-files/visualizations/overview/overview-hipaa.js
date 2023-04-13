"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview/HIPAA visualizations
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
  _id: 'Wazuh-App-Overview-HIPAA-Tag-cloud',
  _source: {
    title: 'Most common alerts',
    visState: JSON.stringify({
      title: 'Most common alerts',
      type: 'tagcloud',
      params: {
        scale: 'linear',
        orientation: 'single',
        minFontSize: 10,
        maxFontSize: 30,
        showLabel: false,
        metric: {
          type: 'vis_dimension',
          accessor: 1,
          format: {
            id: 'string',
            params: {}
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
          field: 'rule.hipaa',
          orderBy: '1',
          order: 'desc',
          size: 5,
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
  _id: 'Wazuh-App-Overview-HIPAA-Top-10-requirements',
  _source: {
    title: 'Top 10 requirements',
    visState: JSON.stringify({
      title: 'Top 10 requirements',
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
          field: 'rule.hipaa',
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
  _id: 'Wazuh-App-Overview-HIPAA-Top-10-agents',
  _source: {
    title: 'Most active agents',
    visState: JSON.stringify({
      title: 'Most active agents',
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
          customLabel: 'Agent',
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
  _id: 'Wazuh-App-Overview-HIPAA-Metrics',
  _source: {
    title: 'Stats',
    visState: JSON.stringify({
      title: 'Stats',
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
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Alerts-summary',
  _source: {
    title: 'Alerts summary',
    visState: JSON.stringify({
      title: 'Alerts summary',
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
          field: 'rule.hipaa',
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
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Heatmap',
  _source: {
    title: 'Alerts volume by agent',
    visState: JSON.stringify({
      title: 'Alerts volume by agent',
      type: 'heatmap',
      params: {
        type: 'heatmap',
        addTooltip: true,
        addLegend: true,
        enableHover: false,
        legendPosition: 'right',
        times: [],
        colorsNumber: 10,
        colorSchema: 'Greens',
        setColorRange: false,
        colorsRange: [],
        invertColors: false,
        percentageMode: false,
        valueAxes: [{
          show: false,
          id: 'ValueAxis-1',
          type: 'value',
          scale: {
            type: 'linear',
            defaultYExtents: false
          },
          labels: {
            show: false,
            rotate: 0,
            overwriteColor: false,
            color: 'black'
          }
        }],
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
          customLabel: 'Agent ID'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'rule.hipaa',
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
        defaultColors: {
          '0 - 260': 'rgb(247,252,245)',
          '260 - 520': 'rgb(233,247,228)',
          '520 - 780': 'rgb(211,238,205)',
          '780 - 1,040': 'rgb(184,227,177)',
          '1,040 - 1,300': 'rgb(152,213,148)',
          '1,300 - 1,560': 'rgb(116,196,118)',
          '1,560 - 1,820': 'rgb(75,176,98)',
          '1,820 - 2,080': 'rgb(47,152,79)',
          '2,080 - 2,340': 'rgb(21,127,59)',
          '2,340 - 2,600': 'rgb(0,100,40)'
        },
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
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-HIPAA-Top-10-requirements-over-time-by-agent',
  _source: {
    title: 'Requirements distribution by agent',
    visState: JSON.stringify({
      title: 'Requirements distribution by agent',
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
              interval: 'auto',
              format: 'YYYY-MM-DD HH:mm',
              bounds: {
                min: '2019-08-15T12:25:44.851Z',
                max: '2019-08-22T12:25:44.851Z'
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
        schema: 'group',
        params: {
          field: 'rule.hipaa',
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
  _id: 'Wazuh-App-Overview-HIPAA-Top-requirements-over-time',
  _source: {
    title: 'Requirements evolution over time',
    visState: JSON.stringify({
      title: 'Requirements evolution over time',
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
              interval: 'auto',
              format: 'YYYY-MM-DD HH:mm',
              bounds: {
                min: '2019-08-15T12:25:29.501Z',
                max: '2019-08-22T12:25:29.501Z'
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
          field: 'rule.hipaa',
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
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LWhpcGFhLnRzIl0sIm5hbWVzIjpbIl9pZCIsIl9zb3VyY2UiLCJ0aXRsZSIsInZpc1N0YXRlIiwiSlNPTiIsInN0cmluZ2lmeSIsInR5cGUiLCJwYXJhbXMiLCJzY2FsZSIsIm9yaWVudGF0aW9uIiwibWluRm9udFNpemUiLCJtYXhGb250U2l6ZSIsInNob3dMYWJlbCIsIm1ldHJpYyIsImFjY2Vzc29yIiwiZm9ybWF0IiwiaWQiLCJhZ2dzIiwiZW5hYmxlZCIsInNjaGVtYSIsImZpZWxkIiwib3JkZXJCeSIsIm9yZGVyIiwic2l6ZSIsIm90aGVyQnVja2V0Iiwib3RoZXJCdWNrZXRMYWJlbCIsIm1pc3NpbmdCdWNrZXQiLCJtaXNzaW5nQnVja2V0TGFiZWwiLCJjdXN0b21MYWJlbCIsInVpU3RhdGVKU09OIiwiZGVzY3JpcHRpb24iLCJ2ZXJzaW9uIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImluZGV4IiwiZmlsdGVyIiwicXVlcnkiLCJsYW5ndWFnZSIsIl90eXBlIiwiYWRkVG9vbHRpcCIsImFkZExlZ2VuZCIsImxlZ2VuZFBvc2l0aW9uIiwiaXNEb251dCIsImxhYmVscyIsInNob3ciLCJ2YWx1ZXMiLCJsYXN0X2xldmVsIiwidHJ1bmNhdGUiLCJkaW1lbnNpb25zIiwiYWdnVHlwZSIsImJ1Y2tldHMiLCJwZXJjZW50YWdlTW9kZSIsInVzZVJhbmdlcyIsImNvbG9yU2NoZW1hIiwibWV0cmljQ29sb3JNb2RlIiwiY29sb3JzUmFuZ2UiLCJmcm9tIiwidG8iLCJpbnZlcnRDb2xvcnMiLCJzdHlsZSIsImJnRmlsbCIsImJnQ29sb3IiLCJsYWJlbENvbG9yIiwic3ViVGV4dCIsImZvbnRTaXplIiwibWV0cmljcyIsInBlclBhZ2UiLCJzaG93UGFydGlhbFJvd3MiLCJzaG93TWV0cmljc0F0QWxsTGV2ZWxzIiwic29ydCIsImNvbHVtbkluZGV4IiwiZGlyZWN0aW9uIiwic2hvd1RvdGFsIiwic2hvd1Rvb2xiYXIiLCJ0b3RhbEZ1bmMiLCJ2aXMiLCJlbmFibGVIb3ZlciIsInRpbWVzIiwiY29sb3JzTnVtYmVyIiwic2V0Q29sb3JSYW5nZSIsInZhbHVlQXhlcyIsImRlZmF1bHRZRXh0ZW50cyIsInJvdGF0ZSIsIm92ZXJ3cml0ZUNvbG9yIiwiY29sb3IiLCJ4IiwieSIsInNlcmllcyIsImRlZmF1bHRDb2xvcnMiLCJsZWdlbmRPcGVuIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJ2YWx1ZUF4aXMiLCJjYXRlZ29yeUF4ZXMiLCJwb3NpdGlvbiIsIm5hbWUiLCJtb2RlIiwidGV4dCIsInNlcmllc1BhcmFtcyIsImRhdGEiLCJsYWJlbCIsImRyYXdMaW5lc0JldHdlZW5Qb2ludHMiLCJzaG93Q2lyY2xlcyIsImFkZFRpbWVNYXJrZXIiLCJwYXR0ZXJuIiwiZGF0ZSIsImludGVydmFsIiwiYm91bmRzIiwibWluIiwibWF4IiwidGltZVJhbmdlIiwidXNlTm9ybWFsaXplZEVzSW50ZXJ2YWwiLCJkcm9wX3BhcnRpYWxzIiwibWluX2RvY19jb3VudCIsImV4dGVuZGVkX2JvdW5kcyJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7ZUFDZSxDQUNiO0FBQ0VBLEVBQUFBLEdBQUcsRUFBRSxvQ0FEUDtBQUVFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLG9CQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxvQkFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxVQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05DLFFBQUFBLEtBQUssRUFBRSxRQUREO0FBRU5DLFFBQUFBLFdBQVcsRUFBRSxRQUZQO0FBR05DLFFBQUFBLFdBQVcsRUFBRSxFQUhQO0FBSU5DLFFBQUFBLFdBQVcsRUFBRSxFQUpQO0FBS05DLFFBQUFB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QUEsSUFBSSxFQUFFLE9BSFI7QUFJRWEsUUFBQUEsTUFBTSxFQUFFLE9BSlY7QUFLRVosUUFBQUEsTUFBTSxFQUFFO0FBQ05hLFVBQUFBLEtBQUssRUFBRSxZQUREO0FBRU5DLFVBQUFBLE9BQU8sRUFBRSxHQUZIO0FBR05DLFVBQUFBLEtBQUssRUFBRSxNQUhEO0FBSU5DLFVBQUFBLElBQUksRUFBRSxFQUpBO0FBS05DLFVBQUFBLFdBQVcsRUFBRSxLQUxQO0FBTU5DLFVBQUFBLGdCQUFnQixFQUFFLE9BTlo7QUFPTkMsVUFBQUEsYUFBYSxFQUFFLEtBUFQ7QUFRTkMsVUFBQUEsa0JBQWtCLEVBQUU7QUFSZDtBQUxWLE9BakJJO0FBOUVpQixLQUFmLENBRkg7QUFtSFBFLElBQUFBLFdBQVcsRUFBRSxJQW5ITjtBQW9IUEMsSUFBQUEsV0FBVyxFQUFFLEVBcEhOO0FBcUhQQyxJQUFBQSxPQUFPLEVBQUUsQ0FySEY7QUFzSFBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRTdCLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CNkIsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsRUFGdUI7QUFHL0JDLFFBQUFBLEtBQUssRUFBRTtBQUFFQyxVQUFBQSxRQUFRLEVBQUUsUUFBWjtBQUFzQkQsVUFBQUEsS0FBSyxFQUFFO0FBQTdCO0FBSHdCLE9BQWY7QUFERztBQXRIaEIsR0FGWDtBQWdJRUUsRUFBQUEsS0FBSyxFQUFFO0FBaElULENBbG5CYSxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgT3ZlcnZpZXcvSElQQUEgdmlzdWFsaXphdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgZGVmYXVsdCBbXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctSElQQUEtVGFnLWNsb3VkJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ01vc3QgY29tbW9uIGFsZXJ0cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ01vc3QgY29tbW9uIGFsZXJ0cycsXG4gICAgICAgIHR5cGU6ICd0YWdjbG91ZCcsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHNjYWxlOiAnbGluZWFyJyxcbiAgICAgICAgICBvcmllbnRhdGlvbjogJ3NpbmdsZScsXG4gICAgICAgICAgbWluRm9udFNpemU6IDEwLFxuICAgICAgICAgIG1heEZvbnRTaXplOiAzMCxcbiAgICAgICAgICBzaG93TGFiZWw6IGZhbHNlLFxuICAgICAgICAgIG1ldHJpYzogeyB0eXBlOiAndmlzX2RpbWVuc2lvbicsIGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdzdHJpbmcnLCBwYXJhbXM6IHt9IH0gfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5oaXBhYScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUmVxdWlyZW1lbnQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IGxhbmd1YWdlOiAnbHVjZW5lJywgcXVlcnk6ICcnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctSElQQUEtVG9wLTEwLXJlcXVpcmVtZW50cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgMTAgcmVxdWlyZW1lbnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnVG9wIDEwIHJlcXVpcmVtZW50cycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSwgdmFsdWVzOiB0cnVlLCBsYXN0X2xldmVsOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljOiB7IGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfSxcbiAgICAgICAgICAgIGJ1Y2tldHM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaGlwYWEnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDEwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBsYW5ndWFnZTogJ2x1Y2VuZScsIHF1ZXJ5OiAnJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUhJUEFBLVRvcC0xMC1hZ2VudHMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTW9zdCBhY3RpdmUgYWdlbnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTW9zdCBhY3RpdmUgYWdlbnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnYWdlbnQubmFtZScsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnQWdlbnQnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDEwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBsYW5ndWFnZTogJ2x1Y2VuZScsIHF1ZXJ5OiAnJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUhJUEFBLU1ldHJpY3MnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnU3RhdHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdTdGF0cycsXG4gICAgICAgIHR5cGU6ICdtZXRyaWMnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgIHBlcmNlbnRhZ2VNb2RlOiBmYWxzZSxcbiAgICAgICAgICAgIHVzZVJhbmdlczogZmFsc2UsXG4gICAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgICBtZXRyaWNDb2xvck1vZGU6ICdOb25lJyxcbiAgICAgICAgICAgIGNvbG9yc1JhbmdlOiBbeyB0eXBlOiAncmFuZ2UnLCBmcm9tOiAwLCB0bzogMTAwMDAgfV0sXG4gICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSB9LFxuICAgICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICAgIHN0eWxlOiB7IGJnRmlsbDogJyMwMDAnLCBiZ0NvbG9yOiBmYWxzZSwgbGFiZWxDb2xvcjogZmFsc2UsIHN1YlRleHQ6ICcnLCBmb250U2l6ZTogMjAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIG1ldHJpY3M6IFtcbiAgICAgICAgICAgICAgeyB0eXBlOiAndmlzX2RpbWVuc2lvbicsIGFjY2Vzc29yOiAwLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInLCBwYXJhbXM6IHt9IH0gfSxcbiAgICAgICAgICAgICAgeyB0eXBlOiAndmlzX2RpbWVuc2lvbicsIGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInLCBwYXJhbXM6IHt9IH0gfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogZmFsc2UsXG4gICAgICAgICAgdHlwZTogJ21ldHJpYycsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzEnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICBzY2hlbWE6ICdtZXRyaWMnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGN1c3RvbUxhYmVsOiAnVG90YWwgYWxlcnRzJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnbWF4JyxcbiAgICAgICAgICAgIHNjaGVtYTogJ21ldHJpYycsXG4gICAgICAgICAgICBwYXJhbXM6IHsgZmllbGQ6ICdydWxlLmxldmVsJywgY3VzdG9tTGFiZWw6ICdNYXggcnVsZSBsZXZlbCBkZXRlY3RlZCcgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IGxhbmd1YWdlOiAnbHVjZW5lJywgcXVlcnk6ICcnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctSElQQUEtQWxlcnRzLXN1bW1hcnknLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldHJpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljczogW3sgYWNjZXNzb3I6IDMsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9XSxcbiAgICAgICAgICAgIGJ1Y2tldHM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMSxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDIsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ251bWJlcicsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdhZ2VudC5uYW1lJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1MCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnQWdlbnQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmhpcGFhJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAyMCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUmVxdWlyZW1lbnQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNCcsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmxldmVsJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIGxldmVsJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1ISVBBQS1IZWF0bWFwJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyB2b2x1bWUgYnkgYWdlbnQnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgdm9sdW1lIGJ5IGFnZW50JyxcbiAgICAgICAgdHlwZTogJ2hlYXRtYXAnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGVhdG1hcCcsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgZW5hYmxlSG92ZXI6IGZhbHNlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBjb2xvcnNOdW1iZXI6IDEwLFxuICAgICAgICAgIGNvbG9yU2NoZW1hOiAnR3JlZW5zJyxcbiAgICAgICAgICBzZXRDb2xvclJhbmdlOiBmYWxzZSxcbiAgICAgICAgICBjb2xvcnNSYW5nZTogW10sXG4gICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICBwZXJjZW50YWdlTW9kZTogZmFsc2UsXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIGRlZmF1bHRZRXh0ZW50czogZmFsc2UgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCByb3RhdGU6IDAsIG92ZXJ3cml0ZUNvbG9yOiBmYWxzZSwgY29sb3I6ICdibGFjaycgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHsgaWQ6ICdzdHJpbmcnLCBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLCBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHk6IFt7IGFjY2Vzc29yOiAyLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBzZXJpZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2FnZW50LmlkJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdBZ2VudCBJRCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5oaXBhYScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7XG4gICAgICAgICAgZGVmYXVsdENvbG9yczoge1xuICAgICAgICAgICAgJzAgLSAyNjAnOiAncmdiKDI0NywyNTIsMjQ1KScsXG4gICAgICAgICAgICAnMjYwIC0gNTIwJzogJ3JnYigyMzMsMjQ3LDIyOCknLFxuICAgICAgICAgICAgJzUyMCAtIDc4MCc6ICdyZ2IoMjExLDIzOCwyMDUpJyxcbiAgICAgICAgICAgICc3ODAgLSAxLDA0MCc6ICdyZ2IoMTg0LDIyNywxNzcpJyxcbiAgICAgICAgICAgICcxLDA0MCAtIDEsMzAwJzogJ3JnYigxNTIsMjEzLDE0OCknLFxuICAgICAgICAgICAgJzEsMzAwIC0gMSw1NjAnOiAncmdiKDExNiwxOTYsMTE4KScsXG4gICAgICAgICAgICAnMSw1NjAgLSAxLDgyMCc6ICdyZ2IoNzUsMTc2LDk4KScsXG4gICAgICAgICAgICAnMSw4MjAgLSAyLDA4MCc6ICdyZ2IoNDcsMTUyLDc5KScsXG4gICAgICAgICAgICAnMiwwODAgLSAyLDM0MCc6ICdyZ2IoMjEsMTI3LDU5KScsXG4gICAgICAgICAgICAnMiwzNDAgLSAyLDYwMCc6ICdyZ2IoMCwxMDAsNDApJyxcbiAgICAgICAgICB9LFxuICAgICAgICAgIGxlZ2VuZE9wZW46IHRydWUsXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IGxhbmd1YWdlOiAnbHVjZW5lJywgcXVlcnk6ICcnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctSElQQUEtVG9wLTEwLXJlcXVpcmVtZW50cy1vdmVyLXRpbWUtYnktYWdlbnQnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUmVxdWlyZW1lbnRzIGRpc3RyaWJ1dGlvbiBieSBhZ2VudCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1JlcXVpcmVtZW50cyBkaXN0cmlidXRpb24gYnkgYWdlbnQnLFxuICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiB0cnVlLCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgICAgIG1vZGU6ICdzdGFja2VkJyxcbiAgICAgICAgICAgICAgZGF0YTogeyBsYWJlbDogJ0NvdW50JywgaWQ6ICcxJyB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHsgaWQ6ICdkYXRlJywgcGFyYW1zOiB7IHBhdHRlcm46ICdZWVlZLU1NLUREIEhIOm1tJyB9IH0sXG4gICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGRhdGU6IHRydWUsXG4gICAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6ICdZWVlZLU1NLUREIEhIOm1tJyxcbiAgICAgICAgICAgICAgICBib3VuZHM6IHsgbWluOiAnMjAxOS0wOC0xNVQxMjoyNTo0NC44NTFaJywgbWF4OiAnMjAxOS0wOC0yMlQxMjoyNTo0NC44NTFaJyB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBhZ2dUeXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHk6IFt7IGFjY2Vzc29yOiAyLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBzZXJpZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2FnZW50Lm5hbWUnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaGlwYWEnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDEwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBsYW5ndWFnZTogJ2x1Y2VuZScsIHF1ZXJ5OiAnJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUhJUEFBLVRvcC1yZXF1aXJlbWVudHMtb3Zlci10aW1lJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1JlcXVpcmVtZW50cyBldm9sdXRpb24gb3ZlciB0aW1lJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnUmVxdWlyZW1lbnRzIGV2b2x1dGlvbiBvdmVyIHRpbWUnLFxuICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiB0cnVlLCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgICAgIG1vZGU6ICdzdGFja2VkJyxcbiAgICAgICAgICAgICAgZGF0YTogeyBsYWJlbDogJ0NvdW50JywgaWQ6ICcxJyB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHsgaWQ6ICdkYXRlJywgcGFyYW1zOiB7IHBhdHRlcm46ICdZWVlZLU1NLUREIEhIOm1tJyB9IH0sXG4gICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGRhdGU6IHRydWUsXG4gICAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6ICdZWVlZLU1NLUREIEhIOm1tJyxcbiAgICAgICAgICAgICAgICBib3VuZHM6IHsgbWluOiAnMjAxOS0wOC0xNVQxMjoyNToyOS41MDFaJywgbWF4OiAnMjAxOS0wOC0yMlQxMjoyNToyOS41MDFaJyB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBhZ2dUeXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHk6IFt7IGFjY2Vzc29yOiAyLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBzZXJpZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3RpbWVzdGFtcCcsXG4gICAgICAgICAgICAgIHRpbWVSYW5nZTogeyBmcm9tOiAnbm93LTdkJywgdG86ICdub3cnIH0sXG4gICAgICAgICAgICAgIHVzZU5vcm1hbGl6ZWRFc0ludGVydmFsOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ2F1dG8nLFxuICAgICAgICAgICAgICBkcm9wX3BhcnRpYWxzOiBmYWxzZSxcbiAgICAgICAgICAgICAgbWluX2RvY19jb3VudDogMSxcbiAgICAgICAgICAgICAgZXh0ZW5kZWRfYm91bmRzOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmhpcGFhJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgbGFuZ3VhZ2U6ICdsdWNlbmUnLCBxdWVyeTogJycgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbl07XG4iXX0=