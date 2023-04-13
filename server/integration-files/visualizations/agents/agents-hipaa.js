"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Agents/HIPAA visualizations
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
  _id: 'Wazuh-App-Agents-HIPAA-Burbles',
  _source: {
    title: 'HIPAA requirements',
    visState: JSON.stringify({
      title: 'HIPAA requirements',
      type: 'line',
      params: {
        type: 'line',
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
          drawLinesBetweenPoints: false,
          showCircles: true
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
              id: 'date',
              params: {
                pattern: 'YYYY-MM-DD HH:mm'
              }
            },
            params: {
              date: true,
              interval: 'PT12H',
              format: 'YYYY-MM-DD HH:mm',
              bounds: {
                min: '2019-07-24T10:27:37.970Z',
                max: '2019-08-23T10:27:37.970Z'
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
          z: [{
            accessor: 3,
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
        },
        radiusRatio: 20
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
            from: 'now-30d',
            to: 'now'
          },
          useNormalizedEsInterval: true,
          interval: 'auto',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {},
          customLabel: 'Timestampt'
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
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Requirement'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'count',
        schema: 'radius',
        params: {}
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
  _id: 'Wazuh-App-Agents-HIPAA-Distributed-By-Level',
  _source: {
    title: 'Requirements distribution by level',
    visState: JSON.stringify({
      title: 'Requirements distribution by level',
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
                id: 'number',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing'
              }
            },
            params: {},
            aggType: 'terms'
          }]
        },
        orderBucketsBySum: true
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
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'rule.level',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Level'
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
  _id: 'Wazuh-App-Agents-HIPAA-Most-Common',
  _source: {
    title: 'Most common alerts',
    visState: JSON.stringify({
      title: 'Most common alerts',
      type: 'tagcloud',
      params: {
        scale: 'linear',
        orientation: 'single',
        minFontSize: 15,
        maxFontSize: 25,
        showLabel: true,
        metric: {
          type: 'vis_dimension',
          accessor: 1,
          format: {
            id: 'string',
            params: {}
          }
        },
        bucket: {
          type: 'vis_dimension',
          accessor: 0,
          format: {
            id: 'terms',
            params: {
              id: 'string',
              otherBucketLabel: 'Other',
              missingBucketLabel: 'Missing'
            }
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
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-HIPAA-top-10',
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
  _id: 'Wazuh-App-Agents-HIPAA-Requirements-Stacked-Overtime',
  _source: {
    title: 'Requirements over time',
    visState: JSON.stringify({
      title: 'Requirements over time',
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
                min: '2019-08-19T09:19:10.911Z',
                max: '2019-08-23T09:19:10.911Z'
              }
            },
            aggType: 'date_histogram'
          },
          y: [{
            accessor: 1,
            format: {
              id: 'number'
            },
            params: {},
            aggType: 'count'
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
            from: 'now-4d',
            to: 'now'
          },
          useNormalizedEsInterval: true,
          interval: 'auto',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {},
          customLabel: 'Timestampt'
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
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Agents-HIPAA-Last-alerts',
  _type: 'visualization',
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
                id: 'number',
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
      }, {
        id: '5',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.description',
          orderBy: '1',
          order: 'desc',
          size: 200,
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy1oaXBhYS50cyJdLCJuYW1lcyI6WyJfaWQiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJ2YWx1ZUF4aXMiLCJjYXRlZ29yeUF4ZXMiLCJpZCIsInBvc2l0aW9uIiwic2hvdyIsInN0eWxlIiwic2NhbGUiLCJsYWJlbHMiLCJmaWx0ZXIiLCJ0cnVuY2F0ZSIsInZhbHVlQXhlcyIsIm5hbWUiLCJtb2RlIiwicm90YXRlIiwidGV4dCIsInNlcmllc1BhcmFtcyIsImRhdGEiLCJsYWJlbCIsImRyYXdMaW5lc0JldHdlZW5Qb2ludHMiLCJzaG93Q2lyY2xlcyIsImFkZFRvb2x0aXAiLCJhZGRMZWdlbmQiLCJsZWdlbmRQb3NpdGlvbiIsInRpbWVzIiwiYWRkVGltZU1hcmtlciIsImRpbWVuc2lvbnMiLCJ4IiwiYWNjZXNzb3IiLCJmb3JtYXQiLCJwYXR0ZXJuIiwiZGF0ZSIsImludGVydmFsIiwiYm91bmRzIiwibWluIiwibWF4IiwiYWdnVHlwZSIsInkiLCJ6Iiwic2VyaWVzIiwib3RoZXJCdWNrZXRMYWJlbCIsIm1pc3NpbmdCdWNrZXRMYWJlbCIsInJhZGl1c1JhdGlvIiwiYWdncyIsImVuYWJsZWQiLCJzY2hlbWEiLCJmaWVsZCIsInRpbWVSYW5nZSIsImZyb20iLCJ0byIsInVzZU5vcm1hbGl6ZWRFc0ludGVydmFsIiwiZHJvcF9wYXJ0aWFscyIsIm1pbl9kb2NfY291bnQiLCJleHRlbmRlZF9ib3VuZHMiLCJjdXN0b21MYWJlbCIsIm9yZGVyQnkiLCJvcmRlciIsInNpemUiLCJvdGhlckJ1Y2tldCIsIm1pc3NpbmdCdWNrZXQiLCJ1aVN0YXRlSlNPTiIsImRlc2NyaXB0aW9uIiwidmVyc2lvbiIsImtpYmFuYVNhdmVkT2JqZWN0TWV0YSIsInNlYXJjaFNvdXJjZUpTT04iLCJpbmRleCIsInF1ZXJ5IiwibGFuZ3VhZ2UiLCJfdHlwZSIsIm9yZGVyQnVja2V0c0J5U3VtIiwib3JpZW50YXRpb24iLCJtaW5Gb250U2l6ZSIsIm1heEZvbnRTaXplIiwic2hvd0xhYmVsIiwibWV0cmljIiwiYnVja2V0IiwiaXNEb251dCIsInZhbHVlcyIsImxhc3RfbGV2ZWwiLCJidWNrZXRzIiwicGVyUGFnZSIsInNob3dQYXJ0aWFsUm93cyIsInNob3dNZXRyaWNzQXRBbGxMZXZlbHMiLCJzb3J0IiwiY29sdW1uSW5kZXgiLCJkaXJlY3Rpb24iLCJzaG93VG90YWwiLCJzaG93VG9vbGJhciIsInRvdGFsRnVuYyIsIm1ldHJpY3MiLCJ2aXMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO2VBQ2UsQ0FDYjtBQUNFQSxFQUFBQSxHQUFHLEVBQUUsZ0NBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxvQkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUsb0JBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsTUFGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNORCxRQUFBQSxJQUFJLEVBQUUsTUFEQTtBQUVORSxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsYUFBYSxFQUFFLElBQWpCO0FBQXVCQyxVQUFBQSxTQUFTLEVBQUU7QUFBbEMsU0FGQTtBQUdOQyxRQUFBQSxZQUFZLEVBQUUsQ0FDWjtBQUNFQyxVQUFBQSxFQUFFLEVBQUUsZ0JBRE47QUFFRU4sVUFBQUEsSUFBSSxFQUFFLFVBRlI7QUFHRU8sVUFBQUEsUUFBUSxFQUFFLFFBSFo7QUFJRUMsVUFBQUEsSUFBSSxFQUFFLElBSlI7QUFLRUMsVUFBQUEsS0FBSyxFQUFFLEVBTFQ7QUFNRUMsVUFBQUEsS0FBSyxFQUFFO0FBQUVWLFlBQUFBLElBQUksRUFBRTtBQUFSLFdBTlQ7QUFPRVcs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UHhCLElBQUFBLFdBQVcsRUFBRSxFQXBITjtBQXFIUEMsSUFBQUEsT0FBTyxFQUFFLENBckhGO0FBc0hQQyxJQUFBQSxxQkFBcUIsRUFBRTtBQUNyQkMsTUFBQUEsZ0JBQWdCLEVBQUVyRSxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQnFFLFFBQUFBLEtBQUssRUFBRSxjQUR3QjtBQUUvQnhELFFBQUFBLE1BQU0sRUFBRSxFQUZ1QjtBQUcvQnlELFFBQUFBLEtBQUssRUFBRTtBQUFFQSxVQUFBQSxLQUFLLEVBQUUsRUFBVDtBQUFhQyxVQUFBQSxRQUFRLEVBQUU7QUFBdkI7QUFId0IsT0FBZjtBQURHO0FBdEhoQjtBQUhYLENBNWZhLEMiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTW9kdWxlIGZvciBBZ2VudHMvSElQQUEgdmlzdWFsaXphdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgZGVmYXVsdCBbXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUhJUEFBLUJ1cmJsZXMnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnSElQQUEgcmVxdWlyZW1lbnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnSElQQUEgcmVxdWlyZW1lbnRzJyxcbiAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiB0cnVlLCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICAgICAgICBtb2RlOiAnbm9ybWFsJyxcbiAgICAgICAgICAgICAgZGF0YTogeyBsYWJlbDogJ0NvdW50JywgaWQ6ICcxJyB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IGZhbHNlLFxuICAgICAgICAgICAgICBzaG93Q2lyY2xlczogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDoge1xuICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgZm9ybWF0OiB7IGlkOiAnZGF0ZScsIHBhcmFtczogeyBwYXR0ZXJuOiAnWVlZWS1NTS1ERCBISDptbScgfSB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBkYXRlOiB0cnVlLFxuICAgICAgICAgICAgICAgIGludGVydmFsOiAnUFQxMkgnLFxuICAgICAgICAgICAgICAgIGZvcm1hdDogJ1lZWVktTU0tREQgSEg6bW0nLFxuICAgICAgICAgICAgICAgIGJvdW5kczogeyBtaW46ICcyMDE5LTA3LTI0VDEwOjI3OjM3Ljk3MFonLCBtYXg6ICcyMDE5LTA4LTIzVDEwOjI3OjM3Ljk3MFonIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgeTogW3sgYWNjZXNzb3I6IDIsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9XSxcbiAgICAgICAgICAgIHo6IFt7IGFjY2Vzc29yOiAzLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBzZXJpZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgcmFkaXVzUmF0aW86IDIwLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHsgZnJvbTogJ25vdy0zMGQnLCB0bzogJ25vdycgfSxcbiAgICAgICAgICAgICAgdXNlTm9ybWFsaXplZEVzSW50ZXJ2YWw6IHRydWUsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnYXV0bycsXG4gICAgICAgICAgICAgIGRyb3BfcGFydGlhbHM6IGZhbHNlLFxuICAgICAgICAgICAgICBtaW5fZG9jX2NvdW50OiAxLFxuICAgICAgICAgICAgICBleHRlbmRlZF9ib3VuZHM6IHt9LFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1RpbWVzdGFtcHQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaGlwYWEnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7IGlkOiAnNCcsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ3JhZGl1cycsIHBhcmFtczoge30gfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1ISVBBQS1EaXN0cmlidXRlZC1CeS1MZXZlbCcsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSZXF1aXJlbWVudHMgZGlzdHJpYnV0aW9uIGJ5IGxldmVsJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnUmVxdWlyZW1lbnRzIGRpc3RyaWJ1dGlvbiBieSBsZXZlbCcsXG4gICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IHRydWUsIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIGFkZFRpbWVNYXJrZXI6IGZhbHNlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSB9LFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIHg6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgIHBhcmFtczogeyBpZDogJ3N0cmluZycsIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgeTogW3sgYWNjZXNzb3I6IDIsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9XSxcbiAgICAgICAgICAgIHNlcmllczogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDEsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ251bWJlcicsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBvcmRlckJ1Y2tldHNCeVN1bTogdHJ1ZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5oaXBhYScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUmVxdWlyZW1lbnQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0xldmVsJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1ISVBBQS1Nb3N0LUNvbW1vbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdNb3N0IGNvbW1vbiBhbGVydHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdNb3N0IGNvbW1vbiBhbGVydHMnLFxuICAgICAgICB0eXBlOiAndGFnY2xvdWQnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBzY2FsZTogJ2xpbmVhcicsXG4gICAgICAgICAgb3JpZW50YXRpb246ICdzaW5nbGUnLFxuICAgICAgICAgIG1pbkZvbnRTaXplOiAxNSxcbiAgICAgICAgICBtYXhGb250U2l6ZTogMjUsXG4gICAgICAgICAgc2hvd0xhYmVsOiB0cnVlLFxuICAgICAgICAgIG1ldHJpYzogeyB0eXBlOiAndmlzX2RpbWVuc2lvbicsIGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdzdHJpbmcnLCBwYXJhbXM6IHt9IH0gfSxcbiAgICAgICAgICBidWNrZXQ6IHtcbiAgICAgICAgICAgIHR5cGU6ICd2aXNfZGltZW5zaW9uJyxcbiAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICBwYXJhbXM6IHsgaWQ6ICdzdHJpbmcnLCBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLCBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmhpcGFhJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSZXF1aXJlbWVudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtSElQQUEtdG9wLTEwJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCAxMCByZXF1aXJlbWVudHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgMTAgcmVxdWlyZW1lbnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5oaXBhYScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1ISVBBQS1SZXF1aXJlbWVudHMtU3RhY2tlZC1PdmVydGltZScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSZXF1aXJlbWVudHMgb3ZlciB0aW1lJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnUmVxdWlyZW1lbnRzIG92ZXIgdGltZScsXG4gICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IGZhbHNlIH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGZpbHRlcjogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIG1vZGU6ICdub3JtYWwnIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCByb3RhdGU6IDAsIGZpbHRlcjogZmFsc2UsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiAndHJ1ZScsXG4gICAgICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgICAgICBtb2RlOiAnc3RhY2tlZCcsXG4gICAgICAgICAgICAgIGRhdGE6IHsgbGFiZWw6ICdDb3VudCcsIGlkOiAnMScgfSxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBkcmF3TGluZXNCZXR3ZWVuUG9pbnRzOiB0cnVlLFxuICAgICAgICAgICAgICBzaG93Q2lyY2xlczogdHJ1ZSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDoge1xuICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgZm9ybWF0OiB7IGlkOiAnZGF0ZScsIHBhcmFtczogeyBwYXR0ZXJuOiAnWVlZWS1NTS1ERCBISDptbScgfSB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICBkYXRlOiB0cnVlLFxuICAgICAgICAgICAgICAgIGludGVydmFsOiAnUFQxSCcsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiAnWVlZWS1NTS1ERCBISDptbScsXG4gICAgICAgICAgICAgICAgYm91bmRzOiB7IG1pbjogJzIwMTktMDgtMTlUMDk6MTk6MTAuOTExWicsIG1heDogJzIwMTktMDgtMjNUMDk6MTk6MTAuOTExWicgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB5OiBbeyBhY2Nlc3NvcjogMSwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH1dLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3RpbWVzdGFtcCcsXG4gICAgICAgICAgICAgIHRpbWVSYW5nZTogeyBmcm9tOiAnbm93LTRkJywgdG86ICdub3cnIH0sXG4gICAgICAgICAgICAgIHVzZU5vcm1hbGl6ZWRFc0ludGVydmFsOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ2F1dG8nLFxuICAgICAgICAgICAgICBkcm9wX3BhcnRpYWxzOiBmYWxzZSxcbiAgICAgICAgICAgICAgbWluX2RvY19jb3VudDogMSxcbiAgICAgICAgICAgICAgZXh0ZW5kZWRfYm91bmRzOiB7fSxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdUaW1lc3RhbXB0JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmhpcGFhJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSZXF1aXJlbWVudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtSElQQUEtTGFzdC1hbGVydHMnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0cmljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9LFxuICAgICAgICAgIHNob3dUb3RhbDogZmFsc2UsXG4gICAgICAgICAgc2hvd1Rvb2xiYXI6IHRydWUsXG4gICAgICAgICAgdG90YWxGdW5jOiAnc3VtJyxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWNzOiBbeyBhY2Nlc3NvcjogMywgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH1dLFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdudW1iZXInLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMixcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaGlwYWEnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDIwLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSZXF1aXJlbWVudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1J1bGUgbGV2ZWwnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnNScsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmRlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiAyMDAsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0Rlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG5dO1xuIl19