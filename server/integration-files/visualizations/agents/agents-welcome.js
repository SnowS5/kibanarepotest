"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Agents/GCP visualizations
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
  _id: 'Wazuh-App-Agents-Welcome-Top-PCI',
  _type: 'visualization',
  _source: {
    title: 'Top 5 rules',
    visState: JSON.stringify({
      title: 'top pci requirements',
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
            label: 'Count',
            aggType: 'count'
          },
          buckets: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing',
                parsedUrl: {
                  origin: 'http://172.16.1.2:5601',
                  pathname: '/app/kibana',
                  basePath: ''
                }
              }
            },
            params: {},
            label: 'Requirement',
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
          field: 'rule.pci_dss',
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
  _id: 'Wazuh-App-Agents-Welcome-Top-GDPR',
  _type: 'visualization',
  _source: {
    title: 'Top 5 GDPR',
    visState: JSON.stringify({
      title: 'top gdpr requirements',
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
            label: 'Count',
            aggType: 'count'
          },
          buckets: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing',
                parsedUrl: {
                  origin: 'http://172.16.1.2:5601',
                  pathname: '/app/kibana',
                  basePath: ''
                }
              }
            },
            params: {},
            label: 'Requirement',
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
          field: 'rule.gdpr',
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
  _id: 'Wazuh-App-Agents-Welcome-Top-HIPAA',
  _type: 'visualization',
  _source: {
    title: 'Top 5 HIPAA',
    visState: JSON.stringify({
      title: 'top hipaa requirements',
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
            label: 'Count',
            aggType: 'count'
          },
          buckets: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing',
                parsedUrl: {
                  origin: 'http://172.16.1.2:5601',
                  pathname: '/app/kibana',
                  basePath: ''
                }
              }
            },
            params: {},
            label: 'Requirement',
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
          size: 5,
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
  _id: 'Wazuh-App-Agents-Welcome-Top-NIST-800-53',
  _type: 'visualization',
  _source: {
    title: 'Top 5 NIST-800-53',
    visState: JSON.stringify({
      title: 'top NIST-800-53 requirements',
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
            label: 'Count',
            aggType: 'count'
          },
          buckets: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing',
                parsedUrl: {
                  origin: 'http://172.16.1.2:5601',
                  pathname: '/app/kibana',
                  basePath: ''
                }
              }
            },
            params: {},
            label: 'Requirement',
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
          size: 5,
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
  _id: 'Wazuh-App-Agents-Welcome-Top-GPG-13',
  _type: 'visualization',
  _source: {
    title: 'Top 5 GPG-13',
    visState: JSON.stringify({
      title: 'top GPG-13 requirements',
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
            label: 'Count',
            aggType: 'count'
          },
          buckets: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing',
                parsedUrl: {
                  origin: 'http://172.16.1.2:5601',
                  pathname: '/app/kibana',
                  basePath: ''
                }
              }
            },
            params: {},
            label: 'Requirement',
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
          field: 'rule.gpg13',
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
  _id: 'Wazuh-App-Agents-Welcome-Top-TSC',
  _type: 'visualization',
  _source: {
    title: 'Top 5 TSC',
    visState: JSON.stringify({
      title: 'top TSC requirements',
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
            label: 'Count',
            aggType: 'count'
          },
          buckets: [{
            accessor: 0,
            format: {
              id: 'terms',
              params: {
                id: 'string',
                otherBucketLabel: 'Other',
                missingBucketLabel: 'Missing',
                parsedUrl: {
                  origin: 'http://172.16.1.2:5601',
                  pathname: '/app/kibana',
                  basePath: ''
                }
              }
            },
            params: {},
            label: 'Requirement',
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
          field: 'rule.tsc',
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
  _id: 'Wazuh-App-Agents-Welcome-Events-Evolution',
  _type: 'visualization',
  _source: {
    title: 'Events evolution',
    visState: JSON.stringify({
      title: 'event evolution',
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
        addLegend: false,
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
        dimensions: {
          x: null,
          y: [{
            accessor: 0,
            format: {
              id: 'number'
            },
            params: {},
            label: 'Count',
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
          useNormalizedEsInterval: true,
          scaleMetricValues: false,
          interval: 'auto',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {}
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
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy13ZWxjb21lLnRzIl0sIm5hbWVzIjpbIl9pZCIsIl90eXBlIiwiX3NvdXJjZSIsInRpdGxlIiwidmlzU3RhdGUiLCJKU09OIiwic3RyaW5naWZ5IiwidHlwZSIsInBhcmFtcyIsImFkZFRvb2x0aXAiLCJhZGRMZWdlbmQiLCJsZWdlbmRQb3NpdGlvbiIsImlzRG9udXQiLCJsYWJlbHMiLCJzaG93IiwidmFsdWVzIiwibGFzdF9sZXZlbCIsInRydW5jYXRlIiwiZGltZW5zaW9ucyIsIm1ldHJpYyIsImFjY2Vzc29yIiwiZm9ybWF0IiwiaWQiLCJsYWJlbCIsImFnZ1R5cGUiLCJidWNrZXRzIiwib3RoZXJCdWNrZXRMYWJlbCIsIm1pc3NpbmdCdWNrZXRMYWJlbCIsInBhcnNlZFVybCIsIm9yaWdpbiIsInBhdGhuYW1lIiwiYmFzZVBhdGgiLCJhZ2dzIiwiZW5hYmxlZCIsInNjaGVtYSIsImZpZWxkIiwib3JkZXJCeSIsIm9yZGVyIiwic2l6ZSIsIm90aGVyQnVja2V0IiwibWlzc2luZ0J1Y2tldCIsImN1c3RvbUxhYmVsIiwidWlTdGF0ZUpTT04iLCJ2aXMiLCJzb3J0IiwiY29sdW1uSW5kZXgiLCJkaXJlY3Rpb24iLCJkZXNjcmlwdGlvbiIsInZlcnNpb24iLCJraWJhbmFTYXZlZE9iamVjdE1ldGEiLCJzZWFyY2hTb3VyY2VKU09OIiwiaW5kZXgiLCJxdWVyeSIsImxhbmd1YWdlIiwiZmlsdGVyIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJjYXRlZ29yeUF4ZXMiLCJwb3NpdGlvbiIsInN0eWxlIiwic2NhbGUiLCJ2YWx1ZUF4ZXMiLCJuYW1lIiwibW9kZSIsInJvdGF0ZSIsInRleHQiLCJzZXJpZXNQYXJhbXMiLCJkYXRhIiwidmFsdWVBeGlzIiwiZHJhd0xpbmVzQmV0d2VlblBvaW50cyIsImxpbmVXaWR0aCIsImludGVycG9sYXRlIiwic2hvd0NpcmNsZXMiLCJ0aW1lcyIsImFkZFRpbWVNYXJrZXIiLCJ0aHJlc2hvbGRMaW5lIiwidmFsdWUiLCJ3aWR0aCIsImNvbG9yIiwieCIsInkiLCJ1c2VOb3JtYWxpemVkRXNJbnRlcnZhbCIsInNjYWxlTWV0cmljVmFsdWVzIiwiaW50ZXJ2YWwiLCJkcm9wX3BhcnRpYWxzIiwibWluX2RvY19jb3VudCIsImV4dGVuZGVkX2JvdW5kcyJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7ZUFDZSxDQUNiO0FBQ0VBLEVBQUFBLEdBQUcsRUFBRSxrQ0FEUDtBQUVFQyxFQUFBQSxLQUFLLEVBQUUsZUFGVDtBQUdFQyxFQUFBQSxPQUFPLEVBQUU7QUFDUEMsSUFBQUEsS0FBSyxFQUFFLGFBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLHNCQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLEtBRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkQsUUFBQUEsSUFBSSxFQUFFLEtBREE7QUFFTkUsUUFBQUEsVUFBVSxFQUFFLElBRk47QUFHTkMsUUFBQUEsU0FBUyxFQUFFLElBSEw7QUFJTkMsUUFBQUEsY0FBYyxFQUFFLE9BSlY7QUFLTkMsUUFBQUEsT0FBTyxFQUFFLElBTEg7QUFNTkMsUUFBQUEsTUFBTSxFQUFFO0FBQUVDLFVBQUFBLElBQUksRUFBRSxLQUFSO0FBQWVDLFVBQUFBLE1BQU0sRUFBRSxJQUF2QjtBQUE2QkMsVUFBQUEsVUFBVSxFQUFFLElBQXpDO0FBQStDQyxVQUFBQSxRQUFRLEVBQUU7QUFBekQsU0FORjtBQU9OQyxRQUFBQSxVQUFVLEVBQUU7QUFDVkMsVUFBQUEsTUFBTSxFQUFFO0FBQ05DLFlBQUFBLFFBQVEsRUFBRSxDQURKO0FBRU5DLFlBQUFBLE1BQU0sRUFBRTtBQUFFQyxjQUFBQSxFQUFFLEVBQUU7QUFBTixhQUZGO0FBR05kLFlBQUFBLE1BQU0sRUFBRSxFQUhGO0FBSU5lLFlBQUFBLEtBQUssRUFBRSxP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QUFLRTFCLFFBQUFBLE1BQU0sRUFBRTtBQUNOMkIsVUFBQUEsS0FBSyxFQUFFLFdBREQ7QUFFTjhDLFVBQUFBLHVCQUF1QixFQUFFLElBRm5CO0FBR05DLFVBQUFBLGlCQUFpQixFQUFFLEtBSGI7QUFJTkMsVUFBQUEsUUFBUSxFQUFFLE1BSko7QUFLTkMsVUFBQUEsYUFBYSxFQUFFLEtBTFQ7QUFNTkMsVUFBQUEsYUFBYSxFQUFFLENBTlQ7QUFPTkMsVUFBQUEsZUFBZSxFQUFFO0FBUFg7QUFMVixPQUZJO0FBaEVpQixLQUFmLENBRkg7QUFxRlA1QyxJQUFBQSxXQUFXLEVBQUVyQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMxQnFDLE1BQUFBLEdBQUcsRUFBRTtBQUFFbkMsUUFBQUEsTUFBTSxFQUFFO0FBQUVvQyxVQUFBQSxJQUFJLEVBQUU7QUFBRUMsWUFBQUEsV0FBVyxFQUFFLENBQWY7QUFBa0JDLFlBQUFBLFNBQVMsRUFBRTtBQUE3QjtBQUFSO0FBQVY7QUFEcUIsS0FBZixDQXJGTjtBQXdGUEMsSUFBQUEsV0FBVyxFQUFFLEVBeEZOO0FBeUZQQyxJQUFBQSxPQUFPLEVBQUUsQ0F6RkY7QUEwRlBDLElBQUFBLHFCQUFxQixFQUFFO0FBQ3JCQyxNQUFBQSxnQkFBZ0IsRUFBRTdDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQy9CNkMsUUFBQUEsS0FBSyxFQUFFLGNBRHdCO0FBRS9CQyxRQUFBQSxLQUFLLEVBQUU7QUFBRUEsVUFBQUEsS0FBSyxFQUFFLEVBQVQ7QUFBYUMsVUFBQUEsUUFBUSxFQUFFO0FBQXZCLFNBRndCO0FBRy9CQyxRQUFBQSxNQUFNLEVBQUU7QUFIdUIsT0FBZjtBQURHO0FBMUZoQjtBQUhYLENBdmVhLEMiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTW9kdWxlIGZvciBBZ2VudHMvR0NQIHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1XZWxjb21lLVRvcC1QQ0knLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgNSBydWxlcycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ3RvcCBwY2kgcmVxdWlyZW1lbnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDEsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgbGFiZWw6ICdDb3VudCcsXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgICBwYXJzZWRVcmw6IHtcbiAgICAgICAgICAgICAgICAgICAgICBvcmlnaW46ICdodHRwOi8vMTcyLjE2LjEuMjo1NjAxJyxcbiAgICAgICAgICAgICAgICAgICAgICBwYXRobmFtZTogJy9hcHAva2liYW5hJyxcbiAgICAgICAgICAgICAgICAgICAgICBiYXNlUGF0aDogJycsXG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBsYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLnBjaV9kc3MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAyLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLVdlbGNvbWUtVG9wLUdEUFInLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgNSBHRFBSJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAndG9wIGdkcHIgcmVxdWlyZW1lbnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDEsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgbGFiZWw6ICdDb3VudCcsXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgICBwYXJzZWRVcmw6IHtcbiAgICAgICAgICAgICAgICAgICAgICBvcmlnaW46ICdodHRwOi8vMTcyLjE2LjEuMjo1NjAxJyxcbiAgICAgICAgICAgICAgICAgICAgICBwYXRobmFtZTogJy9hcHAva2liYW5hJyxcbiAgICAgICAgICAgICAgICAgICAgICBiYXNlUGF0aDogJycsXG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBsYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmdkcHInLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAyLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLVdlbGNvbWUtVG9wLUhJUEFBJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIDUgSElQQUEnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICd0b3AgaGlwYWEgcmVxdWlyZW1lbnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDEsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgbGFiZWw6ICdDb3VudCcsXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgICBwYXJzZWRVcmw6IHtcbiAgICAgICAgICAgICAgICAgICAgICBvcmlnaW46ICdodHRwOi8vMTcyLjE2LjEuMjo1NjAxJyxcbiAgICAgICAgICAgICAgICAgICAgICBwYXRobmFtZTogJy9hcHAva2liYW5hJyxcbiAgICAgICAgICAgICAgICAgICAgICBiYXNlUGF0aDogJycsXG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBsYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmhpcGFhJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSZXF1aXJlbWVudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMiwgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1XZWxjb21lLVRvcC1OSVNULTgwMC01MycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IE5JU1QtODAwLTUzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAndG9wIE5JU1QtODAwLTUzIHJlcXVpcmVtZW50cycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSwgdmFsdWVzOiB0cnVlLCBsYXN0X2xldmVsOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljOiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sXG4gICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgIGxhYmVsOiAnQ291bnQnLFxuICAgICAgICAgICAgICBhZ2dUeXBlOiAnY291bnQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIGJ1Y2tldHM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgcGFyc2VkVXJsOiB7XG4gICAgICAgICAgICAgICAgICAgICAgb3JpZ2luOiAnaHR0cDovLzE3Mi4xNi4xLjI6NTYwMScsXG4gICAgICAgICAgICAgICAgICAgICAgcGF0aG5hbWU6ICcvYXBwL2tpYmFuYScsXG4gICAgICAgICAgICAgICAgICAgICAgYmFzZVBhdGg6ICcnLFxuICAgICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgbGFiZWw6ICdSZXF1aXJlbWVudCcsXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5uaXN0XzgwMF81MycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUmVxdWlyZW1lbnQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB2aXM6IHsgcGFyYW1zOiB7IHNvcnQ6IHsgY29sdW1uSW5kZXg6IDIsIGRpcmVjdGlvbjogJ2Rlc2MnIH0gfSB9LFxuICAgICAgfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtV2VsY29tZS1Ub3AtR1BHLTEzJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIDUgR1BHLTEzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAndG9wIEdQRy0xMyByZXF1aXJlbWVudHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UsIHZhbHVlczogdHJ1ZSwgbGFzdF9sZXZlbDogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIG1ldHJpYzoge1xuICAgICAgICAgICAgICBhY2Nlc3NvcjogMSxcbiAgICAgICAgICAgICAgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICBsYWJlbDogJ0NvdW50JyxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBidWNrZXRzOiBbXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICAgIHBhcnNlZFVybDoge1xuICAgICAgICAgICAgICAgICAgICAgIG9yaWdpbjogJ2h0dHA6Ly8xNzIuMTYuMS4yOjU2MDEnLFxuICAgICAgICAgICAgICAgICAgICAgIHBhdGhuYW1lOiAnL2FwcC9raWJhbmEnLFxuICAgICAgICAgICAgICAgICAgICAgIGJhc2VQYXRoOiAnJyxcbiAgICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGxhYmVsOiAnUmVxdWlyZW1lbnQnLFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZ3BnMTMnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAyLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLVdlbGNvbWUtVG9wLVRTQycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IFRTQycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ3RvcCBUU0MgcmVxdWlyZW1lbnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDEsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgbGFiZWw6ICdDb3VudCcsXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICdjb3VudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgICBwYXJzZWRVcmw6IHtcbiAgICAgICAgICAgICAgICAgICAgICBvcmlnaW46ICdodHRwOi8vMTcyLjE2LjEuMjo1NjAxJyxcbiAgICAgICAgICAgICAgICAgICAgICBwYXRobmFtZTogJy9hcHAva2liYW5hJyxcbiAgICAgICAgICAgICAgICAgICAgICBiYXNlUGF0aDogJycsXG4gICAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBsYWJlbDogJ1JlcXVpcmVtZW50JyxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLnRzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUmVxdWlyZW1lbnQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB2aXM6IHsgcGFyYW1zOiB7IHNvcnQ6IHsgY29sdW1uSW5kZXg6IDIsIGRpcmVjdGlvbjogJ2Rlc2MnIH0gfSB9LFxuICAgICAgfSksXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtV2VsY29tZS1FdmVudHMtRXZvbHV0aW9uJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnRXZlbnRzIGV2b2x1dGlvbicsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ2V2ZW50IGV2b2x1dGlvbicsXG4gICAgICAgIHR5cGU6ICdsaW5lJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogZmFsc2UgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHR5cGU6ICdsaW5lJyxcbiAgICAgICAgICAgICAgbW9kZTogJ25vcm1hbCcsXG4gICAgICAgICAgICAgIGRhdGE6IHsgbGFiZWw6ICdDb3VudCcsIGlkOiAnMScgfSxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBkcmF3TGluZXNCZXR3ZWVuUG9pbnRzOiB0cnVlLFxuICAgICAgICAgICAgICBsaW5lV2lkdGg6IDIsXG4gICAgICAgICAgICAgIGludGVycG9sYXRlOiAnbGluZWFyJyxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IGZhbHNlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHt9LFxuICAgICAgICAgIHRocmVzaG9sZExpbmU6IHsgc2hvdzogZmFsc2UsIHZhbHVlOiAxMCwgd2lkdGg6IDEsIHN0eWxlOiAnZnVsbCcsIGNvbG9yOiAnI0U3NjY0QycgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiBudWxsLFxuICAgICAgICAgICAgeTogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgbGFiZWw6ICdDb3VudCcsXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ2NvdW50JyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAndGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgdXNlTm9ybWFsaXplZEVzSW50ZXJ2YWw6IHRydWUsXG4gICAgICAgICAgICAgIHNjYWxlTWV0cmljVmFsdWVzOiBmYWxzZSxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgZHJvcF9wYXJ0aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMiwgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXTtcbiJdfQ==