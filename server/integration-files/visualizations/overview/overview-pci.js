"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview/PCI visualizations
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
  _id: 'Wazuh-App-Overview-PCI-DSS-Requirements-over-time',
  _source: {
    title: 'Requirements over time',
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
          field: 'rule.pci_dss',
          size: '5',
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
          language: 'lucene',
          query: ''
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-PCI-DSS-Requirements-Agents-heatmap',
  _type: 'visualization',
  _source: {
    title: 'PCI requirements heatmap',
    visState: JSON.stringify({
      title: 'PCI requirements heatmap',
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
            color: '#555'
          }
        }]
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
          missingBucketLabel: 'Missing',
          customLabel: 'Requirements'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'agent.name',
          size: 5,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Agents'
        }
      }]
    }),
    uiStateJSON: JSON.stringify({
      vis: {
        defaultColors: {
          '0 - 13': 'rgb(247,252,245)',
          '13 - 26': 'rgb(233,247,228)',
          '26 - 39': 'rgb(211,238,205)',
          '39 - 52': 'rgb(184,227,177)',
          '52 - 65': 'rgb(152,213,148)',
          '65 - 78': 'rgb(116,196,118)',
          '78 - 91': 'rgb(75,176,98)',
          '91 - 104': 'rgb(47,152,79)',
          '104 - 117': 'rgb(21,127,59)',
          '117 - 130': 'rgb(0,100,40)'
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
  _id: 'Wazuh-App-Overview-PCI-DSS-requirements',
  _source: {
    title: 'PCI DSS requirements',
    visState: JSON.stringify({
      title: 'PCI DSS requirements',
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
                pattern: 'YYYY-MM-DD'
              }
            },
            params: {
              date: true,
              interval: 'P1D',
              format: 'YYYY-MM-DD'
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
        radiusRatio: 50
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
            from: 'now-1h',
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
          field: 'rule.pci_dss',
          orderBy: '1',
          order: 'desc',
          size: 50,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
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
  _id: 'Wazuh-App-Overview-PCI-DSS-Agents',
  _source: {
    title: 'Agents',
    visState: JSON.stringify({
      title: 'Agents',
      type: 'pie',
      params: {
        type: 'pie',
        addTooltip: true,
        addLegend: true,
        legendPosition: 'right',
        isDonut: false
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
  _id: 'Wazuh-App-Overview-PCI-DSS-Requirements-by-agent',
  _source: {
    title: 'Requirements by agent',
    visState: JSON.stringify({
      title: 'Requirements by agent',
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
        radiusRatio: 51
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
          customLabel: 'Requirements'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
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
  _id: 'Wazuh-App-Overview-PCI-DSS-Last-alerts',
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
          field: 'agent.name',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 50,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Agent name'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.pci_dss',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 10,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Requirement'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.description',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 10,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Rule description'
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
  _id: 'Wazuh-App-Overview-PCI-DSS-Alerts-summary',
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
          field: 'agent.name',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 50,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Agent name'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.pci_dss',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 10,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Requirement'
        }
      }, {
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.description',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          size: 10,
          order: 'desc',
          orderBy: '1',
          customLabel: 'Rule description'
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LXBjaS50cyJdLCJuYW1lcyI6WyJfaWQiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJzdHlsZSIsImNvbG9yIiwidmFsdWVBeGlzIiwiY2F0ZWdvcnlBeGVzIiwiaWQiLCJwb3NpdGlvbiIsInNob3ciLCJzY2FsZSIsImxhYmVscyIsImZpbHRlciIsInRydW5jYXRlIiwidmFsdWVBeGVzIiwibmFtZSIsIm1vZGUiLCJyb3RhdGUiLCJ0ZXh0Iiwic2VyaWVzUGFyYW1zIiwiZGF0YSIsImxhYmVsIiwiZHJhd0xpbmVzQmV0d2VlblBvaW50cyIsInNob3dDaXJjbGVzIiwiaW50ZXJwb2xhdGUiLCJhZGRUb29sdGlwIiwiYWRkTGVnZW5kIiwibGVnZW5kUG9zaXRpb24iLCJ0aW1lcyIsImFkZFRpbWVNYXJrZXIiLCJhZ2dzIiwiZW5hYmxlZCIsInNjaGVtYSIsImZpZWxkIiwidGltZVJhbmdlIiwiZnJvbSIsInRvIiwidXNlTm9ybWFsaXplZEVzSW50ZXJ2YWwiLCJpbnRlcnZhbCIsInRpbWVfem9uZSIsImRyb3BfcGFydGlhbHMiLCJjdXN0b21JbnRlcnZhbCIsIm1pbl9kb2NfY291bnQiLCJleHRlbmRlZF9ib3VuZHMiLCJzaXplIiwib3JkZXIiLCJvcmRlckJ5Iiwib3RoZXJCdWNrZXQiLCJvdGhlckJ1Y2tldExhYmVsIiwibWlzc2luZ0J1Y2tldCIsIm1pc3NpbmdCdWNrZXRMYWJlbCIsInVpU3RhdGVKU09OIiwiZGVzY3JpcHRpb24iLCJ2ZXJzaW9uIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImluZGV4IiwicXVlcnkiLCJsYW5ndWFnZSIsIl90eXBlIiwiZW5hYmxlSG92ZXIiLCJjb2xvcnNOdW1iZXIiLCJjb2xvclNjaGVtYSIsInNldENvbG9yUmFuZ2UiLCJjb2xvcnNSYW5nZSIsImludmVydENvbG9ycyIsInBlcmNlbnRhZ2VNb2RlIiwiZGVmYXVsdFlFeHRlbnRzIiwib3ZlcndyaXRlQ29sb3IiLCJjdXN0b21MYWJlbCIsInZpcyIsImRlZmF1bHRDb2xvcnMiLCJkaW1lbnNpb25zIiwieCIsImFjY2Vzc29yIiwiZm9ybWF0IiwicGF0dGVybiIsImRhdGUiLCJhZ2dUeXBlIiwieSIsInoiLCJzZXJpZXMiLCJyYWRpdXNSYXRpbyIsImlzRG9udXQiLCJwZXJQYWdlIiwic2hvd1BhcnRpYWxSb3dzIiwic2hvd01ldGljc0F0QWxsTGV2ZWxzIiwic29ydCIsImNvbHVtbkluZGV4IiwiZGlyZWN0aW9uIiwic2hvd1RvdGFsIiwic2hvd1Rvb2xiYXIiLCJ0b3RhbEZ1bmMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO2VBQ2UsQ0FDYjtBQUNFQSxFQUFBQSxHQUFHLEVBQUUsbURBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSx3QkFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUsNEJBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsTUFGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNORCxRQUFBQSxJQUFJLEVBQUUsTUFEQTtBQUVORSxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsYUFBYSxFQUFFLElBQWpCO0FBQXVCQyxVQUFBQSxLQUFLLEVBQUU7QUFBRUMsWUFBQUEsS0FBSyxFQUFFO0FBQVQsV0FBOUI7QUFBaURDLFVBQUFBLFNBQVMsRUFBRTtBQUE1RCxTQUZBO0FBR05DLFFBQUFBLFlBQVksRUFBRSxDQUNaO0FBQ0VDLFVBQUFBLEVBQUUsRUFBRSxnQkFETjtBQUVFUixVQUFBQSxJQUFJLEVBQUUsVUFGUjtBQUdFUyxVQUFBQSxRQUFRLEVBQUUsUUFIWjtBQUlFQyxV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QUhYLENBN2hCYSxDIiwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIFdhenVoIGFwcCAtIE1vZHVsZSBmb3IgT3ZlcnZpZXcvUENJIHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuZXhwb3J0IGRlZmF1bHQgW1xuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LVBDSS1EU1MtUmVxdWlyZW1lbnRzLW92ZXItdGltZScsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdSZXF1aXJlbWVudHMgb3ZlciB0aW1lJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnRzIGJ5IGFjdGlvbiBvdmVyIHRpbWUnLFxuICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IHRydWUsIHN0eWxlOiB7IGNvbG9yOiAnI2VlZScgfSwgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnIH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGZpbHRlcjogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIG1vZGU6ICdub3JtYWwnIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCByb3RhdGU6IDAsIGZpbHRlcjogZmFsc2UsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiAndHJ1ZScsXG4gICAgICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnBvbGF0ZTogJ2NhcmRpbmFsJyxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAndGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgdGltZVJhbmdlOiB7IGZyb206ICdub3ctMjRoJywgdG86ICdub3cnLCBtb2RlOiAncXVpY2snIH0sXG4gICAgICAgICAgICAgIHVzZU5vcm1hbGl6ZWRFc0ludGVydmFsOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnZhbDogJ2F1dG8nLFxuICAgICAgICAgICAgICB0aW1lX3pvbmU6ICdFdXJvcGUvQmVybGluJyxcbiAgICAgICAgICAgICAgZHJvcF9wYXJ0aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIGN1c3RvbUludGVydmFsOiAnMmgnLFxuICAgICAgICAgICAgICBtaW5fZG9jX2NvdW50OiAxLFxuICAgICAgICAgICAgICBleHRlbmRlZF9ib3VuZHM6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUucGNpX2RzcycsXG4gICAgICAgICAgICAgIHNpemU6ICc1JyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBsYW5ndWFnZTogJ2x1Y2VuZScsIHF1ZXJ5OiAnJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LVBDSS1EU1MtUmVxdWlyZW1lbnRzLUFnZW50cy1oZWF0bWFwJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUENJIHJlcXVpcmVtZW50cyBoZWF0bWFwJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnUENJIHJlcXVpcmVtZW50cyBoZWF0bWFwJyxcbiAgICAgICAgdHlwZTogJ2hlYXRtYXAnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGVhdG1hcCcsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgZW5hYmxlSG92ZXI6IGZhbHNlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBjb2xvcnNOdW1iZXI6IDEwLFxuICAgICAgICAgIGNvbG9yU2NoZW1hOiAnR3JlZW5zJyxcbiAgICAgICAgICBzZXRDb2xvclJhbmdlOiBmYWxzZSxcbiAgICAgICAgICBjb2xvcnNSYW5nZTogW10sXG4gICAgICAgICAgaW52ZXJ0Q29sb3JzOiBmYWxzZSxcbiAgICAgICAgICBwZXJjZW50YWdlTW9kZTogZmFsc2UsXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6IGZhbHNlLFxuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIGRlZmF1bHRZRXh0ZW50czogZmFsc2UgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCByb3RhdGU6IDAsIG92ZXJ3cml0ZUNvbG9yOiBmYWxzZSwgY29sb3I6ICcjNTU1JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLnBjaV9kc3MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50cycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnYWdlbnQubmFtZScsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnQWdlbnRzJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7XG4gICAgICAgICAgZGVmYXVsdENvbG9yczoge1xuICAgICAgICAgICAgJzAgLSAxMyc6ICdyZ2IoMjQ3LDI1MiwyNDUpJyxcbiAgICAgICAgICAgICcxMyAtIDI2JzogJ3JnYigyMzMsMjQ3LDIyOCknLFxuICAgICAgICAgICAgJzI2IC0gMzknOiAncmdiKDIxMSwyMzgsMjA1KScsXG4gICAgICAgICAgICAnMzkgLSA1Mic6ICdyZ2IoMTg0LDIyNywxNzcpJyxcbiAgICAgICAgICAgICc1MiAtIDY1JzogJ3JnYigxNTIsMjEzLDE0OCknLFxuICAgICAgICAgICAgJzY1IC0gNzgnOiAncmdiKDExNiwxOTYsMTE4KScsXG4gICAgICAgICAgICAnNzggLSA5MSc6ICdyZ2IoNzUsMTc2LDk4KScsXG4gICAgICAgICAgICAnOTEgLSAxMDQnOiAncmdiKDQ3LDE1Miw3OSknLFxuICAgICAgICAgICAgJzEwNCAtIDExNyc6ICdyZ2IoMjEsMTI3LDU5KScsXG4gICAgICAgICAgICAnMTE3IC0gMTMwJzogJ3JnYigwLDEwMCw0MCknLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LVBDSS1EU1MtcmVxdWlyZW1lbnRzJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1BDSSBEU1MgcmVxdWlyZW1lbnRzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnUENJIERTUyByZXF1aXJlbWVudHMnLFxuICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdsaW5lJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IHRydWUsIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyB9LFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCBmaWx0ZXI6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgICAgICAgIG1vZGU6ICdub3JtYWwnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogZmFsc2UsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHsgaWQ6ICdkYXRlJywgcGFyYW1zOiB7IHBhdHRlcm46ICdZWVlZLU1NLUREJyB9IH0sXG4gICAgICAgICAgICAgIHBhcmFtczogeyBkYXRlOiB0cnVlLCBpbnRlcnZhbDogJ1AxRCcsIGZvcm1hdDogJ1lZWVktTU0tREQnIH0sXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgeTogW3sgYWNjZXNzb3I6IDIsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9XSxcbiAgICAgICAgICAgIHo6IFt7IGFjY2Vzc29yOiAzLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBzZXJpZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgcmFkaXVzUmF0aW86IDUwLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHsgZnJvbTogJ25vdy0xaCcsIHRvOiAnbm93JyB9LFxuICAgICAgICAgICAgICB1c2VOb3JtYWxpemVkRXNJbnRlcnZhbDogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgZHJvcF9wYXJ0aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5wY2lfZHNzJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1MCxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAgeyBpZDogJzQnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdyYWRpdXMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1QQ0ktRFNTLUFnZW50cycsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBZ2VudHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBZ2VudHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogZmFsc2UsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczogeyBmaWVsZDogJ2FnZW50Lm5hbWUnLCBzaXplOiAxMCwgb3JkZXI6ICdkZXNjJywgb3JkZXJCeTogJzEnIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LVBDSS1EU1MtUmVxdWlyZW1lbnRzLWJ5LWFnZW50JyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1JlcXVpcmVtZW50cyBieSBhZ2VudCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1JlcXVpcmVtZW50cyBieSBhZ2VudCcsXG4gICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IGZhbHNlLCBzdHlsZTogeyBjb2xvcjogJyNlZWUnIH0gfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwLCByb3RhdGU6IDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAndmFsdWUnLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInLCBtb2RlOiAnbm9ybWFsJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgcm90YXRlOiAwLCBmaWx0ZXI6IGZhbHNlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgc2hvdzogJ3RydWUnLFxuICAgICAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIGFkZFRpbWVNYXJrZXI6IGZhbHNlLFxuICAgICAgICAgIHJhZGl1c1JhdGlvOiA1MSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5wY2lfZHNzJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1JlcXVpcmVtZW50cycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7IGZpZWxkOiAnYWdlbnQubmFtZScsIHNpemU6IDUsIG9yZGVyOiAnZGVzYycsIG9yZGVyQnk6ICcxJyB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1QQ0ktRFNTLUxhc3QtYWxlcnRzJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnTGFzdCBhbGVydHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdMYXN0IGFsZXJ0cycsXG4gICAgICAgIHR5cGU6ICd0YWJsZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHBlclBhZ2U6IDEwLFxuICAgICAgICAgIHNob3dQYXJ0aWFsUm93czogZmFsc2UsXG4gICAgICAgICAgc2hvd01ldGljc0F0QWxsTGV2ZWxzOiBmYWxzZSxcbiAgICAgICAgICBzb3J0OiB7IGNvbHVtbkluZGV4OiBudWxsLCBkaXJlY3Rpb246IG51bGwgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnYWdlbnQubmFtZScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiA1MCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FnZW50IG5hbWUnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLnBjaV9kc3MnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSZXF1aXJlbWVudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIGRlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctUENJLURTUy1BbGVydHMtc3VtbWFyeScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnYWdlbnQubmFtZScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiA1MCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0FnZW50IG5hbWUnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLnBjaV9kc3MnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSZXF1aXJlbWVudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIGRlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG5dO1xuIl19