"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview/AWS visualizations
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
  _id: 'Wazuh-App-Overview-AWS-Top-5-rules',
  _type: 'visualization',
  _source: {
    title: 'Top rules',
    visState: JSON.stringify({
      title: 'Top rules',
      type: 'table',
      params: {
        perPage: 10,
        showPartialRows: false,
        showMetricsAtAllLevels: false,
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
          field: 'rule.id',
          size: 500,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Rule ID'
        }
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'bucket',
        params: {
          field: 'rule.description',
          size: 10,
          order: 'desc',
          orderBy: '1',
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Event'
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
  _id: 'Wazuh-App-Overview-AWS-geo',
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
  _id: 'Wazuh-App-Overview-AWS-Events-by-source',
  _type: 'visualization',
  _source: {
    title: 'Events by source over time',
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
        legendPosition: 'left',
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
          field: 'data.aws.source',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-AWS-Top-accounts',
  _type: 'visualization',
  _source: {
    title: 'Accounts',
    visState: JSON.stringify({
      title: 'Accounts',
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
          field: 'data.aws.accountId',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-AWS-Top-sources',
  _type: 'visualization',
  _source: {
    title: 'Sources',
    visState: JSON.stringify({
      title: 'Sources',
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
          field: 'data.aws.source',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-AWS-Top-buckets',
  _type: 'visualization',
  _source: {
    title: 'Buckets',
    visState: JSON.stringify({
      title: 'Buckets',
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
          field: 'data.aws.log_info.s3bucket',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-AWS-Top-regions',
  _type: 'visualization',
  _source: {
    title: 'Regions',
    visState: JSON.stringify({
      title: 'Regions',
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
          field: 'data.aws.region',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-AWS-Events-by-s3-bucket',
  _type: 'visualization',
  _source: {
    title: 'Events by S3 bucket over time',
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
          field: 'data.aws.log_info.s3bucket',
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
        query: {
          query: '',
          language: 'lucene'
        },
        filter: []
      })
    }
  }
}, {
  _id: 'Wazuh-App-Overview-AWS-Alerts-summary',
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
          size: 1000,
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
}];
exports.default = _default;
module.exports = exports.default;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LWF3cy50cyJdLCJuYW1lcyI6WyJfaWQiLCJfdHlwZSIsIl9zb3VyY2UiLCJ0aXRsZSIsInZpc1N0YXRlIiwiSlNPTiIsInN0cmluZ2lmeSIsInR5cGUiLCJwYXJhbXMiLCJwZXJQYWdlIiwic2hvd1BhcnRpYWxSb3dzIiwic2hvd01ldHJpY3NBdEFsbExldmVscyIsInNvcnQiLCJjb2x1bW5JbmRleCIsImRpcmVjdGlvbiIsInNob3dUb3RhbCIsInNob3dUb29sYmFyIiwidG90YWxGdW5jIiwiYWdncyIsImlkIiwiZW5hYmxlZCIsInNjaGVtYSIsImZpZWxkIiwic2l6ZSIsIm9yZGVyIiwib3JkZXJCeSIsIm90aGVyQnVja2V0Iiwib3RoZXJCdWNrZXRMYWJlbCIsIm1pc3NpbmdCdWNrZXQiLCJtaXNzaW5nQnVja2V0TGFiZWwiLCJjdXN0b21MYWJlbCIsInVpU3RhdGVKU09OIiwidmlzIiwiZGVzY3JpcHRpb24iLCJ2ZXJzaW9uIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImluZGV4IiwicXVlcnkiLCJsYW5ndWFnZSIsImZpbHRlciIsImNvbG9yU2NoZW1hIiwibWFwVHlwZSIsImlzRGVzYXR1cmF0ZWQiLCJhZGRUb29sdGlwIiwiaGVhdENsdXN0ZXJTaXplIiwibGVnZW5kUG9zaXRpb24iLCJtYXBab29tIiwibWFwQ2VudGVyIiwid21zIiwib3B0aW9ucyIsImZvcm1hdCIsInRyYW5zcGFyZW50IiwiZGltZW5zaW9ucyIsIm1ldHJpYyIsImFjY2Vzc29yIiwiYWdnVHlwZSIsImdlb2hhc2giLCJwcmVjaXNpb24iLCJ1c2VHZW9jZW50cm9pZCIsImdlb2NlbnRyb2lkIiwiYXV0b1ByZWNpc2lvbiIsImlzRmlsdGVyZWRCeUNvbGxhciIsImdyaWQiLCJjYXRlZ29yeUxpbmVzIiwic3R5bGUiLCJjb2xvciIsInZhbHVlQXhpcyIsImNhdGVnb3J5QXhlcyIsInBvc2l0aW9uIiwic2hvdyIsInNjYWxlIiwibGFiZWxzIiwidHJ1bmNhdGUiLCJ2YWx1ZUF4ZXMiLCJuYW1lIiwibW9kZSIsInJvdGF0ZSIsInRleHQiLCJzZXJpZXNQYXJhbXMiLCJkYXRhIiwibGFiZWwiLCJkcmF3TGluZXNCZXR3ZWVuUG9pbnRzIiwic2hvd0NpcmNsZXMiLCJpbnRlcnBvbGF0ZSIsImFkZExlZ2VuZCIsInRpbWVzIiwiYWRkVGltZU1hcmtlciIsInRpbWVSYW5nZSIsImZyb20iLCJ0byIsInVzZU5vcm1hbGl6ZWRFc0ludGVydmFsIiwiaW50ZXJ2YWwiLCJ0aW1lX3pvbmUiLCJkcm9wX3BhcnRpYWxzIiwiY3VzdG9tSW50ZXJ2YWwiLCJtaW5fZG9jX2NvdW50IiwiZXh0ZW5kZWRfYm91bmRzIiwiaXNEb251dCIsInZhbHVlcyIsImxhc3RfbGV2ZWwiLCJzaG93TWV0aWNzQXRBbGxMZXZlbHMiXSwibWFwcGluZ3MiOiI7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO2VBQ2UsQ0FDYjtBQUNFQSxFQUFBQSxHQUFHLEVBQUUsb0NBRFA7QUFFRUMsRUFBQUEsS0FBSyxFQUFFLGVBRlQ7QUFHRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxXQURBO0FBRVBDLElBQUFBLFFBQVEsRUFBRUMsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDdkJILE1BQUFBLEtBQUssRUFBRSxXQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLE9BRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkMsUUFBQUEsT0FBTyxFQUFFLEVBREg7QUFFTkMsUUFBQUEsZUFBZSxFQUFFLEtBRlg7QUFHTkMsUUFBQUEsc0JBQXNCLEVBQUUsS0FIbEI7QUFJTkMsUUFBQUEsSUFBSSxFQUFFO0FBQUVDLFVBQUFBLFdBQVcsRUFBRSxDQUFmO0FBQWtCQyxVQUFBQSxTQUFTLEVBQUU7QUFBN0IsU0FKQTtBQUtOQyxRQUFBQSxTQUFTLEVBQUUsS0FMTDtBQU1OQyxRQUFBQSxXQUFX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b2R1bGUgZm9yIE92ZXJ2aWV3L0FXUyB2aXN1YWxpemF0aW9uc1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmV4cG9ydCBkZWZhdWx0IFtcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1BV1MtVG9wLTUtcnVsZXMnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgcnVsZXMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdUb3AgcnVsZXMnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRyaWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IDIsIGRpcmVjdGlvbjogJ2Rlc2MnIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaWQnLFxuICAgICAgICAgICAgICBzaXplOiA1MDAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUnVsZSBJRCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdFdmVudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMiwgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUFXUy1nZW8nLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdHZW9sb2NhdGlvbiBtYXAnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdHZW9sb2NhdGlvbiBtYXAnLFxuICAgICAgICB0eXBlOiAndGlsZV9tYXAnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgbWFwVHlwZTogJ1NjYWxlZCBDaXJjbGUgTWFya2VycycsXG4gICAgICAgICAgaXNEZXNhdHVyYXRlZDogZmFsc2UsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBoZWF0Q2x1c3RlclNpemU6IDEuNSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ2JvdHRvbXJpZ2h0JyxcbiAgICAgICAgICBtYXBab29tOiAxLFxuICAgICAgICAgIG1hcENlbnRlcjogWzAsIDBdLFxuICAgICAgICAgIHdtczogeyBlbmFibGVkOiBmYWxzZSwgb3B0aW9uczogeyBmb3JtYXQ6ICdpbWFnZS9wbmcnLCB0cmFuc3BhcmVudDogdHJ1ZSB9IH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljOiB7IGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfSxcbiAgICAgICAgICAgIGdlb2hhc2g6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ3N0cmluZycgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7IHByZWNpc2lvbjogMiwgdXNlR2VvY2VudHJvaWQ6IHRydWUgfSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2dlb2hhc2hfZ3JpZCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgZ2VvY2VudHJvaWQ6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDIsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ3N0cmluZycgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2dlb19jZW50cm9pZCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdnZW9oYXNoX2dyaWQnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdHZW9Mb2NhdGlvbi5sb2NhdGlvbicsXG4gICAgICAgICAgICAgIGF1dG9QcmVjaXNpb246IHRydWUsXG4gICAgICAgICAgICAgIHByZWNpc2lvbjogMixcbiAgICAgICAgICAgICAgdXNlR2VvY2VudHJvaWQ6IHRydWUsXG4gICAgICAgICAgICAgIGlzRmlsdGVyZWRCeUNvbGxhcjogdHJ1ZSxcbiAgICAgICAgICAgICAgbWFwWm9vbTogMSxcbiAgICAgICAgICAgICAgbWFwQ2VudGVyOiBbMCwgMF0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIG1hcFpvb206IDIsXG4gICAgICAgIG1hcENlbnRlcjogWzM4LjY4NTUwOTc2MDAxMjAyNSwgLTMxLjgxNjQwNjI1MDAwMDAwNF0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUFXUy1FdmVudHMtYnktc291cmNlJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnRXZlbnRzIGJ5IHNvdXJjZSBvdmVyIHRpbWUnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgYnkgYWN0aW9uIG92ZXIgdGltZScsXG4gICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogdHJ1ZSwgc3R5bGU6IHsgY29sb3I6ICcjZWVlJyB9LCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICAgICAgICBtb2RlOiAnc3RhY2tlZCcsXG4gICAgICAgICAgICAgIGRhdGE6IHsgbGFiZWw6ICdDb3VudCcsIGlkOiAnMScgfSxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGludGVycG9sYXRlOiAnY2FyZGluYWwnLFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3RpbWVzdGFtcCcsXG4gICAgICAgICAgICAgIHRpbWVSYW5nZTogeyBmcm9tOiAnbm93LTI0aCcsIHRvOiAnbm93JywgbW9kZTogJ3F1aWNrJyB9LFxuICAgICAgICAgICAgICB1c2VOb3JtYWxpemVkRXNJbnRlcnZhbDogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgdGltZV96b25lOiAnRXVyb3BlL0JlcmxpbicsXG4gICAgICAgICAgICAgIGRyb3BfcGFydGlhbHM6IGZhbHNlLFxuICAgICAgICAgICAgICBjdXN0b21JbnRlcnZhbDogJzJoJyxcbiAgICAgICAgICAgICAgbWluX2RvY19jb3VudDogMSxcbiAgICAgICAgICAgICAgZXh0ZW5kZWRfYm91bmRzOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLmF3cy5zb3VyY2UnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUFXUy1Ub3AtYWNjb3VudHMnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBY2NvdW50cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0FjY291bnRzJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5hd3MuYWNjb3VudElkJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1BV1MtVG9wLXNvdXJjZXMnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdTb3VyY2VzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnU291cmNlcycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSwgdmFsdWVzOiB0cnVlLCBsYXN0X2xldmVsOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuYXdzLnNvdXJjZScsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctQVdTLVRvcC1idWNrZXRzJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQnVja2V0cycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0J1Y2tldHMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UsIHZhbHVlczogdHJ1ZSwgbGFzdF9sZXZlbDogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLmF3cy5sb2dfaW5mby5zM2J1Y2tldCcsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctQVdTLVRvcC1yZWdpb25zJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUmVnaW9ucycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1JlZ2lvbnMnLFxuICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgaXNEb251dDogdHJ1ZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UsIHZhbHVlczogdHJ1ZSwgbGFzdF9sZXZlbDogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLmF3cy5yZWdpb24nLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUFXUy1FdmVudHMtYnktczMtYnVja2V0JyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnRXZlbnRzIGJ5IFMzIGJ1Y2tldCBvdmVyIHRpbWUnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydHMgYnkgYWN0aW9uIG92ZXIgdGltZScsXG4gICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICAgIGdyaWQ6IHsgY2F0ZWdvcnlMaW5lczogdHJ1ZSwgc3R5bGU6IHsgY29sb3I6ICcjZWVlJyB9LCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2FyZWEnLFxuICAgICAgICAgICAgICBtb2RlOiAnc3RhY2tlZCcsXG4gICAgICAgICAgICAgIGRhdGE6IHsgbGFiZWw6ICdDb3VudCcsIGlkOiAnMScgfSxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGludGVycG9sYXRlOiAnY2FyZGluYWwnLFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIGFkZFRpbWVNYXJrZXI6IGZhbHNlLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHsgZnJvbTogJ25vdy0yNGgnLCB0bzogJ25vdycsIG1vZGU6ICdxdWljaycgfSxcbiAgICAgICAgICAgICAgdXNlTm9ybWFsaXplZEVzSW50ZXJ2YWw6IHRydWUsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnYXV0bycsXG4gICAgICAgICAgICAgIHRpbWVfem9uZTogJ0V1cm9wZS9CZXJsaW4nLFxuICAgICAgICAgICAgICBkcm9wX3BhcnRpYWxzOiBmYWxzZSxcbiAgICAgICAgICAgICAgY3VzdG9tSW50ZXJ2YWw6ICcyaCcsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnZ3JvdXAnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5hd3MubG9nX2luZm8uczNidWNrZXQnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUFXUy1BbGVydHMtc3VtbWFyeScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5pZCcsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiA1MCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1J1bGUgSUQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmRlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIHNpemU6IDEwMDAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdEZXNjcmlwdGlvbicsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTIsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdMZXZlbCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXTtcbiJdfQ==