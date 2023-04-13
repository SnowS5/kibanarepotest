"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Module for Overview/GCP visualizations
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
var _default = [// NUEVO DASHBOARD
{
  _id: 'Wazuh-App-Overview-GCP-Alerts-Evolution-By-AuthAnswer',
  _source: {
    title: 'Events over time by auth answer',
    visState: JSON.stringify({
      title: 'Alert evolution by auth result',
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
          type: 'area',
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
        thresholdLine: {
          show: false,
          value: 10,
          width: 1,
          style: 'full',
          color: '#34130C'
        },
        labels: {},
        dimensions: {
          x: null,
          y: [{
            accessor: 0,
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
          field: 'data.gcp.jsonPayload.authAnswer',
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
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-GCP-Top-vmInstances-By-ResponseCode',
  _source: {
    title: 'Top instances by response code',
    visState: JSON.stringify({
      title: 'Top VM instances by response code',
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
          field: 'data.gcp.jsonPayload.vmInstanceName',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'VM Instance Name'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'data.gcp.jsonPayload.responseCode',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Response Code'
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
  _id: 'Wazuh-App-Overview-GCP-Top-ResourceType-By-Project-Id',
  _source: {
    title: 'Resource type by project id',
    visState: JSON.stringify({
      title: 'Top resource type by project',
      type: 'horizontal_bar',
      params: {
        addLegend: true,
        addTimeMarker: false,
        addTooltip: true,
        categoryAxes: [{
          id: 'CategoryAxis-1',
          labels: {
            filter: false,
            rotate: 0,
            show: true,
            truncate: 200
          },
          position: 'bottom',
          scale: {
            type: 'linear'
          },
          show: true,
          style: {},
          title: {},
          type: 'category'
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
        },
        grid: {
          categoryLines: false
        },
        labels: {},
        legendPosition: 'right',
        seriesParams: [{
          data: {
            id: '1',
            label: 'Count'
          },
          drawLinesBetweenPoints: true,
          mode: 'normal',
          show: true,
          showCircles: true,
          type: 'histogram',
          valueAxis: 'ValueAxis-1'
        }],
        times: [],
        type: 'histogram',
        valueAxes: [{
          id: 'ValueAxis-1',
          labels: {
            filter: true,
            rotate: 75,
            show: true,
            truncate: 100
          },
          name: 'LeftAxis-2',
          position: 'left',
          scale: {
            mode: 'normal',
            type: 'linear'
          },
          show: true,
          style: {},
          title: {
            text: 'Count'
          },
          type: 'value'
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
          field: 'data.gcp.resource.labels.project_id',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Project ID'
        }
      }, {
        id: '3',
        enabled: true,
        type: 'terms',
        schema: 'group',
        params: {
          field: 'data.gcp.resource.type',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Resource type'
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
  _id: 'Wazuh-App-Overview-GCP-Top-ProjectId-By-SourceType',
  _source: {
    title: 'Top project id by sourcetype',
    visState: JSON.stringify({
      title: 'top project id by source type',
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
        id: '4',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'data.gcp.resource.labels.location',
          customLabel: 'Location',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing'
        }
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'data.gcp.resource.labels.project_id',
          customLabel: 'Project ID',
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
          field: 'data.gcp.resource.labels.source_type',
          customLabel: 'Source type',
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
          query: '',
          language: 'lucene'
        }
      })
    }
  },
  _type: 'visualization'
}, {
  _id: 'Wazuh-App-Overview-GCP-Map-By-SourceIp',
  _source: {
    title: 'Top 5 Map by source ip',
    visState: JSON.stringify({
      title: 'Map GCP source IP',
      type: 'tile_map',
      params: {
        colorSchema: 'Green to Red',
        mapType: 'Scaled Circle Markers',
        isDesaturated: false,
        addTooltip: true,
        heatClusterSize: 1.5,
        legendPosition: 'bottomright',
        mapZoom: 2,
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
            accessor: 2,
            format: {
              id: 'number'
            },
            params: {},
            aggType: 'count'
          },
          geohash: {
            accessor: 1,
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
            accessor: 3,
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
          mapZoom: 3,
          mapCenter: {
            lon: 1.3183593750000002,
            lat: 18.06231230454674
          },
          mapBounds: {
            bottom_right: {
              lat: -50.736455137010644,
              lon: 125.68359375000001
            },
            top_left: {
              lat: 68.72044056989829,
              lon: -123.04687500000001
            }
          }
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
  _id: 'Wazuh-App-Overview-GCP-Alerts-summary',
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
          size: 100,
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
    uiStateJSON: '{"vis":{"params":{"sort":{"columnIndex":3,"direction":"desc"}}}}',
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm92ZXJ2aWV3LWdjcC50cyJdLCJuYW1lcyI6WyJfaWQiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwiZ3JpZCIsImNhdGVnb3J5TGluZXMiLCJjYXRlZ29yeUF4ZXMiLCJpZCIsInBvc2l0aW9uIiwic2hvdyIsInN0eWxlIiwic2NhbGUiLCJsYWJlbHMiLCJmaWx0ZXIiLCJ0cnVuY2F0ZSIsInZhbHVlQXhlcyIsIm5hbWUiLCJtb2RlIiwicm90YXRlIiwidGV4dCIsInNlcmllc1BhcmFtcyIsImRhdGEiLCJsYWJlbCIsImRyYXdMaW5lc0JldHdlZW5Qb2ludHMiLCJzaG93Q2lyY2xlcyIsImludGVycG9sYXRlIiwidmFsdWVBeGlzIiwiYWRkVG9vbHRpcCIsImFkZExlZ2VuZCIsImxlZ2VuZFBvc2l0aW9uIiwidGltZXMiLCJhZGRUaW1lTWFya2VyIiwidGhyZXNob2xkTGluZSIsInZhbHVlIiwid2lkdGgiLCJjb2xvciIsImRpbWVuc2lvbnMiLCJ4IiwieSIsImFjY2Vzc29yIiwiZm9ybWF0IiwiYWdnVHlwZSIsImFnZ3MiLCJlbmFibGVkIiwic2NoZW1hIiwiZmllbGQiLCJ1c2VOb3JtYWxpemVkRXNJbnRlcnZhbCIsImludGVydmFsIiwiZHJvcF9wYXJ0aWFscyIsIm1pbl9kb2NfY291bnQiLCJleHRlbmRlZF9ib3VuZHMiLCJvcmRlckJ5Iiwib3JkZXIiLCJzaXplIiwib3RoZXJCdWNrZXQiLCJvdGhlckJ1Y2tldExhYmVsIiwibWlzc2luZ0J1Y2tldCIsIm1pc3NpbmdCdWNrZXRMYWJlbCIsInVpU3RhdGVKU09OIiwiZGVzY3JpcHRpb24iLCJ2ZXJzaW9uIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImluZGV4IiwicXVlcnkiLCJsYW5ndWFnZSIsIl90eXBlIiwiaXNEb251dCIsInZhbHVlcyIsImxhc3RfbGV2ZWwiLCJtZXRyaWMiLCJidWNrZXRzIiwiY3VzdG9tTGFiZWwiLCJzZXJpZXMiLCJjb2xvclNjaGVtYSIsIm1hcFR5cGUiLCJpc0Rlc2F0dXJhdGVkIiwiaGVhdENsdXN0ZXJTaXplIiwibWFwWm9vbSIsIm1hcENlbnRlciIsIndtcyIsIm9wdGlvbnMiLCJ0cmFuc3BhcmVudCIsImdlb2hhc2giLCJwcmVjaXNpb24iLCJ1c2VHZW9jZW50cm9pZCIsImdlb2NlbnRyb2lkIiwiYXV0b1ByZWNpc2lvbiIsImlzRmlsdGVyZWRCeUNvbGxhciIsImxvbiIsImxhdCIsIm1hcEJvdW5kcyIsImJvdHRvbV9yaWdodCIsInRvcF9sZWZ0IiwicGVyUGFnZSIsInNob3dQYXJ0aWFsUm93cyIsInNob3dNZXRpY3NBdEFsbExldmVscyIsInNvcnQiLCJjb2x1bW5JbmRleCIsImRpcmVjdGlvbiIsInNob3dUb3RhbCIsInNob3dUb29sYmFyIiwidG90YWxGdW5jIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtlQUNlLENBQ2I7QUFFQTtBQUNFQSxFQUFBQSxHQUFHLEVBQUUsdURBRFA7QUFFRUMsRUFBQUEsT0FBTyxFQUFFO0FBQ1BDLElBQUFBLEtBQUssRUFBRSxpQ0FEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUsZ0NBRGdCO0FBRXZCSSxNQUFBQSxJQUFJLEVBQUUsTUFGaUI7QUFHdkJDLE1BQUFBLE1BQU0sRUFBRTtBQUNORCxRQUFBQSxJQUFJLEVBQUUsTUFEQTtBQUVORSxRQUFBQSxJQUFJLEVBQUU7QUFBRUMsVUFBQUEsYUFBYSxFQUFFO0FBQWpCLFNBRkE7QUFHTkMsUUFBQUEsWUFBWSxFQUFFLENBQ1o7QUFDRUMsVUFBQUEsRUFBRSxFQUFFLGdCQUROO0FBRUVMLFVBQUFBLElBQUksRUFBRSxVQUZSO0FBR0VNLFVBQUFBLFFBQVEsRUFBRSxRQUhaO0FBSUVDLFVBQUFBLElB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O0FBQXZCO0FBSHdCLE9BQWY7QUFERztBQXhFaEI7QUFIWCxDQXJoQmEsQyIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgZm9yIE92ZXJ2aWV3L0dDUCB2aXN1YWxpemF0aW9uc1xuICogQ29weXJpZ2h0IChDKSAyMDE1LTIwMjIgV2F6dWgsIEluYy5cbiAqXG4gKiBUaGlzIHByb2dyYW0gaXMgZnJlZSBzb2Z0d2FyZTsgeW91IGNhbiByZWRpc3RyaWJ1dGUgaXQgYW5kL29yIG1vZGlmeVxuICogaXQgdW5kZXIgdGhlIHRlcm1zIG9mIHRoZSBHTlUgR2VuZXJhbCBQdWJsaWMgTGljZW5zZSBhcyBwdWJsaXNoZWQgYnlcbiAqIHRoZSBGcmVlIFNvZnR3YXJlIEZvdW5kYXRpb247IGVpdGhlciB2ZXJzaW9uIDIgb2YgdGhlIExpY2Vuc2UsIG9yXG4gKiAoYXQgeW91ciBvcHRpb24pIGFueSBsYXRlciB2ZXJzaW9uLlxuICpcbiAqIEZpbmQgbW9yZSBpbmZvcm1hdGlvbiBhYm91dCB0aGlzIG9uIHRoZSBMSUNFTlNFIGZpbGUuXG4gKi9cbmV4cG9ydCBkZWZhdWx0IFtcbiAgLy8gTlVFVk8gREFTSEJPQVJEXG5cbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1HQ1AtQWxlcnRzLUV2b2x1dGlvbi1CeS1BdXRoQW5zd2VyJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0V2ZW50cyBvdmVyIHRpbWUgYnkgYXV0aCBhbnN3ZXInLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdBbGVydCBldm9sdXRpb24gYnkgYXV0aCByZXN1bHQnLFxuICAgICAgICB0eXBlOiAnYXJlYScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IGZhbHNlIH0sXG4gICAgICAgICAgY2F0ZWdvcnlBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnQ2F0ZWdvcnlBeGlzLTEnLFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIGZpbHRlcjogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZToge30sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdmFsdWVBeGVzOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGlkOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgc2NhbGU6IHsgdHlwZTogJ2xpbmVhcicsIG1vZGU6ICdub3JtYWwnIH0sXG4gICAgICAgICAgICAgIGxhYmVsczogeyBzaG93OiB0cnVlLCByb3RhdGU6IDAsIGZpbHRlcjogZmFsc2UsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgdGl0bGU6IHsgdGV4dDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHNlcmllc1BhcmFtczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBzaG93OiAndHJ1ZScsXG4gICAgICAgICAgICAgIHR5cGU6ICdhcmVhJyxcbiAgICAgICAgICAgICAgbW9kZTogJ3N0YWNrZWQnLFxuICAgICAgICAgICAgICBkYXRhOiB7IGxhYmVsOiAnQ291bnQnLCBpZDogJzEnIH0sXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgICBpbnRlcnBvbGF0ZTogJ2xpbmVhcicsXG4gICAgICAgICAgICAgIHZhbHVlQXhpczogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICB0aW1lczogW10sXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgdGhyZXNob2xkTGluZTogeyBzaG93OiBmYWxzZSwgdmFsdWU6IDEwLCB3aWR0aDogMSwgc3R5bGU6ICdmdWxsJywgY29sb3I6ICcjMzQxMzBDJyB9LFxuICAgICAgICAgIGxhYmVsczoge30sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDogbnVsbCxcbiAgICAgICAgICAgIHk6IFt7IGFjY2Vzc29yOiAwLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ2RhdGVfaGlzdG9ncmFtJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAndGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgdXNlTm9ybWFsaXplZEVzSW50ZXJ2YWw6IHRydWUsXG4gICAgICAgICAgICAgIGludGVydmFsOiAnYXV0bycsXG4gICAgICAgICAgICAgIGRyb3BfcGFydGlhbHM6IGZhbHNlLFxuICAgICAgICAgICAgICBtaW5fZG9jX2NvdW50OiAxLFxuICAgICAgICAgICAgICBleHRlbmRlZF9ib3VuZHM6IHt9LFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLmpzb25QYXlsb2FkLmF1dGhBbnN3ZXInLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctR0NQLVRvcC12bUluc3RhbmNlcy1CeS1SZXNwb25zZUNvZGUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIGluc3RhbmNlcyBieSByZXNwb25zZSBjb2RlJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnVG9wIFZNIGluc3RhbmNlcyBieSByZXNwb25zZSBjb2RlJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAyLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLmpzb25QYXlsb2FkLnZtSW5zdGFuY2VOYW1lJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdWTSBJbnN0YW5jZSBOYW1lJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLmpzb25QYXlsb2FkLnJlc3BvbnNlQ29kZScsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUmVzcG9uc2UgQ29kZScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1HQ1AtVG9wLVJlc291cmNlVHlwZS1CeS1Qcm9qZWN0LUlkJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1Jlc291cmNlIHR5cGUgYnkgcHJvamVjdCBpZCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1RvcCByZXNvdXJjZSB0eXBlIGJ5IHByb2plY3QnLFxuICAgICAgICB0eXBlOiAnaG9yaXpvbnRhbF9iYXInLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBhZGRMZWdlbmQ6IHRydWUsXG4gICAgICAgICAgYWRkVGltZU1hcmtlcjogZmFsc2UsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIGxhYmVsczogeyBmaWx0ZXI6IGZhbHNlLCByb3RhdGU6IDAsIHNob3c6IHRydWUsIHRydW5jYXRlOiAyMDAgfSxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdib3R0b20nLFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgICAgdHlwZTogJ2NhdGVnb3J5JyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHsgaWQ6ICdzdHJpbmcnLCBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLCBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyB9LFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIHk6IFt7IGFjY2Vzc29yOiAyLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfV0sXG4gICAgICAgICAgICBzZXJpZXM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAxLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgICAgZ3JpZDogeyBjYXRlZ29yeUxpbmVzOiBmYWxzZSB9LFxuICAgICAgICAgIGxhYmVsczoge30sXG4gICAgICAgICAgbGVnZW5kUG9zaXRpb246ICdyaWdodCcsXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIGRhdGE6IHsgaWQ6ICcxJywgbGFiZWw6ICdDb3VudCcgfSxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgbW9kZTogJ25vcm1hbCcsXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGxhYmVsczogeyBmaWx0ZXI6IHRydWUsIHJvdGF0ZTogNzUsIHNob3c6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICAgICAgbmFtZTogJ0xlZnRBeGlzLTInLFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2xlZnQnLFxuICAgICAgICAgICAgICBzY2FsZTogeyBtb2RlOiAnbm9ybWFsJywgdHlwZTogJ2xpbmVhcicgfSxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICAgIHR5cGU6ICd2YWx1ZScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLnJlc291cmNlLmxhYmVscy5wcm9qZWN0X2lkJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdQcm9qZWN0IElEJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdncm91cCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLmdjcC5yZXNvdXJjZS50eXBlJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSZXNvdXJjZSB0eXBlJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLU92ZXJ2aWV3LUdDUC1Ub3AtUHJvamVjdElkLUJ5LVNvdXJjZVR5cGUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIHByb2plY3QgaWQgYnkgc291cmNldHlwZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ3RvcCBwcm9qZWN0IGlkIGJ5IHNvdXJjZSB0eXBlJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAyLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogNCxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLmdjcC5yZXNvdXJjZS5sYWJlbHMubG9jYXRpb24nLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0xvY2F0aW9uJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLnJlc291cmNlLmxhYmVscy5wcm9qZWN0X2lkJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdQcm9qZWN0IElEJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLnJlc291cmNlLmxhYmVscy5zb3VyY2VfdHlwZScsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnU291cmNlIHR5cGUnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtT3ZlcnZpZXctR0NQLU1hcC1CeS1Tb3VyY2VJcCcsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdUb3AgNSBNYXAgYnkgc291cmNlIGlwJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnTWFwIEdDUCBzb3VyY2UgSVAnLFxuICAgICAgICB0eXBlOiAndGlsZV9tYXAnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBjb2xvclNjaGVtYTogJ0dyZWVuIHRvIFJlZCcsXG4gICAgICAgICAgbWFwVHlwZTogJ1NjYWxlZCBDaXJjbGUgTWFya2VycycsXG4gICAgICAgICAgaXNEZXNhdHVyYXRlZDogZmFsc2UsXG4gICAgICAgICAgYWRkVG9vbHRpcDogdHJ1ZSxcbiAgICAgICAgICBoZWF0Q2x1c3RlclNpemU6IDEuNSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ2JvdHRvbXJpZ2h0JyxcbiAgICAgICAgICBtYXBab29tOiAyLFxuICAgICAgICAgIG1hcENlbnRlcjogWzAsIDBdLFxuICAgICAgICAgIHdtczogeyBlbmFibGVkOiBmYWxzZSwgb3B0aW9uczogeyBmb3JtYXQ6ICdpbWFnZS9wbmcnLCB0cmFuc3BhcmVudDogdHJ1ZSB9IH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljOiB7IGFjY2Vzc29yOiAyLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfSxcbiAgICAgICAgICAgIGdlb2hhc2g6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDEsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ3N0cmluZycgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7IHByZWNpc2lvbjogMiwgdXNlR2VvY2VudHJvaWQ6IHRydWUgfSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2dlb2hhc2hfZ3JpZCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgZ2VvY2VudHJvaWQ6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDMsXG4gICAgICAgICAgICAgIGZvcm1hdDogeyBpZDogJ3N0cmluZycgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ2dlb19jZW50cm9pZCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICdnZW9oYXNoX2dyaWQnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdHZW9Mb2NhdGlvbi5sb2NhdGlvbicsXG4gICAgICAgICAgICAgIGF1dG9QcmVjaXNpb246IHRydWUsXG4gICAgICAgICAgICAgIHByZWNpc2lvbjogMixcbiAgICAgICAgICAgICAgdXNlR2VvY2VudHJvaWQ6IHRydWUsXG4gICAgICAgICAgICAgIGlzRmlsdGVyZWRCeUNvbGxhcjogdHJ1ZSxcbiAgICAgICAgICAgICAgbWFwWm9vbTogMyxcbiAgICAgICAgICAgICAgbWFwQ2VudGVyOiB7IGxvbjogMS4zMTgzNTkzNzUwMDAwMDAyLCBsYXQ6IDE4LjA2MjMxMjMwNDU0Njc0IH0sXG4gICAgICAgICAgICAgIG1hcEJvdW5kczoge1xuICAgICAgICAgICAgICAgIGJvdHRvbV9yaWdodDogeyBsYXQ6IC01MC43MzY0NTUxMzcwMTA2NDQsIGxvbjogMTI1LjY4MzU5Mzc1MDAwMDAxIH0sXG4gICAgICAgICAgICAgICAgdG9wX2xlZnQ6IHsgbGF0OiA2OC43MjA0NDA1Njk4OTgyOSwgbG9uOiAtMTIzLjA0Njg3NTAwMDAwMDAxIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1PdmVydmlldy1HQ1AtQWxlcnRzLXN1bW1hcnknLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdBbGVydHMgc3VtbWFyeScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgICAgdHlwZTogJ3RhYmxlJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgcGVyUGFnZTogMTAsXG4gICAgICAgICAgc2hvd1BhcnRpYWxSb3dzOiBmYWxzZSxcbiAgICAgICAgICBzaG93TWV0aWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IDMsIGRpcmVjdGlvbjogJ2Rlc2MnIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaWQnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogNTAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdSdWxlIElEJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5kZXNjcmlwdGlvbicsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiAxMDAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdEZXNjcmlwdGlvbicsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMTIsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdMZXZlbCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne1widmlzXCI6e1wicGFyYW1zXCI6e1wic29ydFwiOntcImNvbHVtbkluZGV4XCI6MyxcImRpcmVjdGlvblwiOlwiZGVzY1wifX19fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbl07XG4iXX0=