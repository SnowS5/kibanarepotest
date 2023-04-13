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
  _id: 'Wazuh-App-Agents-GCP-Top-5-rules',
  _type: 'visualization',
  _source: {
    title: 'Top 5 rules',
    visState: JSON.stringify({
      title: 'Top 5 rules',
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
  _id: 'Wazuh-App-Agents-GCP-Event-Query-Name',
  _type: 'visualization',
  _source: {
    title: 'Top query events',
    visState: JSON.stringify({
      title: 'Wazuh-App-Agents-GCP-Query-Name',
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
          field: 'data.gcp.jsonPayload.queryName',
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
    uiStateJSON: '',
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
  _id: 'Wazuh-App-Agents-GCP-Tag-Severities',
  _type: 'visualization',
  _source: {
    title: 'Severities count',
    visState: JSON.stringify({
      title: 'Wazuh-App-Agents-GCP-Tag-Severities',
      type: 'tagcloud',
      params: {
        scale: 'linear',
        orientation: 'single',
        minFontSize: 18,
        maxFontSize: 72,
        showLabel: true,
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
        params: {
          customLabel: ''
        }
      }, {
        id: '2',
        enabled: true,
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'data.gcp.severity',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: true,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'Severities'
        }
      }]
    }),
    uiStateJSON: '',
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
  _id: 'Wazuh-App-Agents-GCP-Top-5-instances',
  _type: 'visualization',
  _source: {
    title: 'Top 5 instances',
    visState: JSON.stringify({
      title: 'Wazuh-App-Agents-GCP-Top-5-instances',
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
          field: 'data.gcp.jsonPayload.vmInstanceId',
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
    uiStateJSON: '',
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
  _id: 'Wazuh-App-Agents-GCP-Top-5-resource-type',
  _type: 'visualization',
  _source: {
    title: 'Top 5 Events type',
    visState: JSON.stringify({
      title: 'Wazuh-App-Agents-GCP-Top-5-resource-type',
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
          field: 'data.gcp.resource.type',
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
    uiStateJSON: '',
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
  _id: 'Wazuh-App-Agents-GCP-authAnswer-Bar',
  _type: 'visualization',
  _source: {
    title: 'Auth answer count',
    visState: JSON.stringify({
      title: 'Wazuh-App-Agents-GCP-authAnswer-Bar',
      type: 'histogram',
      params: {
        type: 'histogram',
        grid: {
          categoryLines: false,
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
        type: 'terms',
        schema: 'segment',
        params: {
          field: 'data.gcp.jsonPayload.authAnswer',
          orderBy: '1',
          order: 'desc',
          size: 5,
          otherBucket: false,
          otherBucketLabel: 'Other',
          missingBucket: false,
          missingBucketLabel: 'Missing',
          customLabel: 'authAnswer'
        }
      }]
    }),
    uiStateJSON: '',
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
  _id: 'Wazuh-App-Agents-GCP-Events-Over-Time',
  _type: 'visualization',
  _source: {
    title: 'GCP alerts evolution',
    visState: JSON.stringify({
      title: 'Wazuh-App-Agents-GCP-Events-Over-Time',
      type: 'line',
      params: {
        type: 'line',
        grid: {
          categoryLines: false,
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
              format: 'YYYY-MM-DD',
              bounds: {
                min: '2019-09-07T14:30:14.047Z',
                max: '2019-11-07T14:19:07.505Z'
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
            from: 'now-2M',
            to: '2019-11-07T14:19:07.505Z'
          },
          useNormalizedEsInterval: true,
          interval: 'auto',
          drop_partials: false,
          min_doc_count: 1,
          extended_bounds: {},
          customLabel: ''
        }
      }]
    }),
    uiStateJSON: '',
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
  _id: 'Wazuh-App-Agents-GCP-Top-ResourceType-By-Project-Id',
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
  _id: 'Wazuh-App-Agents-GCP-Top-ProjectId-By-SourceType',
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
  _id: 'Wazuh-App-Agents-GCP-Alerts-summary',
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFnZW50cy1nY3AudHMiXSwibmFtZXMiOlsiX2lkIiwiX3R5cGUiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwicGVyUGFnZSIsInNob3dQYXJ0aWFsUm93cyIsInNob3dNZXRyaWNzQXRBbGxMZXZlbHMiLCJzb3J0IiwiY29sdW1uSW5kZXgiLCJkaXJlY3Rpb24iLCJzaG93VG90YWwiLCJzaG93VG9vbGJhciIsInRvdGFsRnVuYyIsImFnZ3MiLCJpZCIsImVuYWJsZWQiLCJzY2hlbWEiLCJmaWVsZCIsInNpemUiLCJvcmRlciIsIm9yZGVyQnkiLCJvdGhlckJ1Y2tldCIsIm90aGVyQnVja2V0TGFiZWwiLCJtaXNzaW5nQnVja2V0IiwibWlzc2luZ0J1Y2tldExhYmVsIiwiY3VzdG9tTGFiZWwiLCJ1aVN0YXRlSlNPTiIsInZpcyIsImRlc2NyaXB0aW9uIiwidmVyc2lvbiIsImtpYmFuYVNhdmVkT2JqZWN0TWV0YSIsInNlYXJjaFNvdXJjZUpTT04iLCJpbmRleCIsInF1ZXJ5IiwibGFuZ3VhZ2UiLCJmaWx0ZXIiLCJhZGRUb29sdGlwIiwiYWRkTGVnZW5kIiwibGVnZW5kUG9zaXRpb24iLCJpc0RvbnV0IiwibGFiZWxzIiwic2hvdyIsInZhbHVlcyIsImxhc3RfbGV2ZWwiLCJ0cnVuY2F0ZSIsImRpbWVuc2lvbnMiLCJtZXRyaWMiLCJhY2Nlc3NvciIsImZvcm1hdCIsImFnZ1R5cGUiLCJidWNrZXRzIiwic2NhbGUiLCJvcmllbnRhdGlvbiIsIm1pbkZvbnRTaXplIiwibWF4Rm9udFNpemUiLCJzaG93TGFiZWwiLCJncmlkIiwiY2F0ZWdvcnlMaW5lcyIsInZhbHVlQXhpcyIsImNhdGVnb3J5QXhlcyIsInBvc2l0aW9uIiwic3R5bGUiLCJ2YWx1ZUF4ZXMiLCJuYW1lIiwibW9kZSIsInJvdGF0ZSIsInRleHQiLCJzZXJpZXNQYXJhbXMiLCJkYXRhIiwibGFiZWwiLCJkcmF3TGluZXNCZXR3ZWVuUG9pbnRzIiwic2hvd0NpcmNsZXMiLCJ0aW1lcyIsImFkZFRpbWVNYXJrZXIiLCJ0aHJlc2hvbGRMaW5lIiwidmFsdWUiLCJ3aWR0aCIsImNvbG9yIiwieCIsInkiLCJpbnRlcnBvbGF0ZSIsInBhdHRlcm4iLCJkYXRlIiwiaW50ZXJ2YWwiLCJib3VuZHMiLCJtaW4iLCJtYXgiLCJ0aW1lUmFuZ2UiLCJmcm9tIiwidG8iLCJ1c2VOb3JtYWxpemVkRXNJbnRlcnZhbCIsImRyb3BfcGFydGlhbHMiLCJtaW5fZG9jX2NvdW50IiwiZXh0ZW5kZWRfYm91bmRzIiwic2VyaWVzIiwic2hvd01ldGljc0F0QWxsTGV2ZWxzIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtlQUVlLENBQ2I7QUFDRUEsRUFBQUEsR0FBRyxFQUFFLGtDQURQO0FBRUVDLEVBQUFBLEtBQUssRUFBRSxlQUZUO0FBR0VDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUsYUFEQTtBQUVQQyxJQUFBQSxRQUFRLEVBQUVDLElBQUksQ0FBQ0MsU0FBTCxDQUFlO0FBQ3ZCSCxNQUFBQSxLQUFLLEVBQUUsYUFEZ0I7QUFFdkJJLE1BQUFBLElBQUksRUFBRSxPQUZpQjtBQUd2QkMsTUFBQUEsTUFBTSxFQUFFO0FBQ05DLFFBQUFBLE9BQU8sRUFBRSxFQURIO0FBRU5DLFFBQUFBLGVBQWUsRUFBRSxLQUZYO0FBR05DLFFBQUFBLHNCQUFzQixFQUFFLEtBSGxCO0FBSU5DLFFBQUFBLElBQUksRUFBRTtBQUFFQyxVQUFBQSxXQUFXLEVBQUUsQ0FBZjtBQUFrQkMsVUFBQUEsU0FBUyxFQUFFO0FBQTdCLFNBSkE7QUFLTkMsUUFBQUEsU0FBUyxFQUFFLEtBTEw7QUFNTkMsUUFBQUEsV0FBVyxFQUFFLElBTlA7QUFPTkMsUUFBQUEsU0FBUyxFQUFFO0FBUEwsT0FIZTtBQVl2QkMsTUFBQUEsSUFBSSxFQUFFLENBQ0o7QUFBRUMsUUFB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QUksQ0FBQ0MsU0FBTCxDQUFlO0FBQzFCMEIsTUFBQUEsR0FBRyxFQUFFO0FBQUV4QixRQUFBQSxNQUFNLEVBQUU7QUFBRUksVUFBQUEsSUFBSSxFQUFFO0FBQUVDLFlBQUFBLFdBQVcsRUFBRSxDQUFmO0FBQWtCQyxZQUFBQSxTQUFTLEVBQUU7QUFBN0I7QUFBUjtBQUFWO0FBRHFCLEtBQWYsQ0FyRU47QUF3RVBtQixJQUFBQSxXQUFXLEVBQUUsRUF4RU47QUF5RVBDLElBQUFBLE9BQU8sRUFBRSxDQXpFRjtBQTBFUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUFFL0IsSUFBSSxDQUFDQyxTQUFMLENBQWU7QUFDL0IrQixRQUFBQSxLQUFLLEVBQUUsY0FEd0I7QUFFL0JHLFFBQUFBLE1BQU0sRUFBRSxFQUZ1QjtBQUcvQkYsUUFBQUEsS0FBSyxFQUFFO0FBQUVBLFVBQUFBLEtBQUssRUFBRSxFQUFUO0FBQWFDLFVBQUFBLFFBQVEsRUFBRTtBQUF2QjtBQUh3QixPQUFmO0FBREc7QUExRWhCO0FBSFgsQ0F6d0JhLEMiLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogV2F6dWggYXBwIC0gTW9kdWxlIGZvciBBZ2VudHMvR0NQIHZpc3VhbGl6YXRpb25zXG4gKiBDb3B5cmlnaHQgKEMpIDIwMTUtMjAyMiBXYXp1aCwgSW5jLlxuICpcbiAqIFRoaXMgcHJvZ3JhbSBpcyBmcmVlIHNvZnR3YXJlOyB5b3UgY2FuIHJlZGlzdHJpYnV0ZSBpdCBhbmQvb3IgbW9kaWZ5XG4gKiBpdCB1bmRlciB0aGUgdGVybXMgb2YgdGhlIEdOVSBHZW5lcmFsIFB1YmxpYyBMaWNlbnNlIGFzIHB1Ymxpc2hlZCBieVxuICogdGhlIEZyZWUgU29mdHdhcmUgRm91bmRhdGlvbjsgZWl0aGVyIHZlcnNpb24gMiBvZiB0aGUgTGljZW5zZSwgb3JcbiAqIChhdCB5b3VyIG9wdGlvbikgYW55IGxhdGVyIHZlcnNpb24uXG4gKlxuICogRmluZCBtb3JlIGluZm9ybWF0aW9uIGFib3V0IHRoaXMgb24gdGhlIExJQ0VOU0UgZmlsZS5cbiAqL1xuXG5leHBvcnQgZGVmYXVsdCBbXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdDUC1Ub3AtNS1ydWxlcycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IHJ1bGVzJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnVG9wIDUgcnVsZXMnLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRyaWNzQXRBbGxMZXZlbHM6IGZhbHNlLFxuICAgICAgICAgIHNvcnQ6IHsgY29sdW1uSW5kZXg6IDIsIGRpcmVjdGlvbjogJ2Rlc2MnIH0sXG4gICAgICAgICAgc2hvd1RvdGFsOiBmYWxzZSxcbiAgICAgICAgICBzaG93VG9vbGJhcjogdHJ1ZSxcbiAgICAgICAgICB0b3RhbEZ1bmM6ICdzdW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICczJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuaWQnLFxuICAgICAgICAgICAgICBzaXplOiA1MDAsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnUnVsZSBJRCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUuZGVzY3JpcHRpb24nLFxuICAgICAgICAgICAgICBzaXplOiAxMCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdFdmVudCcsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHZpczogeyBwYXJhbXM6IHsgc29ydDogeyBjb2x1bW5JbmRleDogMiwgZGlyZWN0aW9uOiAnZGVzYycgfSB9IH0sXG4gICAgICB9KSxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1HQ1AtRXZlbnQtUXVlcnktTmFtZScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCBxdWVyeSBldmVudHMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aC1BcHAtQWdlbnRzLUdDUC1RdWVyeS1OYW1lJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5nY3AuanNvblBheWxvYWQucXVlcnlOYW1lJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICcnLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdDUC1UYWctU2V2ZXJpdGllcycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1NldmVyaXRpZXMgY291bnQnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aC1BcHAtQWdlbnRzLUdDUC1UYWctU2V2ZXJpdGllcycsXG4gICAgICAgIHR5cGU6ICd0YWdjbG91ZCcsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHNjYWxlOiAnbGluZWFyJyxcbiAgICAgICAgICBvcmllbnRhdGlvbjogJ3NpbmdsZScsXG4gICAgICAgICAgbWluRm9udFNpemU6IDE4LFxuICAgICAgICAgIG1heEZvbnRTaXplOiA3MixcbiAgICAgICAgICBzaG93TGFiZWw6IHRydWUsXG4gICAgICAgICAgbWV0cmljOiB7IHR5cGU6ICd2aXNfZGltZW5zaW9uJywgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ3N0cmluZycsIHBhcmFtczoge30gfSB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHsgY3VzdG9tTGFiZWw6ICcnIH0gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLnNldmVyaXR5JyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogdHJ1ZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1NldmVyaXRpZXMnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJycsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtR0NQLVRvcC01LWluc3RhbmNlcycsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IGluc3RhbmNlcycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1dhenVoLUFwcC1BZ2VudHMtR0NQLVRvcC01LWluc3RhbmNlcycsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSwgdmFsdWVzOiB0cnVlLCBsYXN0X2xldmVsOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljOiB7IGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfSxcbiAgICAgICAgICAgIGJ1Y2tldHM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLmpzb25QYXlsb2FkLnZtSW5zdGFuY2VJZCcsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgc2l6ZTogNSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgIF0sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAnJyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLUFnZW50cy1HQ1AtVG9wLTUtcmVzb3VyY2UtdHlwZScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1RvcCA1IEV2ZW50cyB0eXBlJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnV2F6dWgtQXBwLUFnZW50cy1HQ1AtVG9wLTUtcmVzb3VyY2UtdHlwZScsXG4gICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAncGllJyxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBpc0RvbnV0OiB0cnVlLFxuICAgICAgICAgIGxhYmVsczogeyBzaG93OiBmYWxzZSwgdmFsdWVzOiB0cnVlLCBsYXN0X2xldmVsOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgbWV0cmljOiB7IGFjY2Vzc29yOiAxLCBmb3JtYXQ6IHsgaWQ6ICdudW1iZXInIH0sIHBhcmFtczoge30sIGFnZ1R5cGU6ICdjb3VudCcgfSxcbiAgICAgICAgICAgIGJ1Y2tldHM6IFtcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICBdLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLnJlc291cmNlLnR5cGUnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJycsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtR0NQLWF1dGhBbnN3ZXItQmFyJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnQXV0aCBhbnN3ZXIgY291bnQnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aC1BcHAtQWdlbnRzLUdDUC1hdXRoQW5zd2VyLUJhcicsXG4gICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICB0eXBlOiAnaGlzdG9ncmFtJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IGZhbHNlLCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2hpc3RvZ3JhbScsXG4gICAgICAgICAgICAgIG1vZGU6ICdzdGFja2VkJyxcbiAgICAgICAgICAgICAgZGF0YTogeyBsYWJlbDogJ0NvdW50JywgaWQ6ICcxJyB9LFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIGRyYXdMaW5lc0JldHdlZW5Qb2ludHM6IHRydWUsXG4gICAgICAgICAgICAgIHNob3dDaXJjbGVzOiB0cnVlLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogZmFsc2UgfSxcbiAgICAgICAgICB0aHJlc2hvbGRMaW5lOiB7IHNob3c6IGZhbHNlLCB2YWx1ZTogMTAsIHdpZHRoOiAxLCBzdHlsZTogJ2Z1bGwnLCBjb2xvcjogJyMzNDEzMEMnIH0sXG4gICAgICAgICAgZGltZW5zaW9uczoge1xuICAgICAgICAgICAgeDoge1xuICAgICAgICAgICAgICBhY2Nlc3NvcjogMCxcbiAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7IGlkOiAnc3RyaW5nJywgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJywgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycgfSxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB5OiBbeyBhY2Nlc3NvcjogMSwgZm9ybWF0OiB7IGlkOiAnbnVtYmVyJyB9LCBwYXJhbXM6IHt9LCBhZ2dUeXBlOiAnY291bnQnIH1dLFxuICAgICAgICAgIH0sXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLmpzb25QYXlsb2FkLmF1dGhBbnN3ZXInLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ2F1dGhBbnN3ZXInLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJycsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLWFsZXJ0cycsXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1BZ2VudHMtR0NQLUV2ZW50cy1PdmVyLVRpbWUnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdHQ1AgYWxlcnRzIGV2b2x1dGlvbicsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1dhenVoLUFwcC1BZ2VudHMtR0NQLUV2ZW50cy1PdmVyLVRpbWUnLFxuICAgICAgICB0eXBlOiAnbGluZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdsaW5lJyxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IGZhbHNlLCB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScgfSxcbiAgICAgICAgICBjYXRlZ29yeUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdDYXRlZ29yeUF4aXMtMScsXG4gICAgICAgICAgICAgIHR5cGU6ICdjYXRlZ29yeScsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnYm90dG9tJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBsYWJlbHM6IHsgc2hvdzogdHJ1ZSwgZmlsdGVyOiB0cnVlLCB0cnVuY2F0ZTogMTAwIH0sXG4gICAgICAgICAgICAgIHRpdGxlOiB7fSxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgICB2YWx1ZUF4ZXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgaWQ6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICAgIG5hbWU6ICdMZWZ0QXhpcy0xJyxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgcG9zaXRpb246ICdsZWZ0JyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc3R5bGU6IHt9LFxuICAgICAgICAgICAgICBzY2FsZTogeyB0eXBlOiAnbGluZWFyJywgbW9kZTogJ25vcm1hbCcgfSxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IHNob3c6IHRydWUsIHJvdGF0ZTogMCwgZmlsdGVyOiBmYWxzZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICB0aXRsZTogeyB0ZXh0OiAnQ291bnQnIH0sXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgc2VyaWVzUGFyYW1zOiBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgIHNob3c6ICd0cnVlJyxcbiAgICAgICAgICAgICAgdHlwZTogJ2xpbmUnLFxuICAgICAgICAgICAgICBtb2RlOiAnc3RhY2tlZCcsXG4gICAgICAgICAgICAgIGRhdGE6IHsgbGFiZWw6ICdDb3VudCcsIGlkOiAnMScgfSxcbiAgICAgICAgICAgICAgZHJhd0xpbmVzQmV0d2VlblBvaW50czogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIGludGVycG9sYXRlOiAnbGluZWFyJyxcbiAgICAgICAgICAgICAgdmFsdWVBeGlzOiAnVmFsdWVBeGlzLTEnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIHRpbWVzOiBbXSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICB0aHJlc2hvbGRMaW5lOiB7IHNob3c6IGZhbHNlLCB2YWx1ZTogMTAsIHdpZHRoOiAxLCBzdHlsZTogJ2Z1bGwnLCBjb2xvcjogJyMzNDEzMEMnIH0sXG4gICAgICAgICAgbGFiZWxzOiB7fSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICB4OiB7XG4gICAgICAgICAgICAgIGFjY2Vzc29yOiAwLFxuICAgICAgICAgICAgICBmb3JtYXQ6IHsgaWQ6ICdkYXRlJywgcGFyYW1zOiB7IHBhdHRlcm46ICdZWVlZLU1NLUREJyB9IH0sXG4gICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgIGRhdGU6IHRydWUsXG4gICAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdQMUQnLFxuICAgICAgICAgICAgICAgIGZvcm1hdDogJ1lZWVktTU0tREQnLFxuICAgICAgICAgICAgICAgIGJvdW5kczogeyBtaW46ICcyMDE5LTA5LTA3VDE0OjMwOjE0LjA0N1onLCBtYXg6ICcyMDE5LTExLTA3VDE0OjE5OjA3LjUwNVonIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICdkYXRlX2hpc3RvZ3JhbScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgeTogW3sgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9XSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICcyJyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAnZGF0ZV9oaXN0b2dyYW0nLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICd0aW1lc3RhbXAnLFxuICAgICAgICAgICAgICB0aW1lUmFuZ2U6IHsgZnJvbTogJ25vdy0yTScsIHRvOiAnMjAxOS0xMS0wN1QxNDoxOTowNy41MDVaJyB9LFxuICAgICAgICAgICAgICB1c2VOb3JtYWxpemVkRXNJbnRlcnZhbDogdHJ1ZSxcbiAgICAgICAgICAgICAgaW50ZXJ2YWw6ICdhdXRvJyxcbiAgICAgICAgICAgICAgZHJvcF9wYXJ0aWFsczogZmFsc2UsXG4gICAgICAgICAgICAgIG1pbl9kb2NfY291bnQ6IDEsXG4gICAgICAgICAgICAgIGV4dGVuZGVkX2JvdW5kczoge30sXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICcnLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdDUC1Ub3AtUmVzb3VyY2VUeXBlLUJ5LVByb2plY3QtSWQnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnUmVzb3VyY2UgdHlwZSBieSBwcm9qZWN0IGlkJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnVG9wIHJlc291cmNlIHR5cGUgYnkgcHJvamVjdCcsXG4gICAgICAgIHR5cGU6ICdob3Jpem9udGFsX2JhcicsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGFkZExlZ2VuZDogdHJ1ZSxcbiAgICAgICAgICBhZGRUaW1lTWFya2VyOiBmYWxzZSxcbiAgICAgICAgICBhZGRUb29sdGlwOiB0cnVlLFxuICAgICAgICAgIGNhdGVnb3J5QXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ0NhdGVnb3J5QXhpcy0xJyxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IGZpbHRlcjogZmFsc2UsIHJvdGF0ZTogMCwgc2hvdzogdHJ1ZSwgdHJ1bmNhdGU6IDIwMCB9LFxuICAgICAgICAgICAgICBwb3NpdGlvbjogJ2JvdHRvbScsXG4gICAgICAgICAgICAgIHNjYWxlOiB7IHR5cGU6ICdsaW5lYXInIH0sXG4gICAgICAgICAgICAgIHNob3c6IHRydWUsXG4gICAgICAgICAgICAgIHN0eWxlOiB7fSxcbiAgICAgICAgICAgICAgdGl0bGU6IHt9LFxuICAgICAgICAgICAgICB0eXBlOiAnY2F0ZWdvcnknLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICBdLFxuICAgICAgICAgIGRpbWVuc2lvbnM6IHtcbiAgICAgICAgICAgIHg6IHtcbiAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgIHBhcmFtczogeyBpZDogJ3N0cmluZycsIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnIH0sXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgeTogW3sgYWNjZXNzb3I6IDIsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9XSxcbiAgICAgICAgICAgIHNlcmllczogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDEsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgIF0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICBncmlkOiB7IGNhdGVnb3J5TGluZXM6IGZhbHNlIH0sXG4gICAgICAgICAgbGFiZWxzOiB7fSxcbiAgICAgICAgICBsZWdlbmRQb3NpdGlvbjogJ3JpZ2h0JyxcbiAgICAgICAgICBzZXJpZXNQYXJhbXM6IFtcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgZGF0YTogeyBpZDogJzEnLCBsYWJlbDogJ0NvdW50JyB9LFxuICAgICAgICAgICAgICBkcmF3TGluZXNCZXR3ZWVuUG9pbnRzOiB0cnVlLFxuICAgICAgICAgICAgICBtb2RlOiAnbm9ybWFsJyxcbiAgICAgICAgICAgICAgc2hvdzogdHJ1ZSxcbiAgICAgICAgICAgICAgc2hvd0NpcmNsZXM6IHRydWUsXG4gICAgICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgICAgICB2YWx1ZUF4aXM6ICdWYWx1ZUF4aXMtMScsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIF0sXG4gICAgICAgICAgdGltZXM6IFtdLFxuICAgICAgICAgIHR5cGU6ICdoaXN0b2dyYW0nLFxuICAgICAgICAgIHZhbHVlQXhlczogW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICBpZDogJ1ZhbHVlQXhpcy0xJyxcbiAgICAgICAgICAgICAgbGFiZWxzOiB7IGZpbHRlcjogdHJ1ZSwgcm90YXRlOiA3NSwgc2hvdzogdHJ1ZSwgdHJ1bmNhdGU6IDEwMCB9LFxuICAgICAgICAgICAgICBuYW1lOiAnTGVmdEF4aXMtMicsXG4gICAgICAgICAgICAgIHBvc2l0aW9uOiAnbGVmdCcsXG4gICAgICAgICAgICAgIHNjYWxlOiB7IG1vZGU6ICdub3JtYWwnLCB0eXBlOiAnbGluZWFyJyB9LFxuICAgICAgICAgICAgICBzaG93OiB0cnVlLFxuICAgICAgICAgICAgICBzdHlsZToge30sXG4gICAgICAgICAgICAgIHRpdGxlOiB7IHRleHQ6ICdDb3VudCcgfSxcbiAgICAgICAgICAgICAgdHlwZTogJ3ZhbHVlJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgXSxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW1xuICAgICAgICAgIHsgaWQ6ICcxJywgZW5hYmxlZDogdHJ1ZSwgdHlwZTogJ2NvdW50Jywgc2NoZW1hOiAnbWV0cmljJywgcGFyYW1zOiB7fSB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMicsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ3NlZ21lbnQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAnZGF0YS5nY3AucmVzb3VyY2UubGFiZWxzLnByb2plY3RfaWQnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1Byb2plY3QgSUQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2dyb3VwJyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLnJlc291cmNlLnR5cGUnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1Jlc291cmNlIHR5cGUnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdDUC1Ub3AtUHJvamVjdElkLUJ5LVNvdXJjZVR5cGUnLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnVG9wIHByb2plY3QgaWQgYnkgc291cmNldHlwZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ3RvcCBwcm9qZWN0IGlkIGJ5IHNvdXJjZSB0eXBlJyxcbiAgICAgICAgdHlwZTogJ3BpZScsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIHR5cGU6ICdwaWUnLFxuICAgICAgICAgIGFkZFRvb2x0aXA6IHRydWUsXG4gICAgICAgICAgYWRkTGVnZW5kOiB0cnVlLFxuICAgICAgICAgIGxlZ2VuZFBvc2l0aW9uOiAncmlnaHQnLFxuICAgICAgICAgIGlzRG9udXQ6IHRydWUsXG4gICAgICAgICAgbGFiZWxzOiB7IHNob3c6IGZhbHNlLCB2YWx1ZXM6IHRydWUsIGxhc3RfbGV2ZWw6IHRydWUsIHRydW5jYXRlOiAxMDAgfSxcbiAgICAgICAgICBkaW1lbnNpb25zOiB7XG4gICAgICAgICAgICBtZXRyaWM6IHsgYWNjZXNzb3I6IDEsIGZvcm1hdDogeyBpZDogJ251bWJlcicgfSwgcGFyYW1zOiB7fSwgYWdnVHlwZTogJ2NvdW50JyB9LFxuICAgICAgICAgICAgYnVja2V0czogW1xuICAgICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgYWNjZXNzb3I6IDAsXG4gICAgICAgICAgICAgICAgZm9ybWF0OiB7XG4gICAgICAgICAgICAgICAgICBpZDogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICAgICAgICBpZDogJ3N0cmluZycsXG4gICAgICAgICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIHBhcmFtczoge30sXG4gICAgICAgICAgICAgICAgYWdnVHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGFjY2Vzc29yOiAyLFxuICAgICAgICAgICAgICAgIGZvcm1hdDoge1xuICAgICAgICAgICAgICAgICAgaWQ6ICd0ZXJtcycsXG4gICAgICAgICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgICAgICAgaWQ6ICdzdHJpbmcnLFxuICAgICAgICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgfSxcbiAgICAgICAgICAgICAgICBwYXJhbXM6IHt9LFxuICAgICAgICAgICAgICAgIGFnZ1R5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBhY2Nlc3NvcjogNCxcbiAgICAgICAgICAgICAgICBmb3JtYXQ6IHtcbiAgICAgICAgICAgICAgICAgIGlkOiAndGVybXMnLFxuICAgICAgICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgICAgICAgIGlkOiAnc3RyaW5nJyxcbiAgICAgICAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgcGFyYW1zOiB7fSxcbiAgICAgICAgICAgICAgICBhZ2dUeXBlOiAndGVybXMnLFxuICAgICAgICAgICAgICB9LFxuICAgICAgICAgICAgXSxcbiAgICAgICAgICB9LFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXG4gICAgICAgICAgeyBpZDogJzEnLCBlbmFibGVkOiB0cnVlLCB0eXBlOiAnY291bnQnLCBzY2hlbWE6ICdtZXRyaWMnLCBwYXJhbXM6IHt9IH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnc2VnbWVudCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdkYXRhLmdjcC5yZXNvdXJjZS5sYWJlbHMubG9jYXRpb24nLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0xvY2F0aW9uJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLnJlc291cmNlLmxhYmVscy5wcm9qZWN0X2lkJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdQcm9qZWN0IElEJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBvcmRlcjogJ2Rlc2MnLFxuICAgICAgICAgICAgICBzaXplOiA1LFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzMnLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdzZWdtZW50JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ2RhdGEuZ2NwLnJlc291cmNlLmxhYmVscy5zb3VyY2VfdHlwZScsXG4gICAgICAgICAgICAgIGN1c3RvbUxhYmVsOiAnU291cmNlIHR5cGUnLFxuICAgICAgICAgICAgICBvcmRlckJ5OiAnMScsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIHNpemU6IDUsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICBdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtYWxlcnRzJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtQWdlbnRzLUdDUC1BbGVydHMtc3VtbWFyeScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ0FsZXJ0cyBzdW1tYXJ5JyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnQWxlcnRzIHN1bW1hcnknLFxuICAgICAgICB0eXBlOiAndGFibGUnLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBwZXJQYWdlOiAxMCxcbiAgICAgICAgICBzaG93UGFydGlhbFJvd3M6IGZhbHNlLFxuICAgICAgICAgIHNob3dNZXRpY3NBdEFsbExldmVsczogZmFsc2UsXG4gICAgICAgICAgc29ydDogeyBjb2x1bW5JbmRleDogMywgZGlyZWN0aW9uOiAnZGVzYycgfSxcbiAgICAgICAgICBzaG93VG90YWw6IGZhbHNlLFxuICAgICAgICAgIHNob3dUb29sYmFyOiB0cnVlLFxuICAgICAgICAgIHRvdGFsRnVuYzogJ3N1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtcbiAgICAgICAgICB7IGlkOiAnMScsIGVuYWJsZWQ6IHRydWUsIHR5cGU6ICdjb3VudCcsIHNjaGVtYTogJ21ldHJpYycsIHBhcmFtczoge30gfSxcbiAgICAgICAgICB7XG4gICAgICAgICAgICBpZDogJzInLFxuICAgICAgICAgICAgZW5hYmxlZDogdHJ1ZSxcbiAgICAgICAgICAgIHR5cGU6ICd0ZXJtcycsXG4gICAgICAgICAgICBzY2hlbWE6ICdidWNrZXQnLFxuICAgICAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgICAgIGZpZWxkOiAncnVsZS5pZCcsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXRMYWJlbDogJ090aGVyJyxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXRMYWJlbDogJ01pc3NpbmcnLFxuICAgICAgICAgICAgICBzaXplOiA1MCxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ1J1bGUgSUQnLFxuICAgICAgICAgICAgfSxcbiAgICAgICAgICB9LFxuICAgICAgICAgIHtcbiAgICAgICAgICAgIGlkOiAnMycsXG4gICAgICAgICAgICBlbmFibGVkOiB0cnVlLFxuICAgICAgICAgICAgdHlwZTogJ3Rlcm1zJyxcbiAgICAgICAgICAgIHNjaGVtYTogJ2J1Y2tldCcsXG4gICAgICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICAgICAgZmllbGQ6ICdydWxlLmRlc2NyaXB0aW9uJyxcbiAgICAgICAgICAgICAgb3RoZXJCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldExhYmVsOiAnT3RoZXInLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0OiBmYWxzZSxcbiAgICAgICAgICAgICAgbWlzc2luZ0J1Y2tldExhYmVsOiAnTWlzc2luZycsXG4gICAgICAgICAgICAgIHNpemU6IDEsXG4gICAgICAgICAgICAgIG9yZGVyOiAnZGVzYycsXG4gICAgICAgICAgICAgIG9yZGVyQnk6ICcxJyxcbiAgICAgICAgICAgICAgY3VzdG9tTGFiZWw6ICdEZXNjcmlwdGlvbicsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgIH0sXG4gICAgICAgICAge1xuICAgICAgICAgICAgaWQ6ICc0JyxcbiAgICAgICAgICAgIGVuYWJsZWQ6IHRydWUsXG4gICAgICAgICAgICB0eXBlOiAndGVybXMnLFxuICAgICAgICAgICAgc2NoZW1hOiAnYnVja2V0JyxcbiAgICAgICAgICAgIHBhcmFtczoge1xuICAgICAgICAgICAgICBmaWVsZDogJ3J1bGUubGV2ZWwnLFxuICAgICAgICAgICAgICBvdGhlckJ1Y2tldDogZmFsc2UsXG4gICAgICAgICAgICAgIG90aGVyQnVja2V0TGFiZWw6ICdPdGhlcicsXG4gICAgICAgICAgICAgIG1pc3NpbmdCdWNrZXQ6IGZhbHNlLFxuICAgICAgICAgICAgICBtaXNzaW5nQnVja2V0TGFiZWw6ICdNaXNzaW5nJyxcbiAgICAgICAgICAgICAgc2l6ZTogMSxcbiAgICAgICAgICAgICAgb3JkZXI6ICdkZXNjJyxcbiAgICAgICAgICAgICAgb3JkZXJCeTogJzEnLFxuICAgICAgICAgICAgICBjdXN0b21MYWJlbDogJ0xldmVsJyxcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgfSxcbiAgICAgICAgXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdmlzOiB7IHBhcmFtczogeyBzb3J0OiB7IGNvbHVtbkluZGV4OiAzLCBkaXJlY3Rpb246ICdkZXNjJyB9IH0gfSxcbiAgICAgIH0pLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1hbGVydHMnLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG5dO1xuIl19