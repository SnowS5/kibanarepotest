"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.default = void 0;

/*
 * Wazuh app - Cluster monitoring visualizations
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
  _id: 'Wazuh-App-Statistics-remoted-Recv-bytes',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics remoted Recv bytes',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics remoted Recv bytes',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:remoted.recv_bytes, q='*').label(recv_bytes),.es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:remoted.recv_bytes, q='*').trend().label(Trend).lines(width=1.5)",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-remoted-event-count',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics remoted event count',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics remoted event count',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:remoted.evt_count, q='*').label(evt_count),.es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:remoted.evt_count, q='*').trend().label(Trend).lines(width=1.5)",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-remoted-messages',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics remoted messages',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics remoted messages',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:remoted.msg_sent, q='*').label(msg_sent),.es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:remoted.ctrl_msg_count, q='*').label(ctrl_msg_count),.es(index=wazuh-statistics-*,timefield=timestamp,metric=avg:remoted.discarded_count).label(discarded_count),.es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:remoted.dequeued_after_close, q='*').label(dequeued_after_close)",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-remoted-tcp-sessions',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics remoted tcp sessions',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics remoted tcp sessions',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=sum:remoted.tcp_sessions, q='*').label(tcp_sessions)",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-Overview-Events-Decoded',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics Overview events decoded',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics Overview events decode',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_events_decoded, q='*').label('Syscheck Events Decoded').bars(stack=true), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck, q='*').label('Syscollector Events Decoded').bars(stack=true), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_events_decoded, q='*').label('Rootcheck Events Decoded').bars(stack=true), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_events_decoded, q='*').label('SCA Events Decoded').bars(stack=true), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_events_decoded, q='*').label('Other Events Decoded').bars(stack=true), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_events_decoded, q='*').label('Host Info Events Decoded').bars(stack=true)",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-Syscheck',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics Syscheck',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics Syscheck',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_events_decoded, q='*').label('Syscheck Events Decoded'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_edps, q='*').label('Syscheck EDPS'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*').if(gte, 0.7, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*').if(gte, 0.9, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscheck_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-Syscollector',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics Syscollector',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics Syscollector',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_events_decoded, q='*').label('syscollector Events Decoded'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_edps, q='*').label('syscollector EDPS'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*').if(gte, 0.7, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*').if(gte, 0.9, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.syscollector_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-Rootcheck',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics Rootcheck',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics Rootcheck',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_events_decoded, q='*').label('Rootcheck Events Decoded'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_edps, q='*').label('Rootcheck EDPS'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage, q='*').if(gte, 0.7, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage, q='*').if(gte, 0.9, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rootcheck_queue_usage) ), null) .color('red').label('Queue Usage 90%+')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-SCA',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics SCA',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics SCA',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_events_decoded, q='*').label('SCA Events Decoded'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_edps, q='*').label('SCA EDPS'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*').if(gte, 0.7, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*').if(gte, 0.9, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.sca_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-HostInfo',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics HostInfo',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics HostInfo',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_events_decoded, q='*').label('Host info Events Decoded'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_edps, q='*').label('Host info EDPS'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*').if(gte, 0.7, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*').if(gte, 0.9, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.hostinfo_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-Other',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics Other',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics Other',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_events_decoded, q='*').label('Host info Events Decoded'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_edps, q='*').label('Host info EDPS'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*') ).label('Queue Usage').color('green'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*').if(gte, 0.7, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*') ), null) .color('#FFCC11').label('Queue Usage 70%+'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*').if(gte, 0.9, .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.other_queue_usage, q='*') ), null) .color('red').label('Queue Usage 90%+')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-Events-By-Node',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics Events by Node',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics Events by Node',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=sum:analysisd.events_processed, q='*') .label('Total'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=sum:analysisd.events_processed, q='*', split=nodeName.keyword:5).label('Events processed by Node: $1','^.* > nodeName.keyword:(\\\\S+) > .*')",
        interval: '5m'
      },
      aggs: []
    }),
    visStateByNode: JSON.stringify({
      title: 'Wazuh App Statistics Events by Node',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=sum:analysisd.events_processed, q='*') .label('Events processed by Node: NODE_NAME')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-Events-Dropped-By-Node',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics Events Dropped by Node',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics Events Dropped by Node',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=sum:analysisd.events_dropped, q='*') .label('Total'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=sum:analysisd.events_dropped, q='*', split=nodeName.keyword:5).label('Events dropped by Node: $1','^.* > nodeName.keyword:(\\\\S+) > .*')",
        interval: '5m'
      },
      aggs: []
    }),
    visStateByNode: JSON.stringify({
      title: 'Wazuh App Statistics Events by Node',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=sum:analysisd.events_dropped, q='*') .label('Events dropped by Node: NODE_NAME')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
        filter: [],
        query: {
          query: '',
          language: 'lucene'
        }
      })
    }
  }
}, {
  _id: 'Wazuh-App-Statistics-Analysisd-Queues-Usage',
  _type: 'visualization',
  _source: {
    title: 'Wazuh App Statistics Queues Usage',
    visState: JSON.stringify({
      title: 'Wazuh App Statistics Queues Usage',
      type: 'timelion',
      params: {
        expression: ".es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.event_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.event_queue_usage, q='*') ).label('Event queue usage'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rule_matching_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.rule_matching_queue_usage, q='*') ).label('Rule matching queue usage'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.alerts_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.alerts_queue_usage, q='*') ).label('Alerts log queue usage'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.firewall_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.firewall_queue_usage, q='*') ).label('Firewall log queue usage'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.statistical_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.statistical_queue_usage, q='*') ).label('Statistical log queue usage'), .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.archives_queue_size, q='*').multiply( .es(index=wazuh-statistics-*, timefield=timestamp,metric=avg:analysisd.archives_queue_usage, q='*') ).label('Statistical log queue usage')",
        interval: '5m'
      },
      aggs: []
    }),
    uiStateJSON: '{}',
    description: '',
    version: 1,
    kibanaSavedObjectMeta: {
      searchSourceJSON: JSON.stringify({
        index: 'wazuh-statistics-*',
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInN0YXRpc3RpY3MudHMiXSwibmFtZXMiOlsiX2lkIiwiX3R5cGUiLCJfc291cmNlIiwidGl0bGUiLCJ2aXNTdGF0ZSIsIkpTT04iLCJzdHJpbmdpZnkiLCJ0eXBlIiwicGFyYW1zIiwiZXhwcmVzc2lvbiIsImludGVydmFsIiwiYWdncyIsInVpU3RhdGVKU09OIiwiZGVzY3JpcHRpb24iLCJ2ZXJzaW9uIiwia2liYW5hU2F2ZWRPYmplY3RNZXRhIiwic2VhcmNoU291cmNlSlNPTiIsImluZGV4IiwiZmlsdGVyIiwicXVlcnkiLCJsYW5ndWFnZSIsInZpc1N0YXRlQnlOb2RlIl0sIm1hcHBpbmdzIjoiOzs7Ozs7O0FBQUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtlQUNlLENBQ2I7QUFDRUEsRUFBQUEsR0FBRyxFQUFFLHlDQURQO0FBRUVDLEVBQUFBLEtBQUssRUFBRSxlQUZUO0FBR0VDLEVBQUFBLE9BQU8sRUFBRTtBQUNQQyxJQUFBQSxLQUFLLEVBQUUseUNBREE7QUFFUEMsSUFBQUEsUUFBUSxFQUFFQyxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUN2QkgsTUFBQUEsS0FBSyxFQUFFLHlDQURnQjtBQUV2QkksTUFBQUEsSUFBSSxFQUFFLFVBRmlCO0FBR3ZCQyxNQUFBQSxNQUFNLEVBQUU7QUFDTkMsUUFBQUEsVUFBVSxFQUNSLHlPQUZJO0FBR05DLFFBQUFBLFFBQVEsRUFBRTtBQUhKLE9BSGU7QUFRdkJDLE1BQUFBLElBQUksRUFBRTtBQVJpQixLQUFmLENBRkg7QUFZUEMsSUFBQUEsV0FBVyxFQUFFLElBWk47QUFhUEMsSUFBQUEsV0FBVyxFQUFFLEVBYk47QUFjUEMsSUFBQUEsT0FBTyxFQUFFLENBZEY7QUFlUEMsSUFBQUEscUJBQXFCLEVBQUU7QUFDckJDLE1BQUFBLGdCQUFnQixFQUFFWCxJQUFJLENBQUNDLFNBQUwsQ0FBZTtBQUMvQlcsUUFBQUEsS0FBSyxFQUFFLG9CQUR3QjtBQUUvQkMsUUFB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QUFlO0FBQy9CVyxRQUFBQSxLQUFLLEVBQUUsb0JBRHdCO0FBRS9CQyxRQUFBQSxNQUFNLEVBQUUsRUFGdUI7QUFHL0JDLFFBQUFBLEtBQUssRUFBRTtBQUFFQSxVQUFBQSxLQUFLLEVBQUUsRUFBVDtBQUFhQyxVQUFBQSxRQUFRLEVBQUU7QUFBdkI7QUFId0IsT0FBZjtBQURHO0FBZmhCO0FBSFgsQ0FyWGEsQyIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBDbHVzdGVyIG1vbml0b3JpbmcgdmlzdWFsaXphdGlvbnNcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgZGVmYXVsdCBbXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtU3RhdGlzdGljcy1yZW1vdGVkLVJlY3YtYnl0ZXMnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyByZW1vdGVkIFJlY3YgYnl0ZXMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyByZW1vdGVkIFJlY3YgYnl0ZXMnLFxuICAgICAgICB0eXBlOiAndGltZWxpb24nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBleHByZXNzaW9uOlxuICAgICAgICAgICAgXCIuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6cmVtb3RlZC5yZWN2X2J5dGVzLCBxPScqJykubGFiZWwocmVjdl9ieXRlcyksLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOnJlbW90ZWQucmVjdl9ieXRlcywgcT0nKicpLnRyZW5kKCkubGFiZWwoVHJlbmQpLmxpbmVzKHdpZHRoPTEuNSlcIixcbiAgICAgICAgICBpbnRlcnZhbDogJzVtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW10sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1zdGF0aXN0aWNzLSonLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtU3RhdGlzdGljcy1yZW1vdGVkLWV2ZW50LWNvdW50JyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgcmVtb3RlZCBldmVudCBjb3VudCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1dhenVoIEFwcCBTdGF0aXN0aWNzIHJlbW90ZWQgZXZlbnQgY291bnQnLFxuICAgICAgICB0eXBlOiAndGltZWxpb24nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBleHByZXNzaW9uOlxuICAgICAgICAgICAgXCIuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6cmVtb3RlZC5ldnRfY291bnQsIHE9JyonKS5sYWJlbChldnRfY291bnQpLC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzpyZW1vdGVkLmV2dF9jb3VudCwgcT0nKicpLnRyZW5kKCkubGFiZWwoVHJlbmQpLmxpbmVzKHdpZHRoPTEuNSlcIixcbiAgICAgICAgICBpbnRlcnZhbDogJzVtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW10sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1zdGF0aXN0aWNzLSonLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtU3RhdGlzdGljcy1yZW1vdGVkLW1lc3NhZ2VzJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgcmVtb3RlZCBtZXNzYWdlcycsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1dhenVoIEFwcCBTdGF0aXN0aWNzIHJlbW90ZWQgbWVzc2FnZXMnLFxuICAgICAgICB0eXBlOiAndGltZWxpb24nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBleHByZXNzaW9uOlxuICAgICAgICAgICAgXCIuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6cmVtb3RlZC5tc2dfc2VudCwgcT0nKicpLmxhYmVsKG1zZ19zZW50KSwuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6cmVtb3RlZC5jdHJsX21zZ19jb3VudCwgcT0nKicpLmxhYmVsKGN0cmxfbXNnX2NvdW50KSwuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzpyZW1vdGVkLmRpc2NhcmRlZF9jb3VudCkubGFiZWwoZGlzY2FyZGVkX2NvdW50KSwuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6cmVtb3RlZC5kZXF1ZXVlZF9hZnRlcl9jbG9zZSwgcT0nKicpLmxhYmVsKGRlcXVldWVkX2FmdGVyX2Nsb3NlKVwiLFxuICAgICAgICAgIGludGVydmFsOiAnNW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLXN0YXRpc3RpY3MtKicsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1TdGF0aXN0aWNzLXJlbW90ZWQtdGNwLXNlc3Npb25zJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgcmVtb3RlZCB0Y3Agc2Vzc2lvbnMnLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyByZW1vdGVkIHRjcCBzZXNzaW9ucycsXG4gICAgICAgIHR5cGU6ICd0aW1lbGlvbicsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGV4cHJlc3Npb246XG4gICAgICAgICAgICBcIi5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPXN1bTpyZW1vdGVkLnRjcF9zZXNzaW9ucywgcT0nKicpLmxhYmVsKHRjcF9zZXNzaW9ucylcIixcbiAgICAgICAgICBpbnRlcnZhbDogJzVtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW10sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1zdGF0aXN0aWNzLSonLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtU3RhdGlzdGljcy1BbmFseXNpc2QtT3ZlcnZpZXctRXZlbnRzLURlY29kZWQnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBPdmVydmlldyBldmVudHMgZGVjb2RlZCcsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1dhenVoIEFwcCBTdGF0aXN0aWNzIE92ZXJ2aWV3IGV2ZW50cyBkZWNvZGUnLFxuICAgICAgICB0eXBlOiAndGltZWxpb24nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBleHByZXNzaW9uOlxuICAgICAgICAgICAgXCIuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnN5c2NoZWNrX2V2ZW50c19kZWNvZGVkLCBxPScqJykubGFiZWwoJ1N5c2NoZWNrIEV2ZW50cyBEZWNvZGVkJykuYmFycyhzdGFjaz10cnVlKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjaGVjaywgcT0nKicpLmxhYmVsKCdTeXNjb2xsZWN0b3IgRXZlbnRzIERlY29kZWQnKS5iYXJzKHN0YWNrPXRydWUpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnJvb3RjaGVja19ldmVudHNfZGVjb2RlZCwgcT0nKicpLmxhYmVsKCdSb290Y2hlY2sgRXZlbnRzIERlY29kZWQnKS5iYXJzKHN0YWNrPXRydWUpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnNjYV9ldmVudHNfZGVjb2RlZCwgcT0nKicpLmxhYmVsKCdTQ0EgRXZlbnRzIERlY29kZWQnKS5iYXJzKHN0YWNrPXRydWUpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLm90aGVyX2V2ZW50c19kZWNvZGVkLCBxPScqJykubGFiZWwoJ090aGVyIEV2ZW50cyBEZWNvZGVkJykuYmFycyhzdGFjaz10cnVlKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5ob3N0aW5mb19ldmVudHNfZGVjb2RlZCwgcT0nKicpLmxhYmVsKCdIb3N0IEluZm8gRXZlbnRzIERlY29kZWQnKS5iYXJzKHN0YWNrPXRydWUpXCIsXG4gICAgICAgICAgaW50ZXJ2YWw6ICc1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtc3RhdGlzdGljcy0qJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLVN0YXRpc3RpY3MtQW5hbHlzaXNkLVN5c2NoZWNrJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgU3lzY2hlY2snLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBTeXNjaGVjaycsXG4gICAgICAgIHR5cGU6ICd0aW1lbGlvbicsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGV4cHJlc3Npb246XG4gICAgICAgICAgICBcIi5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc3lzY2hlY2tfZXZlbnRzX2RlY29kZWQsIHE9JyonKS5sYWJlbCgnU3lzY2hlY2sgRXZlbnRzIERlY29kZWQnKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjaGVja19lZHBzLCBxPScqJykubGFiZWwoJ1N5c2NoZWNrIEVEUFMnKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjaGVja19xdWV1ZV9zaXplLCBxPScqJykubXVsdGlwbHkoIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc3lzY2hlY2tfcXVldWVfdXNhZ2UsIHE9JyonKSApLmxhYmVsKCdRdWV1ZSBVc2FnZScpLmNvbG9yKCdncmVlbicpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnN5c2NoZWNrX3F1ZXVlX3VzYWdlLCBxPScqJykuaWYoZ3RlLCAwLjcsIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc3lzY2hlY2tfcXVldWVfc2l6ZSwgcT0nKicpLm11bHRpcGx5KCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnN5c2NoZWNrX3F1ZXVlX3VzYWdlLCBxPScqJykgKSwgbnVsbCkgLmNvbG9yKCcjRkZDQzExJykubGFiZWwoJ1F1ZXVlIFVzYWdlIDcwJSsnKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjaGVja19xdWV1ZV91c2FnZSwgcT0nKicpLmlmKGd0ZSwgMC45LCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnN5c2NoZWNrX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjaGVja19xdWV1ZV91c2FnZSwgcT0nKicpICksIG51bGwpIC5jb2xvcigncmVkJykubGFiZWwoJ1F1ZXVlIFVzYWdlIDkwJSsnKVwiLFxuICAgICAgICAgIGludGVydmFsOiAnNW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXSxcbiAgICAgIH0pLFxuICAgICAgdWlTdGF0ZUpTT046ICd7fScsXG4gICAgICBkZXNjcmlwdGlvbjogJycsXG4gICAgICB2ZXJzaW9uOiAxLFxuICAgICAga2liYW5hU2F2ZWRPYmplY3RNZXRhOiB7XG4gICAgICAgIHNlYXJjaFNvdXJjZUpTT046IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgICBpbmRleDogJ3dhenVoLXN0YXRpc3RpY3MtKicsXG4gICAgICAgICAgZmlsdGVyOiBbXSxcbiAgICAgICAgICBxdWVyeTogeyBxdWVyeTogJycsIGxhbmd1YWdlOiAnbHVjZW5lJyB9LFxuICAgICAgICB9KSxcbiAgICAgIH0sXG4gICAgfSxcbiAgfSxcbiAge1xuICAgIF9pZDogJ1dhenVoLUFwcC1TdGF0aXN0aWNzLUFuYWx5c2lzZC1TeXNjb2xsZWN0b3InLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBTeXNjb2xsZWN0b3InLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBTeXNjb2xsZWN0b3InLFxuICAgICAgICB0eXBlOiAndGltZWxpb24nLFxuICAgICAgICBwYXJhbXM6IHtcbiAgICAgICAgICBleHByZXNzaW9uOlxuICAgICAgICAgICAgXCIuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnN5c2NvbGxlY3Rvcl9ldmVudHNfZGVjb2RlZCwgcT0nKicpLmxhYmVsKCdzeXNjb2xsZWN0b3IgRXZlbnRzIERlY29kZWQnKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjb2xsZWN0b3JfZWRwcywgcT0nKicpLmxhYmVsKCdzeXNjb2xsZWN0b3IgRURQUycpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnN5c2NvbGxlY3Rvcl9xdWV1ZV9zaXplLCBxPScqJykubXVsdGlwbHkoIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc3lzY29sbGVjdG9yX3F1ZXVlX3VzYWdlLCBxPScqJykgKS5sYWJlbCgnUXVldWUgVXNhZ2UnKS5jb2xvcignZ3JlZW4nKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjb2xsZWN0b3JfcXVldWVfdXNhZ2UsIHE9JyonKS5pZihndGUsIDAuNywgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjb2xsZWN0b3JfcXVldWVfc2l6ZSwgcT0nKicpLm11bHRpcGx5KCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnN5c2NvbGxlY3Rvcl9xdWV1ZV91c2FnZSwgcT0nKicpICksIG51bGwpIC5jb2xvcignI0ZGQ0MxMScpLmxhYmVsKCdRdWV1ZSBVc2FnZSA3MCUrJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc3lzY29sbGVjdG9yX3F1ZXVlX3VzYWdlLCBxPScqJykuaWYoZ3RlLCAwLjksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc3lzY29sbGVjdG9yX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zeXNjb2xsZWN0b3JfcXVldWVfdXNhZ2UsIHE9JyonKSApLCBudWxsKSAuY29sb3IoJ3JlZCcpLmxhYmVsKCdRdWV1ZSBVc2FnZSA5MCUrJylcIixcbiAgICAgICAgICBpbnRlcnZhbDogJzVtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW10sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1zdGF0aXN0aWNzLSonLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtU3RhdGlzdGljcy1BbmFseXNpc2QtUm9vdGNoZWNrJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgUm9vdGNoZWNrJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgUm9vdGNoZWNrJyxcbiAgICAgICAgdHlwZTogJ3RpbWVsaW9uJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgZXhwcmVzc2lvbjpcbiAgICAgICAgICAgIFwiLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5yb290Y2hlY2tfZXZlbnRzX2RlY29kZWQsIHE9JyonKS5sYWJlbCgnUm9vdGNoZWNrIEV2ZW50cyBEZWNvZGVkJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qucm9vdGNoZWNrX2VkcHMsIHE9JyonKS5sYWJlbCgnUm9vdGNoZWNrIEVEUFMnKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5yb290Y2hlY2tfcXVldWVfc2l6ZSwgcT0nKicpLm11bHRpcGx5KCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnJvb3RjaGVja19xdWV1ZV91c2FnZSwgcT0nKicpICkubGFiZWwoJ1F1ZXVlIFVzYWdlJykuY29sb3IoJ2dyZWVuJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qucm9vdGNoZWNrX3F1ZXVlX3VzYWdlLCBxPScqJykuaWYoZ3RlLCAwLjcsIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qucm9vdGNoZWNrX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5yb290Y2hlY2tfcXVldWVfdXNhZ2UsIHE9JyonKSApLCBudWxsKSAuY29sb3IoJyNGRkNDMTEnKS5sYWJlbCgnUXVldWUgVXNhZ2UgNzAlKycpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnJvb3RjaGVja19xdWV1ZV91c2FnZSwgcT0nKicpLmlmKGd0ZSwgMC45LCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnJvb3RjaGVja19xdWV1ZV9zaXplLCBxPScqJykubXVsdGlwbHkoIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qucm9vdGNoZWNrX3F1ZXVlX3VzYWdlKSApLCBudWxsKSAuY29sb3IoJ3JlZCcpLmxhYmVsKCdRdWV1ZSBVc2FnZSA5MCUrJylcIixcbiAgICAgICAgICBpbnRlcnZhbDogJzVtJyxcbiAgICAgICAgfSxcbiAgICAgICAgYWdnczogW10sXG4gICAgICB9KSxcbiAgICAgIHVpU3RhdGVKU09OOiAne30nLFxuICAgICAgZGVzY3JpcHRpb246ICcnLFxuICAgICAgdmVyc2lvbjogMSxcbiAgICAgIGtpYmFuYVNhdmVkT2JqZWN0TWV0YToge1xuICAgICAgICBzZWFyY2hTb3VyY2VKU09OOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgICAgaW5kZXg6ICd3YXp1aC1zdGF0aXN0aWNzLSonLFxuICAgICAgICAgIGZpbHRlcjogW10sXG4gICAgICAgICAgcXVlcnk6IHsgcXVlcnk6ICcnLCBsYW5ndWFnZTogJ2x1Y2VuZScgfSxcbiAgICAgICAgfSksXG4gICAgICB9LFxuICAgIH0sXG4gIH0sXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtU3RhdGlzdGljcy1BbmFseXNpc2QtU0NBJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgU0NBJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgU0NBJyxcbiAgICAgICAgdHlwZTogJ3RpbWVsaW9uJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgZXhwcmVzc2lvbjpcbiAgICAgICAgICAgIFwiLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zY2FfZXZlbnRzX2RlY29kZWQsIHE9JyonKS5sYWJlbCgnU0NBIEV2ZW50cyBEZWNvZGVkJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc2NhX2VkcHMsIHE9JyonKS5sYWJlbCgnU0NBIEVEUFMnKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zY2FfcXVldWVfc2l6ZSwgcT0nKicpLm11bHRpcGx5KCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnNjYV9xdWV1ZV91c2FnZSwgcT0nKicpICkubGFiZWwoJ1F1ZXVlIFVzYWdlJykuY29sb3IoJ2dyZWVuJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc2NhX3F1ZXVlX3VzYWdlLCBxPScqJykuaWYoZ3RlLCAwLjcsIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc2NhX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zY2FfcXVldWVfdXNhZ2UsIHE9JyonKSApLCBudWxsKSAuY29sb3IoJyNGRkNDMTEnKS5sYWJlbCgnUXVldWUgVXNhZ2UgNzAlKycpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnNjYV9xdWV1ZV91c2FnZSwgcT0nKicpLmlmKGd0ZSwgMC45LCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnNjYV9xdWV1ZV9zaXplLCBxPScqJykubXVsdGlwbHkoIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Quc2NhX3F1ZXVlX3VzYWdlLCBxPScqJykgKSwgbnVsbCkgLmNvbG9yKCdyZWQnKS5sYWJlbCgnUXVldWUgVXNhZ2UgOTAlKycpXCIsXG4gICAgICAgICAgaW50ZXJ2YWw6ICc1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtc3RhdGlzdGljcy0qJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLVN0YXRpc3RpY3MtQW5hbHlzaXNkLUhvc3RJbmZvJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgSG9zdEluZm8nLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBIb3N0SW5mbycsXG4gICAgICAgIHR5cGU6ICd0aW1lbGlvbicsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGV4cHJlc3Npb246XG4gICAgICAgICAgICBcIi5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2QuaG9zdGluZm9fZXZlbnRzX2RlY29kZWQsIHE9JyonKS5sYWJlbCgnSG9zdCBpbmZvIEV2ZW50cyBEZWNvZGVkJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2QuaG9zdGluZm9fZWRwcywgcT0nKicpLmxhYmVsKCdIb3N0IGluZm8gRURQUycpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLmhvc3RpbmZvX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5ob3N0aW5mb19xdWV1ZV91c2FnZSwgcT0nKicpICkubGFiZWwoJ1F1ZXVlIFVzYWdlJykuY29sb3IoJ2dyZWVuJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2QuaG9zdGluZm9fcXVldWVfdXNhZ2UsIHE9JyonKS5pZihndGUsIDAuNywgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5ob3N0aW5mb19xdWV1ZV9zaXplLCBxPScqJykubXVsdGlwbHkoIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2QuaG9zdGluZm9fcXVldWVfdXNhZ2UsIHE9JyonKSApLCBudWxsKSAuY29sb3IoJyNGRkNDMTEnKS5sYWJlbCgnUXVldWUgVXNhZ2UgNzAlKycpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLmhvc3RpbmZvX3F1ZXVlX3VzYWdlLCBxPScqJykuaWYoZ3RlLCAwLjksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2QuaG9zdGluZm9fcXVldWVfc2l6ZSwgcT0nKicpLm11bHRpcGx5KCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLmhvc3RpbmZvX3F1ZXVlX3VzYWdlLCBxPScqJykgKSwgbnVsbCkgLmNvbG9yKCdyZWQnKS5sYWJlbCgnUXVldWUgVXNhZ2UgOTAlKycpXCIsXG4gICAgICAgICAgaW50ZXJ2YWw6ICc1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtc3RhdGlzdGljcy0qJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLVN0YXRpc3RpY3MtQW5hbHlzaXNkLU90aGVyJyxcbiAgICBfdHlwZTogJ3Zpc3VhbGl6YXRpb24nLFxuICAgIF9zb3VyY2U6IHtcbiAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgT3RoZXInLFxuICAgICAgdmlzU3RhdGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBPdGhlcicsXG4gICAgICAgIHR5cGU6ICd0aW1lbGlvbicsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGV4cHJlc3Npb246XG4gICAgICAgICAgICBcIi5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qub3RoZXJfZXZlbnRzX2RlY29kZWQsIHE9JyonKS5sYWJlbCgnSG9zdCBpbmZvIEV2ZW50cyBEZWNvZGVkJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qub3RoZXJfZWRwcywgcT0nKicpLmxhYmVsKCdIb3N0IGluZm8gRURQUycpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLm90aGVyX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5vdGhlcl9xdWV1ZV91c2FnZSwgcT0nKicpICkubGFiZWwoJ1F1ZXVlIFVzYWdlJykuY29sb3IoJ2dyZWVuJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qub3RoZXJfcXVldWVfdXNhZ2UsIHE9JyonKS5pZihndGUsIDAuNywgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5vdGhlcl9xdWV1ZV9zaXplLCBxPScqJykubXVsdGlwbHkoIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qub3RoZXJfcXVldWVfdXNhZ2UsIHE9JyonKSApLCBudWxsKSAuY29sb3IoJyNGRkNDMTEnKS5sYWJlbCgnUXVldWUgVXNhZ2UgNzAlKycpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLm90aGVyX3F1ZXVlX3VzYWdlLCBxPScqJykuaWYoZ3RlLCAwLjksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2Qub3RoZXJfcXVldWVfc2l6ZSwgcT0nKicpLm11bHRpcGx5KCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLm90aGVyX3F1ZXVlX3VzYWdlLCBxPScqJykgKSwgbnVsbCkgLmNvbG9yKCdyZWQnKS5sYWJlbCgnUXVldWUgVXNhZ2UgOTAlKycpXCIsXG4gICAgICAgICAgaW50ZXJ2YWw6ICc1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtc3RhdGlzdGljcy0qJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXG4gIHtcbiAgICBfaWQ6ICdXYXp1aC1BcHAtU3RhdGlzdGljcy1BbmFseXNpc2QtRXZlbnRzLUJ5LU5vZGUnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBFdmVudHMgYnkgTm9kZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1dhenVoIEFwcCBTdGF0aXN0aWNzIEV2ZW50cyBieSBOb2RlJyxcbiAgICAgICAgdHlwZTogJ3RpbWVsaW9uJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgZXhwcmVzc2lvbjpcbiAgICAgICAgICAgIFwiLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9c3VtOmFuYWx5c2lzZC5ldmVudHNfcHJvY2Vzc2VkLCBxPScqJykgLmxhYmVsKCdUb3RhbCcpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1zdW06YW5hbHlzaXNkLmV2ZW50c19wcm9jZXNzZWQsIHE9JyonLCBzcGxpdD1ub2RlTmFtZS5rZXl3b3JkOjUpLmxhYmVsKCdFdmVudHMgcHJvY2Vzc2VkIGJ5IE5vZGU6ICQxJywnXi4qID4gbm9kZU5hbWUua2V5d29yZDooXFxcXFxcXFxTKykgPiAuKicpXCIsXG4gICAgICAgICAgaW50ZXJ2YWw6ICc1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtdLFxuICAgICAgfSksXG4gICAgICB2aXNTdGF0ZUJ5Tm9kZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1dhenVoIEFwcCBTdGF0aXN0aWNzIEV2ZW50cyBieSBOb2RlJyxcbiAgICAgICAgdHlwZTogJ3RpbWVsaW9uJyxcbiAgICAgICAgcGFyYW1zOiB7XG4gICAgICAgICAgZXhwcmVzc2lvbjpcbiAgICAgICAgICAgIFwiLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9c3VtOmFuYWx5c2lzZC5ldmVudHNfcHJvY2Vzc2VkLCBxPScqJykgLmxhYmVsKCdFdmVudHMgcHJvY2Vzc2VkIGJ5IE5vZGU6IE5PREVfTkFNRScpXCIsXG4gICAgICAgICAgaW50ZXJ2YWw6ICc1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtc3RhdGlzdGljcy0qJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLVN0YXRpc3RpY3MtQW5hbHlzaXNkLUV2ZW50cy1Ecm9wcGVkLUJ5LU5vZGUnLFxuICAgIF90eXBlOiAndmlzdWFsaXphdGlvbicsXG4gICAgX3NvdXJjZToge1xuICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBFdmVudHMgRHJvcHBlZCBieSBOb2RlJyxcbiAgICAgIHZpc1N0YXRlOiBKU09OLnN0cmluZ2lmeSh7XG4gICAgICAgIHRpdGxlOiAnV2F6dWggQXBwIFN0YXRpc3RpY3MgRXZlbnRzIERyb3BwZWQgYnkgTm9kZScsXG4gICAgICAgIHR5cGU6ICd0aW1lbGlvbicsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGV4cHJlc3Npb246XG4gICAgICAgICAgICBcIi5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPXN1bTphbmFseXNpc2QuZXZlbnRzX2Ryb3BwZWQsIHE9JyonKSAubGFiZWwoJ1RvdGFsJyksIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPXN1bTphbmFseXNpc2QuZXZlbnRzX2Ryb3BwZWQsIHE9JyonLCBzcGxpdD1ub2RlTmFtZS5rZXl3b3JkOjUpLmxhYmVsKCdFdmVudHMgZHJvcHBlZCBieSBOb2RlOiAkMScsJ14uKiA+IG5vZGVOYW1lLmtleXdvcmQ6KFxcXFxcXFxcUyspID4gLionKVwiLFxuICAgICAgICAgIGludGVydmFsOiAnNW0nLFxuICAgICAgICB9LFxuICAgICAgICBhZ2dzOiBbXSxcbiAgICAgIH0pLFxuICAgICAgdmlzU3RhdGVCeU5vZGU6IEpTT04uc3RyaW5naWZ5KHtcbiAgICAgICAgdGl0bGU6ICdXYXp1aCBBcHAgU3RhdGlzdGljcyBFdmVudHMgYnkgTm9kZScsXG4gICAgICAgIHR5cGU6ICd0aW1lbGlvbicsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGV4cHJlc3Npb246XG4gICAgICAgICAgICBcIi5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPXN1bTphbmFseXNpc2QuZXZlbnRzX2Ryb3BwZWQsIHE9JyonKSAubGFiZWwoJ0V2ZW50cyBkcm9wcGVkIGJ5IE5vZGU6IE5PREVfTkFNRScpXCIsXG4gICAgICAgICAgaW50ZXJ2YWw6ICc1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtc3RhdGlzdGljcy0qJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuICB7XG4gICAgX2lkOiAnV2F6dWgtQXBwLVN0YXRpc3RpY3MtQW5hbHlzaXNkLVF1ZXVlcy1Vc2FnZScsXG4gICAgX3R5cGU6ICd2aXN1YWxpemF0aW9uJyxcbiAgICBfc291cmNlOiB7XG4gICAgICB0aXRsZTogJ1dhenVoIEFwcCBTdGF0aXN0aWNzIFF1ZXVlcyBVc2FnZScsXG4gICAgICB2aXNTdGF0ZTogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICB0aXRsZTogJ1dhenVoIEFwcCBTdGF0aXN0aWNzIFF1ZXVlcyBVc2FnZScsXG4gICAgICAgIHR5cGU6ICd0aW1lbGlvbicsXG4gICAgICAgIHBhcmFtczoge1xuICAgICAgICAgIGV4cHJlc3Npb246XG4gICAgICAgICAgICBcIi5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2QuZXZlbnRfcXVldWVfc2l6ZSwgcT0nKicpLm11bHRpcGx5KCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLmV2ZW50X3F1ZXVlX3VzYWdlLCBxPScqJykgKS5sYWJlbCgnRXZlbnQgcXVldWUgdXNhZ2UnKSwgLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5ydWxlX21hdGNoaW5nX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5ydWxlX21hdGNoaW5nX3F1ZXVlX3VzYWdlLCBxPScqJykgKS5sYWJlbCgnUnVsZSBtYXRjaGluZyBxdWV1ZSB1c2FnZScpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLmFsZXJ0c19xdWV1ZV9zaXplLCBxPScqJykubXVsdGlwbHkoIC5lcyhpbmRleD13YXp1aC1zdGF0aXN0aWNzLSosIHRpbWVmaWVsZD10aW1lc3RhbXAsbWV0cmljPWF2ZzphbmFseXNpc2QuYWxlcnRzX3F1ZXVlX3VzYWdlLCBxPScqJykgKS5sYWJlbCgnQWxlcnRzIGxvZyBxdWV1ZSB1c2FnZScpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLmZpcmV3YWxsX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5maXJld2FsbF9xdWV1ZV91c2FnZSwgcT0nKicpICkubGFiZWwoJ0ZpcmV3YWxsIGxvZyBxdWV1ZSB1c2FnZScpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLnN0YXRpc3RpY2FsX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5zdGF0aXN0aWNhbF9xdWV1ZV91c2FnZSwgcT0nKicpICkubGFiZWwoJ1N0YXRpc3RpY2FsIGxvZyBxdWV1ZSB1c2FnZScpLCAuZXMoaW5kZXg9d2F6dWgtc3RhdGlzdGljcy0qLCB0aW1lZmllbGQ9dGltZXN0YW1wLG1ldHJpYz1hdmc6YW5hbHlzaXNkLmFyY2hpdmVzX3F1ZXVlX3NpemUsIHE9JyonKS5tdWx0aXBseSggLmVzKGluZGV4PXdhenVoLXN0YXRpc3RpY3MtKiwgdGltZWZpZWxkPXRpbWVzdGFtcCxtZXRyaWM9YXZnOmFuYWx5c2lzZC5hcmNoaXZlc19xdWV1ZV91c2FnZSwgcT0nKicpICkubGFiZWwoJ1N0YXRpc3RpY2FsIGxvZyBxdWV1ZSB1c2FnZScpXCIsXG4gICAgICAgICAgaW50ZXJ2YWw6ICc1bScsXG4gICAgICAgIH0sXG4gICAgICAgIGFnZ3M6IFtdLFxuICAgICAgfSksXG4gICAgICB1aVN0YXRlSlNPTjogJ3t9JyxcbiAgICAgIGRlc2NyaXB0aW9uOiAnJyxcbiAgICAgIHZlcnNpb246IDEsXG4gICAgICBraWJhbmFTYXZlZE9iamVjdE1ldGE6IHtcbiAgICAgICAgc2VhcmNoU291cmNlSlNPTjogSlNPTi5zdHJpbmdpZnkoe1xuICAgICAgICAgIGluZGV4OiAnd2F6dWgtc3RhdGlzdGljcy0qJyxcbiAgICAgICAgICBmaWx0ZXI6IFtdLFxuICAgICAgICAgIHF1ZXJ5OiB7IHF1ZXJ5OiAnJywgbGFuZ3VhZ2U6ICdsdWNlbmUnIH0sXG4gICAgICAgIH0pLFxuICAgICAgfSxcbiAgICB9LFxuICB9LFxuXTtcbiJdfQ==