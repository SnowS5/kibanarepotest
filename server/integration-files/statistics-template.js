"use strict";

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.statisticsTemplate = void 0;

/*
 * Wazuh app - Module for statistics template
 * Copyright (C) 2015-2022 Wazuh, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Find more information about this on the LICENSE file.
 */
const statisticsTemplate = {
  order: 0,
  settings: {
    'index.refresh_interval': '5s'
  },
  "mappings": {
    "dynamic_templates": [{
      "string_as_keyword": {
        "match_mapping_type": "string",
        "mapping": {
          "type": "keyword"
        }
      }
    }],
    "properties": {
      "analysisd": {
        "properties": {
          "alerts_queue_size": {
            "type": "long"
          },
          "alerts_queue_usage": {
            "type": "long"
          },
          "alerts_written": {
            "type": "long"
          },
          "archives_queue_size": {
            "type": "long"
          },
          "archives_queue_usage": {
            "type": "long"
          },
          "dbsync_mdps": {
            "type": "long"
          },
          "dbsync_messages_dispatched": {
            "type": "long"
          },
          "dbsync_queue_size": {
            "type": "long"
          },
          "dbsync_queue_usage": {
            "type": "long"
          },
          "event_queue_size": {
            "type": "long"
          },
          "event_queue_usage": {
            "type": "long"
          },
          "events_dropped": {
            "type": "long"
          },
          "events_edps": {
            "type": "long"
          },
          "events_processed": {
            "type": "long"
          },
          "events_received": {
            "type": "long"
          },
          "firewall_queue_size": {
            "type": "long"
          },
          "firewall_queue_usage": {
            "type": "long"
          },
          "firewall_written": {
            "type": "long"
          },
          "fts_written": {
            "type": "long"
          },
          "hostinfo_edps": {
            "type": "long"
          },
          "hostinfo_events_decoded": {
            "type": "long"
          },
          "hostinfo_queue_size": {
            "type": "long"
          },
          "hostinfo_queue_usage": {
            "type": "long"
          },
          "other_events_decoded": {
            "type": "long"
          },
          "other_events_edps": {
            "type": "long"
          },
          "rootcheck_edps": {
            "type": "long"
          },
          "rootcheck_events_decoded": {
            "type": "long"
          },
          "rootcheck_queue_size": {
            "type": "long"
          },
          "rootcheck_queue_usage": {
            "type": "long"
          },
          "rule_matching_queue_size": {
            "type": "long"
          },
          "rule_matching_queue_usage": {
            "type": "long"
          },
          "sca_edps": {
            "type": "long"
          },
          "sca_events_decoded": {
            "type": "long"
          },
          "sca_queue_size": {
            "type": "long"
          },
          "sca_queue_usage": {
            "type": "long"
          },
          "statistical_queue_size": {
            "type": "long"
          },
          "statistical_queue_usage": {
            "type": "long"
          },
          "syscheck_edps": {
            "type": "long"
          },
          "syscheck_events_decoded": {
            "type": "long"
          },
          "syscheck_queue_size": {
            "type": "long"
          },
          "syscheck_queue_usage": {
            "type": "long"
          },
          "syscollector_edps": {
            "type": "long"
          },
          "syscollector_events_decoded": {
            "type": "long"
          },
          "syscollector_queue_size": {
            "type": "long"
          },
          "syscollector_queue_usage": {
            "type": "long"
          },
          "total_events_decoded": {
            "type": "long"
          },
          "upgrade_queue_size": {
            "type": "long"
          },
          "upgrade_queue_usage": {
            "type": "long"
          },
          "winevt_edps": {
            "type": "long"
          },
          "winevt_events_decoded": {
            "type": "long"
          },
          "winevt_queue_size": {
            "type": "long"
          },
          "winevt_queue_usage": {
            "type": "long"
          }
        }
      },
      "apiName": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "cluster": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "nodeName": {
        "type": "text",
        "fields": {
          "keyword": {
            "type": "keyword",
            "ignore_above": 256
          }
        }
      },
      "name": {
        "type": "keyword"
      },
      "remoted": {
        "properties": {
          "ctrl_msg_count": {
            "type": "long"
          },
          "dequeued_after_close": {
            "type": "long"
          },
          "discarded_count": {
            "type": "long"
          },
          "evt_count": {
            "type": "long"
          },
          "msg_sent": {
            "type": "long"
          },
          "queue_size": {
            "type": "keyword"
          },
          "recv_bytes": {
            "type": "long"
          },
          "tcp_sessions": {
            "type": "long"
          },
          "total_queue_size": {
            "type": "long"
          }
        }
      },
      "status": {
        "type": "keyword"
      },
      "timestamp": {
        "type": "date",
        "format": "dateOptionalTime"
      }
    }
  }
};
exports.statisticsTemplate = statisticsTemplate;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInN0YXRpc3RpY3MtdGVtcGxhdGUudHMiXSwibmFtZXMiOlsic3RhdGlzdGljc1RlbXBsYXRlIiwib3JkZXIiLCJzZXR0aW5ncyJdLCJtYXBwaW5ncyI6Ijs7Ozs7OztBQUFBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDTyxNQUFNQSxrQkFBa0IsR0FBRztBQUNoQ0MsRUFBQUEsS0FBSyxFQUFFLENBRHlCO0FBRWhDQyxFQUFBQSxRQUFRLEVBQUU7QUFDUiw4QkFBMEI7QUFEbEIsR0FGc0I7QUFLaEMsY0FBYTtBQUNYLHlCQUFzQixDQUNwQjtBQUNFLDJCQUFzQjtBQUNwQiw4QkFBdUIsUUFESDtBQUVwQixtQkFBWTtBQUNWLGtCQUFTO0FBREM7QUFGUTtBQUR4QixLQURvQixDQURYO0FBV1gsa0JBQWU7QUFDYixtQkFBYztBQUNaLHNCQUFlO0FBQ2IsK0JBQXNCO0FBQ3BCLG9CQUFTO0FBRFcsV0FEVDtBQUliLGdDQUF1QjtBQUNyQixvQkFBUztBQURZLFdBSlY7QUFPYiw0QkFBbUI7QUFDakIsb0JBQVM7QUFEUSxXQVBOO0FBVWIsaUNBQXdCO0FBQ3RCLG9CQUFTO0FBRGEsV0FWWDtBQWFiLGtDQUF5QjtBQUN2QixvQkFBUztBQURjLFdBYlo7QUFnQmIseUJBQWdCO0FBQ2Qsb0JBQVM7QUFESyxXQWhCSDtBQW1CYix3Q0FBK0I7QUFDN0Isb0JBQVM7QUFEb0IsV0FuQmxCO0FBc0JiLCtCQUFzQjtBQUNwQixvQkFBUztBQURXLFdBdEJUO0FBeUJiLGdDQUF1QjtBQUNyQixvQkFBUztBQURZLFdBekJWO0FBNEJiLDhCQUFxQjtBQUNuQixvQkFBUztBQURVLFdBNUJSO0FBK0JiLCtCQUFzQjtBQUNwQixvQkFBUztBQURXLFdBL0JUO0FBa0NiLDRCQUFtQjtBQUNqQixvQkFBUztBQURRLFdBbENOO0FBcUNiLHlCQUFnQjtBQUNkLG9CQUFTO0FBREssV0FyQ0g7QUF3Q2IsOEJBQXFCO0FBQ25CLG9CQUFTO0FBRFUsV0F4Q1I7QUEyQ2IsNkJBQW9CO0FBQ2xCLG9CQUFTO0FBRFMsV0EzQ1A7QUE4Q2IsaUNBQXdCO0FBQ3RCLG9CQUFTO0FBRGEsV0E5Q1g7QUFpRGIsa0NBQXlCO0FBQ3ZCLG9CQUFTO0FBRGMsV0FqRFo7QUFvRGIsOEJBQXFCO0FBQ25CLG9CQUFTO0FBRFUsV0FwRFI7QUF1RGIseUJBQWdCO0FBQ2Qsb0JBQVM7QUFESyxXQXZESDtBQTBEYiwyQkFBa0I7QUFDaEIsb0JBQVM7QUFETyxXQTFETDtBQTZEYixxQ0FBNEI7QUFDMUIsb0JBQVM7QUFEaUIsV0E3RGY7QUFnRWIsaUNBQXdCO0FBQ3RCLG9CQUFTO0FBRGEsV0FoRVg7QUFtRWIsa0NBQXlCO0FBQ3ZCLG9CQUFTO0FBRGMsV0FuRVo7QUFzRWIsa0NBQXlCO0FBQ3ZCLG9CQUFTO0FBRGMsV0F0RVo7QUF5RWIsK0JBQXNCO0FBQ3BCLG9CQUFTO0FBRFcsV0F6RVQ7QUE0RWIsNEJBQW1CO0FBQ2pCLG9CQUFTO0FBRFEsV0E1RU47QUErRWIsc0NBQTZCO0FBQzNCLG9CQUFTO0FBRGtCLFdBL0VoQjtBQWtGYixrQ0FBeUI7QUFDdkIsb0JBQVM7QUFEYyxXQWxGWjtBQXFGYixtQ0FBMEI7QUFDeEIsb0JBQVM7QUFEZSxXQXJGYjtBQXdGYixzQ0FBNkI7QUFDM0Isb0JBQVM7QUFEa0IsV0F4RmhCO0FBMkZiLHVDQUE4QjtBQUM1QixvQkFBUztBQURtQixXQTNGakI7QUE4RmIsc0JBQWE7QUFDWCxvQkFBUztBQURFLFdBOUZBO0FBaUdiLGdDQUF1QjtBQUNyQixvQkFBUztBQURZLFdBakdWO0FBb0diLDRCQUFtQjtBQUNqQixvQkFBUztBQURRLFdBcEdOO0FBdUdiLDZCQUFvQjtBQUNsQixvQkFBUztBQURTLFdBdkdQO0FBMEdiLG9DQUEyQjtBQUN6QixvQkFBUztBQURnQixXQTFHZDtBQTZHYixxQ0FBNEI7QUFDMUIsb0JBQVM7QUFEaUIsV0E3R2Y7QUFnSGIsMkJBQWtCO0FBQ2hCLG9CQUFTO0FBRE8sV0FoSEw7QUFtSGIscUNBQTRCO0FBQzFCLG9CQUFTO0FBRGlCLFdBbkhmO0FBc0hiLGlDQUF3QjtBQUN0QixvQkFBUztBQURhLFdBdEhYO0FBeUhiLGtDQUF5QjtBQUN2QixvQkFBUztBQURjLFdBekhaO0FBNEhiLCtCQUFzQjtBQUNwQixvQkFBUztBQURXLFdBNUhUO0FBK0hiLHlDQUFnQztBQUM5QixvQkFBUztBQURxQixXQS9IbkI7QUFrSWIscUNBQTRCO0FBQzFCLG9CQUFTO0FBRGlCLFdBbElmO0FBcUliLHNDQUE2QjtBQUMzQixvQkFBUztBQURrQixXQXJJaEI7QUF3SWIsa0NBQXlCO0FBQ3ZCLG9CQUFTO0FBRGMsV0F4SVo7QUEySWIsZ0NBQXVCO0FBQ3JCLG9CQUFTO0FBRFksV0EzSVY7QUE4SWIsaUNBQXdCO0FBQ3RCLG9CQUFTO0FBRGEsV0E5SVg7QUFpSmIseUJBQWdCO0FBQ2Qsb0JBQVM7QUFESyxXQWpKSDtBQW9KYixtQ0FBMEI7QUFDeEIsb0JBQVM7QUFEZSxXQXBKYjtBQXVKYiwrQkFBc0I7QUFDcEIsb0JBQVM7QUFEVyxXQXZKVDtBQTBKYixnQ0FBdUI7QUFDckIsb0JBQVM7QUFEWTtBQTFKVjtBQURILE9BREQ7QUFpS2IsaUJBQVk7QUFDVixnQkFBUyxNQURDO0FBRVYsa0JBQVc7QUFDVCxxQkFBWTtBQUNWLG9CQUFTLFNBREM7QUFFViw0QkFBaUI7QUFGUDtBQURIO0FBRkQsT0FqS0M7QUEwS2IsaUJBQVk7QUFDVixnQkFBUyxNQURDO0FBRVYsa0JBQVc7QUFDVCxxQkFBWTtBQUNWLG9CQUFTLFNBREM7QUFFViw0QkFBaUI7QUFGUDtBQURIO0FBRkQsT0ExS0M7QUFtTGIsa0JBQWE7QUFDWCxnQkFBUyxNQURFO0FBRVgsa0JBQVc7QUFDVCxxQkFBWTtBQUNWLG9CQUFTLFNBREM7QUFFViw0QkFBaUI7QUFGUDtBQURIO0FBRkEsT0FuTEE7QUE0TGIsY0FBUztBQUNQLGdCQUFTO0FBREYsT0E1TEk7QUErTGIsaUJBQVk7QUFDVixzQkFBZTtBQUNiLDRCQUFtQjtBQUNqQixvQkFBUztBQURRLFdBRE47QUFJYixrQ0FBeUI7QUFDdkIsb0JBQVM7QUFEYyxXQUpaO0FBT2IsNkJBQW9CO0FBQ2xCLG9CQUFTO0FBRFMsV0FQUDtBQVViLHVCQUFjO0FBQ1osb0JBQVM7QUFERyxXQVZEO0FBYWIsc0JBQWE7QUFDWCxvQkFBUztBQURFLFdBYkE7QUFnQmIsd0JBQWU7QUFDYixvQkFBUztBQURJLFdBaEJGO0FBbUJiLHdCQUFlO0FBQ2Isb0JBQVM7QUFESSxXQW5CRjtBQXNCYiwwQkFBaUI7QUFDZixvQkFBUztBQURNLFdBdEJKO0FBeUJiLDhCQUFxQjtBQUNuQixvQkFBUztBQURVO0FBekJSO0FBREwsT0EvTEM7QUE4TmIsZ0JBQVc7QUFDVCxnQkFBUztBQURBLE9BOU5FO0FBaU9iLG1CQUFjO0FBQ1osZ0JBQVMsTUFERztBQUVaLGtCQUFXO0FBRkM7QUFqT0Q7QUFYSjtBQUxtQixDQUEzQiIsInNvdXJjZXNDb250ZW50IjpbIi8qXG4gKiBXYXp1aCBhcHAgLSBNb2R1bGUgZm9yIHN0YXRpc3RpY3MgdGVtcGxhdGVcbiAqIENvcHlyaWdodCAoQykgMjAxNS0yMDIyIFdhenVoLCBJbmMuXG4gKlxuICogVGhpcyBwcm9ncmFtIGlzIGZyZWUgc29mdHdhcmU7IHlvdSBjYW4gcmVkaXN0cmlidXRlIGl0IGFuZC9vciBtb2RpZnlcbiAqIGl0IHVuZGVyIHRoZSB0ZXJtcyBvZiB0aGUgR05VIEdlbmVyYWwgUHVibGljIExpY2Vuc2UgYXMgcHVibGlzaGVkIGJ5XG4gKiB0aGUgRnJlZSBTb2Z0d2FyZSBGb3VuZGF0aW9uOyBlaXRoZXIgdmVyc2lvbiAyIG9mIHRoZSBMaWNlbnNlLCBvclxuICogKGF0IHlvdXIgb3B0aW9uKSBhbnkgbGF0ZXIgdmVyc2lvbi5cbiAqXG4gKiBGaW5kIG1vcmUgaW5mb3JtYXRpb24gYWJvdXQgdGhpcyBvbiB0aGUgTElDRU5TRSBmaWxlLlxuICovXG5leHBvcnQgY29uc3Qgc3RhdGlzdGljc1RlbXBsYXRlID0ge1xuICBvcmRlcjogMCxcbiAgc2V0dGluZ3M6IHtcbiAgICAnaW5kZXgucmVmcmVzaF9pbnRlcnZhbCc6ICc1cydcbiAgfSxcbiAgXCJtYXBwaW5nc1wiIDoge1xuICAgIFwiZHluYW1pY190ZW1wbGF0ZXNcIiA6IFtcbiAgICAgIHtcbiAgICAgICAgXCJzdHJpbmdfYXNfa2V5d29yZFwiIDoge1xuICAgICAgICAgIFwibWF0Y2hfbWFwcGluZ190eXBlXCIgOiBcInN0cmluZ1wiLFxuICAgICAgICAgIFwibWFwcGluZ1wiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImtleXdvcmRcIlxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfVxuICAgIF0sXG4gICAgXCJwcm9wZXJ0aWVzXCIgOiB7XG4gICAgICBcImFuYWx5c2lzZFwiIDoge1xuICAgICAgICBcInByb3BlcnRpZXNcIiA6IHtcbiAgICAgICAgICBcImFsZXJ0c19xdWV1ZV9zaXplXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImFsZXJ0c19xdWV1ZV91c2FnZVwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJhbGVydHNfd3JpdHRlblwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJhcmNoaXZlc19xdWV1ZV9zaXplXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImFyY2hpdmVzX3F1ZXVlX3VzYWdlXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImRic3luY19tZHBzXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImRic3luY19tZXNzYWdlc19kaXNwYXRjaGVkXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImRic3luY19xdWV1ZV9zaXplXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImRic3luY19xdWV1ZV91c2FnZVwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJldmVudF9xdWV1ZV9zaXplXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImV2ZW50X3F1ZXVlX3VzYWdlXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImV2ZW50c19kcm9wcGVkXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImV2ZW50c19lZHBzXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImV2ZW50c19wcm9jZXNzZWRcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwiZXZlbnRzX3JlY2VpdmVkXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImZpcmV3YWxsX3F1ZXVlX3NpemVcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwiZmlyZXdhbGxfcXVldWVfdXNhZ2VcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwiZmlyZXdhbGxfd3JpdHRlblwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJmdHNfd3JpdHRlblwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJob3N0aW5mb19lZHBzXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImhvc3RpbmZvX2V2ZW50c19kZWNvZGVkXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcImhvc3RpbmZvX3F1ZXVlX3NpemVcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwiaG9zdGluZm9fcXVldWVfdXNhZ2VcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwib3RoZXJfZXZlbnRzX2RlY29kZWRcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwib3RoZXJfZXZlbnRzX2VkcHNcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwicm9vdGNoZWNrX2VkcHNcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwicm9vdGNoZWNrX2V2ZW50c19kZWNvZGVkXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInJvb3RjaGVja19xdWV1ZV9zaXplXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInJvb3RjaGVja19xdWV1ZV91c2FnZVwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJydWxlX21hdGNoaW5nX3F1ZXVlX3NpemVcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwicnVsZV9tYXRjaGluZ19xdWV1ZV91c2FnZVwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJzY2FfZWRwc1wiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJzY2FfZXZlbnRzX2RlY29kZWRcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwic2NhX3F1ZXVlX3NpemVcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwic2NhX3F1ZXVlX3VzYWdlXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInN0YXRpc3RpY2FsX3F1ZXVlX3NpemVcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwic3RhdGlzdGljYWxfcXVldWVfdXNhZ2VcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwic3lzY2hlY2tfZWRwc1wiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJzeXNjaGVja19ldmVudHNfZGVjb2RlZFwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJzeXNjaGVja19xdWV1ZV9zaXplXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInN5c2NoZWNrX3F1ZXVlX3VzYWdlXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInN5c2NvbGxlY3Rvcl9lZHBzXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInN5c2NvbGxlY3Rvcl9ldmVudHNfZGVjb2RlZFwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJzeXNjb2xsZWN0b3JfcXVldWVfc2l6ZVwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJzeXNjb2xsZWN0b3JfcXVldWVfdXNhZ2VcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwidG90YWxfZXZlbnRzX2RlY29kZWRcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwidXBncmFkZV9xdWV1ZV9zaXplXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInVwZ3JhZGVfcXVldWVfdXNhZ2VcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwid2luZXZ0X2VkcHNcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwid2luZXZ0X2V2ZW50c19kZWNvZGVkXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcIndpbmV2dF9xdWV1ZV9zaXplXCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcIndpbmV2dF9xdWV1ZV91c2FnZVwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIFwiYXBpTmFtZVwiIDoge1xuICAgICAgICBcInR5cGVcIiA6IFwidGV4dFwiLFxuICAgICAgICBcImZpZWxkc1wiIDoge1xuICAgICAgICAgIFwia2V5d29yZFwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImtleXdvcmRcIixcbiAgICAgICAgICAgIFwiaWdub3JlX2Fib3ZlXCIgOiAyNTZcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBcImNsdXN0ZXJcIiA6IHtcbiAgICAgICAgXCJ0eXBlXCIgOiBcInRleHRcIixcbiAgICAgICAgXCJmaWVsZHNcIiA6IHtcbiAgICAgICAgICBcImtleXdvcmRcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJrZXl3b3JkXCIsXG4gICAgICAgICAgICBcImlnbm9yZV9hYm92ZVwiIDogMjU2XG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9LFxuICAgICAgXCJub2RlTmFtZVwiIDoge1xuICAgICAgICBcInR5cGVcIiA6IFwidGV4dFwiLFxuICAgICAgICBcImZpZWxkc1wiIDoge1xuICAgICAgICAgIFwia2V5d29yZFwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImtleXdvcmRcIixcbiAgICAgICAgICAgIFwiaWdub3JlX2Fib3ZlXCIgOiAyNTZcbiAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICAgIH0sXG4gICAgICBcIm5hbWVcIiA6IHtcbiAgICAgICAgXCJ0eXBlXCIgOiBcImtleXdvcmRcIlxuICAgICAgfSwgXG4gICAgICBcInJlbW90ZWRcIiA6IHtcbiAgICAgICAgXCJwcm9wZXJ0aWVzXCIgOiB7XG4gICAgICAgICAgXCJjdHJsX21zZ19jb3VudFwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJkZXF1ZXVlZF9hZnRlcl9jbG9zZVwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJkaXNjYXJkZWRfY291bnRcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwiZXZ0X2NvdW50XCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcIm1zZ19zZW50XCIgOiB7XG4gICAgICAgICAgICBcInR5cGVcIiA6IFwibG9uZ1wiXG4gICAgICAgICAgfSxcbiAgICAgICAgICBcInF1ZXVlX3NpemVcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJrZXl3b3JkXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwicmVjdl9ieXRlc1wiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH0sXG4gICAgICAgICAgXCJ0Y3Bfc2Vzc2lvbnNcIiA6IHtcbiAgICAgICAgICAgIFwidHlwZVwiIDogXCJsb25nXCJcbiAgICAgICAgICB9LFxuICAgICAgICAgIFwidG90YWxfcXVldWVfc2l6ZVwiIDoge1xuICAgICAgICAgICAgXCJ0eXBlXCIgOiBcImxvbmdcIlxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSxcbiAgICAgIFwic3RhdHVzXCIgOiB7XG4gICAgICAgIFwidHlwZVwiIDogXCJrZXl3b3JkXCJcbiAgICAgIH0sXG4gICAgICBcInRpbWVzdGFtcFwiIDoge1xuICAgICAgICBcInR5cGVcIiA6IFwiZGF0ZVwiLFxuICAgICAgICBcImZvcm1hdFwiIDogXCJkYXRlT3B0aW9uYWxUaW1lXCJcbiAgICAgIH1cbiAgICB9XG4gIH1cbn07XG4iXX0=